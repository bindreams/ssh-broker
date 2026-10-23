//! Keeping a child's loader failure from becoming a message box nobody can answer.
//!
//! A process that fails to load (a missing DLL, a failed DLL initializer) asks the system to show
//! a message box and waits for the answer. On a CI runner no desktop is there to answer, so the
//! child, and the test waiting for it, never end. With the process's hard-error boxes switched
//! off, the loader ends the process with the failing NTSTATUS as its exit code instead.
#![allow(dead_code)]

use std::ffi::c_void;

use windows::Wdk::System::Threading::{NtQueryInformationProcess, PROCESSINFOCLASS, ProcessDefaultHardErrorMode};
use windows::Win32::Foundation::{HANDLE, NTSTATUS};

#[link(name = "ntdll", kind = "raw-dylib")]
unsafe extern "system" {
    fn NtSetInformationProcess(
        process: HANDLE,
        class: PROCESSINFOCLASS,
        information: *const c_void,
        length: u32,
    ) -> NTSTATUS;
}

/// `SEM_NOGPFAULTERRORBOX` in the value of `ProcessDefaultHardErrorMode`, which is the Win32
/// error mode with `SEM_FAILCRITICALERRORS` (bit 0) inverted: set means boxes are raised.
const NO_GP_FAULT_ERROR_BOX: u32 = 0x2;
const RAISE_HARD_ERROR_BOXES: u32 = 0x1;

fn mode(process: HANDLE) -> windows::core::Result<u32> {
    let mut value = 0u32;
    // SAFETY: `value` is a valid 4-byte out buffer; `process` is a live handle with query access.
    unsafe {
        NtQueryInformationProcess(
            process,
            ProcessDefaultHardErrorMode,
            &mut value as *mut u32 as *mut c_void,
            4,
            std::ptr::null_mut(),
        )
    }
    .ok()?;
    Ok(value)
}

/// Whether `process` would show a message box for a hard error such as a loader failure.
pub fn raises_hard_error_boxes(process: HANDLE) -> bool {
    mode(process).expect("NtQueryInformationProcess(ProcessDefaultHardErrorMode)") & RAISE_HARD_ERROR_BOXES != 0
}

/// Switch off the hard-error boxes (and the crash dialog) of `process`, which must not have run
/// yet: a child created suspended. The setting is the process's own, so it does not depend on
/// what the creator's error mode was, nor on whether a launcher service passed it on.
pub fn suppress_hard_error_boxes(process: HANDLE) -> windows::core::Result<()> {
    let value = (mode(process)? & !RAISE_HARD_ERROR_BOXES) | NO_GP_FAULT_ERROR_BOX;
    // SAFETY: `value` is a valid 4-byte buffer; `process` is a live handle with set access.
    unsafe {
        NtSetInformationProcess(
            process,
            ProcessDefaultHardErrorMode,
            &value as *const u32 as *const c_void,
            4,
        )
    }
    .ok()
}

/// An exit code for a failure message: decimal for an ordinary one, hex with the name of the
/// loader's NTSTATUS when it is one the loader ends a process with.
pub fn describe_exit(code: u32) -> String {
    let name = match code {
        0xC000_0005 => "STATUS_ACCESS_VIOLATION",
        0xC000_0022 => "STATUS_ACCESS_DENIED",
        0xC000_007B => "STATUS_INVALID_IMAGE_FORMAT",
        0xC000_0135 => "STATUS_DLL_NOT_FOUND",
        0xC000_0139 => "STATUS_ENTRYPOINT_NOT_FOUND",
        0xC000_0142 => "STATUS_DLL_INIT_FAILED",
        _ if code < 0xC000_0000 => return code.to_string(),
        _ => return format!("{code:#010x}"),
    };
    format!("{code:#010x} ({name})")
}
