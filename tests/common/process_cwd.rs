//! The working directory of another process, read from its `PEB`, for a test that measures what a
//! service runs in. Elevated (CI only): reading a service's memory needs `SeDebugPrivilege`.
#![allow(dead_code)]

use std::ffi::c_void;
use std::path::PathBuf;

use ssh_broker::winutil::OwnedHandle;
use windows::Wdk::System::Threading::{NtQueryInformationProcess, ProcessBasicInformation};
use windows::Win32::Foundation::{ERROR_SUCCESS, GetLastError, HANDLE, LUID, UNICODE_STRING};
use windows::Win32::Security::{
    AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_DEBUG_NAME, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PEB, PROCESS_BASIC_INFORMATION, PROCESS_QUERY_INFORMATION,
    PROCESS_VM_READ,
};
use windows::core::PCWSTR;

/// Enable `SeDebugPrivilege` on this process (held, disabled, by an elevated administrator).
pub fn enable_debug_privilege() {
    // SAFETY: plain calls with valid out pointers; the token is closed by `OwnedHandle`.
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token)
            .expect("open this process's token");
        let _token = OwnedHandle(token);
        let mut luid = LUID::default();
        LookupPrivilegeValueW(PCWSTR::null(), SE_DEBUG_NAME, &mut luid).expect("look up SeDebugPrivilege");
        let privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        AdjustTokenPrivileges(token, false, Some(&privileges), 0, None, None).expect("enable SeDebugPrivilege");
        // AdjustTokenPrivileges succeeds even when it assigned nothing; that case is an error here.
        assert_eq!(
            GetLastError(),
            ERROR_SUCCESS,
            "SeDebugPrivilege is not held: run elevated"
        );
    }
}

/// Read `size_of::<T>()` bytes of `process` at `address`.
fn read<T: Default>(process: HANDLE, address: *const c_void) -> Result<T, String> {
    let mut value = T::default();
    // SAFETY: `value` is a valid buffer of the size passed; `process` has `PROCESS_VM_READ`.
    unsafe {
        ReadProcessMemory(
            process,
            address,
            &mut value as *mut T as *mut c_void,
            std::mem::size_of::<T>(),
            None,
        )
    }
    .map_err(|e| format!("ReadProcessMemory at {address:p}: {e}"))?;
    Ok(value)
}

/// The current directory of process `pid`: the `CurrentDirectory.DosPath` of its process parameters.
/// Needs [`enable_debug_privilege`] for a service.
pub fn current_directory(pid: u32) -> Result<PathBuf, String> {
    // SAFETY: a plain open by id; the handle is closed by `OwnedHandle`.
    let process = OwnedHandle(
        unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) }
            .map_err(|e| format!("OpenProcess({pid}): {e}"))?,
    );
    let mut info = PROCESS_BASIC_INFORMATION::default();
    // SAFETY: `info` is a valid out buffer of the size passed; `process` has query access.
    unsafe {
        NtQueryInformationProcess(
            process.0,
            ProcessBasicInformation,
            &mut info as *mut PROCESS_BASIC_INFORMATION as *mut c_void,
            std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            std::ptr::null_mut(),
        )
    }
    .ok()
    .map_err(|e| format!("NtQueryInformationProcess({pid}): {e}"))?;
    let peb: PEB = read(process.0, info.PebBaseAddress as *const c_void)?;
    // `RTL_USER_PROCESS_PARAMETERS.CurrentDirectory.DosPath` follows the two lengths, the flags, the
    // console handle and flags and the three standard handles: at 0x38 in a 64-bit process, 0x24 in a 32-bit one.
    let dos_path_offset = if size_of::<usize>() == 8 { 0x38 } else { 0x24 };
    let dos_path: UNICODE_STRING = read(
        process.0,
        (peb.ProcessParameters as usize + dos_path_offset) as *const c_void,
    )?;
    let mut units = vec![0u16; dos_path.Length as usize / 2];
    // SAFETY: `units` is a valid buffer of `Length` bytes; `process` has `PROCESS_VM_READ`.
    unsafe {
        ReadProcessMemory(
            process.0,
            dos_path.Buffer.0 as *const c_void,
            units.as_mut_ptr() as *mut c_void,
            dos_path.Length as usize,
            None,
        )
    }
    .map_err(|e| format!("ReadProcessMemory of the path of process {pid}: {e}"))?;
    Ok(PathBuf::from(String::from_utf16_lossy(&units)))
}
