//! `CreateProcessWithLogonW` as the product would call it: `LOGON_WITH_PROFILE`, `CREATE_NO_WINDOW`,
//! no desktop given.

use std::path::Path;

use ssh_broker::winutil::OwnedHandle;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::Storage::FileSystem::{
    CREATE_ALWAYS, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE,
};
use windows::Win32::System::Threading::{
    CREATE_BREAKAWAY_FROM_JOB, CREATE_NO_WINDOW, CREATE_SUSPENDED, CreateProcessWithLogonW, LOGON_WITH_PROFILE,
    PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOW,
};
use windows::core::{BOOL, PCWSTR, PWSTR};

use crate::hard_errors;
use crate::rec::Rec;
use crate::win::wide;

pub struct Logon<'a> {
    pub user: &'a str,
    pub password: &'a str,
    pub exe: &'a Path,
    /// The command line after the quoted exe path.
    pub args: &'a str,
    pub breakaway: bool,
    /// Standard output and error of the new process go to this file.
    pub redirect_to: Option<&'a Path>,
}

pub struct Started {
    pub process: OwnedHandle,
    pub pid: u32,
}

/// Start the process. It starts suspended so its hard-error boxes can be switched off first (a
/// loader failure must end it, not wait on a box nobody answers); that step's outcome is recorded.
pub fn start(l: &Logon, rec: &Rec, prefix: &str) -> windows::core::Result<Started> {
    let mut command = wide(&format!("\"{}\" {}", l.exe.display(), l.args));
    let mut flags = CREATE_NO_WINDOW | CREATE_SUSPENDED;
    if l.breakaway {
        flags |= CREATE_BREAKAWAY_FROM_JOB;
    }
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: BOOL(1),
    };
    let redirect = match l.redirect_to {
        Some(path) => {
            // SAFETY: NUL-terminated path; the handle is closed by `OwnedHandle`.
            let file = unsafe {
                CreateFileW(
                    PCWSTR(wide(&path.to_string_lossy()).as_ptr()),
                    0x4000_0000, // GENERIC_WRITE
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    Some(&sa),
                    CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL,
                    None,
                )
            }?;
            Some(OwnedHandle(file))
        }
        None => None,
    };
    let mut startup = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    if let Some(file) = &redirect {
        startup.dwFlags = STARTF_USESTDHANDLES;
        startup.hStdOutput = file.0;
        startup.hStdError = file.0;
        startup.hStdInput = HANDLE::default();
    }
    let mut info = PROCESS_INFORMATION::default();
    // SAFETY: every pointer is to a local that outlives the call.
    unsafe {
        CreateProcessWithLogonW(
            PCWSTR(wide(l.user).as_ptr()),
            PCWSTR(wide(".").as_ptr()),
            PCWSTR(wide(l.password).as_ptr()),
            LOGON_WITH_PROFILE,
            PCWSTR(wide(&l.exe.to_string_lossy()).as_ptr()),
            Some(PWSTR(command.as_mut_ptr())),
            flags,
            None,
            PCWSTR::null(),
            &startup,
            &mut info,
        )
    }?;
    let process = OwnedHandle(info.hProcess);
    let thread = OwnedHandle(info.hThread);
    match hard_errors::suppress_hard_error_boxes(process.0) {
        Ok(()) => rec.put(&format!("{prefix}.hard_error_boxes_off"), "true"),
        Err(e) => rec.err(&format!("{prefix}.hard_error_boxes_off"), &e),
    }
    // SAFETY: the primary thread of the process just created.
    if unsafe { ResumeThread(thread.0) } == u32::MAX {
        let e = windows::core::Error::from_thread();
        crate::win::terminate(process.0);
        return Err(e);
    }
    Ok(Started {
        process,
        pid: info.dwProcessId,
    })
}
