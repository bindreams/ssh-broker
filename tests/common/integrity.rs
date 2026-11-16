//! Running a child of this process's own user at a lower mandatory integrity level, and reading a
//! process's own level. Lowering one's own integrity needs no privilege and no elevation.
#![allow(dead_code)]

use std::path::Path;

use ssh_broker::winutil::OwnedHandle;
use windows::Win32::Foundation::{HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows::Win32::Security::{
    DuplicateTokenEx, GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, PSID, SID_AND_ATTRIBUTES,
    SecurityImpersonation, SetTokenInformation, TOKEN_ALL_ACCESS, TOKEN_DUPLICATE, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
    TokenIntegrityLevel, TokenPrimary,
};
use windows::Win32::System::Threading::{
    CREATE_NO_WINDOW, CreateProcessAsUserW, GetCurrentProcess, OpenProcessToken, PROCESS_INFORMATION, STARTUPINFOW,
    TerminateProcess,
};
use windows::core::{PCWSTR, PWSTR};

use crate::account::wide;
use crate::{bounded_wait, hard_errors};

/// `SE_GROUP_INTEGRITY`: the attribute of a token's integrity label (the `windows` crate has no constant).
const SE_GROUP_INTEGRITY: u32 = 0x20;

/// The relative id of the Low mandatory label, `S-1-16-4096`.
pub const LOW: u32 = 0x1000;
/// The relative id of the Medium mandatory label, `S-1-16-8192`.
pub const MEDIUM: u32 = 0x2000;

/// This process's mandatory integrity level, as the relative id of its label SID.
pub fn current_rid() -> u32 {
    let mut token = HANDLE::default();
    // SAFETY: valid out-pointers; the token is closed by `OwnedHandle`. The label SID is read out
    // of a buffer that outlives the reads.
    unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).expect("open the process token");
        let token = OwnedHandle(token);
        let mut len = 0u32;
        let _ = GetTokenInformation(token.0, TokenIntegrityLevel, None, 0, &mut len);
        let mut buf = vec![0u8; len as usize];
        GetTokenInformation(
            token.0,
            TokenIntegrityLevel,
            Some(buf.as_mut_ptr().cast()),
            len,
            &mut len,
        )
        .expect("read the token's integrity level");
        let label = &*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL);
        let sid = label.Label.Sid;
        let count = *GetSidSubAuthorityCount(sid);
        *GetSidSubAuthority(sid, u32::from(count) - 1)
    }
}

/// Start `exe` with `command_line` as this process's user at the Low integrity level and return its
/// exit code. The child is a copy of this process's token with only its label lowered, so what
/// separates it from a Medium child is the integrity check and nothing else. A child that does not
/// exit fails the test through [`bounded_wait`].
pub fn run_at_low(exe: &Path, command_line: &str, cwd: &Path) -> u32 {
    let mut own = HANDLE::default();
    let mut primary = HANDLE::default();
    let mut low_sid = PSID::default();
    // SAFETY: valid in/out handles and pointers; every handle is closed by `OwnedHandle`, the SID
    // allocation is freed below, and every buffer outlives the call that reads it.
    let (process, pid) = unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &mut own).expect("open the process token");
        let own = OwnedHandle(own);
        DuplicateTokenEx(
            own.0,
            TOKEN_ALL_ACCESS,
            None,
            SecurityImpersonation,
            TokenPrimary,
            &mut primary,
        )
        .expect("duplicate the token as a primary token");
        let primary = OwnedHandle(primary);

        ConvertStringSidToSidW(PCWSTR(wide("S-1-16-4096").as_ptr()), &mut low_sid).expect("parse the Low label SID");
        let label = TOKEN_MANDATORY_LABEL {
            Label: SID_AND_ATTRIBUTES {
                Sid: low_sid,
                Attributes: SE_GROUP_INTEGRITY,
            },
        };
        // The size is the structure and the SID it points at, as the API documents.
        let sid_len = windows::Win32::Security::GetLengthSid(low_sid);
        SetTokenInformation(
            primary.0,
            TokenIntegrityLevel,
            &label as *const _ as *const core::ffi::c_void,
            std::mem::size_of::<TOKEN_MANDATORY_LABEL>() as u32 + sid_len,
        )
        .expect("lower the token's integrity level to Low");

        let mut command = wide(command_line);
        let exe_w = wide(&exe.to_string_lossy());
        let cwd_w = wide(&cwd.to_string_lossy());
        let startup = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            ..Default::default()
        };
        let mut info = PROCESS_INFORMATION::default();
        let created = CreateProcessAsUserW(
            Some(primary.0),
            PCWSTR(exe_w.as_ptr()),
            Some(PWSTR(command.as_mut_ptr())),
            None,
            None,
            false,
            CREATE_NO_WINDOW,
            None,
            PCWSTR(cwd_w.as_ptr()),
            &startup,
            &mut info,
        );
        let _ = LocalFree(Some(HLOCAL(low_sid.0)));
        created.unwrap_or_else(|e| panic!("start {exe:?} at Low integrity: {e}"));
        let _ = OwnedHandle(info.hThread);
        (OwnedHandle(info.hProcess), info.dwProcessId)
    };
    if let Err(e) = hard_errors::suppress_hard_error_boxes(process.0) {
        // SAFETY: the handle is the live process created above.
        let _ = unsafe { TerminateProcess(process.0, 1) };
        panic!("switch off the hard-error boxes of {exe:?}: {e}");
    }
    bounded_wait::wait_for_exit(
        process.0,
        pid,
        &format!("{exe:?} at Low integrity"),
        bounded_wait::CHILD_EXIT_BOUND,
        &[],
    )
}
