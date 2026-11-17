//! A copy of this process's own token, and one with its mandatory integrity label set. One source for both
//! homes: the integration tests include it with `#[path]`, and so does the unit tests' `src/test_support.rs`.
//! It needs only `std` and `windows`, so it neither names the crate (the library cannot, the tests do it
//! under another path) nor returns its `OwnedHandle`: the caller wraps the handle and hands over
//! `SE_GROUP_INTEGRITY` from `winutil`.
#![allow(dead_code)]

use windows::Win32::Foundation::{HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows::Win32::Security::{
    DuplicateTokenEx, GetLengthSid, PSID, SID_AND_ATTRIBUTES, SecurityImpersonation, SetTokenInformation,
    TOKEN_ALL_ACCESS, TOKEN_DUPLICATE, TOKEN_MANDATORY_LABEL, TokenIntegrityLevel, TokenPrimary,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::PCWSTR;

/// A primary token with all access that is a copy of this process's. The caller closes it.
pub fn own_token_copy() -> HANDLE {
    let mut own = HANDLE::default();
    let mut copy = HANDLE::default();
    // SAFETY: valid out-pointers; the source handle is closed before the return, the copy is the caller's.
    unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE, &mut own).expect("open the process token");
        let duplicated = DuplicateTokenEx(
            own,
            TOKEN_ALL_ACCESS,
            None,
            SecurityImpersonation,
            TokenPrimary,
            &mut copy,
        );
        let _ = windows::Win32::Foundation::CloseHandle(own);
        duplicated.expect("copy the process token as a primary token");
    }
    copy
}

/// [`own_token_copy`] with its mandatory integrity label set to `rid` (`ssh_broker::account::INTEGRITY_*`);
/// `se_group_integrity` is `ssh_broker::winutil::SE_GROUP_INTEGRITY`. Setting a level above the process's
/// own needs a privilege and fails, so a level at or below it is the only one a test can ask for.
pub fn own_token_at(rid: u32, se_group_integrity: u32) -> HANDLE {
    let token = own_token_copy();
    let mut sid: Vec<u16> = format!("S-1-16-{rid}").encode_utf16().collect();
    sid.push(0);
    let mut label_sid = PSID::default();
    // SAFETY: valid pointers; the SID allocation is freed below, and every buffer outlives the call that
    // reads it.
    unsafe {
        ConvertStringSidToSidW(PCWSTR(sid.as_ptr()), &mut label_sid).expect("parse the label SID");
        let label = TOKEN_MANDATORY_LABEL {
            Label: SID_AND_ATTRIBUTES {
                Sid: label_sid,
                Attributes: se_group_integrity,
            },
        };
        // The size is the structure and the SID it points to, as the API documents.
        let set = SetTokenInformation(
            token,
            TokenIntegrityLevel,
            (&raw const label).cast(),
            size_of::<TOKEN_MANDATORY_LABEL>() as u32 + GetLengthSid(label_sid),
        );
        let _ = LocalFree(Some(HLOCAL(label_sid.0)));
        set.unwrap_or_else(|e| panic!("set the token's integrity level to {rid:#x}: {e}"));
    }
    token
}
