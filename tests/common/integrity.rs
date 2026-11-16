//! Running a child of this process's own user at a chosen mandatory integrity level, and reading a
//! process's own level. Lowering one's own integrity needs no privilege and no elevation; the start
//! itself is [`account::spawn_with_token`](crate::account::spawn_with_token).
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use ssh_broker::acl::Sid;
use ssh_broker::winutil::OwnedHandle;
use windows::Win32::Foundation::{HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows::Win32::Security::{
    DuplicateTokenEx, GetLengthSid, GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, PSID,
    SID_AND_ATTRIBUTES, SecurityImpersonation, SetTokenInformation, TOKEN_ALL_ACCESS, TOKEN_DUPLICATE,
    TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TokenIntegrityLevel, TokenPrimary,
};
use windows::Win32::System::Threading::{CREATE_NO_WINDOW, GetCurrentProcess, OpenProcessToken};
use windows::core::PCWSTR;

use crate::account::{Starter, is_elevated, spawn_with_token, wide};
use crate::desktop::PrivateDesktop;

/// `SE_GROUP_INTEGRITY`: the attribute of a token's integrity label. The `windows` crate has it, with
/// the label RIDs, in `Win32::System::SystemServices`, a feature this crate does not enable.
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
        // The buffer is bytes, so the structure in it may be unaligned.
        let label = std::ptr::read_unaligned(buf.as_ptr().cast::<TOKEN_MANDATORY_LABEL>());
        let sid = label.Label.Sid;
        let count = *GetSidSubAuthorityCount(sid);
        *GetSidSubAuthority(sid, u32::from(count) - 1)
    }
}

/// A primary token that is a copy of this process's, with its mandatory integrity label set to `rid`.
/// Lowering the label (or keeping it) needs no privilege.
fn token_at(rid: u32) -> OwnedHandle {
    let mut own = HANDLE::default();
    let mut primary = HANDLE::default();
    let mut label_sid = PSID::default();
    // SAFETY: valid in/out handles and pointers; every handle is closed by `OwnedHandle`, the SID
    // allocation is freed below, and every buffer outlives the call that reads it.
    unsafe {
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

        ConvertStringSidToSidW(PCWSTR(wide(&format!("S-1-16-{rid}")).as_ptr()), &mut label_sid)
            .expect("parse the label SID");
        let label = TOKEN_MANDATORY_LABEL {
            Label: SID_AND_ATTRIBUTES {
                Sid: label_sid,
                Attributes: SE_GROUP_INTEGRITY,
            },
        };
        // The size is the structure and the SID it points at, as the API documents.
        let sid_len = GetLengthSid(label_sid);
        let set = SetTokenInformation(
            primary.0,
            TokenIntegrityLevel,
            &label as *const _ as *const core::ffi::c_void,
            std::mem::size_of::<TOKEN_MANDATORY_LABEL>() as u32 + sid_len,
        );
        let _ = LocalFree(Some(HLOCAL(label_sid.0)));
        set.unwrap_or_else(|e| panic!("set the token's integrity level to {rid:#x}: {e}"));
        primary
    }
}

/// Run `exe` with `command_line` as this process's user at mandatory integrity level `rid` ([`LOW`],
/// [`MEDIUM`]) and return its exit code. The child's token is a copy of this process's with only its
/// label set, so two levels differ in the integrity check and nothing else. It starts through
/// [`spawn_with_token`]; a child that does not exit fails the test with `evidence` printed.
///
/// An elevated process gives the child a window station and desktop of its own, labelled at `rid`: a
/// pair without a label is Medium, and a Low child cannot write to it. An unelevated process may not
/// name a window station, so the child takes this process's own, which an interactive user's Low
/// processes use anyway. The two supported contexts are therefore an elevated administrator (CI) and
/// an unelevated user on an interactive desktop (a workstation); an unelevated process with no
/// interactive desktop gives a Low child nothing it may use.
pub fn run_at(rid: u32, exe: &Path, command_line: &str, cwd: &Path, evidence: &[PathBuf]) -> u32 {
    let private = is_elevated().then(|| {
        let user = Sid::current_user().unwrap().to_sddl().unwrap();
        PrivateDesktop::create_labelled(&[&user], Some(rid))
            .unwrap_or_else(|e| panic!("create a window station and desktop at integrity {rid:#x}: {e}"))
    });
    let token = token_at(rid);
    let child = spawn_with_token(
        Starter::AsUser,
        token.0,
        &format!("this user at integrity {rid:#x}"),
        private,
        exe,
        command_line,
        cwd,
        evidence,
        None,
        None,
        CREATE_NO_WINDOW,
    );
    child.resume();
    child.wait()
}
