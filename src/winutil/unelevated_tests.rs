//! Unit tests for `winutil::unelevated`. They start a `cmd /c exit 0` child of the test and read its token;
//! they change no machine state, and run the same in an elevated process (where the token is cut down) and
//! an ordinary one (where it is the token the process has). The elevated half is
//! `tests/unelevated_token_windows.rs`.
use super::*;
use crate::account::{Elevation, INTEGRITY_MEDIUM, elevation, elevation_of, integrity_of};
use crate::winutil::{ChildConsole, spawn_suspended, token_information};
use windows::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION, AclSizeInformation, GetAce, GetAclInformation, TOKEN_DEFAULT_DACL,
    TOKEN_QUERY, TokenDefaultDacl,
};
use windows::Win32::System::Threading::{OpenProcessToken, TerminateProcess};

/// Start `cmd /c exit 0` suspended with `token`, and hand its token to `read`; the child is ended after.
fn with_child_token<R>(token: &UnelevatedToken, read: impl FnOnce(HANDLE) -> R) -> R {
    let null = HANDLE::default();
    // SAFETY: no handles are passed; the child is suspended and ended below.
    let (process, _thread) = unsafe {
        spawn_suspended(
            "cmd.exe /c exit 0",
            None,
            ChildConsole::NoWindow,
            [null; 3],
            &[],
            Some(token),
        )
    }
    .expect("start a child with the unelevated token");
    let mut child_token = HANDLE::default();
    // SAFETY: the suspended process just created; the handle is closed by `OwnedHandle`.
    unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &mut child_token) }.expect("open the child's token");
    let child_token = OwnedHandle(child_token);
    let result = read(child_token.0);
    // SAFETY: the suspended process just created.
    unsafe { TerminateProcess(process.0, 1) }.expect("end the suspended child");
    result
}

/// The child is at Medium integrity, and its token no longer carries the administrator's power: an
/// elevated process's token becomes `Filtered`, and any other keeps the elevation it had.
#[test]
fn a_child_started_with_the_token_is_at_medium_integrity_and_not_elevated() {
    let own = elevation().unwrap();
    let token = UnelevatedToken::of_this_process().expect("make the token");
    let (integrity, got) = with_child_token(&token, |child| {
        (integrity_of(child).unwrap(), elevation_of(child).unwrap())
    });
    assert_eq!(integrity, INTEGRITY_MEDIUM);
    let expected = if own == Elevation::Full {
        Elevation::Filtered
    } else {
        own
    };
    assert_eq!(got, expected);
}

/// The default DACL is the one UAC's filtered token has: the user, SYSTEM and the logon session, with the
/// rights it gives them. The elevated token's names Administrators instead of the user, and a child on pipes
/// started with that dies at once (measured, T1).
#[test]
fn the_default_dacl_of_the_token_gives_the_user_system_and_the_logon_session_their_rights() {
    const GENERIC_ALL: u32 = 0x1000_0000;
    const GENERIC_EXECUTE_READ: u32 = 0xA000_0000;
    let token = UnelevatedToken::of_this_process().expect("make the token");
    let masks = with_child_token(&token, |child| {
        let info = token_information(child, TokenDefaultDacl).expect("read the child's default DACL");
        // SAFETY: every bit pattern is a valid `TOKEN_DEFAULT_DACL` (one pointer).
        let default = unsafe { info.header::<TOKEN_DEFAULT_DACL>() }.expect("read the default DACL's header");
        // The ACL is only handed to the ACL functions of Windows, which wrote it into `info`.
        let acl: *mut ACL = default.DefaultDacl;
        assert!(!acl.is_null(), "the token has a default DACL");
        let mut size = ACL_SIZE_INFORMATION::default();
        // SAFETY: `size` is the structure the class names.
        unsafe {
            GetAclInformation(
                acl,
                (&raw mut size).cast(),
                size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        }
        .expect("read the ACL's size information");
        (0..size.AceCount)
            .map(|index| {
                let mut ace = std::ptr::null_mut();
                // SAFETY: `index` is below the ACE count of a valid ACL.
                unsafe { GetAce(acl, index, &mut ace) }.expect("read an ACE");
                // SAFETY: the ACEs of this ACL are all access-allowed ones, which the first check pins.
                let ace = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
                assert_eq!(ace.Header.AceType, 0, "an access-allowed ACE");
                ace.Mask
            })
            .collect::<Vec<_>>()
    });
    assert_eq!(masks, vec![GENERIC_ALL, GENERIC_ALL, GENERIC_EXECUTE_READ]);
}

/// The session starts take the token: a command on pipes and one in a pseudoconsole run to the end with it, and
/// their exit codes come back. (Whether the elevated process's child survives the start is
/// `tests/unelevated_token_windows.rs`.)
#[test]
fn a_command_on_pipes_and_one_in_a_pseudoconsole_run_with_the_token() {
    let token = UnelevatedToken::of_this_process().expect("make the token");
    let on_pipes = crate::pipes::ExecChild::spawn("cmd.exe /c exit 5", None, Some(&token)).expect("start on pipes");
    assert_eq!(on_pipes.wait().unwrap(), 5);
    let in_pty = crate::conpty::PtySession::spawn("cmd.exe /c exit 6", 80, 24, None, None, Some(&token))
        .expect("start in a pseudoconsole");
    assert_eq!(in_pty.wait().unwrap(), 6);
}
