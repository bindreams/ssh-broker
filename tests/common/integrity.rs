//! Running a child of this process's own user at a chosen mandatory integrity level, and reading a
//! process's own level. Lowering one's own integrity needs no privilege and no elevation.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use ssh_broker::acl::Sid;
use ssh_broker::winutil::{OwnedHandle, SE_GROUP_INTEGRITY};
use windows::Win32::System::Threading::CREATE_NO_WINDOW;

use crate::account::{Starter, is_elevated, spawn_with_token};
use crate::desktop::PrivateDesktop;
use crate::token_copy::own_token_at;

/// This process's mandatory integrity level, as the relative id of its label SID.
pub fn current_rid() -> u32 {
    ssh_broker::account::integrity_of(ssh_broker::winutil::own_token().unwrap().0).unwrap()
}

/// Run `exe` with `command_line` as this process's user at mandatory integrity level `rid`
/// ([`INTEGRITY_LOW`], [`INTEGRITY_MEDIUM`] of `ssh_broker::account`) and return its exit code. The
/// child's token is a copy of this process's with only its label set ([`own_token_at`]), so two levels
/// differ in the integrity check and nothing else. It starts through [`spawn_with_token`]; a child that
/// does not exit fails the test with `evidence` printed.
///
/// An elevated process gives the child a window station and desktop of its own, labelled at `rid`: a
/// pair without a label is Medium, and a Low child cannot write to it. An unelevated process may not
/// name a window station, so the child takes this process's own, which an interactive user's Low
/// processes use anyway. An unelevated process with no interactive desktop gives a Low child nothing
/// it may use.
pub fn run_at(rid: u32, exe: &Path, command_line: &str, cwd: &Path, evidence: &[PathBuf]) -> u32 {
    let private = is_elevated().then(|| {
        let user = Sid::current_user().unwrap().to_sddl().unwrap();
        PrivateDesktop::create_labelled(&[&user], Some(rid))
            .unwrap_or_else(|e| panic!("create a window station and desktop at integrity {rid:#x}: {e}"))
    });
    let token = OwnedHandle(own_token_at(rid, SE_GROUP_INTEGRITY));
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
