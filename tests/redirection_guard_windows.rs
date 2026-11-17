//! The premise of `verify`'s junction row: RedirectionGuard refuses to follow a junction that a
//! non-administrator made, and follows one that an elevated process made. Windows only; **Elevated (CI only)**.
//!
//! The reader is the child half of a test of this binary (`common/child_entry.rs`), which sets
//! `ProcessRedirectionTrustPolicy` (enforce) on itself and reads through two junctions to the same file:
//! one this elevated process made, and one that a child of this process made with the unelevated token
//! (`winutil::UnelevatedToken`, the token an `internal-unelevated` session runs with). The junction row of
//! `verify` rests on the second being refused with error 448 while the first is followed, so that a
//! junction an elevated probe made itself, which is always followed, is not what the row reads through.
#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::Command;

use ssh_broker::account::{Elevation, elevation};
use ssh_broker::pipes::ExecChild;
use ssh_broker::winutil::UnelevatedToken;
use windows::Win32::System::SystemServices::PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY;
use windows::Win32::System::Threading::{ProcessRedirectionTrustPolicy, SetProcessMitigationPolicy};

#[path = "common/child_entry.rs"]
mod child_entry;
#[path = "common/drain.rs"]
mod drain;
#[path = "common/fs_state.rs"]
mod fs_state;

const CHILD: &str = "a_process_that_enforces_redirection_trust_reads_through_two_junctions";
const FILE: &str = "parity.txt";
/// `ERROR_UNTRUSTED_MOUNT_POINT`.
const UNTRUSTED_MOUNT_POINT: i32 = 448;

/// The pair's directory, removed on drop. `remove_dir_all` removes a junction itself and does not follow it.
struct Dir(PathBuf);

impl Dir {
    fn new() -> Dir {
        let path = std::env::temp_dir().join(format!("sb-redirection-guard-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Dir(path)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn by_admin(dir: &Path) -> PathBuf {
    dir.join("by-admin")
}

fn by_unelevated(dir: &Path) -> PathBuf {
    dir.join("by-unelevated")
}

/// A junction made by an elevated process is followed under RedirectionGuard, and one made by an unelevated
/// process of the same account is refused with error 448.
#[test]
fn an_elevated_junction_is_followed_and_an_unelevated_one_is_refused_under_redirection_guard() {
    assert_eq!(
        elevation().unwrap(),
        Elevation::Full,
        "this test needs an elevated administrator (CI runs it); not running it here"
    );
    let dir = Dir::new();
    let target = dir.0.join("target");
    std::fs::create_dir(&target).unwrap();
    std::fs::write(target.join(FILE), b"parity").unwrap();

    fs_state::junction(&by_admin(&dir.0), &target);

    // The unelevated process of this account makes the other: `mklink /J` needs no privilege.
    let token = UnelevatedToken::of_this_process().expect("make the unelevated token");
    let line = format!(
        "cmd.exe /C mklink /J \"{}\" \"{}\"",
        by_unelevated(&dir.0).display(),
        target.display()
    );
    let child = ExecChild::spawn(&line, None, Some(&token)).expect("start the unelevated mklink");
    let (out, err) = (
        drain::drain(child.stdout_read_raw()),
        drain::drain(child.stderr_read_raw()),
    );
    let code = child.wait();
    let said = format!("{}{}", drain::text_of(out), drain::text_of(err));
    assert_eq!(code.unwrap(), 0, "the unelevated mklink said:\n{said}");
    assert!(
        std::fs::symlink_metadata(by_unelevated(&dir.0)).is_ok(),
        "control: the unelevated junction exists"
    );

    let exe = std::env::current_exe().unwrap();
    let output = Command::new(exe)
        .args(child_entry::args(CHILD, &dir.0))
        .output()
        .expect("start the reader");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        child_entry::result(&dir.0),
        format!("by_admin=followed\nby_unelevated=refused {UNTRUSTED_MOUNT_POINT}\n"),
        "the reader said:\n{said}"
    );
}

/// The child half. Run by the test above with `--ignored`, never on its own.
#[test]
#[ignore = "the child half of a parent/child pair; its parent starts it with the pair's directory"]
fn a_process_that_enforces_redirection_trust_reads_through_two_junctions() {
    let dir = child_entry::dir();

    let mut policy = PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY::default();
    policy.Anonymous.Flags = 1; // EnforceRedirectionTrust
    // SAFETY: a policy structure of the size the call is given, which it only reads.
    unsafe {
        SetProcessMitigationPolicy(
            ProcessRedirectionTrustPolicy,
            std::ptr::from_ref(&policy).cast(),
            size_of::<PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY>(),
        )
    }
    .expect("enforce redirection trust on this process");

    let read = |link: PathBuf| match std::fs::read(link.join(FILE)) {
        Ok(content) if content == b"parity" => "followed".to_owned(),
        Ok(content) => format!("read {content:?}"),
        Err(e) => format!(
            "refused {}",
            e.raw_os_error().map_or("none".to_owned(), |code| code.to_string())
        ),
    };
    child_entry::write_result(
        &dir,
        &format!(
            "by_admin={}\nby_unelevated={}\n",
            read(by_admin(&dir)),
            read(by_unelevated(&dir))
        ),
    );
}
