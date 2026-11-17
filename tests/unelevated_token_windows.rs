//! What a child started with `winutil::UnelevatedToken` is, from an elevated administrator's process, on
//! pipes (the EXEC path) and in a pseudoconsole (the PTY path). Windows only; **Elevated (CI only)**.
//!
//! The child is the child half of a test of this binary (`common/child_entry.rs`): it reads its own token,
//! tries to open `HKLM\SOFTWARE` for writing without writing anything, and starts a grandchild, and it
//! records the answers for the parent to compare. The unit tests of `winutil::unelevated` cover what does
//! not need an elevated parent.
#![cfg(windows)]

use std::path::PathBuf;

use ssh_broker::account::{Elevation, INTEGRITY_MEDIUM, elevation, elevation_of, integrity_of};
use ssh_broker::conpty::PtySession;
use ssh_broker::pipes::ExecChild;
use ssh_broker::winutil::{UnelevatedToken, own_token};

#[path = "common/child_entry.rs"]
mod child_entry;
#[path = "common/drain.rs"]
mod drain;

const CHILD: &str = "the_unelevated_child_reports_what_it_is";

/// The facts the child records, which the parent expects verbatim: Filtered, Medium, no write access to
/// `HKLM\SOFTWARE`, and a grandchild that ran and exited 0.
fn expected() -> String {
    format!("elevation=Filtered\nintegrity={INTEGRITY_MEDIUM}\nhklm_software_write=denied\ngrandchild_exit=0\n")
}

/// A directory for one child's input and result, removed on drop.
struct Dir(PathBuf);

impl Dir {
    fn new(tag: &str) -> Dir {
        let path = std::env::temp_dir().join(format!("sb-unelevated-{tag}-{}", std::process::id()));
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

fn child_line(dir: &Dir) -> String {
    child_entry::command_line(&std::env::current_exe().unwrap(), CHILD, &dir.0)
}

fn unelevated_token() -> UnelevatedToken {
    assert_eq!(
        elevation().unwrap(),
        Elevation::Full,
        "this test needs an elevated administrator (CI runs it); not running it here"
    );
    UnelevatedToken::of_this_process().expect("make the unelevated token")
}

/// The child's result, which must be what [`expected`] says; `said` is what the child wrote, shown when it
/// is not, or when there is none.
fn assert_result(dir: &Dir, said: &str) {
    let got = std::fs::read_to_string(child_entry::result_path(&dir.0))
        .unwrap_or_else(|e| panic!("the child wrote no result ({e}); it said:\n{said}"));
    assert_eq!(got, expected(), "the child said:\n{said}");
}

/// The EXEC path: a child on pipes, with the token, starts and is what the token says.
#[test]
fn a_child_on_pipes_with_the_unelevated_token_is_filtered_and_medium() {
    let token = unelevated_token();
    let dir = Dir::new("pipes");
    let child = ExecChild::spawn(&child_line(&dir), None, Some(&token)).expect("start the child on pipes");
    // Both pipes are read from the start, so a child that fails noisily ends and says why.
    let (out, err) = (
        drain::drain(child.stdout_read_raw()),
        drain::drain(child.stderr_read_raw()),
    );
    let waited = child.wait();
    // Join before any assert: the readers use handles `child` closes.
    let said = format!("{}{}", drain::text_of(out), drain::text_of(err));
    waited.unwrap_or_else(|e| {
        panic!(
            "wait for the child: {e}
it said:
{said}"
        )
    });
    assert_result(&dir, &said);
}

/// The PTY path: the same child in a pseudoconsole.
#[test]
fn a_child_in_a_pseudoconsole_with_the_unelevated_token_is_filtered_and_medium() {
    let token = unelevated_token();
    let dir = Dir::new("pty");
    let mut session =
        PtySession::spawn(&child_line(&dir), 120, 30, None, None, Some(&token)).expect("start the child in a pty");
    let output = drain::drain(session.out_read_raw());
    let waited = session.wait();
    session.close_pty(); // the output pipe ends once the pseudoconsole is closed
    let said = drain::text_of(output);
    waited.unwrap_or_else(|e| {
        panic!(
            "wait for the child: {e}
it said:
{said}"
        )
    });
    assert_result(&dir, &said);
}

/// The child half. Run by the tests above with `--ignored`, never on its own.
#[test]
#[ignore = "the child half of a parent/child pair; its parent starts it with the pair's directory"]
fn the_unelevated_child_reports_what_it_is() {
    use windows::Win32::Foundation::ERROR_ACCESS_DENIED;
    use windows::Win32::System::Registry::{HKEY, HKEY_LOCAL_MACHINE, KEY_SET_VALUE, RegCloseKey, RegOpenKeyExW};
    use windows::core::w;

    let dir = child_entry::dir();
    let token = own_token().expect("open the child's own token");
    let elevation = elevation_of(token.0).unwrap();
    let integrity = integrity_of(token.0).unwrap();

    let mut key = HKEY::default();
    // SAFETY: a constant key name and a valid out-pointer; an opened key is closed below.
    let opened = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, w!("SOFTWARE"), None, KEY_SET_VALUE, &mut key) };
    let write = if opened == ERROR_ACCESS_DENIED {
        "denied".to_owned()
    } else {
        if opened.is_ok() {
            // SAFETY: the key just opened.
            let _ = unsafe { RegCloseKey(key) };
        }
        format!("not denied ({opened:?})")
    };

    let grandchild = std::process::Command::new("cmd.exe")
        .args(["/c", "exit", "0"])
        .status()
        .expect("start a grandchild");

    child_entry::write_result(
        &dir,
        &format!(
            "elevation={elevation:?}\nintegrity={integrity}\nhklm_software_write={write}\ngrandchild_exit={}\n",
            grandchild.code().map_or("none".to_owned(), |code| code.to_string())
        ),
    );
}
