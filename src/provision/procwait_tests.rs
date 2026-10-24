//! Tests for waiting on processes by handle. The children are console-less (`CREATE_NO_WINDOW`)
//! and live until the test closes their stdin.
use super::*;
use std::os::windows::process::CommandExt;
use std::process::{Child, Command, Stdio};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

fn cmd_exe() -> PathBuf {
    PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot is set")).join(r"System32\cmd.exe")
}

/// A `cmd.exe` that exits when its stdin closes, and not before.
fn child_until_stdin_closes() -> Child {
    Command::new(cmd_exe())
        .args(["/d", "/c", "set /p unused="])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .unwrap()
}

#[test]
fn a_running_process_of_the_expected_image_is_opened() {
    let mut child = child_until_stdin_closes();
    let found = open_if_image(child.id(), &cmd_exe()).unwrap();
    assert_eq!(found.map(|p| p.pid), Some(child.id()));
    drop(child.stdin.take());
    child.wait().unwrap();
}

#[test]
fn a_process_of_another_image_is_not_taken_for_the_agent() {
    // A reused PID names some other program; waiting on it would wait on the wrong thing.
    let mut child = child_until_stdin_closes();
    let other = PathBuf::from(r"C:\Windows\System32\notepad.exe");
    assert!(open_if_image(child.id(), &other).unwrap().is_none());
    drop(child.stdin.take());
    child.wait().unwrap();
}

#[test]
fn a_pid_that_names_no_process_is_an_exited_one() {
    assert!(open_if_image(u32::MAX - 1, &cmd_exe()).unwrap().is_none());
}

#[test]
fn the_wait_ends_when_the_process_exits_and_fails_at_the_bound_while_it_runs() {
    let mut child = child_until_stdin_closes();
    let process = open_if_image(child.id(), &cmd_exe()).unwrap().unwrap();

    // The child cannot exit until its stdin closes, so this expiry is the bound being reported,
    // not a race.
    let err = wait_all_exited(std::slice::from_ref(&process), Duration::from_millis(50)).unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains(&child.id().to_string()), "names the process: {text}");
    assert!(text.contains("did not exit"), "{text}");

    drop(child.stdin.take());
    wait_all_exited(std::slice::from_ref(&process), Duration::from_secs(60)).unwrap();
    assert!(
        child.try_wait().unwrap().is_some(),
        "the process had exited when the wait returned"
    );
}

#[test]
fn waiting_for_no_processes_returns_at_once() {
    wait_all_exited(&[], Duration::from_millis(1)).unwrap();
}
