//! Host tests for the line a handshake asks the agent to start (pure; runs on any platform).

use std::path::PathBuf;

use super::{Launched, launch_line, notice_frame};
use crate::protocol::{Handshake, Launch, Mode, Stream};
use crate::shell::test_host::{SYSTEM_CMD, TestHost, USER_CONFIG};

const PWSH: &str = r"C:\Program Files\PowerShell\7\pwsh.exe";

fn pwsh_host() -> TestHost {
    TestHost::new()
        .with_program("pwsh.exe", PWSH)
        .with_user_config("shell: pwsh.exe\n")
}

fn handshake(mode: Mode, command: Option<&str>, launch: Launch) -> Handshake {
    Handshake {
        mode,
        command: command.map(str::to_owned),
        launch,
        ..Handshake::pty_default()
    }
}

fn launched(hs: &Handshake, host: &TestHost) -> Launched {
    match launch_line(hs, host) {
        Ok(launched) => launched,
        Err(error) => panic!("{hs:?} was refused: {error:?}"),
    }
}

#[test]
fn a_direct_launch_runs_the_line_unchanged() {
    for mode in [Mode::Exec, Mode::Pty] {
        let line = r#""C:\a b\ssh-broker.exe" verify-probe"#;
        let got = launched(&handshake(mode, Some(line), Launch::Direct), &pwsh_host());
        assert_eq!(got.line, line);
        assert_eq!(got.notice, None);
    }
}

#[test]
fn a_shell_launch_runs_the_command_through_the_configured_shell() {
    let host = pwsh_host();
    let exec = launched(&handshake(Mode::Exec, Some("echo hi"), Launch::Shell), &host);
    assert_eq!(exec.line, format!(r#""{PWSH}" -c "echo hi""#));
    // A terminal with a command appends it as written, the way OpenSSH does.
    let pty = launched(&handshake(Mode::Pty, Some("echo  hi"), Launch::Shell), &host);
    assert_eq!(pty.line, format!(r#""{PWSH}" -c echo  hi"#));
    let login = launched(&handshake(Mode::Pty, None, Launch::Shell), &host);
    assert_eq!(login.line, format!(r#""{PWSH}""#));
}

#[test]
fn the_built_in_cmd_exe_runs_with_cmd_packing() {
    let host = TestHost::new();
    let exec = launched(&handshake(Mode::Exec, Some("echo hi"), Launch::Shell), &host);
    assert_eq!(exec.line, format!(r#"{SYSTEM_CMD} /c "echo hi""#));
}

#[test]
fn exec_without_a_command_and_direct_without_a_command_are_bad_requests() {
    for hs in [
        handshake(Mode::Exec, None, Launch::Shell),
        handshake(Mode::Exec, None, Launch::Direct),
        handshake(Mode::Pty, None, Launch::Direct),
    ] {
        assert!(launch_line(&hs, &pwsh_host()).is_err(), "{hs:?}");
    }
}

#[test]
fn a_broken_config_sends_one_warning_then_runs_cmd_exe() {
    let host = TestHost::new().with_user_config("shell: {strt: pwsh.exe}\n");
    let got = launched(&handshake(Mode::Exec, Some("echo hi"), Launch::Shell), &host);
    assert_eq!(got.line, format!(r#"{SYSTEM_CMD} /c "echo hi""#));
    let notice = got.notice.expect("a warning");
    assert!(
        notice.contains(USER_CONFIG) && notice.contains("strt") && notice.contains("cmd.exe"),
        "{notice}"
    );
}

#[test]
fn an_unresolvable_program_warns_with_its_name() {
    let host = TestHost::new().with_user_config("shell: nonesuch.exe\n");
    let got = launched(&handshake(Mode::Pty, None, Launch::Shell), &host);
    assert_eq!(got.line, SYSTEM_CMD);
    assert!(got.notice.unwrap().contains("nonesuch.exe"));
}

#[test]
fn a_line_that_cannot_be_made_is_an_error() {
    let long = "x".repeat(40_000);
    assert!(launch_line(&handshake(Mode::Exec, Some(&long), Launch::Shell), &pwsh_host()).is_err());
    assert!(launch_line(&handshake(Mode::Exec, Some("a\0b"), Launch::Shell), &pwsh_host()).is_err());
}

#[test]
fn the_config_is_read_once_per_connection_and_again_for_the_next() {
    let host = pwsh_host();
    let hs = handshake(Mode::Exec, Some("echo hi"), Launch::Shell);
    launched(&hs, &host);
    assert_eq!(
        host.read_log(),
        [PathBuf::from(USER_CONFIG)],
        "one connection reads each layer once"
    );
    launched(&hs, &host);
    assert_eq!(
        host.read_log(),
        [PathBuf::from(USER_CONFIG), PathBuf::from(USER_CONFIG)]
    );
}

#[test]
fn a_direct_launch_reads_no_config() {
    let host = pwsh_host();
    launched(&handshake(Mode::Exec, Some("x"), Launch::Direct), &host);
    assert!(host.read_log().is_empty());
}

#[test]
fn the_warning_goes_to_the_stream_the_session_shows() {
    let text = "ssh-broker: cannot use the shell from x (pwsh.exe): not found on PATH; using the built-in cmd.exe";
    let (stream, bytes) = notice_frame(Mode::Pty, text);
    assert_eq!(stream, Stream::Pty);
    assert_eq!(
        bytes,
        format!("{text}\r\n").into_bytes(),
        "a terminal needs a carriage return"
    );
    let (stream, bytes) = notice_frame(Mode::Exec, text);
    assert_eq!(stream, Stream::Stderr);
    assert_eq!(bytes, format!("{text}\n").into_bytes());
}
