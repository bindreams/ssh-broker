//! Host tests for the line a handshake asks the agent to start (pure; runs on any platform).

use std::path::{Path, PathBuf};

use super::{Launched, console_fallback_line, launch_line, notice_frame, start};
use crate::cmdline::split_args;
use crate::protocol::{Handshake, Launch, Mode, Stream};
use crate::route::{Route, route};
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

fn launched<'a>(hs: &'a Handshake, host: &TestHost) -> Launched<'a> {
    match launch_line(hs, host) {
        Ok(launched) => launched,
        Err(error) => panic!("{hs:?} was refused: {error:?}"),
    }
}

#[test]
fn a_direct_launch_runs_the_line_unchanged() {
    for mode in [Mode::Exec, Mode::Pty] {
        let line = r#""C:\a b\ssh-broker.exe" verify-probe"#;
        let hs_got = handshake(mode, Some(line), Launch::Direct);
        let got = launched(&hs_got, &pwsh_host());
        assert_eq!(got.line, line);
        assert_eq!(got.notice, None);
    }
}

#[test]
fn a_shell_launch_runs_the_command_through_the_configured_shell() {
    let host = pwsh_host();
    let hs_exec = handshake(Mode::Exec, Some("echo hi"), Launch::Shell);
    let exec = launched(&hs_exec, &host);
    assert_eq!(exec.line, format!(r#""{PWSH}" -c "echo hi""#));
    // A terminal with a command appends it as written, the way OpenSSH does.
    let hs_pty = handshake(Mode::Pty, Some("echo  hi"), Launch::Shell);
    let pty = launched(&hs_pty, &host);
    assert_eq!(pty.line, format!(r#""{PWSH}" -c echo  hi"#));
    let hs_login = handshake(Mode::Pty, None, Launch::Shell);
    let login = launched(&hs_login, &host);
    assert_eq!(login.line, format!(r#""{PWSH}""#));
}

#[test]
fn the_built_in_cmd_exe_runs_with_cmd_packing() {
    let host = TestHost::new();
    let hs_exec = handshake(Mode::Exec, Some("echo hi"), Launch::Shell);
    let exec = launched(&hs_exec, &host);
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
    let hs_got = handshake(Mode::Exec, Some("echo hi"), Launch::Shell);
    let got = launched(&hs_got, &host);
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
    let hs_got = handshake(Mode::Pty, None, Launch::Shell);
    let got = launched(&hs_got, &host);
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

#[test]
fn a_shell_that_cannot_start_is_replaced_by_cmd_exe_and_the_warning_names_the_error() {
    let host = pwsh_host();
    for (mode, command) in [
        (Mode::Exec, Some("echo hi")),
        (Mode::Pty, Some("echo hi")),
        (Mode::Pty, None),
    ] {
        let hs = handshake(mode, command, Launch::Shell);
        let first = launched(&hs, &host);
        let mut tried = Vec::new();
        let mut notice = None;
        let started = start(
            &host,
            &first,
            None,
            |line| {
                tried.push(line.to_owned());
                if line.contains("pwsh.exe") {
                    anyhow::bail!("%1 is not a valid Win32 application. (os error 193)");
                }
                Ok(line.to_owned())
            },
            |text| notice = Some(text.to_owned()),
        )
        .unwrap();
        assert!(started.starts_with(SYSTEM_CMD), "{started}");
        assert_eq!(tried.len(), 2, "{tried:?}");
        let notice = notice.expect("a warning for the replacement");
        assert!(
            notice.contains("pwsh.exe") && notice.contains(USER_CONFIG) && notice.contains("os error 193"),
            "{notice}"
        );
    }
}

#[test]
fn a_direct_launch_is_never_replaced() {
    let hs = handshake(Mode::Exec, Some(r"C:\ssh-broker.exe verify-probe"), Launch::Direct);
    let first = launched(&hs, &pwsh_host());
    let mut tried = 0;
    let error = start(
        &pwsh_host(),
        &first,
        None,
        |_| -> anyhow::Result<()> {
            tried += 1;
            anyhow::bail!("refused")
        },
        |_| panic!("nothing to warn about"),
    )
    .unwrap_err();
    assert_eq!((tried, format!("{error:#}")), (1, "refused".to_string()));
}

#[test]
fn a_shell_that_starts_has_no_extra_warning() {
    let hs = handshake(Mode::Exec, Some("echo hi"), Launch::Shell);
    let first = launched(&hs, &pwsh_host());
    start(
        &pwsh_host(),
        &first,
        None,
        |_| Ok(()),
        |_| panic!("nothing to warn about"),
    )
    .unwrap();
}

// The warning of a terminal session ==========================================================

const BROKER: &str = r"C:\Program Files\ssh-broker\ssh-broker.exe";

/// The lines `start` spawned, and the warnings it asked the caller to show, for `launched`.
fn started(
    host: &TestHost,
    launched: &Launched<'_>,
    console: Option<&Path>,
    fails: impl Fn(&str) -> bool,
) -> (Vec<String>, Vec<String>) {
    let (mut tried, mut warned) = (Vec::new(), Vec::new());
    let _ = start(
        host,
        launched,
        console,
        |line| {
            tried.push(line.to_owned());
            if fails(line) {
                anyhow::bail!("%1 is not a valid Win32 application. (os error 193)");
            }
            Ok(())
        },
        |text| warned.push(text.to_owned()),
    );
    (tried, warned)
}

/// What the hidden verb is handed by the line that starts it: the notice, and the line it starts.
fn handed_over(wrapper: &str) -> (String, String) {
    let args = split_args(wrapper);
    assert_eq!(args[0], BROKER, "{wrapper}");
    match route(&args[1..], wrapper) {
        Route::ConsoleFallback { notice, line } => (notice, line),
        other => panic!("{wrapper:?} routes to {other:?}"),
    }
}

/// A pseudoconsole clears the screen after anything written to it ahead of the shell, so the
/// warning of a terminal session is printed from inside it: the line that starts is the hidden
/// verb, given the notice and the fallback shell's line.
#[test]
fn a_terminal_session_with_a_broken_config_starts_the_verb_that_prints_the_warning() {
    let host = TestHost::new().with_user_config("shell: {strt: pwsh.exe}\n");
    for command in [Some("echo hi"), None] {
        let hs = handshake(Mode::Pty, command, Launch::Shell);
        let first = launched(&hs, &host);
        let (tried, warned) = started(&host, &first, Some(Path::new(BROKER)), |_| false);
        assert_eq!(warned, Vec::<String>::new(), "{command:?}");
        assert_eq!(tried.len(), 1, "{command:?}: {tried:?}");
        let (notice, line) = handed_over(&tried[0]);
        assert_eq!(Some(notice), first.notice, "{command:?}");
        assert_eq!(line, first.line, "{command:?}");
    }
}

#[test]
fn a_shell_that_cannot_start_in_a_terminal_session_is_replaced_by_the_verb() {
    let host = pwsh_host();
    let hs = handshake(Mode::Pty, Some("echo hi"), Launch::Shell);
    let first = launched(&hs, &host);
    let (tried, warned) = started(&host, &first, Some(Path::new(BROKER)), |line| line.contains("pwsh.exe"));
    assert_eq!(tried.len(), 2, "{tried:?}");
    assert_eq!(tried[0], first.line, "the configured shell is tried as it is");
    assert!(warned.is_empty(), "{warned:?}");
    let (notice, line) = handed_over(&tried[1]);
    assert!(
        notice.contains("pwsh.exe") && notice.contains(USER_CONFIG) && notice.contains("os error 193"),
        "{notice}"
    );
    assert_eq!(line, format!("{SYSTEM_CMD} /c echo hi"));
}

/// Whatever the notice and the line hold, the verb is handed exactly them.
#[test]
fn the_verb_is_handed_the_notice_and_the_line_exactly() {
    for text in [
        r#"echo "a  b" \"#,
        "echo a\r\nb",
        r#"echo \\"x\\" ""#,
        "echo héllo ✓",
        "echo \ttab",
    ] {
        let host = TestHost::new().with_user_config("shell: {strt: pwsh.exe}\n");
        let hs = handshake(Mode::Pty, Some(text), Launch::Shell);
        let first = launched(&hs, &host);
        let (tried, _) = started(&host, &first, Some(Path::new(BROKER)), |_| false);
        let (notice, line) = handed_over(&tried[0]);
        assert_eq!(
            (Some(notice), line),
            (first.notice.clone(), first.line.clone()),
            "{text:?}"
        );
    }
}

/// Without a pseudoconsole to print on, the caller shows the warning before the shell starts.
#[test]
fn a_session_without_a_pseudoconsole_has_its_warning_shown_before_the_shell() {
    let host = TestHost::new().with_user_config("shell: {strt: pwsh.exe}\n");
    let hs = handshake(Mode::Exec, Some("echo hi"), Launch::Shell);
    let first = launched(&hs, &host);
    let (tried, warned) = started(&host, &first, None, |_| false);
    assert_eq!(tried, std::slice::from_ref(&first.line));
    assert_eq!(warned, [first.notice.clone().unwrap()]);
}

#[test]
fn a_shell_that_cannot_start_in_a_session_without_a_pseudoconsole_is_warned_about_once() {
    let host = pwsh_host();
    let hs = handshake(Mode::Exec, Some("echo hi"), Launch::Shell);
    let first = launched(&hs, &host);
    let (tried, warned) = started(&host, &first, None, |line| line.contains("pwsh.exe"));
    assert_eq!(tried.len(), 2, "{tried:?}");
    assert_eq!(warned.len(), 1, "{warned:?}");
    assert!(warned[0].contains("os error 193"), "{warned:?}");
}

/// The verb's line has to fit in a command line too. When it does not, the shell starts as it is
/// and the caller shows the warning.
#[test]
fn a_line_the_verb_cannot_carry_starts_the_shell_and_shows_the_warning() {
    let host = TestHost::new().with_user_config("shell: {strt: pwsh.exe}\n");
    // The shell's own line fits; the verb's holds that line and the notice besides.
    let nearly_all = "x".repeat(32_600);
    let hs = handshake(Mode::Pty, Some(&nearly_all), Launch::Shell);
    let first = launched(&hs, &host);
    let (tried, warned) = started(&host, &first, Some(Path::new(BROKER)), |_| false);
    assert_eq!(tried, std::slice::from_ref(&first.line));
    assert_eq!(warned, [first.notice.clone().unwrap()]);
}

/// A NUL ends a command line, so text that holds one cannot be carried.
#[test]
fn text_with_a_nul_cannot_be_carried_by_the_verb() {
    let exe = Path::new(BROKER);
    assert!(console_fallback_line(exe, "a notice", "cmd.exe /c x").is_some());
    assert_eq!(console_fallback_line(exe, "a\0notice", "cmd.exe"), None);
    assert_eq!(console_fallback_line(exe, "a notice", "cmd.exe /c a\0b"), None);
}

#[test]
fn a_terminal_session_with_a_working_shell_starts_it_as_it_is() {
    let host = pwsh_host();
    let hs = handshake(Mode::Pty, Some("echo hi"), Launch::Shell);
    let first = launched(&hs, &host);
    let (tried, warned) = started(&host, &first, Some(Path::new(BROKER)), |_| false);
    assert_eq!((tried, warned), (vec![first.line.clone()], Vec::new()));
}

#[test]
fn a_direct_launch_is_not_wrapped() {
    let hs = handshake(Mode::Pty, Some(r"C:\ssh-broker.exe verify-probe"), Launch::Direct);
    let first = launched(&hs, &pwsh_host());
    let (tried, warned) = started(&pwsh_host(), &first, Some(Path::new(BROKER)), |_| false);
    assert_eq!((tried, warned), (vec![first.line.clone()], Vec::new()));
}
