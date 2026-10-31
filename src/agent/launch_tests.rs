//! Host tests for the line a handshake asks the agent to start (pure; runs on any platform).

use std::path::{Path, PathBuf};

use super::{Launched, Spawn, launch_line, notice_frame, start};
use crate::protocol::{Handshake, Launch, Mode, Stream};
use crate::shell::StartError;
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
            |spawn| {
                let Spawn::Line(line) = spawn else { panic!("{spawn:?}") };
                tried.push(line.to_owned());
                if line.contains("pwsh.exe") {
                    return Err(StartError::Program(anyhow::anyhow!(
                        "%1 is not a valid Win32 application. (os error 193)"
                    )));
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
        verb(),
        |_| -> Result<(), StartError> {
            tried += 1;
            Err(StartError::Program(anyhow::anyhow!("refused")))
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

/// What `start` asked to spawn, in the owned form a test compares.
#[derive(Debug, PartialEq, Eq)]
enum Try {
    Line(String),
    Verb {
        exe: PathBuf,
        notice: String,
        line: String,
        login: bool,
    },
}

impl Try {
    fn of(spawn: &Spawn<'_>) -> Try {
        match spawn {
            Spawn::Line(line) => Try::Line((*line).to_owned()),
            Spawn::Verb {
                exe,
                notice,
                line,
                login,
            } => Try::Verb {
                exe: exe.to_path_buf(),
                notice: (*notice).to_owned(),
                line: (*line).to_owned(),
                login: *login,
            },
        }
    }

    fn line(&self) -> &str {
        match self {
            Try::Line(line) | Try::Verb { line, .. } => line,
        }
    }
}

/// The spawns `start` made, the warnings it asked the caller to show and the error it ended with, for
/// `launched`. `fails` says which spawns fail, and how.
fn started(
    host: &TestHost,
    launched: &Launched<'_>,
    verb: Option<&Path>,
    fails: impl Fn(&Try) -> Option<StartError>,
) -> (Vec<Try>, Vec<String>, Option<String>) {
    let (mut tried, mut warned) = (Vec::new(), Vec::new());
    let result = start(
        host,
        launched,
        verb,
        |spawn| {
            let attempt = Try::of(&spawn);
            let failure = fails(&attempt);
            tried.push(attempt);
            failure.map_or(Ok(()), Err)
        },
        |text| warned.push(text.to_owned()),
    );
    (tried, warned, result.err().map(|e| format!("{e:#}")))
}

const BROKER: &str = r"C:\Program Files\ssh-broker\ssh-broker.exe";

fn verb() -> Option<&'static Path> {
    Some(Path::new(BROKER))
}

const NOT_VALID: &str = "%1 is not a valid Win32 application. (os error 193)";

fn program_fault(attempt: &Try) -> Option<StartError> {
    attempt
        .line()
        .contains("pwsh.exe")
        .then(|| StartError::Program(anyhow::anyhow!(NOT_VALID)))
}

fn never(_: &Try) -> Option<StartError> {
    None
}

/// A pseudoconsole clears the screen after anything written to it ahead of the shell, so the
/// warning of a terminal session is printed from inside it: the spawn is the hidden verb, handed
/// the notice and the fallback shell's line.
#[test]
fn a_terminal_session_with_a_broken_config_starts_the_verb_that_prints_the_warning() {
    let host = TestHost::new().with_user_config("shell: {strt: pwsh.exe}\n");
    for command in [Some("echo hi"), None] {
        let hs = handshake(Mode::Pty, command, Launch::Shell);
        let first = launched(&hs, &host);
        let (tried, warned, error) = started(&host, &first, verb(), never);
        assert_eq!((warned, error), (Vec::new(), None), "{command:?}");
        assert_eq!(
            tried,
            [Try::Verb {
                exe: BROKER.into(),
                notice: first.notice.clone().unwrap(),
                line: first.line.clone(),
                login: command.is_none(),
            }],
            "{command:?}"
        );
    }
}

#[test]
fn a_shell_that_cannot_start_in_a_terminal_session_is_replaced_by_the_verb() {
    let host = pwsh_host();
    let hs = handshake(Mode::Pty, Some("echo hi"), Launch::Shell);
    let first = launched(&hs, &host);
    let (tried, warned, error) = started(&host, &first, verb(), program_fault);
    assert_eq!((warned, error), (Vec::new(), None));
    assert_eq!(tried.len(), 2, "{tried:?}");
    assert_eq!(
        tried[0],
        Try::Line(first.line.clone()),
        "the configured shell is tried as it is"
    );
    let Try::Verb {
        notice, line, login, ..
    } = &tried[1]
    else {
        panic!("{tried:?}")
    };
    assert!(
        notice.contains("pwsh.exe") && notice.contains(USER_CONFIG) && notice.contains("os error 193"),
        "{notice}"
    );
    assert_eq!(
        (line.as_str(), *login),
        (format!("{SYSTEM_CMD} /c echo hi").as_str(), false)
    );
}

/// The verb is an enhancement, never a way to lose the session: when it cannot be started, the
/// shell is started as it was before the verb, with the warning shown ahead of it.
#[test]
fn a_verb_that_cannot_start_leaves_the_shell_to_start_with_the_warning_ahead() {
    let host = TestHost::new().with_user_config("shell: {strt: pwsh.exe}\n");
    for command in [Some("echo hi"), None] {
        let hs = handshake(Mode::Pty, command, Launch::Shell);
        let first = launched(&hs, &host);
        let (tried, warned, error) = started(&host, &first, verb(), |attempt| {
            matches!(attempt, Try::Verb { .. }).then(|| StartError::Other(anyhow::anyhow!("the verb is blocked")))
        });
        assert_eq!(error, None, "{command:?}");
        assert_eq!(tried.len(), 2, "{command:?}: {tried:?}");
        assert_eq!(tried[1], Try::Line(first.line.clone()), "{command:?}");
        assert_eq!(warned, [first.notice.clone().unwrap()], "{command:?}");
    }
}

/// A failure that is not the program's (here the pseudoconsole) is the error of the session: the
/// shell is not blamed and cmd.exe is not tried.
#[test]
fn a_failure_the_shell_did_not_cause_is_reported_as_itself() {
    let host = pwsh_host();
    let hs = handshake(Mode::Pty, None, Launch::Shell);
    let first = launched(&hs, &host);
    let (tried, warned, error) = started(&host, &first, verb(), |_| {
        Some(StartError::Other(anyhow::anyhow!("no pseudoconsole")))
    });
    assert_eq!(tried, [Try::Line(first.line.clone())]);
    assert_eq!(warned, Vec::<String>::new());
    assert_eq!(error.as_deref(), Some("no pseudoconsole"));
}

/// Whatever the notice and the line hold, the verb is given exactly them.
#[test]
fn the_verb_is_given_the_notice_and_the_line_exactly() {
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
        let (tried, _, _) = started(&host, &first, verb(), never);
        assert_eq!(
            tried,
            [Try::Verb {
                exe: BROKER.into(),
                notice: first.notice.clone().unwrap(),
                line: first.line.clone(),
                login: false
            }],
            "{text:?}"
        );
    }
}

/// The verb takes the line in a pipe, so a fallback line at the command-line limit is no different.
#[test]
fn a_fallback_line_at_the_command_line_limit_still_gets_the_verb() {
    use crate::shell::pack::MAX_LINE_UNITS;
    let host = TestHost::new().with_user_config("shell: {strt: pwsh.exe}\n");
    // The longest command whose own line still fits: the line is the shell's name, `/c` and the command.
    let base = {
        let probe = handshake(Mode::Pty, Some(""), Launch::Shell);
        launched(&probe, &host).line.encode_utf16().count()
    };
    let command = "x".repeat(MAX_LINE_UNITS - 1 - base);
    let hs = handshake(Mode::Pty, Some(&command), Launch::Shell);
    let first = launched(&hs, &host);
    assert_eq!(first.line.encode_utf16().count(), MAX_LINE_UNITS - 1);
    let (tried, warned, error) = started(&host, &first, verb(), never);
    assert_eq!((warned, error), (Vec::new(), None));
    assert!(
        matches!(tried.as_slice(), [Try::Verb { line, .. }] if *line == first.line),
        "{tried:?}"
    );
}

/// Without a pseudoconsole to print on, the caller shows the warning before the shell starts.
#[test]
fn a_session_without_a_pseudoconsole_has_its_warning_shown_before_the_shell() {
    let host = TestHost::new().with_user_config("shell: {strt: pwsh.exe}\n");
    let hs = handshake(Mode::Exec, Some("echo hi"), Launch::Shell);
    let first = launched(&hs, &host);
    let (tried, warned, _) = started(&host, &first, None, never);
    assert_eq!(tried, [Try::Line(first.line.clone())]);
    assert_eq!(warned, [first.notice.clone().unwrap()]);
}

#[test]
fn a_shell_that_cannot_start_in_a_session_without_a_pseudoconsole_is_warned_about_once() {
    let host = pwsh_host();
    let hs = handshake(Mode::Exec, Some("echo hi"), Launch::Shell);
    let first = launched(&hs, &host);
    let (tried, warned, _) = started(&host, &first, None, program_fault);
    assert_eq!(tried.len(), 2, "{tried:?}");
    assert_eq!(warned.len(), 1, "{warned:?}");
    assert!(warned[0].contains("os error 193"), "{warned:?}");
}

#[test]
fn a_terminal_session_with_a_working_shell_starts_it_as_it_is() {
    let host = pwsh_host();
    let hs = handshake(Mode::Pty, Some("echo hi"), Launch::Shell);
    let first = launched(&hs, &host);
    let (tried, warned, _) = started(&host, &first, verb(), never);
    assert_eq!((tried, warned), (vec![Try::Line(first.line.clone())], Vec::new()));
}

#[test]
fn a_direct_launch_is_not_wrapped() {
    let hs = handshake(Mode::Pty, Some(r"C:\ssh-broker.exe verify-probe"), Launch::Direct);
    let first = launched(&hs, &pwsh_host());
    let (tried, warned, _) = started(&pwsh_host(), &first, verb(), never);
    assert_eq!((tried, warned), (vec![Try::Line(first.line.clone())], Vec::new()));
}
