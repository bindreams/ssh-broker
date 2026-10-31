//! Host tests for argv dispatch (pure; runs on any platform).
//!
//! Each case is a whole command line, as sshd's `DefaultShell` launch produces it; the argv
//! `route` receives is derived from it the way the C runtime would.

use super::{AgentArgs, AutoLoginArgs, BackgroundArgs, Route, Toggle, Verb, route};
use crate::cmdline::{Encoding, RawExec, resolve_exec, split_args};

fn route_line(line: &str) -> Route {
    let args = split_args(line);
    route(&args[1..], line)
}

/// The `-c` route that carries `tail`, the text after `-c` as written.
fn tail(tail: &str) -> Route {
    Route::Shim {
        exec: Some(RawExec::Tail(tail.into())),
    }
}

/// The command `line` carries once sshd's form is `encoding`: routed, then decoded.
fn command_as(line: &str, encoding: Encoding) -> Option<String> {
    let Route::Shim { exec } = route_line(line) else {
        panic!("{line:?} must select the shim");
    };
    exec.map(|exec| resolve_exec(exec, || encoding).command)
}

/// A line whose form does not matter: commands with nothing sshd would escape.
fn command(line: &str) -> Option<String> {
    command_as(line, Encoding::Escaped)
}

fn some(command: &str) -> Option<String> {
    Some(command.to_string())
}

#[test]
fn bare_is_interactive_shim() {
    assert_eq!(route_line("ssh-broker.exe"), Route::Shim { exec: None });
}

/// Routing keeps the text after `-c` as written; which form it is in is decided later.
#[test]
fn dash_c_routes_the_raw_tail() {
    assert_eq!(route_line("ssh-broker.exe -c echo"), tail("echo"));
    assert_eq!(route_line(r#"ssh-broker.exe -c "echo hi""#), tail(r#""echo hi""#));
    assert_eq!(route_line("ssh-broker.exe -c echo  two"), tail("echo  two"));
}

/// `-c` was given, so it is an exec request even when the command is empty (the shell runs
/// nothing for `-c ""`). Only a line with no `-c` at all is an interactive session.
#[test]
fn dash_c_with_an_empty_command_is_an_empty_exec() {
    assert_eq!(route_line("ssh-broker.exe -c"), tail(""));
    assert_eq!(route_line("ssh-broker.exe -c "), tail(""));
    for encoding in [Encoding::Verbatim, Encoding::Escaped] {
        assert_eq!(command_as("ssh-broker.exe -c", encoding), some(""), "{encoding:?}");
        assert_eq!(command_as("ssh-broker.exe -c ", encoding), some(""), "{encoding:?}");
    }
    assert_eq!(command_as(r#"ssh-broker.exe -c """#, Encoding::Escaped), some(""));
}

#[test]
fn agent_alone_is_a_desktop_agent() {
    assert_eq!(
        route_line("ssh-broker.exe agent"),
        Route::Agent(AgentArgs { background: None })
    );
}

fn background(expect_user: Option<&str>) -> Route {
    Route::Agent(AgentArgs {
        background: Some(BackgroundArgs {
            expect_user: expect_user.map(str::to_string),
        }),
    })
}

#[test]
fn agent_background_flags_parse() {
    assert_eq!(route_line("ssh-broker.exe agent --background"), background(None));
    assert_eq!(
        route_line("ssh-broker.exe agent --background --expect-user S-1-5-21-1-2-3-1001"),
        background(Some("S-1-5-21-1-2-3-1001"))
    );
}

#[test]
fn the_ready_event_flag_is_gone() {
    // The shim passes no named event.
    assert_eq!(
        route_line("ssh-broker.exe agent --background --ready-event ev --expect-user S-1-5-18"),
        Route::Usage(Verb::Agent)
    );
}

#[test]
fn agent_unknown_flag_is_not_the_shim() {
    for line in [
        "ssh-broker.exe agent --expect-user S-1-5-18",
        "ssh-broker.exe agent --bogus",
        "ssh-broker.exe agent stray",
        "ssh-broker.exe agent --background --bogus",
        "ssh-broker.exe agent --background --expect-user",
        "ssh-broker.exe agent --background --expect-user a --expect-user b",
        "ssh-broker.exe agent --background --background",
        "ssh-broker.exe agent --background stray",
    ] {
        assert_eq!(route_line(line), Route::Usage(Verb::Agent), "{line}");
    }
}

#[test]
fn logout_routes() {
    assert_eq!(route_line("ssh-broker.exe logout"), Route::Logout);
}

#[test]
fn logout_takes_no_arguments() {
    assert_eq!(route_line("ssh-broker.exe logout now"), Route::Usage(Verb::Logout));
}

#[test]
fn a_flag_name_is_not_a_flag_value() {
    assert_eq!(
        route_line("ssh-broker.exe agent --background --expect-user --expect-user x"),
        Route::Usage(Verb::Agent)
    );
}

#[test]
fn auto_login_on_off_account_and_invalid() {
    let args = |toggle, account: Option<&str>| {
        Route::AutoLogin(Some(AutoLoginArgs {
            toggle,
            account: account.map(str::to_string),
        }))
    };
    assert_eq!(route_line("ssh-broker.exe auto-login on"), args(Toggle::On, None));
    assert_eq!(route_line("ssh-broker.exe auto-login off"), args(Toggle::Off, None));
    assert_eq!(
        route_line(r#"ssh-broker.exe auto-login on "Zoe Muller""#),
        args(Toggle::On, Some("Zoe Muller"))
    );
    assert_eq!(
        route_line("ssh-broker.exe auto-login off alice"),
        args(Toggle::Off, Some("alice"))
    );
    for line in [
        "ssh-broker.exe auto-login",
        "ssh-broker.exe auto-login maybe",
        "ssh-broker.exe auto-login on a b",
        "ssh-broker.exe auto-login --on",
    ] {
        assert_eq!(route_line(line), Route::AutoLogin(None), "{line}");
    }
}

/// `ssh host logout` arrives as `-c logout`, like every other verb name.
#[test]
fn a_c_flag_after_a_verb_is_still_exec() {
    assert_eq!(command("ssh-broker.exe -c logout"), some("logout"));
    assert_eq!(command("ssh-broker.exe -c \"auto-login on\""), some("auto-login on"));
    assert_eq!(command("ssh-broker.exe -c agent"), some("agent"));
}

#[test]
fn apply_and_verify_verbs() {
    assert_eq!(route_line("ssh-broker.exe apply"), Route::Apply);
    assert_eq!(route_line("ssh-broker.exe verify"), Route::Verify);
    assert_eq!(route_line("ssh-broker.exe verify-probe"), Route::VerifyProbe);
}

/// The hidden verb of a terminal session's fallback shell takes exactly a notice and a line; any
/// other shape is a usage error, never the shim.
#[test]
fn console_fallback_takes_a_notice_and_a_line() {
    assert_eq!(
        route(
            &["console-fallback".into(), "a notice".into(), "cmd.exe /k".into()],
            "ignored"
        ),
        Route::ConsoleFallback {
            notice: "a notice".into(),
            line: "cmd.exe /k".into()
        }
    );
    for args in [
        vec!["console-fallback"],
        vec!["console-fallback", "a notice"],
        vec!["console-fallback", "a notice", "cmd.exe", "extra"],
    ] {
        let args: Vec<String> = args.into_iter().map(str::to_owned).collect();
        assert_eq!(route(&args, "ignored"), Route::Usage(Verb::ConsoleFallback), "{args:?}");
    }
}

/// `ssh host agent` arrives as `-c agent`, so argv[1] is `-c` and no verb can collide with a
/// client command, whatever the command is called.
#[test]
fn a_command_named_like_a_verb_is_still_shim_exec() {
    for verb in [
        "agent",
        "apply",
        "verify",
        "verify-probe",
        "console-fallback",
        "logout",
        "auto-login",
    ] {
        assert_eq!(command(&format!("ssh-broker.exe -c {verb}")), some(verb));
        assert_eq!(
            command(&format!(r#"ssh-broker.exe -c "{verb} --x y""#)),
            some(&format!("{verb} --x y"))
        );
    }
}

/// Every `-c` command is relayed whole, whatever program it names. A command that a classifier
/// would pick out, such as `sftp-server.exe` or `scp`, takes the same route and reaches the shim
/// intact. A reintroduced classifier that diverts or rewrites one fails here.
#[test]
fn every_dash_c_command_routes_to_the_relay_with_its_text_intact() {
    for text in [
        "scp -t /x",
        "scp.exe -f /x",
        "sftp-server.exe -l INFO",
        "internal-sftp",
        r"C:\Program Files\OpenSSH\sftp-server.exe -l INFO",
        r#""C:\Program Files\OpenSSH\sftp-server.exe" -l INFO"#,
        "git status",
        "cmd /c exit 3",
        "ssh-broker.exe agent",
        r"C:\a b\ssh-broker.exe verify",
    ] {
        assert_eq!(
            command_as(&format!("ssh-broker.exe -c {text}"), Encoding::Verbatim),
            some(text),
            "{text}"
        );
    }
}

/// The command is relayed as the client sent it, edges included: the string the shim sends is
/// the string the client wrote. (`shim::spawn_line` trims only its leading edge, for `CreateProcessW`.)
#[test]
fn a_command_keeps_the_whitespace_at_its_edges() {
    assert_eq!(command(r#"ssh-broker.exe -c "  scp -t /x  ""#), some("  scp -t /x  "));
    assert_eq!(command(r#"ssh-broker.exe -c "   ""#), some("   "));
    assert_eq!(
        command_as("ssh-broker.exe -c \t\r\n x \r\n", Encoding::Verbatim),
        some("\t\r\n x \r\n"),
        "one separator after -c is sshd's; the rest is the command"
    );
}

/// `CreateProcessW(NULL, cmdline)` resolves an unquoted program path with spaces by prefix
/// widening, so the shim must hand it the command line untouched: no tokenizing, no
/// re-quoting. sshd's `Subsystem sftp <path>` takes the rest of the line verbatim, and the path
/// is commonly unquoted.
///
/// Pins `route` only: that the string it returns is this one. What the relay and the fail-open
/// do with the string is pinned by `agent_program_path_tests` and `tests/fail_open_windows.rs`.
#[test]
fn dash_c_keeps_an_unquoted_spaced_program_path_verbatim() {
    let text = r"C:\Program Files\OpenSSH\sftp-server.exe -l INFO";
    // A PTY session: the command is appended to the line unquoted.
    assert_eq!(
        command_as(&format!("ssh-broker.exe -c {text}"), Encoding::Verbatim),
        some(text)
    );
    // A non-PTY session: sshd passes the command as one quoted argument.
    assert_eq!(command(&format!(r#"ssh-broker.exe -c "{text}""#)), some(text));
}

#[test]
fn dash_c_keeps_a_quoted_program_path_verbatim() {
    let text = r#""C:\Program Files\OpenSSH\sftp-server.exe" -l INFO"#;
    assert_eq!(
        command_as(&format!("ssh-broker.exe -c {text}"), Encoding::Verbatim),
        some(text)
    );
    // As one escaped argument.
    assert_eq!(
        command(r#"ssh-broker.exe -c "\"C:\Program Files\OpenSSH\sftp-server.exe\" -l INFO""#),
        some(text)
    );
}

/// A PTY session appends the command unquoted, so the C runtime's argv has lost its quotes and
/// collapsed its spaces. The command must come from the raw line.
#[test]
fn a_verbatim_command_keeps_its_quotes_empty_argument_and_double_space() {
    let text = r#""C:\a b\p.exe" "x y" "" end  of  line"#;
    assert_eq!(
        command_as(&format!("ssh-broker.exe -c {text}"), Encoding::Verbatim),
        some(text)
    );
}

/// A non-PTY session passes the command as one escaped argument; unescaping it must restore the
/// command exactly.
#[test]
fn an_escaped_single_argument_keeps_its_quotes_empty_argument_and_double_space() {
    assert_eq!(
        command(r#"ssh-broker.exe -c "\"C:\a b\p.exe\" \"x y\" \"\" end  of  line""#),
        some(r#""C:\a b\p.exe" "x y" "" end  of  line"#)
    );
}

/// The raw line always shows the `-c` argv reports, because both come from the same command
/// line. If it does not, argv is all there is: `route` asserts in a debug build and, in release,
/// returns the joined argv for `resolve_exec` to log.
#[test]
#[should_panic(expected = "no `-c`")]
fn a_raw_line_without_dash_c_is_a_bug_that_asserts_in_debug() {
    route(&["-c".into(), "a b".into(), "c".into()], "");
}
