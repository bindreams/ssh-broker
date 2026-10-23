//! Host tests for argv dispatch (pure; runs on any platform).
//!
//! Each case is a whole command line, as sshd's `DefaultShell` launch produces it; the argv
//! `route` receives is derived from it the way the C runtime would.

use super::{Route, route};
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
    exec.map(|exec| resolve_exec(exec, || encoding))
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
fn agent_verb_is_agent() {
    assert_eq!(route_line("ssh-broker.exe agent"), Route::Agent);
}

#[test]
fn apply_and_verify_verbs() {
    assert_eq!(route_line("ssh-broker.exe apply"), Route::Apply);
    assert_eq!(route_line("ssh-broker.exe verify"), Route::Verify);
    assert_eq!(route_line("ssh-broker.exe verify-probe"), Route::VerifyProbe);
}

/// `ssh host agent` arrives as `-c agent`, so argv[1] is `-c` and no verb can collide with a
/// client command, whatever the command is called.
#[test]
fn a_command_named_like_a_verb_is_still_shim_exec() {
    for verb in ["agent", "apply", "verify", "verify-probe"] {
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
