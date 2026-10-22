//! Host tests for argv dispatch (pure; runs on any platform).
//!
//! Each case is a whole command line, as sshd's `DefaultShell` launch produces it; the argv
//! `route` receives is derived from it the way the C runtime would.

use super::{Route, route};
use crate::cmdline::{Encoding, split_args};

fn route_line_as(line: &str, encoding: Encoding) -> Route {
    let args = split_args(line);
    route(&args[1..], line, encoding)
}

/// A line whose form does not matter: verbs, and commands with nothing sshd would escape.
fn route_line(line: &str) -> Route {
    route_line_as(line, Encoding::Escaped)
}

fn shim(exec: &str) -> Route {
    Route::Shim {
        exec: Some(exec.into()),
    }
}

#[test]
fn bare_is_interactive_shim() {
    assert_eq!(route_line("ssh-broker.exe"), Route::Shim { exec: None });
}

#[test]
fn dash_c_is_exec_shim() {
    assert_eq!(route_line("ssh-broker.exe -c echo"), shim("echo"));
    assert_eq!(route_line(r#"ssh-broker.exe -c "echo hi""#), shim("echo hi"));
}

/// `-c` was given, so it is an exec request even when the command is empty (the shell runs
/// nothing for `-c ""`). Only a line with no `-c` at all is an interactive session.
#[test]
fn dash_c_with_an_empty_command_is_an_empty_exec() {
    for encoding in [Encoding::Verbatim, Encoding::Escaped, Encoding::Wrapped] {
        assert_eq!(route_line_as("ssh-broker.exe -c", encoding), shim(""), "{encoding:?}");
        assert_eq!(route_line_as("ssh-broker.exe -c ", encoding), shim(""), "{encoding:?}");
    }
    assert_eq!(route_line_as(r#"ssh-broker.exe -c """#, Encoding::Wrapped), shim(""));
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
        assert_eq!(route_line(&format!("ssh-broker.exe -c {verb}")), shim(verb));
        assert_eq!(
            route_line(&format!(r#"ssh-broker.exe -c "{verb} --x y""#)),
            shim(&format!("{verb} --x y"))
        );
    }
}

/// Every `-c` command is relayed whole, whatever program it names. Routing makes no decision
/// about the command (#28 deleted the `argv[0]` classifier that did), so a command that a
/// classifier would pick out, such as `sftp-server.exe` or `scp`, takes the same route and
/// reaches the shim intact. A reintroduced classifier that diverts or rewrites one fails here.
#[test]
fn every_dash_c_command_routes_to_the_relay_with_its_text_intact() {
    for command in [
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
            route_line_as(&format!("ssh-broker.exe -c {command}"), Encoding::Verbatim),
            shim(command),
            "{command}"
        );
    }
}

/// The command is normalized where it is assembled, so the string the shim relays is the string
/// it executes. Mutating the call out of `route` left the whole suite green, because nothing here
/// had ever passed an untrimmed command.
#[test]
fn shim_command_is_trimmed_at_the_parse_site() {
    let Route::Shim { exec } = route_line(r#"ssh-broker.exe -c "  scp -t /x  ""#) else {
        panic!("-c must select the shim");
    };
    assert_eq!(exec.as_deref(), Some("scp -t /x"));
    // A blank command stays an exec request rather than becoming an interactive session.
    let Route::Shim { exec } = route_line(r#"ssh-broker.exe -c "   ""#) else {
        panic!("-c must select the shim");
    };
    assert_eq!(exec.as_deref(), Some(""));
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
    let command = r"C:\Program Files\OpenSSH\sftp-server.exe -l INFO";
    // A PTY session: sshd appends the command to the line unquoted.
    assert_eq!(
        route_line_as(&format!("ssh-broker.exe -c {command}"), Encoding::Verbatim),
        shim(command)
    );
    // A non-PTY session: sshd passes the command as one quoted argument.
    assert_eq!(route_line(&format!(r#"ssh-broker.exe -c "{command}""#)), shim(command));
}

#[test]
fn dash_c_keeps_a_quoted_program_path_verbatim() {
    let command = r#""C:\Program Files\OpenSSH\sftp-server.exe" -l INFO"#;
    assert_eq!(
        route_line_as(&format!("ssh-broker.exe -c {command}"), Encoding::Verbatim),
        shim(command)
    );
    // As one escaped argument.
    assert_eq!(
        route_line(r#"ssh-broker.exe -c "\"C:\Program Files\OpenSSH\sftp-server.exe\" -l INFO""#),
        shim(command)
    );
}

/// A PTY session appends the command unquoted, so the C runtime's argv has lost its quotes and
/// collapsed its spaces. The command must come from the raw line.
#[test]
fn a_verbatim_command_keeps_its_quotes_empty_argument_and_double_space() {
    let command = r#""C:\a b\p.exe" "x y" "" end  of  line"#;
    assert_eq!(
        route_line_as(&format!("ssh-broker.exe -c {command}"), Encoding::Verbatim),
        shim(command)
    );
}

/// A non-PTY session passes the command as one escaped argument; unescaping it must restore the
/// command exactly.
#[test]
fn an_escaped_single_argument_keeps_its_quotes_empty_argument_and_double_space() {
    assert_eq!(
        route_line(r#"ssh-broker.exe -c "\"C:\a b\p.exe\" \"x y\" \"\" end  of  line""#),
        shim(r#""C:\a b\p.exe" "x y" "" end  of  line"#)
    );
}

/// A raw line that does not show `-c` first (never the case under sshd) falls back to argv.
#[test]
fn a_raw_line_without_dash_c_falls_back_to_the_joined_args() {
    assert_eq!(
        route(&["-c".into(), "a b".into(), "c".into()], "", Encoding::Escaped),
        shim("a b c")
    );
    assert_eq!(route(&["-c".into()], "", Encoding::Escaped), shim(""));
}
