//! The encoder-inverse property: for every command in a corpus, the command `route` recovers
//! from the line sshd builds equals the command sshd was given, in each of sshd's three forms.
//!
//! The encoder is a port of Win32-OpenSSH, kept in `tests/common/sshd_encoder.rs` so the
//! integration tests use the same one. It is test code, so a change to the decoder cannot pass
//! by changing the encoder it is checked against.

use crate::cmdline::{Encoding, split_args};
use crate::route::{Route, route};

#[path = "../tests/common/sshd_encoder.rs"]
mod sshd_encoder;
use sshd_encoder::{build_exec_command, escape_arg};

const SHELL: &str = r"C:\Program Files\ssh-broker\ssh-broker.exe";

/// `Encoding` selects which of the three lines sshd builds.
fn encode(encoding: Encoding, command: &str) -> String {
    match encoding {
        Encoding::Verbatim => sshd_encoder::verbatim_line(SHELL, command),
        Encoding::Escaped => sshd_encoder::escaped_line(SHELL, command),
        Encoding::Wrapped => sshd_encoder::wrapped_line(SHELL, command),
    }
}

// The corpus =====

/// Commands of every shape the encoder treats specially, plus the ones devvm sends.
const CORPUS: &[&str] = &[
    "whoami",
    "echo hi",
    "echo  two  spaces",
    "echo\ttab",
    "a\tb",
    "\tleading-tab",
    "trailing-tab\t",
    "  leading and trailing  ",
    " ",
    "  ",
    "",
    // Quotes.
    r#"echo "a b""#,
    r#"a"b"#,
    r#""quoted""#,
    r#"--opt="a b""#,
    r#"git commit -m "a b""#,
    r#"""#,
    r#"""x"#,
    // sshd does not quote a command that starts with `'`, even with spaces in it.
    "'single quoted start' x",
    "'x'",
    r#"'a "b" c'"#,
    // Backslashes next to quotes and at the end.
    r#"echo \"a b\""#,
    r#"echo a\\"b c"#,
    r#"echo "a b"\"#,
    r"echo C:\dir\",
    r"echo C:\a b\",
    r"echo C:\a b\\",
    r"echo \\server\share\x y",
    r"\",
    // Program paths, with and without spaces, quoted or not.
    r#""C:\a b\p.exe" "x y""#,
    r#"p.exe "" end"#,
    r#""C:\a b\p.exe" "x y" "" end  of  line"#,
    r"C:\Program Files\OpenSSH\sftp-server.exe -l INFO",
    r#""C:\Program Files\OpenSSH\sftp-server.exe" -l INFO"#,
    // Not ASCII.
    "echo héllo wörld ✓",
    "echo 日本語 \"x y\"",
    // Commands sshd rewrites.
    "scp -t /x",
    "SCP.exe -f /x",
    "scp",
    "sftp-server -l INFO",
    "Sftp-Server.EXE -l INFO",
    "sftp-server.exe",
    "internal-sftp",
    "internal-sftp -l INFO",
    // Commands named like verbs or options.
    "agent",
    "-c x",
];

/// What `route` must make of `command` once sshd has encoded it in `encoding`.
///
/// Three things are not the command itself. sshd rewrites an `scp`/`sftp` command first
/// (`build_exec_command`). The shim then trims the edges, which carry no meaning
/// (`shim::normalize_exec`). And an empty command leaves nothing after `-c` in the first two
/// forms, so it reads as no command; stock clients send an interactive session in that case.
fn expected(encoding: Encoding, command: &str) -> Option<String> {
    let sent = match encoding {
        Encoding::Verbatim => command.to_string(),
        Encoding::Escaped | Encoding::Wrapped => build_exec_command(command),
    };
    if sent.is_empty() && encoding != Encoding::Wrapped {
        return None;
    }
    Some(sent.trim_matches(crate::shim::BOUNDARY).to_string())
}

fn routed(encoding: Encoding, command: &str) -> Option<String> {
    let line = encode(encoding, command);
    let args = split_args(&line);
    match route(&args[1..], &line, encoding) {
        Route::Shim { exec } => exec,
        other => panic!("{line:?} routed to {other:?}, not the shim"),
    }
}

#[test]
fn decoding_inverts_sshds_encoding_for_every_command_in_the_corpus() {
    let mut failures = Vec::new();
    for encoding in [Encoding::Verbatim, Encoding::Escaped, Encoding::Wrapped] {
        for command in CORPUS {
            let got = routed(encoding, command);
            let want = expected(encoding, command);
            if got != want {
                failures.push(format!(
                    "{encoding:?} {command:?}\n  line: {}\n  want: {want:?}\n  got:  {got:?}",
                    encode(encoding, command)
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// sshd quotes a space-containing argument but does not double a trailing backslash, so the
/// closing quote reads as escaped to a C-runtime splitter. The command is still recoverable
/// because the quote that ends the line is the closing one.
#[test]
fn a_trailing_backslash_in_a_quoted_command_is_recovered() {
    let command = r"echo C:\a b\";
    assert_eq!(
        encode(Encoding::Escaped, command),
        format!(r#""{SHELL}" -c "echo C:\a b\""#)
    );
    assert_eq!(routed(Encoding::Escaped, command).as_deref(), Some(command));
    let command = r"echo C:\a b\\";
    assert_eq!(routed(Encoding::Escaped, command).as_deref(), Some(command));
}

// The port itself =====

#[test]
fn the_encoder_matches_sshds_documented_shapes() {
    assert_eq!(escape_arg("whoami"), "whoami");
    assert_eq!(escape_arg("echo hi"), r#""echo hi""#);
    // Quotes are escaped; no space, so no wrapper.
    assert_eq!(escape_arg(r#"a"b"#), r#"a\"b"#);
    // Backslashes double before a quote and not elsewhere.
    assert_eq!(escape_arg(r#"a\"b"#), r#"a\\\"b"#);
    assert_eq!(escape_arg(r"a\b"), r"a\b");
    // A leading `'` suppresses the wrapper.
    assert_eq!(escape_arg("'a b'"), "'a b'");
    assert_eq!(build_exec_command("scp -t /x"), "scp.exe -t /x");
    assert_eq!(build_exec_command("Sftp-Server.EXE -l x"), "sftp-server.exe -l x");
    assert_eq!(build_exec_command("internal-sftp"), "sftp-server.exe");
    assert_eq!(build_exec_command("echo scp"), "echo scp");
}
