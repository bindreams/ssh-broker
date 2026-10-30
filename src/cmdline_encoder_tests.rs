//! The encoder-inverse property: for every command in a corpus, and for every short string over
//! the characters that matter, the command `route` recovers from the line the shim receives
//! equals the command sshd was given, in each of the two forms it can take. In a PTY session conhost
//! rewrites the line first, so there the command recovered is the one conhost rebuilt.
//!
//! The encoder is a port of Win32-OpenSSH and conhost, kept in `tests/common/sshd_encoder.rs` so
//! the integration tests use the same one. It is test code, so a change to the decoder cannot
//! pass by changing the encoder it is checked against.

use crate::cmdline::{Encoding, resolve_exec, split_args};
use crate::route::{Route, route};

#[path = "../tests/common/sshd_encoder.rs"]
mod sshd_encoder;
use sshd_encoder::{build_exec_command, conhost_escape, escape_arg, flag_decides_form, tokenize};

#[path = "../tests/common/command_corpus.rs"]
mod command_corpus;
use command_corpus::CORPUS;

const SHELL: &str = r"C:\Program Files\ssh-broker\ssh-broker.exe";

/// The line the shim receives. `Encoding` selects which of the two lines sshd builds; a PTY
/// session's line has been through conhost.
fn encode(encoding: Encoding, command: &str) -> String {
    match encoding {
        Encoding::Verbatim => sshd_encoder::verbatim_line(SHELL, command),
        Encoding::Escaped => sshd_encoder::escaped_line(SHELL, command),
    }
}

/// The command conhost passes on for a PTY session: the arguments after `-c`, each escaped again
/// and joined by one space. Derived from the tokens, not from the line `encode` builds.
fn conhost_command(command: &str) -> String {
    tokenize(&sshd_encoder::pty_line(SHELL, command))[2..]
        .iter()
        .map(|arg| conhost_escape(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

/// What `route` must make of `command` once sshd has encoded it in `encoding`. sshd rewrites an
/// `scp`/`sftp` command first (`build_exec_command`), and conhost rebuilds a PTY command from its
/// arguments. Otherwise the command arrives exactly as sent, whitespace at its edges included.
fn expected(encoding: Encoding, command: &str) -> String {
    match encoding {
        Encoding::Verbatim => conhost_command(command),
        Encoding::Escaped => build_exec_command(command),
    }
}

/// The command the shim recovers from the line, deciding the form as `encoding`.
fn routed(encoding: Encoding, command: &str) -> String {
    let line = encode(encoding, command);
    let args = split_args(&line);
    match route(&args[1..], &line) {
        Route::Shim { exec: Some(exec) } => resolve_exec(exec, || encoding),
        other => panic!("{line:?} routed to {other:?}, not a shim exec"),
    }
}

fn check(encoding: Encoding, command: &str, failures: &mut Vec<String>) {
    let got = routed(encoding, command);
    let want = expected(encoding, command);
    if got != want {
        failures.push(format!(
            "{encoding:?} {command:?}\n  line: {}\n  want: {want:?}\n  got:  {got:?}",
            encode(encoding, command)
        ));
    }
}

const ENCODINGS: [Encoding; 2] = [Encoding::Verbatim, Encoding::Escaped];

#[test]
fn decoding_inverts_sshds_encoding_for_every_command_in_the_corpus() {
    let mut failures = Vec::new();
    for encoding in ENCODINGS {
        for command in CORPUS {
            check(encoding, command, &mut failures);
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Every string up to `max_len` over `alphabet`, shortest first.
fn strings(alphabet: &[char], max_len: usize) -> impl Iterator<Item = String> + '_ {
    let mut layer = vec![String::new()];
    let mut all = vec![String::new()];
    for _ in 0..max_len {
        layer = layer
            .iter()
            .flat_map(|prefix| {
                alphabet.iter().map(move |c| {
                    let mut s = prefix.clone();
                    s.push(*c);
                    s
                })
            })
            .collect();
        all.extend(layer.iter().cloned());
    }
    all.into_iter()
}

/// The corpus samples shapes; this takes all of them up to a length, over the characters the
/// encoders and the decoder treat specially.
#[test]
fn decoding_inverts_sshds_encoding_for_every_short_string() {
    let alphabet = ['a', ' ', '\t', '"', '\\', '\'', '\n'];
    let mut failures = Vec::new();
    for command in strings(&alphabet, 6) {
        for encoding in ENCODINGS {
            check(encoding, &command, &mut failures);
        }
        if failures.len() > 20 {
            break;
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// conhost changes the text of a PTY command but not the arguments it splits into, so the
/// command the shim relays runs as the client meant it.
#[test]
fn conhost_keeps_the_arguments_of_a_pty_command() {
    let alphabet = ['a', ' ', '\t', '"', '\\', '\n'];
    let argv = |text: &str| tokenize(&format!("p {text}"))[1..].to_vec();
    for command in strings(&alphabet, 6).chain(CORPUS.iter().map(|c| c.to_string())) {
        assert_eq!(
            argv(&routed(Encoding::Verbatim, &command)),
            argv(&command),
            "{command:?}"
        );
    }
}

/// What conhost does to a PTY command, as measured against the real `conhost.exe` (see
/// `tests/conhost_windows.rs`, which checks the model on these and on the corpus): arguments are
/// re-joined by one space, quotes that wrap no space are dropped, and the edges go.
#[test]
fn a_pty_command_is_relayed_as_conhost_rebuilt_it() {
    for (sent, relayed) in [
        (r#"echo  "a  b"   x"#, r#"echo "a  b" x"#),
        ("cmd /c echo a   b", "cmd /c echo a b"),
        (r#"echo "a"b"#, "echo ab"),
        (r#"x""y"#, "xy"),
        ("a\tb", "a b"),
        ("trailing   ", "trailing"),
        ("  leading", "leading"),
        (r#""C:\a b\p.exe" "x y""#, r#""C:\a b\p.exe" "x y""#),
        ("echo hi", "echo hi"),
    ] {
        assert_eq!(routed(Encoding::Verbatim, sent), relayed, "{sent:?}");
    }
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
    assert_eq!(routed(Encoding::Escaped, command), command);
    let command = r"echo C:\a b\\";
    assert_eq!(routed(Encoding::Escaped, command), command);
}

// The port itself =====

/// The shim decodes the escaped form only because `apply` sets the flag AND installs the shim at a
/// path for which sshd reads the flag: a path with `cmd`, `powershell`, `ssh-shellhost`, `bash`
/// or `cygwin` in it would fix the form without it. The path is the one `apply` registers
/// ([`crate::provision::canonical_exe`]).
#[test]
fn sshd_reads_the_flag_for_the_path_apply_registers() {
    let registered = crate::provision::canonical_exe();
    assert!(flag_decides_form(&registered.to_string_lossy()));
    assert!(flag_decides_form(r"c:/programdata/ssh-broker/ssh-broker.exe"));
    assert!(!flag_decides_form(r"C:\Windows\System32\cmd.exe"));
    assert!(!flag_decides_form(
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    ));
    assert!(!flag_decides_form(r"C:\tools\ssh-shellhost.exe"));
    assert!(!flag_decides_form(r"C:\Git\usr\bin\bash.exe"));
    assert!(!flag_decides_form(r"C:\cygwin64\bin\zsh.exe"));
}

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

#[test]
fn the_conhost_port_splits_and_escapes_like_the_c_runtime() {
    assert_eq!(tokenize(r#"p a  b"#), ["p", "a", "b"]);
    assert_eq!(tokenize("p a\tb"), ["p", "a", "b"]);
    assert_eq!(tokenize(r#"p "a b" c"#), ["p", "a b", "c"]);
    assert_eq!(tokenize(r#"p "" c"#), ["p", "", "c"]);
    assert_eq!(tokenize(r#"p "a"b"#), ["p", "ab"]);
    assert_eq!(tokenize(r#"p a\"b"#), ["p", r#"a"b"#]);
    assert_eq!(tokenize(r#"p "a\\" b"#), ["p", r"a\", "b"]);
    assert_eq!(tokenize(r#"p "a""b""#), ["p", r#"a"b"#]);
    // The program name has no escapes.
    assert_eq!(tokenize(r#""C:\a b\" x"#), [r"C:\a b\", "x"]);
    assert_eq!(tokenize("   "), Vec::<String>::new());

    assert_eq!(conhost_escape("abc"), "abc");
    assert_eq!(conhost_escape(""), r#""""#);
    assert_eq!(conhost_escape("a b"), r#""a b""#);
    assert_eq!(conhost_escape("a\tb"), "\"a\tb\"");
    assert_eq!(conhost_escape(r#"a"b"#), r#"a\"b"#);
    assert_eq!(conhost_escape(r#"a\"b"#), r#"a\\\"b"#);
    assert_eq!(conhost_escape(r"a\b"), r"a\b");
    // Backslashes before the closing quote double only in a quoted argument.
    assert_eq!(conhost_escape(r"a b\"), r#""a b\\""#);
    assert_eq!(conhost_escape(r"ab\"), r"ab\");
}
