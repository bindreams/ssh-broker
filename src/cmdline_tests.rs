//! Host tests for command-line recovery (pure; runs on any platform).
//!
//! The forms sshd's `-c` tail takes are taken from Win32-OpenSSH `w32-doexec.c` and `misc.c`
//! (`build_commandline_string`); see `decode_command`.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex};

use super::{Encoding, RawExec, dash_c_tail, decode_command, resolve_exec, split_args};

fn args(line: &str) -> Vec<String> {
    split_args(line)
}

#[test]
fn split_args_follows_the_crt_rules() {
    assert_eq!(args(r#"p a  b"#), ["p", "a", "b"]);
    assert_eq!(args("p a\tb"), ["p", "a", "b"]);
    assert_eq!(args(r#"p "a b" c"#), ["p", "a b", "c"]);
    // An empty quoted argument is an argument.
    assert_eq!(args(r#"p "" c"#), ["p", "", "c"]);
    // Backslashes are literal unless they precede a quote.
    assert_eq!(args(r"p C:\a\b"), ["p", r"C:\a\b"]);
    assert_eq!(args(r#"p a\"b"#), ["p", r#"a"b"#]);
    assert_eq!(args(r#"p "a\\" b"#), ["p", r"a\", "b"]);
    assert_eq!(args(r#"p "a\\\"b""#), ["p", r#"a\"b"#]);
    // A quote inside quotes, doubled, is a literal quote.
    assert_eq!(args(r#"p "a""b""#), ["p", r#"a"b"#]);
    // The program name is split like any argument here; only `dash_c_tail` special-cases it.
    assert_eq!(args(""), Vec::<String>::new());
    assert_eq!(args("   "), Vec::<String>::new());
}

#[test]
fn dash_c_tail_skips_the_program_and_the_dash_c() {
    assert_eq!(dash_c_tail("ssh-broker.exe -c echo hi"), Some("echo hi"));
    // The program name has no escape rules: a quoted path ends at the next quote.
    assert_eq!(
        dash_c_tail(r#""C:\Program Files\ssh-broker\ssh-broker.exe" -c echo hi"#),
        Some("echo hi")
    );
    assert_eq!(dash_c_tail("ssh-broker.exe  -c echo  hi "), Some("echo  hi "));
    assert_eq!(dash_c_tail("ssh-broker.exe -c"), Some(""));
    assert_eq!(dash_c_tail("ssh-broker.exe -c "), Some(""));
}

/// sshd writes one space after `-c`; whatever follows is the command, edges included.
#[test]
fn dash_c_tail_drops_exactly_one_separator() {
    assert_eq!(dash_c_tail("ssh-broker.exe -c \t echo"), Some("\t echo"));
    assert_eq!(dash_c_tail("ssh-broker.exe -c   "), Some("  "));
}

#[test]
fn dash_c_tail_is_none_when_the_first_argument_is_not_dash_c() {
    assert_eq!(dash_c_tail("ssh-broker.exe"), None);
    assert_eq!(dash_c_tail("ssh-broker.exe agent"), None);
    assert_eq!(dash_c_tail("ssh-broker.exe -cx echo"), None);
}

#[test]
fn dash_c_tail_does_not_unquote_the_command() {
    assert_eq!(
        dash_c_tail(r#"ssh-broker.exe -c "C:\a b\p.exe" "x y""#),
        Some(r#""C:\a b\p.exe" "x y""#)
    );
}

// Escaped: non-PTY with sshd's default argument escaping. The command is one argument, quoted if
// it contains a space and with every `"` escaped.

#[test]
fn an_escaped_single_argument_decodes_to_the_command() {
    assert_eq!(decode_command(r#""echo  hi""#, Encoding::Escaped), "echo  hi");
    assert_eq!(
        decode_command(r#""\"C:\a b\p.exe\" \"x y\"""#, Encoding::Escaped),
        r#""C:\a b\p.exe" "x y""#
    );
    assert_eq!(decode_command(r"whoami", Encoding::Escaped), "whoami");
    // No space, so sshd leaves it unquoted but still escapes the quotes.
    assert_eq!(decode_command(r#"a\"b"#, Encoding::Escaped), r#"a"b"#);
}

// Verbatim: a PTY session (`ssh -t host cmd`). The tail is the command as the shim received it.

#[test]
fn a_verbatim_command_is_kept_exactly() {
    assert_eq!(
        decode_command(r#""C:\a b\p.exe" "x y""#, Encoding::Verbatim),
        r#""C:\a b\p.exe" "x y""#
    );
    // An empty argument and a run of spaces both survive.
    assert_eq!(decode_command(r#"p.exe "" end"#, Encoding::Verbatim), r#"p.exe "" end"#);
    assert_eq!(
        decode_command("echo  two  spaces", Encoding::Verbatim),
        "echo  two  spaces"
    );
    assert_eq!(
        decode_command(r"C:\Program Files\OpenSSH\sftp-server.exe -l INFO", Encoding::Verbatim),
        r"C:\Program Files\OpenSSH\sftp-server.exe -l INFO"
    );
}

/// `-c` was given, so the client asked to run something; an empty command is an exec request
/// that runs nothing, not an interactive session.
#[test]
fn an_empty_tail_is_an_empty_command() {
    for encoding in [Encoding::Verbatim, Encoding::Escaped] {
        assert_eq!(decode_command("", encoding), "", "{encoding:?}");
    }
}

// Escaped, again: the forms a C-runtime splitter reads wrongly.

#[test]
fn an_escaped_command_sshd_left_unwrapped_is_not_split() {
    // A leading `'` suppresses the wrapper, spaces and all.
    assert_eq!(decode_command(r#"'a \"b\" c'"#, Encoding::Escaped), r#"'a "b" c'"#);
    // Only a space triggers the wrapper, so a tab stays bare.
    assert_eq!(decode_command("a\tb", Encoding::Escaped), "a\tb");
}

#[test]
fn an_escaped_command_ending_in_a_backslash_keeps_it() {
    // sshd does not double the backslash before the closing quote.
    assert_eq!(decode_command(r#""echo C:\a b\""#, Encoding::Escaped), r"echo C:\a b\");
    assert_eq!(
        decode_command(r#""echo C:\a b\\""#, Encoding::Escaped),
        r"echo C:\a b\\"
    );
}

// Verbatim, again: a single quoted token is the command as written.

#[test]
fn a_verbatim_single_token_keeps_its_quotes() {
    assert_eq!(
        decode_command(r#""C:\a b\p.exe""#, Encoding::Verbatim),
        r#""C:\a b\p.exe""#
    );
    assert_eq!(decode_command(r#"--opt="a b""#, Encoding::Verbatim), r#"--opt="a b""#);
}

// Resolving a `-c` command =====

/// Run `f` and return what it logged, with its result.
pub(super) fn logged<T>(f: impl FnOnce() -> T) -> (String, T) {
    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Buf {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buf {
        type Writer = Buf;
        fn make_writer(&'a self) -> Buf {
            self.clone()
        }
    }
    let buf = Buf::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(buf.clone())
        .with_ansi(false)
        .finish();
    let result = tracing::subscriber::with_default(subscriber, f);
    let log = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    (log, result)
}

#[test]
fn a_tail_is_decoded_by_the_encoding() {
    let tail = || RawExec::Tail(r#""echo \"a b\"""#.into());
    let (log, command) = logged(|| resolve_exec(tail(), || Encoding::Escaped));
    assert_eq!(command, r#"echo "a b""#);
    assert_eq!(log, "", "nothing to report");
    let (_, command) = logged(|| resolve_exec(tail(), || Encoding::Verbatim));
    assert_eq!(command, r#""echo \"a b\"""#);
}

/// argv carried a `-c` the raw line did not show: the joined argv is the command, nothing is
/// detected, and the log says the line was unexpected.
#[test]
fn an_argv_command_is_used_as_it_is_and_logged() {
    let detect = || -> Encoding { panic!("there is no encoding to detect for argv") };
    let (log, command) = logged(|| resolve_exec(RawExec::Argv("a b c".into()), detect));
    assert_eq!(command, "a b c");
    assert!(log.contains("WARN") && log.contains("no `-c`"), "{log}");
}

/// A tail that the form's own rules say cannot occur: an escaped one that opens a quote and never
/// closes it. The tail is decoded as far as it goes and the log says so; a debug build also
/// asserts.
#[test]
fn a_tail_that_does_not_fit_its_form_is_logged() {
    for (tail, encoding) in [(r#""abc"#, Encoding::Escaped), (r#"""#, Encoding::Escaped)] {
        let (log, result) = logged(|| catch_unwind(AssertUnwindSafe(|| decode_command(tail, encoding))));
        assert!(
            log.contains("WARN") && log.contains("does not fit"),
            "{encoding:?} {tail:?}: {log}"
        );
        assert_eq!(
            result.is_err(),
            cfg!(debug_assertions),
            "{encoding:?} {tail:?}: a debug build asserts and a release build does not"
        );
    }
}

#[test]
fn a_tail_that_fits_its_form_is_not_logged() {
    for (tail, encoding) in [
        ("", Encoding::Escaped),
        ("", Encoding::Verbatim),
        (r#""""#, Encoding::Escaped),
        ("abc", Encoding::Escaped),
        (r#"a\"b"#, Encoding::Escaped),
        (r#""a b""#, Encoding::Escaped),
        (r#""abc"#, Encoding::Verbatim),
        ("abc", Encoding::Verbatim),
    ] {
        let (log, _) = logged(|| decode_command(tail, encoding));
        assert_eq!(log, "", "{encoding:?} {tail:?}");
    }
}
