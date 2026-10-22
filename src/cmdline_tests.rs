//! Host tests for command-line recovery (pure; runs on any platform).
//!
//! The three shapes sshd's `-c` tail takes are taken from Win32-OpenSSH `w32-doexec.c` and
//! `misc.c` (`build_commandline_string`); see `decode_command`.

use super::{Encoding, ShellKind, dash_c_tail, decode_command, shell_kind, split_args};

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

// Shape (a): non-PTY with sshd's default argument escaping. The command is one argument,
// quoted if it contains a space and with every `"` escaped.

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

// Shape (b): a PTY session (`ssh -t host cmd`). sshd appends the command verbatim.

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
    for encoding in [Encoding::Verbatim, Encoding::Escaped, Encoding::Wrapped] {
        assert_eq!(decode_command("", encoding), "", "{encoding:?}");
    }
}

#[test]
fn an_empty_quoted_argument_is_an_empty_command() {
    assert_eq!(decode_command(r#""""#, Encoding::Wrapped), "");
}

// Shape (a) again: the forms a C-runtime splitter reads wrongly.

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

// Shape (c): `DefaultShellEscapeArguments=0` wraps the command in quotes and nothing else.

#[test]
fn a_wrapped_command_keeps_the_quotes_inside_it() {
    assert_eq!(decode_command(r#""echo "a b"""#, Encoding::Wrapped), r#"echo "a b""#);
    assert_eq!(decode_command(r#""a"b""#, Encoding::Wrapped), r#"a"b"#);
    // Nothing is escaped, so a backslash before a quote is the command's own.
    assert_eq!(
        decode_command(r#""echo \"a b\"""#, Encoding::Wrapped),
        r#"echo \"a b\""#
    );
}

// Shape (b) again: a single quoted token is the command as written.

#[test]
fn a_verbatim_single_token_keeps_its_quotes() {
    assert_eq!(
        decode_command(r#""C:\a b\p.exe""#, Encoding::Verbatim),
        r#""C:\a b\p.exe""#
    );
    assert_eq!(decode_command(r#"--opt="a b""#, Encoding::Verbatim), r#"--opt="a b""#);
}

// Which non-PTY form sshd uses also depends on the DefaultShell path (`w32-doexec.c:308-318`,
// `:370-371`).

#[test]
fn shell_kind_matches_sshds_substring_checks() {
    for (path, kind) in [
        (r"C:\Windows\System32\cmd.exe", ShellKind::Cmd),
        (
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            ShellKind::PowerShell,
        ),
        // Only the directory name matches.
        (r"C:\Program Files\PowerShell\7\pwsh.exe", ShellKind::PowerShell),
        (r"C:\tools\pwsh.exe", ShellKind::Other),
        (r"C:\tools\ssh-shellhost.exe", ShellKind::ShellHost),
        (r"C:\Program Files\Git\usr\bin\bash.exe", ShellKind::Bash),
        (r"C:\cygwin64\bin\zsh.exe", ShellKind::Cygwin),
        (r"C:\ProgramData\ssh-broker\ssh-broker.exe", ShellKind::Other),
        ("", ShellKind::Other),
    ] {
        assert_eq!(shell_kind(path), kind, "{path}");
    }
}

/// sshd lowercases the path and turns `/` into `\` before it looks (`pwd.c:113-114`).
#[test]
fn shell_kind_ignores_case_and_slash_direction() {
    assert_eq!(shell_kind("C:/Windows/System32/CMD.EXE"), ShellKind::Cmd);
    assert_eq!(shell_kind("c:/x/PowerShell.exe"), ShellKind::PowerShell);
    assert_eq!(shell_kind("c:/x/Bash.exe"), ShellKind::Bash);
}

/// The first check that matches wins, in sshd's order.
#[test]
fn shell_kind_checks_in_sshds_order() {
    assert_eq!(shell_kind(r"c:\cygwin\powershell.exe"), ShellKind::PowerShell);
    assert_eq!(shell_kind(r"c:\windows\system32\cmd-powershell.exe"), ShellKind::Cmd);
    assert_eq!(shell_kind(r"c:\bash\ssh-shellhost.exe"), ShellKind::ShellHost);
    assert_eq!(shell_kind(r"c:\cygwin\bash.exe"), ShellKind::Bash);
}

/// cmd and ssh-shellhost get the wrapped form; PowerShell, bash and cygwin the escaped form; any
/// other path follows the registry flag (`None` here).
#[test]
fn a_shell_kind_fixes_the_form_except_for_other_paths() {
    assert_eq!(ShellKind::Cmd.encoding(), Some(Encoding::Wrapped));
    assert_eq!(ShellKind::ShellHost.encoding(), Some(Encoding::Wrapped));
    assert_eq!(ShellKind::PowerShell.encoding(), Some(Encoding::Escaped));
    assert_eq!(ShellKind::Bash.encoding(), Some(Encoding::Escaped));
    assert_eq!(ShellKind::Cygwin.encoding(), Some(Encoding::Escaped));
    assert_eq!(ShellKind::Other.encoding(), None);
}
