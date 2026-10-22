//! A port of the line Win32-OpenSSH (`PowerShell/openssh-portable`, `latestw_all` at 274893f)
//! builds for the `DefaultShell`: `do_exec_windows` in `contrib/win32/win32compat/w32-doexec.c`,
//! and `build_exec_command` / `build_commandline_string` in `misc.c`; and of the step conhost
//! (`microsoft/terminal`, `ConsoleArguments::_GetClientCommandline`) adds in a PTY session.
//!
//! Test code shared by the unit tests (`src/cmdline_encoder_tests.rs`) and the integration tests
//! (`tests/fail_open_windows.rs`, `tests/conhost_windows.rs`), so a change to the decoder cannot
//! pass by changing the encoder it is checked against. Each includer uses a subset.
#![allow(dead_code)]

/// `build_exec_command` (`misc.c`): sshd rewrites a command that names `scp`, `sftp-server` or
/// `internal-sftp` before it builds the line. Prefix matches are ASCII case-insensitive.
pub fn build_exec_command(command: &str) -> String {
    let b = command.as_bytes();
    let starts = |n: usize, name: &[u8]| b.len() >= n && b[..n].eq_ignore_ascii_case(name);
    // The `.exe` extension is optional and skipped when present.
    let after_exe = |name_len: usize| {
        if b.len() >= name_len + 4 && b[name_len..name_len + 4].eq_ignore_ascii_case(b".exe") {
            name_len + 4
        } else {
            name_len
        }
    };
    if starts(13, b"internal-sftp") {
        format!("sftp-server.exe{}", &command[13..])
    } else if starts(11, b"sftp-server") {
        format!("sftp-server.exe{}", &command[after_exe(11)..])
    } else if starts(3, b"scp") {
        format!("scp.exe{}", &command[after_exe(3)..])
    } else {
        command.to_string()
    }
}

/// The per-argument part of `build_commandline_string` (`misc.c`): quoted only if it contains a
/// space and does not start with `'`; every `"` is escaped; backslashes are doubled only when
/// they precede a `"`. A trailing backslash is not doubled before the closing quote.
pub fn escape_arg(arg: &str) -> String {
    let quote = !arg.starts_with('\'') && arg.contains(' ');
    let mut out = String::new();
    if quote {
        out.push('"');
    }
    let mut chars = arg.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                let mut run = 1;
                while chars.next_if_eq(&'\\').is_some() {
                    run += 1;
                }
                let doubled = chars.peek() == Some(&'"');
                out.extend(std::iter::repeat_n('\\', if doubled { run * 2 } else { run }));
            }
            '"' => out.push_str("\\\""),
            c => out.push(c),
        }
    }
    if quote {
        out.push('"');
    }
    out
}

/// The command line sshd gives conhost for a PTY session, after `--`: `"shell" -c <command>`, the
/// command appended raw (`w32-doexec.c:329-341`). It is not what the shell receives: see
/// [`conhost_client_line`].
pub fn pty_line(shell: &str, command: &str) -> String {
    format!("\"{shell}\" -c {command}")
}

/// The line sshd builds without a PTY and with `DefaultShellEscapeArguments` on:
/// `spawn_argv = {shell, "-c", exec_command}` through `build_commandline_string`
/// (`w32-doexec.c:370-376`).
pub fn escaped_line(shell: &str, command: &str) -> String {
    format!("\"{shell}\" -c {}", escaped_argument(command))
}

/// The command as sshd puts it on the line in the escaped form: everything after `-c`.
pub fn escaped_argument(command: &str) -> String {
    escape_arg(&build_exec_command(command))
}

/// Whether sshd consults `DefaultShellEscapeArguments` for this `DefaultShell` path
/// (`w32-doexec.c:308-318`, `:370-371`): only when none of the substrings it looks for is in the
/// path, which sshd has lowercased and turned `/` into `\` (`pwd.c:113-114`). Otherwise the path
/// alone fixes the form.
pub fn flag_decides_form(shell: &str) -> bool {
    let path = shell.replace('/', "\\").to_ascii_lowercase();
    ["system32\\cmd", "powershell", "ssh-shellhost", "\\bash", "cygwin"]
        .iter()
        .all(|special| !path.contains(special))
}

// conhost =====

type Chars<'a> = std::iter::Peekable<std::str::Chars<'a>>;

fn skip_separators(chars: &mut Chars<'_>) {
    while chars.next_if(|c| matches!(c, ' ' | '\t')).is_some() {}
}

/// Split `line` into arguments the way `CommandLineToArgvW` does: the first is the program name,
/// which has no escapes (a leading quote ends at the next quote); after that, space and tab
/// separate, a quote toggles quoting (two inside quotes are one literal quote and end the
/// quoting), and backslashes count only before a quote. `tests/conhost_windows.rs` checks it against the API.
pub fn tokenize(line: &str) -> Vec<String> {
    let mut chars = line.chars().peekable();
    let mut args = Vec::new();
    skip_separators(&mut chars);
    if chars.peek().is_none() {
        return args;
    }
    let mut program = String::new();
    if chars.next_if_eq(&'"').is_some() {
        program.extend(chars.by_ref().take_while(|&c| c != '"'));
    } else {
        while let Some(c) = chars.next_if(|c| !matches!(c, ' ' | '\t')) {
            program.push(c);
        }
    }
    args.push(program);
    loop {
        skip_separators(&mut chars);
        if chars.peek().is_none() {
            return args;
        }
        args.push(next_argument(&mut chars));
    }
}

fn next_argument(chars: &mut Chars<'_>) -> String {
    let mut arg = String::new();
    let mut in_quotes = false;
    while let Some(&c) = chars.peek() {
        match c {
            '\\' => {
                let mut run = 0;
                while chars.next_if_eq(&'\\').is_some() {
                    run += 1;
                }
                if chars.next_if_eq(&'"').is_some() {
                    arg.extend(std::iter::repeat_n('\\', run / 2));
                    if run % 2 == 1 {
                        arg.push('"');
                    } else if in_quotes && chars.next_if_eq(&'"').is_some() {
                        arg.push('"');
                        in_quotes = false;
                    } else {
                        in_quotes = !in_quotes;
                    }
                } else {
                    arg.extend(std::iter::repeat_n('\\', run));
                }
            }
            '"' => {
                chars.next();
                if in_quotes && chars.next_if_eq(&'"').is_some() {
                    arg.push('"');
                    in_quotes = false;
                } else {
                    in_quotes = !in_quotes;
                }
            }
            ' ' | '\t' if !in_quotes => break,
            c => {
                arg.push(c);
                chars.next();
            }
        }
    }
    arg
}

/// conhost's `EscapeArgument`: an argument is quoted if it is empty or holds a space or tab,
/// every quote is escaped, and backslashes are doubled before a quote and, in a quoted argument,
/// before the closing quote.
pub fn conhost_escape(arg: &str) -> String {
    if arg.is_empty() {
        return "\"\"".to_string();
    }
    let quote = arg.contains([' ', '\t']);
    let mut out = String::new();
    if quote {
        out.push('"');
    }
    let mut slashes = 0;
    for c in arg.chars() {
        match c {
            '\\' => slashes += 1,
            '"' => {
                out.extend(std::iter::repeat_n('\\', slashes + 1));
                slashes = 0;
            }
            _ => slashes = 0,
        }
        out.push(c);
    }
    if quote {
        out.extend(std::iter::repeat_n('\\', slashes));
        out.push('"');
    }
    out
}

/// The command line the shell is started with in a PTY session. sshd runs
/// `conhost.exe --headless ... -- <pty_line>` (`win32_pty.c:90-106`), and conhost splits what
/// follows `--` into arguments and joins them again, escaping each
/// (`ConsoleArguments::_GetClientCommandline`). `pty_line` is [`pty_line`]'s result.
pub fn conhost_client_line(pty_line: &str) -> String {
    tokenize(&format!("conhost.exe --headless -- {pty_line}"))
        .iter()
        .skip(3)
        .map(|arg| conhost_escape(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The line the shim receives in a PTY session: the line sshd builds, as conhost rewrites it.
pub fn verbatim_line(shell: &str, command: &str) -> String {
    conhost_client_line(&pty_line(shell, command))
}
