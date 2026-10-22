//! A port of the line Win32-OpenSSH (`PowerShell/openssh-portable`, `latestw_all` at 274893f)
//! builds for the `DefaultShell`: `do_exec_windows` in `contrib/win32/win32compat/w32-doexec.c`,
//! and `build_exec_command` / `build_commandline_string` in `misc.c`.
//!
//! Test code shared by the unit tests (`src/cmdline_encoder_tests.rs`) and the integration tests
//! (`tests/fail_open_windows.rs`), so a change to the decoder cannot pass by changing the encoder
//! it is checked against. Each includer uses a subset.
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

/// The line sshd builds for a PTY session: `"shell" -c <command>`, the command appended raw
/// (`w32-doexec.c:329-341`).
pub fn verbatim_line(shell: &str, command: &str) -> String {
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

/// The line sshd builds without a PTY and with `DefaultShellEscapeArguments=0`:
/// `sprintf("%s %s \"%s\"", shell, option, exec_command)` (`w32-doexec.c:399-400`).
pub fn wrapped_line(shell: &str, command: &str) -> String {
    format!("\"{shell}\" -c \"{}\"", build_exec_command(command))
}
