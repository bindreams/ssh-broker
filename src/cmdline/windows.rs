//! The process's raw command line, and how sshd encoded it.

use ::windows::Win32::System::Console::{CONSOLE_MODE, GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE};
use ::windows::Win32::System::Environment::GetCommandLineW;

use super::{Detected, Encoding, shell_kind};
use crate::provision::registry::{OPENSSH_KEY, default_shell_path_under, escape_arguments_under};

/// The command line exactly as the parent passed it, program name included.
pub fn current() -> String {
    // SAFETY: GetCommandLineW has no preconditions; the returned buffer is owned by the
    // process and lives until it exits, so reading it here is sound.
    let line = unsafe { GetCommandLineW() };
    String::from_utf16_lossy(unsafe { line.as_wide() })
}

/// How sshd encoded this process's command line.
///
/// A PTY session runs the shell under conhost, so its stdin is a console; a non-PTY session
/// gives it the pipes sshd created, so it is not (`win32_pty.c` and `w32fd.c` in Win32-OpenSSH;
/// `tests/session_encoding_windows.rs` measures it). Without a console, see [`detect_piped`].
pub fn detect() -> Detected {
    if stdin_is_console() {
        Detected {
            encoding: Encoding::Verbatim,
            warning: None,
        }
    } else {
        let own_exe = std::env::current_exe().map(|path| path.to_string_lossy().into_owned());
        detect_piped(
            own_exe,
            || default_shell_path_under(OPENSSH_KEY),
            || escape_arguments_under(OPENSSH_KEY),
        )
    }
}

/// sshd reads `DefaultShellEscapeArguments` only when the path does not decide the form (see
/// [`super::ShellKind::encoding`]). `own_exe` stands in for the path when none is registered or
/// readable: sshd launched the shim as that shell.
fn detect_piped(
    own_exe: std::io::Result<String>,
    read_shell: impl FnOnce() -> ::windows::core::Result<Option<String>>,
    read_flag: impl FnOnce() -> ::windows::core::Result<bool>,
) -> Detected {
    let mut warnings = Vec::new();
    let registered = match read_shell() {
        Ok(path) => path,
        Err(error) => {
            warnings.push(format!(
                "cannot read HKLM\\{OPENSSH_KEY}\\DefaultShell ({error}); assuming it is this program"
            ));
            None
        }
    };
    let shell = match (registered, own_exe) {
        (Some(path), _) => path,
        (None, Ok(path)) => path,
        (None, Err(error)) => {
            warnings.push(format!(
                "cannot find this program's own path ({error}); assuming it is not cmd, PowerShell, \
                 ssh-shellhost, bash or cygwin"
            ));
            String::new()
        }
    };
    let detected = detect_piped_with(&shell, read_flag);
    warnings.extend(detected.warning);
    Detected {
        encoding: detected.encoding,
        warning: (!warnings.is_empty()).then(|| warnings.join("; ")),
    }
}

/// The form for a known shell path and a way to read the escape flag, which is called only when
/// the path leaves the form to the flag.
fn detect_piped_with(shell: &str, escape_arguments: impl FnOnce() -> ::windows::core::Result<bool>) -> Detected {
    match shell_kind(shell).encoding() {
        Some(encoding) => Detected {
            encoding,
            warning: None,
        },
        None => piped_encoding(escape_arguments()),
    }
}

/// The non-PTY form for what reading `DefaultShellEscapeArguments` gave. When the read failed,
/// sshd's own read failed the same way and kept escaping on, so the shim assumes that; if the
/// real value is 0, the command is then decoded as the wrong form, which the warning says.
fn piped_encoding(read: ::windows::core::Result<bool>) -> Detected {
    match read {
        Ok(true) => Detected {
            encoding: Encoding::Escaped,
            warning: None,
        },
        Ok(false) => Detected {
            encoding: Encoding::Wrapped,
            warning: None,
        },
        Err(error) => Detected {
            encoding: Encoding::Escaped,
            warning: Some(format!(
                "cannot read HKLM\\{OPENSSH_KEY}\\DefaultShellEscapeArguments ({error}); assuming sshd \
                 escapes the command (its default); if the value is 0, this command may be decoded wrongly"
            )),
        },
    }
}

fn stdin_is_console() -> bool {
    let mut mode = CONSOLE_MODE(0);
    // SAFETY: `mode` is a valid out-pointer; an invalid or non-console handle only makes the
    // call fail.
    unsafe { GetStdHandle(STD_INPUT_HANDLE).is_ok_and(|stdin| GetConsoleMode(stdin, &mut mode).is_ok()) }
}

#[cfg(test)]
#[path = "windows_tests.rs"]
mod windows_tests;
