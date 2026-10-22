//! The process's raw command line, and how sshd encoded it.

use ::windows::Win32::System::Console::{CONSOLE_MODE, GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE};
use ::windows::Win32::System::Environment::GetCommandLineW;

use super::{Detected, Encoding};
use crate::provision::registry::{OPENSSH_KEY, escape_arguments_under};

/// The command line exactly as the parent passed it, program name included.
pub fn current() -> String {
    // SAFETY: GetCommandLineW has no preconditions; the returned buffer is owned by the
    // process and lives until it exits, so reading it here is sound.
    let line = unsafe { GetCommandLineW() };
    String::from_utf16_lossy(unsafe { line.as_wide() })
}

/// How sshd encoded this process's command line.
///
/// A PTY session runs the shell on a pseudoconsole, so its stdin is a console; a non-PTY session
/// gives it the pipes sshd created, so it is not (`win32_pty.c` and `w32fd.c` in Win32-OpenSSH;
/// `tests/session_encoding_windows.rs` measures it). Without a console, sshd's
/// `DefaultShellEscapeArguments` decides between the escaped and the wrapped form, and sshd
/// reads it from the registry, so the shim does too.
pub fn detect() -> Detected {
    if stdin_is_console() {
        Detected {
            encoding: Encoding::Verbatim,
            warning: None,
        }
    } else {
        piped_encoding(escape_arguments_under(OPENSSH_KEY))
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
