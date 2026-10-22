//! The process's raw command line, and how sshd encoded it.

use ::windows::Win32::Foundation::HANDLE;
use ::windows::Win32::System::Console::{CONSOLE_MODE, GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE};
use ::windows::Win32::System::Environment::GetCommandLineW;

use super::Encoding;

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
/// `tests/session_encoding_windows.rs` measures it). A non-PTY session is [`Encoding::Escaped`]
/// because `apply` sets `DefaultShellEscapeArguments`. Nothing here reads the registry: sshd read
/// the value once when the session started, and a read here could disagree with it.
pub fn detect() -> Encoding {
    if stdin_is_console() {
        Encoding::Verbatim
    } else {
        Encoding::Escaped
    }
}

fn stdin_is_console() -> bool {
    // SAFETY: GetStdHandle has no preconditions.
    stdin_handle_is_console(unsafe { GetStdHandle(STD_INPUT_HANDLE) })
}

/// Whether `stdin`, as `GetStdHandle` returned it, is a console. A handle that is not a console
/// is the normal non-PTY answer and needs no log; a `GetStdHandle` error is not, and the
/// answer then is a guess at [`Encoding::Escaped`], so it is logged.
fn stdin_handle_is_console(stdin: ::windows::core::Result<HANDLE>) -> bool {
    let stdin = match stdin {
        Ok(stdin) => stdin,
        Err(error) => {
            tracing::warn!(
                "cannot get stdin to tell a PTY session from a pipe one ({error}); decoding it as a pipe one"
            );
            return false;
        }
    };
    let mut mode = CONSOLE_MODE(0);
    // SAFETY: `mode` is a valid out-pointer; an invalid or non-console handle only makes the
    // call fail.
    unsafe { GetConsoleMode(stdin, &mut mode).is_ok() }
}

#[cfg(test)]
#[path = "windows_tests.rs"]
mod windows_tests;
