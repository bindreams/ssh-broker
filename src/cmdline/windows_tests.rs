use ::windows::Win32::Foundation::{ERROR_INVALID_HANDLE, HANDLE};

use super::stdin_handle_is_console;
use crate::cmdline::cmdline_tests::logged;

/// Not being a console is how a non-PTY session looks; it is not worth a log line.
#[test]
fn a_handle_that_is_not_a_console_is_silently_not_one() {
    let (log, is_console) = logged(|| stdin_handle_is_console(Ok(HANDLE::default())));
    assert!(!is_console);
    assert_eq!(log, "");
}

/// `GetStdHandle` failing leaves the session's kind unknown and the shim decodes it as a non-PTY
/// one, so the log says the answer is a guess.
#[test]
fn a_get_std_handle_error_is_logged() {
    let (log, is_console) = logged(|| stdin_handle_is_console(Err(ERROR_INVALID_HANDLE.to_hresult().into())));
    assert!(!is_console);
    assert!(log.contains("WARN") && log.contains("stdin"), "{log}");
}
