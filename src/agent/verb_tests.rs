//! Tests for [`super::start`]: no process is started; the "child" reads the pipe in this process.

use std::io::Read;
use std::os::windows::io::{BorrowedHandle, RawHandle};
use std::path::Path;

use super::start;
use crate::cmdline::split_args;
use crate::route::{Route, route};
use crate::shell::StartError;

const EXE: &str = r"C:\Program Files\ssh-broker\ssh-broker.exe";

/// What a verb started by `start` is given: its route, and what it reads from the handle it names.
fn given(login: bool, notice: &str, line: &str) -> (Route, (String, String)) {
    let mut seen = None;
    start(Path::new(EXE), notice, line, login, |verb_line, read| {
        let args = split_args(verb_line);
        assert_eq!(args[0], EXE, "{verb_line}");
        let routed = route(&args[1..], verb_line);
        // The child's inherited copy of the handle.
        let copy = unsafe { BorrowedHandle::borrow_raw(read.0.0 as RawHandle) }
            .try_clone_to_owned()
            .unwrap();
        let mut reader = std::fs::File::from(copy);
        let reading = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes).unwrap();
            bytes
        });
        seen = Some((routed, reading));
        Ok(())
    })
    .unwrap();
    let (routed, reading) = seen.unwrap();
    (routed, crate::handoff::decode(&reading.join().unwrap()).unwrap())
}

#[test]
fn the_verb_names_the_handle_it_inherits_and_reads_the_notice_and_the_line_from_it() {
    for login in [false, true] {
        let line = r#""C:\Windows\System32\cmd.exe" /c echo "a  b" \"#.repeat(500);
        let (routed, (notice, got)) = given(login, "the notice\r\n", &line);
        let Route::ConsoleFallback {
            handle,
            login: routed_login,
        } = routed
        else {
            panic!("{routed:?}")
        };
        assert_ne!(handle, 0);
        assert_eq!(routed_login, login);
        assert_eq!((notice.as_str(), got.as_str()), ("the notice\r\n", line.as_str()));
    }
}

#[test]
fn a_start_that_fails_is_the_error_and_nothing_is_written() {
    let mut reached = false;
    let mut pipe_read = None;
    let error = start(Path::new(EXE), "n", "l", false, |_, read| -> Result<(), StartError> {
        reached = true;
        // A copy of the read end outlives `start`, so what the failed start left in the pipe can be read.
        pipe_read = Some(
            unsafe { BorrowedHandle::borrow_raw(read.0.0 as RawHandle) }
                .try_clone_to_owned()
                .unwrap(),
        );
        Err(StartError::Program(anyhow::anyhow!("blocked")))
    })
    .unwrap_err();
    assert!(reached, "the starter was never called");
    assert!(matches!(error, StartError::Program(_)), "{error:?}");
    let mut bytes = Vec::new();
    std::fs::File::from(pipe_read.unwrap()).read_to_end(&mut bytes).unwrap();
    assert!(bytes.is_empty(), "{} bytes were written", bytes.len());
}

/// The agent writes before the verb has read anything, and a verb that is slow to read (stuck in
/// the loader) must not hold the agent's session thread: the longest line fits the pipe.
#[test]
fn start_returns_when_the_verb_has_not_read_the_longest_line() {
    let line = "x".repeat(3 * 32_766);
    let mut unread = None;
    start(Path::new(EXE), "the notice\r\n", &line, false, |_, read| {
        unread = Some(
            unsafe { BorrowedHandle::borrow_raw(read.0.0 as RawHandle) }
                .try_clone_to_owned()
                .unwrap(),
        );
        Ok(())
    })
    .unwrap();
    let mut bytes = Vec::new();
    std::fs::File::from(unread.unwrap()).read_to_end(&mut bytes).unwrap();
    assert_eq!(
        crate::handoff::decode(&bytes).unwrap(),
        ("the notice\r\n".to_string(), line)
    );
}
