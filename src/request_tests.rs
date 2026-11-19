//! Unit tests for the request loop shared by the verbs that ask the agent (in-process; no socket, no agent).
use super::*;
use std::cell::Cell;
use std::io::{Cursor, Read, Write};
use std::rc::Rc;

/// What an agent would send: stderr text, then an exit code.
fn reply(text: &str, code: i32) -> Vec<u8> {
    let mut bytes = Vec::new();
    crate::relay::write_data(&mut bytes, crate::protocol::Stream::Stderr, text.as_bytes()).unwrap();
    crate::protocol::write_frame(
        &mut bytes,
        crate::protocol::FrameKind::Exit,
        &crate::protocol::ExitCode(code).encode(),
    )
    .unwrap();
    bytes
}

/// The ask of `logout`, which these tests use as the verb: send the request, relay the reply to `err`.
fn ask_logout(rx: &mut Cursor<Vec<u8>>, tx: &mut Vec<u8>, err: &mut dyn Write) -> Asked {
    crate::logout::logout_on(rx, tx, err)
}

const NO_SESSION: &str = "ssh-broker: no session to end.";

/// `ask_at` with a connect that fails with `error`, and a verdict that only a missing agent is "no session".
fn asking_failing_to_connect(error: anyhow::Error) -> (i32, String) {
    let mut err = Vec::new();
    let mut error = Some(error);
    let code = ask_at(
        || Err::<(Cursor<Vec<u8>>, Vec<u8>), _>(error.take().expect("asked to connect once")),
        ask_logout,
        |e| e.to_string() == "nothing listens",
        NO_SESSION,
        &mut err,
        |code| code,
    );
    (code, String::from_utf8(err).unwrap())
}

#[test]
fn asking_with_no_agent_exits_1() {
    let (code, err) = asking_failing_to_connect(anyhow::anyhow!("nothing listens"));
    assert_eq!(code, 1);
    assert_eq!(err, "ssh-broker: no session to end.\n");
}

#[test]
fn asking_where_no_agent_can_be_reached_says_why_and_is_not_no_session() {
    // An agent that serves this user but refuses the connection is not "no session to end".
    let (code, err) = asking_failing_to_connect(anyhow::anyhow!("Access is denied. (0x80070005)"));
    assert_eq!(code, UNREACHABLE_CODE);
    assert_ne!(code, 1);
    assert!(!err.contains("no session to end"), "{err}");
    assert!(err.contains("could not reach your session"), "{err}");
    assert!(err.contains("Access is denied"), "{err}");
}

/// `ask_at` over connections that `script` hands out in turn: each is what the agent says, or the error of a
/// connect that fails. Returns the exit code, what was written to stderr and how many connections were made.
fn asking_over(script: impl IntoIterator<Item = Result<Vec<u8>, &'static str>>) -> (i32, String, usize) {
    let mut script = script.into_iter();
    let mut connects = 0;
    let mut err = Vec::new();
    let code = ask_at(
        || {
            connects += 1;
            match script.next().expect("the script ended: the agent was asked again") {
                Ok(says) => Ok((Cursor::new(says), Vec::new())),
                Err(why) => Err(anyhow::anyhow!(why)),
            }
        },
        ask_logout,
        |e| e.to_string() == "nothing listens",
        NO_SESSION,
        &mut err,
        |code| code,
    );
    (code, String::from_utf8(err).unwrap(), connects)
}

#[test]
fn ask_at_connects_again_once_when_the_agent_closes_without_a_byte_and_no_agent_means_no_session() {
    // The agent was ending when this request reached it: its listener closed with the request queued.
    // The session is gone by the time of the next connect, which is what asking a moment later says too.
    let (code, err, connects) = asking_over([Ok(Vec::new()), Err("nothing listens")]);
    assert_eq!(code, 1);
    assert_eq!(err, "ssh-broker: no session to end.\n");
    assert_eq!(connects, 2);
}

#[test]
fn ask_at_connects_again_once_and_the_second_connection_is_answered() {
    let (code, err, connects) = asking_over([
        Ok(Vec::new()),
        Ok(reply("ssh-broker: ending your background session.\n", 0)),
    ]);
    assert_eq!(code, 0);
    assert_eq!(err, "ssh-broker: ending your background session.\n");
    assert_eq!(connects, 2);
}

#[test]
fn ask_at_reports_a_second_close_as_a_protocol_violation() {
    // An agent that follows the protocol closes a connection without a byte only while its listener
    // closes, so the connect after that fails or is answered. The script has no third connection:
    // asking again would fail the test.
    let (code, err, connects) = asking_over([Ok(Vec::new()), Ok(Vec::new())]);
    assert_eq!(code, crate::shim::PROTOCOL_VIOLATION_CODE);
    assert_eq!(
        err,
        "ssh-broker: the agent closed the connection twice without answering; it may be a different ssh-broker version\n"
    );
    assert_eq!(connects, 2);
}

/// A reader and writer that note when they are dropped.
struct Held(Rc<Cell<bool>>, Cursor<Vec<u8>>);

impl Read for Held {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.1.read(buf)
    }
}

impl Write for Held {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        self.0.set(true);
    }
}

/// The agent ends the shell tree when it sees the client close, and the client is usually inside that tree: it
/// must have its exit code fixed before the agent can see the close.
#[test]
fn the_connection_is_still_open_when_the_exit_code_is_handed_over() {
    let dropped = Rc::new(Cell::new(false));
    let held = Rc::clone(&dropped);
    let mut err = Vec::new();
    let was_open = ask_at(
        move || {
            let rx = Held(Rc::clone(&held), Cursor::new(reply("bye\r\n", 0)));
            let tx = Held(Rc::clone(&held), Cursor::new(Vec::new()));
            Ok((rx, tx))
        },
        |rx: &mut Held, tx: &mut Held, err: &mut dyn Write| crate::logout::logout_on(rx, tx, err),
        |_| false,
        NO_SESSION,
        &mut err,
        |_code| !dropped.get(),
    );
    assert!(was_open, "the exit must happen while the socket is held");
    assert!(dropped.get(), "and the socket is released only afterwards");
}

/// What is asked is the verb's own: `ask_at` hands the connection to it, and its answer is the exit.
#[test]
fn what_is_asked_is_the_callers_and_its_code_is_the_exit() {
    let mut err = Vec::new();
    let mut asked = 0;
    let code = ask_at(
        || Ok((Cursor::new(Vec::<u8>::new()), Vec::<u8>::new())),
        |_: &mut Cursor<Vec<u8>>, tx: &mut Vec<u8>, _: &mut dyn Write| {
            asked += 1;
            tx.push(1);
            Asked::Code(77)
        },
        |_| false,
        NO_SESSION,
        &mut err,
        |code| code,
    );
    assert_eq!((code, asked), (77, 1));
    assert!(err.is_empty());
}
