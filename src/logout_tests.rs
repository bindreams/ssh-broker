//! Unit tests for the `logout` client (in-process; no socket, no agent).
use super::*;
use crate::protocol::{ExitCode, FrameKind, FrameReader, Handshake, Mode, Stream, write_frame};
use crate::relay::write_data;
use std::cell::Cell;
use std::io::Cursor;
use std::rc::Rc;

/// What an agent would send: stderr text, then an exit code.
fn reply(text: &str, code: i32) -> Vec<u8> {
    let mut bytes = Vec::new();
    write_data(&mut bytes, Stream::Stderr, text.as_bytes()).unwrap();
    write_frame(&mut bytes, FrameKind::Exit, &ExitCode(code).encode()).unwrap();
    bytes
}

fn logout(server_says: Vec<u8>) -> (i32, String, Vec<u8>) {
    let mut sent = Vec::new();
    let mut err = Vec::new();
    let Asked::Code(code) = logout_on(&mut Cursor::new(server_says), &mut sent, &mut err) else {
        panic!("the agent answered, so it was not unanswered");
    };
    (code, String::from_utf8(err).unwrap(), sent)
}

#[test]
fn it_sends_a_logout_handshake_and_nothing_else() {
    let (_, _, sent) = logout(reply("bye\r\n", 0));
    let mut fr = FrameReader::new();
    fr.push(&sent);
    let frame = fr.next_frame().unwrap().unwrap();
    assert_eq!(frame.kind, FrameKind::Handshake);
    assert_eq!(Handshake::decode(&frame.payload).unwrap().mode, Mode::Logout);
    assert!(fr.next_frame().unwrap().is_none(), "no stdin, no resize");
}

#[test]
fn the_agents_reply_goes_to_stderr_and_its_exit_code_is_ours() {
    let (code, err, _) = logout(reply("ssh-broker: ending your background session.\r\n", 0));
    assert_eq!(code, 0);
    assert_eq!(err, "ssh-broker: ending your background session.\r\n");

    let (code, err, _) = logout(reply("desktop\r\n", 2));
    assert_eq!(code, 2);
    assert_eq!(err, "desktop\r\n");
}

/// `logout_at` with a connect that fails with `error`, and a verdict that only a missing agent
/// is "no session".
fn logout_failing_to_connect(error: anyhow::Error) -> (i32, String) {
    let mut err = Vec::new();
    let mut error = Some(error);
    let code = logout_at(
        || Err::<(Cursor<Vec<u8>>, Vec<u8>), _>(error.take().expect("asked to connect once")),
        |e| e.to_string() == "nothing listens",
        &mut err,
        |code| code,
    );
    (code, String::from_utf8(err).unwrap())
}

#[test]
fn logout_with_no_agent_exits_1() {
    let (code, err) = logout_failing_to_connect(anyhow::anyhow!("nothing listens"));
    assert_eq!(code, 1);
    assert_eq!(err, "ssh-broker: no session to end.\n");
}

#[test]
fn logout_that_cannot_reach_an_agent_says_why_and_is_not_no_session() {
    // An agent that serves this user but refuses the connection is not "no session to end".
    let (code, err) = logout_failing_to_connect(anyhow::anyhow!("Access is denied. (0x80070005)"));
    assert_eq!(code, UNREACHABLE_CODE);
    assert_ne!(code, 1);
    assert!(!err.contains("no session to end"), "{err}");
    assert!(err.contains("could not reach your session"), "{err}");
    assert!(err.contains("Access is denied"), "{err}");
}

/// `logout_at` over connections that `script` hands out in turn: each is what the agent says, or the
/// error of a connect that fails. Returns the exit code, what was written to stderr and how many
/// connections were made.
fn logout_over(script: impl IntoIterator<Item = Result<Vec<u8>, &'static str>>) -> (i32, String, usize) {
    let mut script = script.into_iter();
    let mut connects = 0;
    let mut err = Vec::new();
    let code = logout_at(
        || {
            connects += 1;
            match script.next().expect("the script ended: logout asked again") {
                Ok(says) => Ok((Cursor::new(says), Vec::new())),
                Err(why) => Err(anyhow::anyhow!(why)),
            }
        },
        |e| e.to_string() == "nothing listens",
        &mut err,
        |code| code,
    );
    (code, String::from_utf8(err).unwrap(), connects)
}

#[test]
fn a_connection_that_ends_before_the_agents_first_byte_is_followed_by_a_new_one_and_no_agent_means_no_session() {
    // The agent was ending when this logout reached it: its listener closed with the request queued.
    // The session is gone by the time of the next connect, which is what running `logout` a moment
    // later says too.
    let (code, err, connects) = logout_over([Ok(Vec::new()), Err("nothing listens")]);
    assert_eq!(code, 1);
    assert_eq!(
        err,
        "ssh-broker: no session to end.
"
    );
    assert_eq!(connects, 2);
}

#[test]
fn a_connection_that_ends_before_the_agents_first_byte_is_followed_by_a_new_one_that_is_answered() {
    let (code, err, connects) = logout_over([
        Ok(Vec::new()),
        Ok(reply(
            "ssh-broker: ending your background session.
",
            0,
        )),
    ]);
    assert_eq!(code, 0);
    assert_eq!(
        err,
        "ssh-broker: ending your background session.
"
    );
    assert_eq!(connects, 2);
}

#[test]
fn a_second_connection_that_ends_before_the_agents_first_byte_is_a_protocol_violation() {
    // An agent that follows the protocol closes a connection without a byte only while its listener
    // closes, so the connect after that fails or is answered. The script has no third connection:
    // asking again would fail the test.
    let (code, err, connects) = logout_over([Ok(Vec::new()), Ok(Vec::new())]);
    assert_eq!(code, crate::shim::PROTOCOL_VIOLATION_CODE);
    assert_eq!(
        err,
        "ssh-broker: the agent closed the connection twice without answering; it may be a different ssh-broker version
"
    );
    assert_eq!(connects, 2);
}

/// A connection whose read fails as told.
struct Failing(std::io::ErrorKind);

impl Read for Failing {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        Err(self.0.into())
    }
}

#[test]
fn a_connection_that_is_reset_or_gone_before_the_agents_first_byte_is_unanswered() {
    use std::io::ErrorKind::{BrokenPipe, ConnectionAborted, ConnectionReset};
    for kind in [ConnectionReset, ConnectionAborted, BrokenPipe] {
        let asked = logout_on(&mut Failing(kind), &mut Vec::new(), &mut Vec::new());
        assert!(matches!(asked, Asked::Unanswered), "{kind:?}");
    }
}

#[test]
fn a_request_that_cannot_be_sent_because_the_agent_has_gone_is_unanswered() {
    struct Gone;
    impl Write for Gone {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
    }
    let mut err = Vec::new();
    let asked = logout_on(&mut Cursor::new(Vec::new()), &mut Gone, &mut err);
    assert!(matches!(asked, Asked::Unanswered));
    assert!(err.is_empty(), "nothing is said until the next connect has answered");
}

#[test]
fn a_crash_after_a_frame_is_not_unanswered() {
    let mut half = Vec::new();
    write_data(&mut half, Stream::Stderr, b"partial\r\n").unwrap();
    let (code, err, _) = logout(half);
    assert_eq!(
        code, 255,
        "the exec relay's code for a peer that closed without an exit"
    );
    assert_eq!(err, "partial\r\n");
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

/// The agent ends the shell tree when it sees the client close, and the client is usually inside
/// that tree: it must have its exit code fixed before the agent can see the close.
#[test]
fn the_connection_is_still_open_when_the_exit_code_is_handed_over() {
    let dropped = Rc::new(Cell::new(false));
    let held = Rc::clone(&dropped);
    let mut err = Vec::new();
    let was_open = logout_at(
        move || {
            let rx = Held(Rc::clone(&held), Cursor::new(reply("bye\r\n", 0)));
            let tx = Held(Rc::clone(&held), Cursor::new(Vec::new()));
            Ok((rx, tx))
        },
        |_| false,
        &mut err,
        |_code| !dropped.get(),
    );
    assert!(was_open, "the exit must happen while the socket is held");
    assert!(dropped.get(), "and the socket is released only afterwards");
}
