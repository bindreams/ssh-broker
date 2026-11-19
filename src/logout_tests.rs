//! Unit tests for the `logout` client (in-process; no socket, no agent).
use super::*;
use crate::protocol::{ExitCode, FrameKind, FrameReader, Handshake, Mode, Stream, write_frame};
use crate::relay::write_data;
use std::io::Cursor;

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

/// A logout is not answered `Serving`: an agent that does is a failure, and its text is not shown.
#[test]
fn a_reply_that_begins_with_the_answer_serving_is_a_failure() {
    let mut server_says = Vec::new();
    crate::relay::write_serving(&mut server_says).unwrap();
    server_says.extend(reply("bye\r\n", 0));
    let (code, err, _) = logout(server_says);
    assert_eq!(code, 254);
    assert_eq!(err, "");
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

// Which socket -----

/// What `connect_in` connected to, in order, and what it returned.
fn connected_in(
    integrity: Integrity,
    agent: Result<&'static str, &'static str>,
    request: Result<&'static str, &'static str>,
) -> (Vec<&'static str>, Result<&'static str, String>) {
    let tried = std::cell::RefCell::new(Vec::new());
    let result = connect_in(
        integrity,
        || {
            tried.borrow_mut().push("agent.sock");
            agent.map_err(|why| anyhow::anyhow!(why))
        },
        || {
            tried.borrow_mut().push("request.sock");
            request.map_err(|why| anyhow::anyhow!(why))
        },
        |e| e.to_string() == "nothing listens",
    );
    (tried.into_inner(), result.map_err(|e| e.to_string()))
}

/// Below High: the plain folder's `agent.sock` first (a standard account's agent has only that), then
/// `request.sock` (an agent at High has only that there), and when neither is there, the error that says so.
#[test]
fn logout_below_high_asks_agent_sock_when_it_is_there_then_request_sock_then_says_no_session() {
    // An agent below High is in the plain folder: the second socket is not tried.
    assert_eq!(
        connected_in(Integrity::Medium, Ok("the agent"), Ok("the requests")),
        (vec!["agent.sock"], Ok("the agent"))
    );
    // No agent there: an agent at High takes the request on its own socket.
    assert_eq!(
        connected_in(Integrity::Medium, Err("nothing listens"), Ok("the requests")),
        (vec!["agent.sock", "request.sock"], Ok("the requests"))
    );
    // Neither: the error is the absence, which `logout` says as "no session".
    assert_eq!(
        connected_in(Integrity::Medium, Err("nothing listens"), Err("nothing listens")),
        (vec!["agent.sock", "request.sock"], Err("nothing listens".to_owned()))
    );
}

/// An agent that is there and refuses this process is not an absent one: its refusal is the answer, and the
/// other socket is not asked in its place. The same for a request socket that refuses.
#[test]
fn a_socket_that_refuses_is_not_a_missing_agent() {
    assert_eq!(
        connected_in(Integrity::Medium, Err("Access is denied"), Ok("the requests")),
        (vec!["agent.sock"], Err("Access is denied".to_owned()))
    );
    assert_eq!(
        connected_in(Integrity::Medium, Err("nothing listens"), Err("Access is denied")),
        (vec!["agent.sock", "request.sock"], Err("Access is denied".to_owned()))
    );
}

/// At High the agent's own socket is the way: a process there can connect to it, and the request socket
/// is for those that cannot.
#[test]
fn logout_at_high_asks_agent_sock_only() {
    assert_eq!(
        connected_in(Integrity::High, Ok("the agent"), Ok("the requests")),
        (vec!["agent.sock"], Ok("the agent"))
    );
    assert_eq!(
        connected_in(Integrity::High, Err("nothing listens"), Ok("the requests")),
        (vec!["agent.sock"], Err("nothing listens".to_owned()))
    );
}

// the line when there is no agent -------------------------------------------------------------

/// An administrator's unelevated process reaches an agent at High as any process does, so no agent found is
/// the plain "no session": there is no place to look elsewhere.
#[test]
fn every_readable_token_gets_the_plain_line() {
    for elevation in [Elevation::Filtered, Elevation::Full, Elevation::Standard] {
        assert_eq!(no_session_line(&Ok(elevation)), NO_SESSION, "{elevation:?}");
    }
}

#[test]
fn a_token_whose_elevation_cannot_be_read_gets_the_plain_line_and_the_cause() {
    let line = no_session_line(&Err(anyhow::anyhow!("the token cannot be read")));
    assert!(line.starts_with(NO_SESSION), "{line}");
    assert!(
        line.contains(&crate::offer::text::elevation_unreadable_clause(
            "the token cannot be read"
        )),
        "{line}"
    );
    assert_eq!(line.lines().count(), 1, "{line}");
}
