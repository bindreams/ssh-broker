//! Unit tests for the `elevate` client (in-process; no socket, no agent).
use super::*;
use crate::cmdline::split_args;
use crate::offer::text;
use crate::protocol::{ExitCode, FrameKind, FrameReader, PROTOCOL_VERSION, Stream, write_frame};
use crate::relay::write_data;
use std::ffi::OsStr;
use std::io::Cursor;

const ID: &str = "0001abcdef102030405060708090a0ff";

/// What an agent would send: stderr text (none when empty), then an exit code.
fn reply(text: &str, code: i32) -> Vec<u8> {
    let mut bytes = Vec::new();
    if !text.is_empty() {
        write_data(&mut bytes, Stream::Stderr, text.as_bytes()).unwrap();
    }
    write_frame(&mut bytes, FrameKind::Exit, &ExitCode(code).encode()).unwrap();
    bytes
}

fn a_request() -> ElevationRequest {
    ElevationRequest {
        version: PROTOCOL_VERSION,
        session: ID.to_owned(),
        command: "whoami".to_owned(),
        cwd: r"C:\work".to_owned(),
    }
}

// The course -----

#[test]
fn course_is_refused_without_a_valid_session_at_every_level() {
    let upper = ID.to_uppercase();
    let cases: [Option<&OsStr>; 5] = [
        None,
        Some(OsStr::new("")),
        Some(OsStr::new(&ID[..31])),
        Some(OsStr::new(&upper)),
        Some(OsStr::new("not a session")),
    ];
    for session in cases {
        for integrity in [Integrity::Medium, Integrity::High] {
            assert_eq!(
                course(session, integrity),
                Err(Refused::NotHosted),
                "{session:?} at {integrity:?}: a process at High is refused too"
            );
        }
    }
}

#[test]
fn course_is_in_place_at_high_and_via_the_agent_below() {
    let id = SessionId::parse(ID).unwrap();
    assert_eq!(course(Some(OsStr::new(ID)), Integrity::High), Ok((id, Course::InPlace)));
    assert_eq!(
        course(Some(OsStr::new(ID)), Integrity::Medium),
        Ok((id, Course::ViaAgent))
    );
}

#[test]
fn elevate_in_a_session_of_an_agent_below_high_is_refused_with_the_sentence() {
    assert_eq!(requestable(true, true), Ok(()), "a request.sock is asked first");
    assert_eq!(requestable(true, false), Ok(()));
    let below = requestable(false, true).unwrap_err();
    assert_eq!(below, Refused::NeedsHighAgent);
    assert_eq!(below.text(), text::elevation_needs_high_agent());
    assert_eq!(below.exit_code(), 126);
    let neither = requestable(false, false).unwrap_err();
    assert_eq!(neither, Refused::NotHosted);
    assert_eq!(neither.text(), text::elevation_not_hosted());
    assert_eq!(neither.exit_code(), REFUSED_EXIT_CODE);
}

#[test]
fn a_local_failure_is_a_refusal_with_the_cause_and_the_same_code() {
    let refused = Refused::CannotStart("the working directory is not Unicode".to_owned());
    assert_eq!(
        refused.text(),
        text::elevation_cannot_start("the working directory is not Unicode")
    );
    assert_eq!(refused.exit_code(), 126);
}

// The request -----

#[test]
fn join_args_quotes_the_command_so_the_agent_gets_what_was_typed() {
    let args: Vec<String> = ["cmd", "/c", "echo", "a b", r#"say "hi""#, r"C:\dir with space\"]
        .map(String::from)
        .to_vec();
    let id = SessionId::parse(ID).unwrap();
    let request = request_for(&id, &args, r"C:\work");
    assert_eq!(split_args(&request.command), args, "{}", request.command);
    assert_eq!(request.session, ID);
    assert_eq!(request.cwd, r"C:\work");
    assert_eq!(request.version, PROTOCOL_VERSION);
    request.check().expect("what the client builds, the agent accepts");
}

// Asking the agent -----

fn elevate(server_says: Vec<u8>) -> (i32, String, Vec<u8>) {
    let mut sent = Vec::new();
    let mut err = Vec::new();
    let Asked::Code(code) = elevate_on(&mut Cursor::new(server_says), &mut sent, &mut err, &a_request()) else {
        panic!("the agent answered, so it was not unanswered");
    };
    (code, String::from_utf8(err).unwrap(), sent)
}

#[test]
fn it_sends_one_request_frame_and_nothing_else() {
    let (_, _, sent) = elevate(reply("", 0));
    let mut fr = FrameReader::new();
    fr.push(&sent);
    let frame = fr.next_frame().unwrap().unwrap();
    assert_eq!(frame.kind, FrameKind::Request);
    assert_eq!(ElevationRequest::decode(&frame.payload).unwrap(), a_request());
    assert!(fr.next_frame().unwrap().is_none(), "no handshake, no input");
}

#[test]
fn the_commands_code_is_ours_and_a_refusals_text_goes_to_stderr() {
    let (code, err, _) = elevate(reply("", 7));
    assert_eq!(
        (code, err.as_str()),
        (7, ""),
        "a command that ran says nothing of its own"
    );

    let (code, err, _) = elevate(reply(&text::elevation_never(), REFUSED_EXIT_CODE));
    assert_eq!(code, 126);
    assert_eq!(err, text::elevation_never());
}

#[test]
fn a_connection_the_agent_closed_without_a_byte_is_unanswered_and_says_nothing() {
    let mut err = Vec::new();
    let asked = elevate_on(&mut Cursor::new(Vec::new()), &mut Vec::new(), &mut err, &a_request());
    assert!(matches!(asked, Asked::Unanswered));
    assert!(err.is_empty());
}

/// An answer `Serving` is for a session's handshake; a request is never answered with one.
#[test]
fn a_reply_that_begins_with_the_answer_serving_is_a_failure() {
    let mut server_says = Vec::new();
    crate::relay::write_serving(&mut server_says).unwrap();
    server_says.extend(reply("", 0));
    let (code, err, _) = elevate(server_says);
    assert_eq!(code, 254);
    assert_eq!(err, "");
}
