//! Unit tests for the `elevate` client (in-process; no socket, no agent).
use super::*;
use crate::offer::text;
use crate::protocol::{ExitCode, FrameKind, FrameReader, PROTOCOL_VERSION, Stream, write_frame};
use crate::relay::{write_data, write_serving};
use crate::shell::test_host::TestHost;
use std::ffi::OsStr;
use std::io::Cursor;

const ID: &str = "0001abcdef102030405060708090a0ff";

/// What an agent would send for a command that started: `Serving`, stderr text (none when empty), then an exit code.
fn served(text: &str, code: i32) -> Vec<u8> {
    served_with("", text, code)
}

/// What an agent would send for a command that started: `Serving`, stdout text and stderr text (none when empty), in
/// that order, then an exit code.
fn served_with(stdout: &str, stderr: &str, code: i32) -> Vec<u8> {
    let mut bytes = Vec::new();
    write_serving(&mut bytes).unwrap();
    bytes.extend(refused_with(stdout, stderr, code));
    bytes
}

/// What an agent would send for a request it refuses: stderr text (none when empty), then an exit code, and no
/// `Serving`.
fn refused(text: &str, code: i32) -> Vec<u8> {
    refused_with("", text, code)
}

fn refused_with(stdout: &str, stderr: &str, code: i32) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (stream, text) in [(Stream::Stdout, stdout), (Stream::Stderr, stderr)] {
        if !text.is_empty() {
            write_data(&mut bytes, stream, text.as_bytes()).unwrap();
        }
    }
    write_frame(&mut bytes, FrameKind::Exit, &ExitCode(code).encode()).unwrap();
    bytes
}

fn a_request() -> ElevationRequest {
    ElevationRequest {
        version: PROTOCOL_VERSION,
        session: ID.to_owned(),
        command: r#""C:\tools\whoami.exe""#.to_owned(),
        cwd: r"C:\work".to_owned(),
        terminal: false,
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

// The line -----

#[test]
fn a_bare_program_is_found_on_the_path_and_the_rest_is_kept() {
    let host = TestHost::new()
        .with_program("probe", r"C:\Program Files\tools\probe.exe")
        .with_file(r"C:\other\tool.exe", "MZ");
    assert_eq!(
        line_of(&host, r#"probe  /groups   "a  b" "a&b""#),
        Ok(r#""C:\Program Files\tools\probe.exe"  /groups   "a  b" "a&b""#.to_owned()),
        "the program is the path that was found, quoted; everything after it is as typed"
    );
    assert_eq!(
        line_of(&host, "probe"),
        Ok(r#""C:\Program Files\tools\probe.exe""#.to_owned())
    );
    assert_eq!(
        line_of(&host, r#""probe" /x"#),
        Ok(r#""C:\Program Files\tools\probe.exe" /x"#.to_owned()),
        "a quoted program is the same program"
    );
    assert_eq!(
        line_of(&host, r"C:\other\tool /x"),
        Ok(r#""C:\other\tool.exe" /x"#.to_owned()),
        "an absolute name without an extension finds the .exe, as the system does"
    );
}

/// The typed line is the tail of `ssh-broker`'s own command line: its first token is an argument, and quotes toggle
/// anywhere in it, as in cmd.exe's `"C:\Program Files"\nodejs\node.exe`.
#[test]
fn a_partly_quoted_program_path_is_one_program() {
    let host = TestHost::new().with_file(r"C:\Program Files\tool\x.exe", "MZ");
    let found = find_program(&host, r#""C:\Program Files"\tool\x.exe -v"#).expect("the file is there");
    assert_eq!(found.program, r"C:\Program Files\tool\x.exe");
    assert_eq!(found.rest, " -v");
    assert_eq!(found.line(), r#""C:\Program Files\tool\x.exe" -v"#);
}

/// The line is what was typed after the program, kept as it was, and the program is found and quoted.
fn line_of(host: &TestHost, typed: &str) -> Result<String, Refused> {
    find_program(host, typed).map(|found| found.line())
}

#[test]
fn a_relative_program_is_made_absolute_against_the_working_directory() {
    let here = std::env::current_dir().unwrap();
    let probe = here.join(r"sub\probe.exe");
    let host = TestHost::new().with_file(probe.to_str().unwrap(), "MZ");
    for typed in [r".\sub\probe.exe", r"sub\probe.exe", "sub/probe.exe"] {
        assert_eq!(
            line_of(&host, &format!("{typed} /groups")),
            Ok(format!(r#""{}" /groups"#, probe.display())),
            "{typed}"
        );
    }
    assert_eq!(
        line_of(&host, r".\sub\absent.exe /x"),
        Err(Refused::CannotStart(
            r".\sub\absent.exe: there is no such file".to_owned()
        )),
        "a relative program that is not there is refused, not searched for elsewhere"
    );
}

#[test]
fn a_program_that_is_not_found_is_refused_naming_it() {
    let host = TestHost::new();
    let refused = line_of(&host, "whoamii /all").unwrap_err();
    assert_eq!(refused, Refused::CannotStart("whoamii: not found on PATH".to_owned()));
    assert_eq!(
        refused.text(),
        "ssh-broker: the command could not be started elevated: whoamii: not found on PATH\r\n"
    );
    assert_eq!(refused.exit_code(), 126);
}

/// No program in the line is no command: it is refused with a sentence that says so, not defaulted to an empty
/// program name that the host would look for.
#[test]
fn a_blank_line_is_refused_and_not_defaulted() {
    let host = TestHost::new();
    // `""` is an argument (argv has it), and an empty program name: still no command.
    for blank in ["", "   ", "\t ", "\"\"", "\"\" /c whoami"] {
        assert_eq!(
            line_of(&host, blank),
            Err(Refused::CannotStart("no command was given".to_owned())),
            "{blank:?}"
        );
    }
}

#[test]
fn the_request_carries_the_line_as_it_is() {
    let id = SessionId::parse(ID).unwrap();
    let line = r#""C:\tools\p.exe"  /c  "a&whoami" \"x\""#;
    let request = request_for(&id, false, line, r"C:\work");
    assert_eq!(request.command, line);
    assert_eq!(request.session, ID);
    assert_eq!(request.cwd, r"C:\work");
    assert_eq!(request.version, PROTOCOL_VERSION);
    assert!(!request.terminal);
    assert!(request_for(&id, true, line, r"C:\work").terminal);
}

// Asking the agent -----

/// What `elevate_on` made of a script of the agent's answer, what it printed to stdout and to stderr, and what it sent.
fn elevate_split(server_says: Vec<u8>) -> (ElevateOutcome, String, String, Vec<u8>) {
    let mut sent = Vec::new();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let outcome = elevate_on(
        &mut Cursor::new(server_says),
        &mut sent,
        &mut out,
        &mut err,
        &a_request(),
    );
    (
        outcome,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
        sent,
    )
}

#[test]
fn the_replys_stdout_goes_to_stdout_and_its_stderr_to_stderr() {
    let (outcome, out, err, _) = elevate_split(served_with("the output\r\n", "the errors\r\n", 3));
    assert_eq!(outcome, ElevateOutcome::Ran(3));
    assert_eq!((out.as_str(), err.as_str()), ("the output\r\n", "the errors\r\n"));
}

#[test]
fn it_sends_one_request_frame_and_nothing_else() {
    let (_, _, _, sent) = elevate_split(served("", 0));
    let mut fr = FrameReader::new();
    fr.push(&sent);
    let frame = fr.next_frame().unwrap().unwrap();
    assert_eq!(frame.kind, FrameKind::Request);
    assert_eq!(ElevationRequest::decode(&frame.payload).unwrap(), a_request());
    assert!(fr.next_frame().unwrap().is_none(), "no handshake, no input");
}

#[test]
fn a_command_that_ran_says_nothing_of_its_own_and_a_refusals_text_goes_to_stderr() {
    let (outcome, _, err, _) = elevate_split(served("", 7));
    assert_eq!((outcome.exit_code(), err.as_str()), (7, ""));
    assert_eq!(outcome.sentence(), None);

    let (outcome, _, err, _) = elevate_split(refused(&text::elevation_never(), REFUSED_EXIT_CODE));
    assert_eq!(outcome, ElevateOutcome::NotRun);
    assert_eq!(outcome.exit_code(), 126);
    assert_eq!(err, text::elevation_never());
    assert_eq!(outcome.sentence(), None, "the agent's sentence is already printed");
}

/// The code of an answer that is not preceded by `Serving` is not the command's, whatever it is: the agent exits with
/// 254 for a request it could not read, 255 for an agent that is ending and 4 for what it likes.
#[test]
fn an_answer_without_serving_exits_126_whatever_its_code() {
    for code in [254, 255, 4, 0, 126] {
        let (outcome, _, err, _) = elevate_split(refused("said why\r\n", code));
        assert_eq!(outcome, ElevateOutcome::NotRun, "code {code}");
        assert_eq!(outcome.exit_code(), 126, "code {code}");
        assert_eq!(err, "said why\r\n");
    }
}

/// After `Serving` the code is the command's: one that is 126 or 255 as well.
#[test]
fn after_serving_the_code_is_the_commands() {
    for code in [4, 126, 255, 0] {
        let (outcome, _, _, _) = elevate_split(served("", code));
        assert_eq!(outcome, ElevateOutcome::Ran(code));
        assert_eq!(outcome.exit_code(), code);
    }
}

#[test]
fn a_connection_the_agent_closed_without_a_byte_is_unanswered_and_says_so() {
    let (outcome, out, err, _) = elevate_split(Vec::new());
    assert_eq!(outcome, ElevateOutcome::Unanswered);
    assert_eq!(outcome.exit_code(), 255);
    assert_eq!(
        outcome.sentence(),
        Some(format!("{}\r\n", text::agent_ended_unanswered()))
    );
    assert!(out.is_empty() && err.is_empty());
}

/// A close without a byte could be an agent that ended before it read the command or one that ran it and died: the
/// command is not sent again.
#[test]
fn a_close_without_a_byte_is_not_sent_again_and_exits_255() {
    let connections = std::cell::Cell::new(0);
    let sent = std::cell::RefCell::new(Vec::new());
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let outcome = elevate_over(
        || {
            connections.set(connections.get() + 1);
            Ok((Cursor::new(Vec::new()), SharedWrite(&sent)))
        },
        &mut out,
        &mut err,
        &a_request(),
    )
    .expect("a connection was made");
    assert_eq!(connections.get(), 1, "exactly one connection");
    assert_eq!(outcome, ElevateOutcome::Unanswered);
    assert_eq!(outcome.exit_code(), 255);
    assert!(!sent.borrow().is_empty(), "the request went out once");
}

/// Writes into a buffer the test also looks at.
struct SharedWrite<'a>(&'a std::cell::RefCell<Vec<u8>>);

impl Write for SharedWrite<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_reply_cut_after_serving_says_the_command_ran_and_exits_255() {
    let mut bytes = Vec::new();
    write_serving(&mut bytes).unwrap();
    write_data(&mut bytes, Stream::Stdout, b"partial").unwrap();
    let (outcome, out, _, _) = elevate_split(bytes);
    assert_eq!(out, "partial");
    let ElevateOutcome::EndUnread(cause) = &outcome else {
        panic!("{outcome:?}");
    };
    assert_eq!(outcome.exit_code(), 255);
    assert_eq!(outcome.sentence(), Some(text::elevation_end_unread(cause)));
}

#[test]
fn bytes_that_are_no_answer_say_the_command_may_or_may_not_have_run_and_exit_255() {
    let (outcome, _, _, _) = elevate_split(vec![0xff; 9]);
    let ElevateOutcome::Unreadable(cause) = &outcome else {
        panic!("{outcome:?}");
    };
    assert_eq!(outcome.exit_code(), 255);
    assert_eq!(outcome.sentence(), Some(text::elevation_answer_unreadable(cause)));

    // Some of a refusal, cut before its code.
    let mut cut = Vec::new();
    write_data(&mut cut, Stream::Stderr, b"said").unwrap();
    let (outcome, _, err, _) = elevate_split(cut);
    assert!(matches!(outcome, ElevateOutcome::Unreadable(_)), "{outcome:?}");
    assert_eq!(err, "said");
}

#[test]
fn a_connection_that_cannot_be_made_exits_126() {
    let cannot = |error: anyhow::Error| {
        elevate_over(
            move || -> anyhow::Result<(Cursor<Vec<u8>>, Vec<u8>)> { Err(error) },
            &mut Vec::new(),
            &mut Vec::new(),
            &a_request(),
        )
        .expect_err("no connection, no outcome")
    };
    let refused = cannot(anyhow::anyhow!("access denied"));
    assert_eq!(
        refused,
        Refused::CannotStart("could not reach your session's agent: access denied".to_owned())
    );
    assert_eq!(refused.exit_code(), 126);

    // 10061 is the OS's "nothing listens": no agent serves this session.
    let none = cannot(anyhow::Error::new(std::io::Error::from_raw_os_error(10061)));
    assert_eq!(none, Refused::NotHosted);
    assert_eq!(none.exit_code(), 126);
}
