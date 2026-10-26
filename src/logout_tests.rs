//! Unit tests for the `logout` client (in-process; no socket, no agent).
use super::*;
use crate::protocol::{ExitCode, FrameKind, FrameReader, Handshake, Mode, Stream, write_frame};
use crate::relay::write_data;
use std::cell::Cell;
use std::io::Cursor;
use std::rc::Rc;

const EXE: &str = r"C:\ProgramData\ssh-broker\ssh-broker.exe";

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
    let code = logout_on(&mut Cursor::new(server_says), &mut sent, &mut err, EXE);
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

#[test]
fn logout_with_no_agent_exits_1() {
    let mut err = Vec::new();
    let code = logout_at(
        || Err::<(Cursor<Vec<u8>>, Vec<u8>), _>(anyhow::anyhow!("no such file")),
        &mut err,
        EXE,
        |code| code,
    );
    assert_eq!(code, 1);
    assert_eq!(String::from_utf8(err).unwrap(), "ssh-broker: no session to end.\n");
}

#[test]
fn eof_before_any_frame_after_logout_is_the_old_agent_signal() {
    let (code, err, _) = logout(Vec::new());
    assert_eq!(code, 3);
    assert!(err.contains("the agent did not answer"), "{err}");
    assert!(err.contains(&format!("run {EXE} apply")), "{err}");
    assert!(err.contains("older than this ssh-broker"), "{err}");
}

#[test]
fn a_crash_after_a_frame_is_not_the_old_agent_signal() {
    let mut half = Vec::new();
    write_data(&mut half, Stream::Stderr, b"partial\r\n").unwrap();
    let (code, err, _) = logout(half);
    assert_ne!(code, 3);
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
            let tx = Held(held, Cursor::new(Vec::new()));
            Ok((rx, tx))
        },
        &mut err,
        EXE,
        |_code| !dropped.get(),
    );
    assert!(was_open, "the exit must happen while the socket is held");
    assert!(dropped.get(), "and the socket is released only afterwards");
}
