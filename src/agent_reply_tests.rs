//! Tests that the agent answers every connection it cannot serve with a frame the shim prints, and
//! closes none of them without a byte while it is alive. No shell is started: the starters of the
//! hooks fail on purpose, and the connections are AF_UNIX pairs in a temp dir.
use super::*;
use crate::afunix::{ConnTx, Whole};
use crate::protocol::{FrameKind, Handshake, Mode, Stream, write_frame};
use crate::relay::{Outcome, TestSink, pump_decode, write_data};

/// What a client saw: how the session ended and what the agent wrote to its stderr.
struct Answer {
    outcome: Outcome,
    stderr: String,
}

/// Connect a client that runs `send`, let the agent handle the server side with `hooks`, and return
/// what the client was told and what the handler returned. The client closes after the reply, which
/// is what the agent waits for.
fn answered(tag: &str, hooks: Hooks, send: impl FnOnce(&mut ConnTx) + Send + 'static) -> (Answer, anyhow::Result<()>) {
    let (server, client, dir) = crate::test_support::raw_socket_pair(tag);
    let agent = std::thread::spawn(move || handle_connection_in(server, hooks, &Control::standalone()));
    let (mut rx, mut tx) = afunix::split(client).unwrap();
    send(&mut tx);
    let mut sink = TestSink::default();
    let outcome = pump_decode(&mut rx, &mut FrameReader::new(), &mut sink).expect("the reply was lost");
    drop((rx, tx));
    let result = agent.join().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    (
        Answer {
            outcome,
            stderr: String::from_utf8(sink.stderr).unwrap(),
        },
        result,
    )
}

fn handshake(mode: Mode, command: &str) -> impl FnOnce(&mut ConnTx) + Send + 'static {
    let hs = Handshake {
        mode,
        command: Some(command.to_owned()),
        ..Handshake::pty_default()
    };
    move |tx| {
        write_frame(tx, FrameKind::Handshake, &hs.encode().unwrap()).unwrap();
        write_data(tx, Stream::Stdin, b"").unwrap();
    }
}

fn failing_starters() -> Hooks {
    Hooks {
        start_exec: |_, _| Err(anyhow::anyhow!("the system cannot find the file")),
        start_pty: |_, _, _, _| Err(anyhow::anyhow!("the system cannot find the file")),
        ..Hooks::production()
    }
}

#[test]
fn a_command_that_cannot_be_started_is_answered_with_the_cause_and_255() {
    let (answer, result) = answered("exec-spawn", failing_starters(), handshake(Mode::Exec, "nosuchprogram"));
    assert_eq!(answer.outcome, Outcome::Exited(255));
    assert_eq!(
        answer.stderr,
        "ssh-broker: the agent could not start the command: the system cannot find the file\r\n"
    );
    assert!(format!("{:#}", result.unwrap_err()).contains("cannot find the file"));
}

#[test]
fn a_shell_that_cannot_be_started_is_answered_with_the_cause_and_255() {
    let (answer, result) = answered("pty-spawn", failing_starters(), handshake(Mode::Pty, "pwsh.exe"));
    assert_eq!(answer.outcome, Outcome::Exited(255));
    assert_eq!(
        answer.stderr,
        "ssh-broker: the agent could not start the shell: the system cannot find the file\r\n"
    );
    assert!(result.is_err());
}

#[test]
fn a_first_frame_that_is_not_a_handshake_is_answered_with_254() {
    let (answer, result) = answered("not-handshake", Hooks::production(), |tx| {
        write_data(tx, Stream::Pty, b"oops").unwrap();
    });
    assert_eq!(answer.outcome, Outcome::Exited(254));
    assert!(
        answer
            .stderr
            .starts_with("ssh-broker: the agent could not read the request: "),
        "{}",
        answer.stderr
    );
    assert!(answer.stderr.contains("not a handshake"), "{}", answer.stderr);
    assert!(result.is_err());
}

#[test]
fn a_handshake_that_cannot_be_decoded_is_answered_with_254() {
    let (answer, result) = answered("junk-handshake", Hooks::production(), |tx| {
        write_frame(tx, FrameKind::Handshake, b"not a handshake").unwrap();
    });
    assert_eq!(answer.outcome, Outcome::Exited(254));
    assert!(
        answer
            .stderr
            .starts_with("ssh-broker: the agent could not read the request: "),
        "{}",
        answer.stderr
    );
    assert!(result.is_err());
}

#[test]
fn a_frame_cut_short_is_answered_not_dropped() {
    // The header promises more than comes: the client then closes its write half and waits.
    let (answer, _result) = answered("cut-short", Hooks::production(), |tx| {
        use std::io::Write;
        tx.write_all(&[FrameKind::Handshake as u8, 100, 0, 0, 0, 1, 2, 3])
            .unwrap();
        tx.shutdown_write().unwrap();
    });
    assert_eq!(answer.outcome, Outcome::Exited(254));
    assert!(
        answer.stderr.contains("could not read the request"),
        "{}",
        answer.stderr
    );
}

#[test]
fn a_connection_that_cannot_be_split_is_answered_on_the_socket_itself() {
    let hooks = Hooks {
        split: |socket| Err((Whole::of(socket), anyhow::anyhow!("no handle to duplicate"))),
        ..Hooks::production()
    };
    let (answer, result) = answered("no-split", hooks, handshake(Mode::Exec, "echo"));
    assert_eq!(answer.outcome, Outcome::Exited(255));
    assert_eq!(
        answer.stderr,
        "ssh-broker: the agent could not set up the connection: no handle to duplicate\r\n"
    );
    assert!(result.is_err());
}

#[test]
fn a_client_that_connects_and_leaves_without_a_byte_is_not_a_fault() {
    // The wake that ends the accept loop is such a client.
    let (server, client, dir) = crate::test_support::raw_socket_pair("left");
    drop(client);
    let result = handle_connection_in(server, Hooks::production(), &Control::standalone());
    assert!(result.is_ok(), "{:#}", result.unwrap_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_client_that_leaves_in_the_middle_of_a_frame_is_still_a_bad_request() {
    // It sent something, so it is not the wake: the log keeps the fault.
    let (server, client, dir) = crate::test_support::raw_socket_pair("left-midway");
    let (_rx, mut tx) = afunix::split(client).unwrap();
    std::io::Write::write_all(&mut tx, &[FrameKind::Handshake as u8, 100, 0, 0, 0, 1]).unwrap();
    tx.shutdown_both().unwrap();
    let result = handle_connection_in(server, Hooks::production(), &Control::standalone());
    assert!(result.is_err());
    let _ = std::fs::remove_dir_all(&dir);
}
