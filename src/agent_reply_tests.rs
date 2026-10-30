//! Tests that the agent answers every connection it cannot serve with a frame the shim prints, and
//! closes none of them without a byte while it is alive. No shell is started: the starters of the
//! hooks fail on purpose, and the connections are AF_UNIX pairs in a temp dir.
use super::*;
use crate::afunix::{ConnTx, Whole};
use crate::protocol::{FrameKind, Handshake, Launch, Mode, Stream, write_frame};
use crate::relay::{Outcome, TestSink, pump_decode, write_data};
use crate::shell::test_host::{TestHost, USER_CONFIG};

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

#[test]
fn a_handler_that_panics_answers_its_connection_with_255_before_it_closes() {
    let hooks = Hooks {
        start_pty: |_, _, _, _| panic!("the starter failed"),
        ..Hooks::production()
    };
    let (server, client, dir) = crate::test_support::raw_socket_pair("panic-reply");
    let agent = std::thread::spawn(move || serve_connection(server, hooks, &Control::standalone()));
    let (mut rx, mut tx) = afunix::split(client).unwrap();
    handshake(Mode::Pty, "pwsh.exe")(&mut tx);
    let mut sink = TestSink::default();
    let outcome = pump_decode(&mut rx, &mut FrameReader::new(), &mut sink).expect("the reply was lost");
    drop((rx, tx));
    let handler = agent.join();
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(outcome, Outcome::Exited(255));
    assert_eq!(
        String::from_utf8(sink.stderr).unwrap(),
        "ssh-broker: the agent failed while serving this connection: the handler panicked\r\n"
    );
    assert!(handler.is_err(), "the panic is not swallowed");
}

#[test]
fn a_handler_that_does_not_panic_adds_nothing_to_its_reply() {
    // A desktop agent answers a logout request and returns without closing anything itself: the
    // connection ends with the handler, and no second reply is behind the first.
    let (server, client, dir) = crate::test_support::raw_socket_pair("no-panic-reply");
    let agent = std::thread::spawn(move || serve_connection(server, Hooks::production(), &Control::standalone()));
    let (mut rx, mut tx) = afunix::split(client).unwrap();
    // Nothing after the handshake: unread input at the agent's close would reset the connection.
    let logout = Handshake {
        mode: Mode::Logout,
        ..Handshake::pty_default()
    };
    write_frame(&mut tx, FrameKind::Handshake, &logout.encode().unwrap()).unwrap();
    let mut sink = TestSink::default();
    let outcome = pump_decode(&mut rx, &mut FrameReader::new(), &mut sink).expect("the reply was lost");
    let mut rest = Vec::new();
    std::io::Read::read_to_end(&mut rx, &mut rest).unwrap();
    drop((rx, tx));
    let result = agent.join().unwrap();
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(outcome, Outcome::Exited(2));
    assert!(result.is_ok());
    assert!(rest.is_empty(), "bytes after the reply: {rest:?}");
}

#[test]
fn a_connection_refused_at_accept_is_answered_with_255_not_dropped() {
    // The system hands out a connection the agent must not give to a shell: its peer is told why.
    let (server, client, dir) = crate::test_support::raw_socket_pair("refused");
    let connections = Connections::new();
    let control = Arc::new(Control::standalone());
    let mut script = Some(AcceptError::Refused {
        socket: server,
        cause: anyhow::anyhow!("the connection is inheritable by child processes"),
    });
    let end = accept_loop_with(
        || {
            Err(script
                .take()
                .unwrap_or_else(|| AcceptError::Fatal(anyhow::anyhow!("end of script"))))
        },
        &connections,
        &control,
        || false,
    );
    assert!(format!("{end:#}").ends_with("end of script"), "{end:#}");

    let (mut rx, tx) = afunix::split(client).unwrap();
    let mut sink = TestSink::default();
    let outcome = pump_decode(&mut rx, &mut FrameReader::new(), &mut sink).expect("the reply was lost");
    drop((rx, tx));
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(outcome, Outcome::Exited(255));
    assert_eq!(
        String::from_utf8(sink.stderr).unwrap(),
        "ssh-broker: the agent could not use the connection: the connection is inheritable by child processes\r\n"
    );
}

// Which line a handshake starts -----

/// `command` as a `Launch::Shell` request in `mode`.
fn shell_request(mode: Mode, command: Option<&str>) -> impl FnOnce(&mut ConnTx) + Send + 'static {
    let hs = Handshake {
        mode,
        command: command.map(str::to_owned),
        launch: Launch::Shell,
        ..Handshake::pty_default()
    };
    move |tx| {
        write_frame(tx, FrameKind::Handshake, &hs.encode().unwrap()).unwrap();
        write_data(tx, Stream::Stdin, b"").unwrap();
    }
}

fn with_host(host: TestHost) -> Hooks {
    Hooks {
        shell_host: Box::new(host),
        ..failing_starters()
    }
}

#[test]
fn a_request_without_the_command_it_needs_is_answered_with_254_and_starts_nothing() {
    for (tag, mode, launch) in [
        ("exec-shell", Mode::Exec, Launch::Shell),
        ("exec-direct", Mode::Exec, Launch::Direct),
        ("pty-direct", Mode::Pty, Launch::Direct),
    ] {
        let hs = Handshake {
            mode,
            launch,
            ..Handshake::pty_default()
        };
        let (answer, result) = answered(tag, failing_starters(), move |tx| {
            write_frame(tx, FrameKind::Handshake, &hs.encode().unwrap()).unwrap();
            write_data(tx, Stream::Stdin, b"").unwrap();
        });
        assert_eq!(answer.outcome, Outcome::Exited(254), "{tag}");
        assert!(
            answer
                .stderr
                .starts_with("ssh-broker: the agent could not read the request: "),
            "{tag}: {}",
            answer.stderr
        );
        assert!(answer.stderr.contains("needs a command"), "{tag}: {}", answer.stderr);
        assert!(result.is_err(), "{tag}");
    }
}

#[test]
fn a_command_too_long_for_a_command_line_is_answered_with_255_and_starts_nothing() {
    let long = "x".repeat(40_000);
    let (answer, result) = answered(
        "too-long",
        with_host(TestHost::new()),
        shell_request(Mode::Exec, Some(&long)),
    );
    assert_eq!(answer.outcome, Outcome::Exited(255));
    assert!(answer.stderr.contains("32,767"), "{}", answer.stderr);
    assert!(
        !answer.stderr.contains("could not start"),
        "a starter was reached: {}",
        answer.stderr
    );
    assert!(result.is_err());
}

#[test]
fn a_broken_config_shows_one_warning_before_anything_else() {
    let host = TestHost::new().with_user_config("shell: {strt: pwsh.exe}\n");
    let (answer, _result) = answered("warn-exec", with_host(host), shell_request(Mode::Exec, Some("echo hi")));
    let warning = format!("ssh-broker: cannot use the shell from {USER_CONFIG}");
    assert!(answer.stderr.starts_with(&warning), "{}", answer.stderr);
    assert_eq!(
        answer.stderr.matches("cannot use the shell").count(),
        1,
        "{}",
        answer.stderr
    );
    assert!(
        answer.stderr.contains("using the built-in cmd.exe\n"),
        "{}",
        answer.stderr
    );
    // The starter fails on purpose after it: the failure reply follows the warning.
    assert!(
        answer.stderr.contains("could not start the command"),
        "{}",
        answer.stderr
    );
}

#[test]
fn a_working_config_shows_no_warning() {
    let host = TestHost::new();
    let (answer, _result) = answered("no-warn", with_host(host), shell_request(Mode::Exec, Some("echo hi")));
    assert!(!answer.stderr.contains("cannot use the shell"), "{}", answer.stderr);
}
