//! Windows-only integration tests for the agent (run on a real Windows host via the cross-compile
//! -> scp -> run loop). They drive `handle_connection` over a real AF_UNIX socket.
use super::{HandleWriter, HangupGuard, Hooks, ParkSignal, end_of_watch};
use crate::afunix::{self, Listener};
use crate::hangup::HangupWatcher;
use crate::protocol::{FrameKind, FrameReader, Handshake, Mode, Stream, write_frame};
use crate::relay::{Outcome, TestSink, pump_decode, write_data};
use std::thread;

fn hardened_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("sb-agent-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let me = crate::acl::Sid::current_user().unwrap();
    crate::acl::harden_dir(&dir, &me).unwrap();
    dir
}

#[test]
fn agent_pty_handler_runs_command_and_returns_exit() {
    let dir = hardened_dir("pty");
    let sock = dir.join("s");
    let listener = Listener::bind(&sock).unwrap();

    let client_path = sock.clone();
    let client = thread::spawn(move || {
        let conn = afunix::connect(&client_path).unwrap();
        let (mut crx, mut ctx) = afunix::split(conn).unwrap();
        let hs = Handshake {
            mode: Mode::Pty,
            command: Some("cmd.exe /c echo agent-pty-ok".into()),
            ..Handshake::pty_default()
        };
        write_frame(&mut ctx, FrameKind::Handshake, &hs.encode().unwrap()).unwrap();
        let mut fr = FrameReader::new();
        let mut sink = TestSink::default();
        let outcome = pump_decode(&mut crx, &mut fr, &mut sink).unwrap();
        (outcome, sink.stdout)
    });

    let conn = listener.accept().unwrap();
    super::handle_connection(conn).unwrap();

    let (outcome, stdout) = client.join().unwrap();
    assert_eq!(outcome, Outcome::Exited(0));
    let text = String::from_utf8_lossy(&stdout);
    assert!(text.contains("agent-pty-ok"), "relayed output was: {text:?}");
    std::fs::remove_dir_all(&dir).ok();
}

/// Run `cmd.exe /c echo pty-ok` as a PTY session under `hooks`; returns the outcome and the output.
fn run_pty_echo_session(tag: &str, hooks: Hooks) -> (Outcome, String) {
    let dir = hardened_dir(tag);
    let sock = dir.join("s");
    let listener = Listener::bind(&sock).unwrap();
    let client_path = sock.clone();
    let client = thread::spawn(move || {
        let conn = afunix::connect(&client_path).unwrap();
        let (mut crx, mut ctx) = afunix::split(conn).unwrap();
        let hs = Handshake {
            mode: Mode::Pty,
            command: Some("cmd.exe /c echo pty-ok".into()),
            ..Handshake::pty_default()
        };
        write_frame(&mut ctx, FrameKind::Handshake, &hs.encode().unwrap()).unwrap();
        let mut fr = FrameReader::new();
        let mut sink = TestSink::default();
        let outcome = pump_decode(&mut crx, &mut fr, &mut sink).unwrap();
        (outcome, sink.stdout)
    });
    let conn = listener.accept().unwrap();
    super::handle_connection_with(conn, hooks).unwrap();
    let (outcome, stdout) = client.join().unwrap();
    std::fs::remove_dir_all(&dir).ok();
    (outcome, String::from_utf8_lossy(&stdout).into_owned())
}

/// The PTY relay creates a hangup watcher for its session, and, like EXEC, runs the command
/// without that protection when the watcher cannot be created.
#[test]
fn agent_pty_session_creates_a_hangup_watcher_and_survives_its_failure() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static CREATED: AtomicUsize = AtomicUsize::new(0);
    let counting = Hooks {
        make_watcher: |tx| {
            CREATED.fetch_add(1, Ordering::SeqCst);
            HangupWatcher::new(tx)
        },
        ..Hooks::production()
    };
    let (outcome, text) = run_pty_echo_session("pty-watcher", counting);
    assert_eq!(outcome, Outcome::Exited(0));
    assert!(text.contains("pty-ok"), "relayed output was: {text:?}");
    assert_eq!(
        CREATED.load(Ordering::SeqCst),
        1,
        "the PTY relay did not ask for a watcher"
    );

    let failing = Hooks {
        make_watcher: |_| Err(std::io::Error::other("forced watcher failure")),
        ..Hooks::production()
    };
    let (outcome, text) = run_pty_echo_session("pty-no-watcher", failing);
    assert_eq!(outcome, Outcome::Exited(0));
    assert!(text.contains("pty-ok"), "relayed output was: {text:?}");
}

// A login that reaches an ending agent -----

/// More than the socket buffers hold, so an agent that has stopped reading cannot hide behind them.
const INPUT_AFTER_HANDSHAKE: usize = 8 * 1024 * 1024;

/// Send a login in `mode` that never ends by itself, then input after the handshake, and return
/// what the agent answers. `agent` handles the connection.
fn refused_login(tag: &str, mode: Mode, agent: impl FnOnce(socket2::Socket)) -> (Outcome, Vec<u8>) {
    refused_login_of(tag, mode, "cmd.exe /c ping -n 120 127.0.0.1 > nul", agent)
}

/// [`refused_login`] for a login that runs `command`.
fn refused_login_of(tag: &str, mode: Mode, command: &str, agent: impl FnOnce(socket2::Socket)) -> (Outcome, Vec<u8>) {
    let command = command.to_owned();
    let dir = hardened_dir(tag);
    let sock = dir.join("s");
    let listener = Listener::bind(&sock).unwrap();
    let client_path = sock.clone();
    let client = thread::spawn(move || {
        let conn = afunix::connect(&client_path).unwrap();
        let (mut crx, mut ctx) = afunix::split(conn).unwrap();
        let hs = Handshake {
            mode,
            command: Some(command),
            ..Handshake::pty_default()
        };
        write_frame(&mut ctx, FrameKind::Handshake, &hs.encode().unwrap()).unwrap();
        let stream = if mode == Mode::Pty { Stream::Pty } else { Stream::Stdin };
        let chunk = [b'x'; 32 * 1024];
        for _ in 0..INPUT_AFTER_HANDSHAKE / chunk.len() {
            write_data(&mut ctx, stream, &chunk).expect("input after the handshake must still be read");
        }
        let mut fr = FrameReader::new();
        let mut sink = TestSink::default();
        let outcome = pump_decode(&mut crx, &mut fr, &mut sink).expect("the refusal was lost");
        (outcome, sink.stderr)
    });
    agent(listener.accept().unwrap());
    let answer = client.join().unwrap();
    std::fs::remove_dir_all(&dir).ok();
    answer
}

fn assert_refused((outcome, stderr): (Outcome, Vec<u8>)) {
    assert_eq!(outcome, Outcome::Exited(255));
    assert_eq!(stderr, super::logout::ENDING_REFUSAL.as_bytes());
}

#[test]
fn an_exec_login_to_an_ending_agent_is_refused_before_a_shell_starts() {
    let control = super::Control::new(true, super::Connections::new());
    control.end_all();
    assert_refused(refused_login("refused-exec", Mode::Exec, |conn| {
        let hooks = Hooks {
            after_spawn: Box::new(|| panic!("a shell was started for a login the agent had refused")),
            ..Hooks::production()
        };
        super::handle_connection_in(conn, hooks, &control).unwrap();
    }));
}

#[test]
fn an_exec_login_that_loses_the_race_with_the_end_is_refused_not_relayed() {
    let control = std::sync::Arc::new(super::Control::new(true, super::Connections::new()));
    assert_refused(refused_login("raced-exec", Mode::Exec, |conn| {
        // The end begins after the shell has started and before it is registered.
        let hooks = Hooks {
            after_spawn: {
                let control = std::sync::Arc::clone(&control);
                Box::new(move || control.end_all())
            },
            ..Hooks::production()
        };
        super::handle_connection_in(conn, hooks, &control).unwrap();
    }));
}

#[test]
fn a_pty_login_that_loses_the_race_with_the_end_is_refused_not_relayed() {
    let control = std::sync::Arc::new(super::Control::new(true, super::Connections::new()));
    assert_refused(refused_login("raced-pty", Mode::Pty, |conn| {
        let hooks = Hooks {
            after_spawn: {
                let control = std::sync::Arc::clone(&control);
                Box::new(move || control.end_all())
            },
            ..Hooks::production()
        };
        super::handle_connection_in(conn, hooks, &control).unwrap();
    }));
}

/// How far a test got, for the message of a failure bound that runs out.
#[derive(Clone, Default)]
struct Seen(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

impl Seen {
    fn note(&self, what: impl Into<String>) {
        self.0.lock().unwrap().push(what.into());
    }

    fn text(&self) -> String {
        self.0.lock().unwrap().join("; ")
    }
}

/// How long the pseudoconsole's output pipe may take to fill, how long the refused shell may take to
/// end, and how long the test may take. Failure bounds on external events (a shell, conhost) that
/// might never come, well inside nextest's limit; the test takes seconds when it works.
const FILL_BOUND: std::time::Duration = std::time::Duration::from_secs(60);
const SHELL_END_BOUND: std::time::Duration = std::time::Duration::from_secs(60);
const TEST_BOUND: std::time::Duration = std::time::Duration::from_secs(120);

/// A login that loses the race with the end, while its shell is writing without end into a
/// pseudoconsole whose output pipe is full and which nothing reads: the refusal has to close the
/// pseudoconsole with that output still pending, which blocks where nothing drains it. The handler
/// would never return, so this test would hang (the watchdog ends it and says how far it got) and not
/// pass. It pins that the refusal reaches the client and ends the shell.
///
/// The end begins once the unread output has filled the pipe, which is when the shell blocks and conhost
/// holds the rest. The shell makes no marker: it cannot be waited for, and it never finishes.
#[test]
fn a_pty_login_refused_after_the_shell_wrote_a_lot_is_still_refused() {
    use crate::test_support::{
        DEFAULT_PIPE_BUFFER, Watchdog, pipe_buffer, process_ended_within, wait_for_pipe_pending,
    };
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};

    const LINE: &str = "0123456789012345678901234567890123456789012345678901234567890123456789";
    // Far more lines than the pipe holds, and more than a test lasts for.
    let command = format!(r#"cmd.exe /d /s /c "for /l %i in (1,1,2147483647) do @echo {LINE}""#);
    let seen = Seen::default();
    let _watchdog = Watchdog::arm("the refused PTY login", TEST_BOUND, {
        let seen = seen.clone();
        move || seen.text()
    });
    let (output, process) = (Arc::new(AtomicIsize::new(0)), Arc::new(AtomicIsize::new(0)));
    let shell_ended = Arc::new(AtomicBool::new(false));
    let control = Arc::new(super::Control::new(true, super::Connections::new()));
    assert_refused(refused_login_of("raced-pty-output", Mode::Pty, &command, |conn| {
        let hooks = Hooks {
            observe: {
                let (seen, output, process, shell_ended) = (
                    seen.clone(),
                    Arc::clone(&output),
                    Arc::clone(&process),
                    Arc::clone(&shell_ended),
                );
                Box::new(move |event| match event {
                    super::Observed::ShellStarted {
                        output: pipe,
                        process: shell,
                    } => {
                        output.store(pipe, Ordering::SeqCst);
                        process.store(shell, Ordering::SeqCst);
                        seen.note("the shell started");
                    }
                    super::Observed::RefusedConsoleClosed { bytes } => {
                        seen.note(format!("ClosePseudoConsole returned after {bytes} bytes were read"));
                        // Before the session is dropped, which closes the handle.
                        shell_ended.store(
                            process_ended_within(process.load(Ordering::SeqCst), SHELL_END_BOUND),
                            Ordering::SeqCst,
                        );
                    }
                })
            },
            after_spawn: {
                let (control, seen, output) = (Arc::clone(&control), seen.clone(), Arc::clone(&output));
                Box::new(move || {
                    let pipe = output.load(Ordering::SeqCst);
                    let full = pipe_buffer(pipe).unwrap_or(DEFAULT_PIPE_BUFFER);
                    match wait_for_pipe_pending(pipe, full, FILL_BOUND) {
                        Ok(pending) => seen.note(format!("{pending} bytes were waiting, of {full} that fill the pipe")),
                        Err(why) => panic!(
                            "the shell's unread output did not fill the output pipe within {FILL_BOUND:?}: {why}. Seen: {}",
                            seen.text()
                        ),
                    }
                    control.end_all();
                    seen.note("the agent was told to end");
                })
            },
            ..Hooks::production()
        };
        super::handle_connection_in(conn, hooks, &control).unwrap();
        seen.note("the agent answered the refusal");
    }));
    assert!(
        shell_ended.load(Ordering::SeqCst),
        "the refused login's shell was still running {SHELL_END_BOUND:?} after the refusal. Seen: {}",
        seen.text()
    );
}

/// While the agent waits for its connections to finish, a login is answered with the refusal at
/// once: the listener stays open, and the answer does not wait for the drain.
#[test]
fn a_login_that_arrives_while_the_agent_drains_gets_the_refusal_at_once() {
    use std::sync::Arc;
    use std::sync::mpsc;

    let dir = hardened_dir("drain-login");
    let sock = dir.join("s");
    let listener = Listener::bind(&sock).unwrap();
    let (events, on_event) = mpsc::channel();
    let connections = super::Connections::observing_drain({
        let events = events.clone();
        move || {
            let _ = events.send("draining");
        }
    });
    // A connection that is still relaying: the drain cannot finish until the test lets it go.
    let relaying = connections.begin();
    let control = Arc::new(super::Control::new(true, Arc::clone(&connections)).with_waker({
        let sock = sock.clone();
        move || {
            super::wake_without_blocking({
                let sock = sock.clone();
                move || drop(afunix::connect(&sock))
            })
        }
    }));
    let serving = thread::spawn({
        let (connections, control) = (Arc::clone(&connections), Arc::clone(&control));
        move || super::serve_until_drained(listener, &connections, &control)
    });

    control.end_all();
    assert_eq!(on_event.recv().unwrap(), "draining");

    let conn = afunix::connect(&sock).expect("the listener was closed while the agent drained");
    let (mut crx, mut ctx) = afunix::split(conn).unwrap();
    let hs = Handshake {
        mode: Mode::Exec,
        command: Some("cmd.exe /c exit /b 0".into()),
        ..Handshake::pty_default()
    };
    write_frame(&mut ctx, FrameKind::Handshake, &hs.encode().unwrap()).unwrap();
    write_data(&mut ctx, Stream::Stdin, b"").unwrap();
    let mut sink = TestSink::default();
    let outcome = pump_decode(&mut crx, &mut FrameReader::new(), &mut sink).expect("the refusal was lost");
    assert_refused((outcome, sink.stderr));

    // Only now does the relaying connection finish, and the drain with it.
    drop((crx, ctx));
    drop(relaying);
    let end = serving.join().unwrap();
    assert!(end.downcast_ref::<super::Stopped>().is_some(), "{end:#}");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn agent_tears_down_when_ssh_side_disconnects_first() {
    // The riskiest path: a long-running shell is alive when the SSH side disconnects
    // (after a resize). The agent must apply the resize, then on disconnect kill the child,
    // join both pump threads, and RETURN. A teardown deadlock would hang this test (surfaced
    // by the test runner), not pass it.
    let dir = hardened_dir("disconnect");
    let sock = dir.join("s");
    let listener = Listener::bind(&sock).unwrap();

    let client_path = sock.clone();
    let client = thread::spawn(move || {
        let conn = afunix::connect(&client_path).unwrap();
        let (_crx, mut ctx) = afunix::split(conn).unwrap();
        let hs = Handshake {
            mode: Mode::Pty,
            command: Some("cmd.exe /k".into()), // stays alive until killed
            ..Handshake::pty_default()
        };
        write_frame(&mut ctx, FrameKind::Handshake, &hs.encode().unwrap()).unwrap();
        // A resize while the shell is live (exercises on_resize under the HPCON lock).
        write_frame(
            &mut ctx,
            FrameKind::Resize,
            &crate::protocol::Resize { cols: 120, rows: 40 }.encode(),
        )
        .unwrap();
        // Disconnect while the shell is still running.
        let _ = ctx.shutdown_both();
    });

    let conn = listener.accept().unwrap();
    // Returns Ok once the child is killed and both threads join; hangs forever if teardown
    // deadlocks (which is the failure we are guarding against).
    super::handle_connection(conn).unwrap();
    let _ = client.join();
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn agent_exec_handler_separates_streams_and_returns_code() {
    let dir = hardened_dir("exec");
    let sock = dir.join("s");
    let listener = Listener::bind(&sock).unwrap();

    let client_path = sock.clone();
    let client = thread::spawn(move || {
        let conn = afunix::connect(&client_path).unwrap();
        let (mut crx, mut ctx) = afunix::split(conn).unwrap();
        let hs = Handshake {
            mode: Mode::Exec,
            command: Some("cmd.exe /c echo OUT& echo ERR 1>&2& exit /b 4".into()),
            ..Handshake::pty_default()
        };
        write_frame(&mut ctx, FrameKind::Handshake, &hs.encode().unwrap()).unwrap();
        // No stdin to send: send the empty-Stdin EOF marker (NOT a half-close, which would
        // read as a disconnect) and keep the socket open to receive stdout/stderr/EXIT.
        write_data(&mut ctx, Stream::Stdin, b"").unwrap();
        let mut fr = FrameReader::new();
        let mut sink = TestSink::default();
        let outcome = pump_decode(&mut crx, &mut fr, &mut sink).unwrap();
        (outcome, sink.stdout, sink.stderr)
    });

    let conn = listener.accept().unwrap();
    super::handle_connection(conn).unwrap();

    let (outcome, stdout, stderr) = client.join().unwrap();
    assert_eq!(outcome, Outcome::Exited(4));
    assert!(
        String::from_utf8_lossy(&stdout).contains("OUT"),
        "stdout was: {:?}",
        String::from_utf8_lossy(&stdout)
    );
    assert!(
        String::from_utf8_lossy(&stderr).contains("ERR"),
        "stderr was: {:?}",
        String::from_utf8_lossy(&stderr)
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// After EXIT the agent only FINs its write half; it keeps reading, and so discarding, the
/// client's input until the client closes. Closing the read side instead resets the connection
/// whenever input is in flight, and the reset discards an EXIT frame the client has not read yet.
///
/// The client therefore gets the EXIT frame and the agent's FIN before it sends anything more,
/// which leaves no race: everything the agent will send has been sent, so the EXIT frame can no
/// longer be lost. Every write after that must succeed. Had the agent shut its read side down, the first would reset the connection and a
/// later one would fail (or block, once the socket buffers fill with data nobody reads).
fn assert_input_after_exit_is_still_read(tag: &str, mode: Mode) {
    use std::io::Read;

    /// More than the socket buffers hold, so a reader that is gone cannot hide behind them.
    const AFTER_EXIT: usize = 8 * 1024 * 1024;

    let dir = hardened_dir(tag);
    let sock = dir.join("s");
    let listener = Listener::bind(&sock).unwrap();

    let client_path = sock.clone();
    let client = thread::spawn(move || {
        let conn = afunix::connect(&client_path).unwrap();
        let (mut crx, mut ctx) = afunix::split(conn).unwrap();
        let hs = Handshake {
            mode,
            command: Some("cmd.exe /c exit /b 3".into()),
            ..Handshake::pty_default()
        };
        write_frame(&mut ctx, FrameKind::Handshake, &hs.encode().unwrap()).unwrap();
        let mut fr = FrameReader::new();
        let mut sink = TestSink::default();
        let outcome = pump_decode(&mut crx, &mut fr, &mut sink).expect("the EXIT frame was lost");
        assert_eq!(outcome, Outcome::Exited(3));
        // Everything the agent will ever send has been sent once it has FINed.
        let mut buf = [0u8; 4096];
        while crx.read(&mut buf).expect("reading up to the agent's FIN") != 0 {}

        let stream = if mode == Mode::Pty { Stream::Pty } else { Stream::Stdin };
        let chunk = [b'x'; 32 * 1024];
        for _ in 0..AFTER_EXIT / chunk.len() {
            write_data(&mut ctx, stream, &chunk).expect("input after EXIT must still be read");
        }
        ctx.shutdown_both().unwrap();
    });

    let conn = listener.accept().unwrap();
    super::handle_connection(conn).unwrap();

    client.join().unwrap();
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn agent_exec_keeps_reading_input_after_exit_until_the_client_closes() {
    assert_input_after_exit_is_still_read("exec-after-exit", Mode::Exec);
}

#[test]
fn agent_pty_keeps_reading_input_after_exit_until_the_client_closes() {
    assert_input_after_exit_is_still_read("pty-after-exit", Mode::Pty);
}

/// A broken broker must not cost the user a session: if the hangup watcher cannot be created the
/// command still runs and reports its exit code, without that protection.
#[test]
fn agent_exec_runs_the_command_when_the_hangup_watcher_cannot_be_created() {
    let dir = hardened_dir("exec-no-watcher");
    let sock = dir.join("s");
    let listener = Listener::bind(&sock).unwrap();

    let client_path = sock.clone();
    let client = thread::spawn(move || {
        let conn = afunix::connect(&client_path).unwrap();
        let (mut crx, mut ctx) = afunix::split(conn).unwrap();
        let hs = Handshake {
            mode: Mode::Exec,
            command: Some("cmd.exe /c echo OUT& exit /b 4".into()),
            ..Handshake::pty_default()
        };
        write_frame(&mut ctx, FrameKind::Handshake, &hs.encode().unwrap()).unwrap();
        write_data(&mut ctx, Stream::Stdin, b"").unwrap();
        let mut fr = FrameReader::new();
        let mut sink = TestSink::default();
        let outcome = pump_decode(&mut crx, &mut fr, &mut sink).unwrap();
        (outcome, sink.stdout)
    });

    let conn = listener.accept().unwrap();
    let hooks = Hooks {
        make_watcher: |_| Err(std::io::Error::other("forced watcher failure")),
        ..Hooks::production()
    };
    super::handle_connection_with(conn, hooks).unwrap();

    let (outcome, stdout) = client.join().unwrap();
    assert_eq!(outcome, Outcome::Exited(4));
    assert!(
        String::from_utf8_lossy(&stdout).contains("OUT"),
        "stdout was: {stdout:?}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn agent_exec_relays_stdin_and_returns_sorted_output() {
    // The documented core of the stdin path: feed a stdin-reading child (`sort`) its full
    // input, signal stdin-EOF with the empty marker, and assert it consumed all input and
    // sorted it. This is the regression guard for the stdin-EOF-marker timing.
    let dir = hardened_dir("exec-stdin");
    let sock = dir.join("s");
    let listener = Listener::bind(&sock).unwrap();

    let client_path = sock.clone();
    let client = thread::spawn(move || {
        let conn = afunix::connect(&client_path).unwrap();
        let (mut crx, mut ctx) = afunix::split(conn).unwrap();
        let hs = Handshake {
            mode: Mode::Exec,
            command: Some("sort".into()), // reads stdin, sorts lines, writes stdout, needs EOF
            ..Handshake::pty_default()
        };
        write_frame(&mut ctx, FrameKind::Handshake, &hs.encode().unwrap()).unwrap();
        write_data(&mut ctx, Stream::Stdin, b"banana\r\napple\r\ncherry\r\n").unwrap();
        write_data(&mut ctx, Stream::Stdin, b"").unwrap(); // stdin-EOF marker → sort finishes
        let mut fr = FrameReader::new();
        let mut sink = TestSink::default();
        let outcome = pump_decode(&mut crx, &mut fr, &mut sink).unwrap();
        (outcome, sink.stdout)
    });

    let conn = listener.accept().unwrap();
    super::handle_connection(conn).unwrap();

    let (outcome, stdout) = client.join().unwrap();
    assert_eq!(outcome, Outcome::Exited(0));
    let out = String::from_utf8_lossy(&stdout);
    let (a, b, c) = (out.find("apple"), out.find("banana"), out.find("cherry"));
    assert!(
        a.is_some() && b.is_some() && c.is_some(),
        "sorted output missing a line: {out:?}"
    );
    assert!(a < b && b < c, "output not in sorted order: {out:?}");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn agent_exec_tears_down_when_ssh_disconnects_first() {
    // A silent, stdin-ignoring, long-running command. The SSH side FULLY disconnects
    // (shutdown_both) without ever sending the stdin-EOF marker. The agent must treat the
    // socket close as a disconnect and kill the child so the waiter unblocks and
    // handle_connection RETURNS. With no kill, the output pumps block in read (nothing to
    // write) and child.wait() blocks forever — this test would hang (surfaced by the runner),
    // which is exactly the bug it guards against.
    let dir = hardened_dir("exec-disc");
    let sock = dir.join("s");
    let listener = Listener::bind(&sock).unwrap();

    let client_path = sock.clone();
    let client = thread::spawn(move || {
        let conn = afunix::connect(&client_path).unwrap();
        let (_crx, mut ctx) = afunix::split(conn).unwrap();
        // A sentinel the child holds until teardown kills it — not a wait for anything.
        let never_exits = format!("pwsh.exe -NoLogo -NoProfile -Command {SLEEP_FOREVER}");
        let hs = Handshake {
            mode: Mode::Exec,
            command: Some(never_exits),
            ..Handshake::pty_default()
        };
        write_frame(&mut ctx, FrameKind::Handshake, &hs.encode().unwrap()).unwrap();
        // Full disconnect with the child still running and producing no output.
        let _ = ctx.shutdown_both();
    });

    let conn = listener.accept().unwrap();
    super::handle_connection(conn).unwrap();
    let _ = client.join();
    std::fs::remove_dir_all(&dir).ok();
}

/// `read_one_frame` is exercised indirectly above; `handle_connection` also reads the
/// handshake via it. This asserts the handler rejects a non-handshake first frame.
#[test]
fn agent_rejects_non_handshake_first_frame() {
    let dir = hardened_dir("badfirst");
    let sock = dir.join("s");
    let listener = Listener::bind(&sock).unwrap();

    let client_path = sock.clone();
    let client = thread::spawn(move || {
        let conn = afunix::connect(&client_path).unwrap();
        let (_crx, mut ctx) = afunix::split(conn).unwrap();
        // A DATA frame where a HANDSHAKE is required; flush it with a FIN (the frame is
        // delivered before the FIN, so the server reads it deterministically).
        crate::relay::write_data(&mut ctx, crate::protocol::Stream::Pty, b"oops").unwrap();
        let _ = ctx.shutdown_both();
    });

    let conn = listener.accept().unwrap();
    let result = super::handle_connection(conn);
    let _ = client.join();
    assert!(result.is_err(), "a non-handshake first frame must be rejected");
    std::fs::remove_dir_all(&dir).ok();
}

/// A disconnect must be noticed even when the input pump is stuck and cannot read the socket.
///
/// Writes to the child's stdin are queued to a writer thread, and once the child stops
/// draining its stdin pipe AND that queue fills, the pump parks in the send — blind to the
/// socket. The output pumps are then the only detector left.
///
/// The sizes are chosen to park it without parking the *client*: one chunk larger than the
/// stdin pipe's buffer stalls the writer thread, then enough one-byte frames to overfill the
/// queue stall the pump. The total is a few KiB, so the client's own socket writes never
/// block and it always reaches the disconnect below.
#[test]
fn exec_disconnect_is_noticed_while_the_input_pump_is_blocked_on_stdin() {
    let dir = hardened_dir("exec-stdin-blocked");
    let sock = dir.join("s");
    let listener = Listener::bind(&sock).unwrap();

    let client_path = sock.clone();
    let client = thread::spawn(move || {
        let conn = afunix::connect(&client_path).unwrap();
        let (_crx, mut ctx) = afunix::split(conn).unwrap();
        let hs = Handshake {
            mode: Mode::Exec,
            // Never reads stdin, and keeps producing output so an output pump attempts a
            // write after the disconnect and can observe it.
            command: Some("pwsh.exe -NoLogo -NoProfile -Command \"while ($true) { Write-Output 'tick' }\"".into()),
            ..Handshake::pty_default()
        };
        write_frame(&mut ctx, FrameKind::Handshake, &hs.encode().unwrap()).unwrap();
        write_data(&mut ctx, Stream::Stdin, &vec![b'x'; 64 * 1024]).unwrap();
        for _ in 0..64 {
            write_data(&mut ctx, Stream::Stdin, b"x").unwrap();
        }
        let _ = ctx.shutdown_both();
    });

    let conn = listener.accept().unwrap();
    // Returns only if something noticed the disconnect and reaped; hangs forever otherwise.
    super::handle_connection(conn).unwrap();
    let _ = client.join();
    std::fs::remove_dir_all(&dir).ok();
}

// ── process-tree teardown ────────────────────────────────────────────────────────────────

/// A command that never returns on its own, so teardown is what ends it.
///
/// Genuinely unbounded, not a large number: a bounded sleep would let a reap regression pass by
/// simply outlasting it, turning the assertion below into a slow yes.
const SLEEP_FOREVER: &str = "[System.Threading.Thread]::Sleep([System.Threading.Timeout]::Infinite)"; // sleep-ok: teardown killing it IS the assertion

/// How the session under test ends.
#[derive(Clone, Copy, PartialEq)]
enum Ending {
    /// The client vanishes mid-session, leaving the command running.
    Disconnect,
    /// The command finishes on its own — but not before the client has pinned the grandchild.
    NormalExit,
}

/// A named Win32 event that holds a relayed command at the starting line.
///
/// Without it the normal-exit cases are a race, not a test: the command exits the instant it
/// prints its marker, so the server can reap the grandchild — and Windows can recycle its pid —
/// before the client reaches `OpenProcess`. The client would then either fail to open a pid that
/// just died or, worse, open an unrelated process that inherited the number and wait on it.
/// Blocking the command on a kernel object until the pin is done removes the window entirely,
/// without anyone guessing a duration.
struct GoEvent {
    raw: isize,
    name: String,
}

impl GoEvent {
    fn create(tag: &str) -> Self {
        use windows::Win32::System::Threading::CreateEventW;
        use windows::core::HSTRING;
        let name = format!("ssh-broker-test-go-{tag}-{}", std::process::id());
        // Manual-reset: the command may reach its wait either side of the signal, and a
        // latching event makes both orders behave the same.
        let h = unsafe { CreateEventW(None, true, false, &HSTRING::from(name.as_str())) }.expect("create the go event");
        Self {
            raw: h.0 as isize,
            name,
        }
    }
}

impl Drop for GoEvent {
    fn drop(&mut self) {
        close_handle(self.raw);
    }
}

fn set_event(raw: isize) {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Threading::SetEvent;
    unsafe { SetEvent(HANDLE(raw as *mut core::ffi::c_void)) }.expect("signal the go event");
}

/// The tail that waits for the go event, then exits cleanly.
fn wait_then_exit(event: &str) -> String {
    // `$ErrorActionPreference='Stop'` is what makes the exit-code check downstream mean
    // anything: PowerShell's default is `Continue`, so a failed `OpenExisting` would print a
    // message, fall through to `exit 0`, and report success while never having waited at all —
    // silently restoring the pid race this event exists to remove.
    format!(
        "$ErrorActionPreference='Stop'; \
         [System.Threading.EventWaitHandle]::OpenExisting('{event}').WaitOne() | Out-Null; exit 0"
    )
}

/// A command that launches a background grandchild, records its pid, then announces itself.
///
/// The ordering is what makes the tests deterministic rather than timed: the pid file is
/// complete *before* the marker is printed, so a client that has read the marker can always
/// read a valid pid and the grandchild is guaranteed to exist.
///
/// `inherit_stdio` selects how the grandchild is attached: `-NoNewWindow` keeps it on the
/// parent's console and standard handles. Otherwise it gets its own fresh console and, measured
/// with pwsh 7.6.6 and a piped stdout, inherits none of the outer command's handles.
///
/// The fresh console is created hidden so no test opens a window on the developer's desktop.
/// Measured with Windows Terminal as the default terminal: the console window is hidden, is the
/// grandchild's own, and is not handed to Windows Terminal. Do not add `-Environment`: it moves
/// `Start-Process` onto `CreateProcess` with handle inheritance, so the grandchild would hold the
/// outer pipes.
fn grandchild_cmd(pidfile: &std::path::Path, tail: &str, inherit_stdio: bool) -> String {
    let window = if inherit_stdio {
        "-NoNewWindow "
    } else {
        "-WindowStyle Hidden "
    };
    format!(
        "pwsh.exe -NoLogo -NoProfile -Command \"$p = Start-Process pwsh.exe {window}-ArgumentList \
         '-NoLogo','-NoProfile','-Command','{SLEEP_FOREVER}' -PassThru; \
         $p.Id | Set-Content -LiteralPath '{}'; Write-Output 'SPAWNED'; {tail}\"",
        pidfile.display()
    )
}

/// Read frames until the accumulated stdout contains the marker.
///
/// Accumulates across frames: DATA carries arbitrary stream chunks, so the marker can split
/// across two of them and a per-frame match would miss it and block forever.
fn read_until_marker(rx: &mut impl std::io::Read, fr: &mut FrameReader) {
    use crate::protocol::read_one_frame;
    let mut seen = Vec::new();
    loop {
        let f = read_one_frame(rx, fr).unwrap();
        if f.kind == FrameKind::Data && f.payload.len() > 1 {
            seen.extend_from_slice(&f.payload[1..]);
            if String::from_utf8_lossy(&seen).contains("SPAWNED") {
                return;
            }
        }
    }
}

/// Open a handle to the recorded grandchild, pinning its pid: Windows will not recycle a pid
/// while a handle to it is open, so a later liveness check cannot be fooled into observing an
/// unrelated process that inherited the number.
fn open_grandchild(pidfile: &std::path::Path) -> isize {
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE};
    let pid: u32 = std::fs::read_to_string(pidfile)
        .expect("pid file is written before the marker is printed")
        .trim()
        .parse()
        .expect("pid file holds a pid");
    let h = unsafe { OpenProcess(PROCESS_SYNCHRONIZE | PROCESS_TERMINATE, false, pid) }
        .expect("grandchild is alive when the marker arrives");
    h.0 as isize
}

fn close_handle(raw: isize) {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    unsafe {
        let _ = CloseHandle(HANDLE(raw as *mut core::ffi::c_void));
    }
}

/// Input the command never drains, so the input pump parks in its bounded queue. A 64 KiB chunk
/// stalls the writer thread and 64 one-byte frames overfill the queue; the total is about 64 KiB,
/// which the socket buffers take, so the client's socket writes never block.
fn flood_input(ctx: &mut impl std::io::Write, stream: Stream) {
    write_data(ctx, stream, &vec![b'x'; 64 * 1024]).unwrap();
    for _ in 0..64 {
        write_data(ctx, stream, b"x").unwrap();
    }
}

/// Drive one relayed command to its marker, pin the grandchild, then end the session the way
/// `ending` says and hand back the pinned handle.
///
/// `flood` sends [`flood_input`] and waits until the input pump reports it is parked before the
/// disconnect, so the session ends with the pump provably parked.
fn run_tree_session(tag: &str, mode: Mode, inherit_stdio: bool, ending: Ending, flood: bool) -> isize {
    let dir = hardened_dir(tag);
    let sock = dir.join("s");
    let pidfile = dir.join("grandchild.pid");
    let listener = Listener::bind(&sock).unwrap();
    // Created before the handshake, so the command can never reach its wait first.
    let go = GoEvent::create(tag);
    let tail = match ending {
        Ending::Disconnect => SLEEP_FOREVER.to_string(),
        Ending::NormalExit => wait_then_exit(&go.name),
    };
    let cmd = grandchild_cmd(&pidfile, &tail, inherit_stdio);

    let (tx_h, rx_h) = std::sync::mpsc::channel::<isize>();
    let client_path = sock.clone();
    let go_raw = go.raw;
    let parked = ParkSignal::default();
    let client_parked = parked.clone();
    let client = thread::spawn(move || {
        let conn = afunix::connect(&client_path).unwrap();
        let (mut crx, mut ctx) = afunix::split(conn).unwrap();
        let hs = Handshake {
            mode,
            command: Some(cmd),
            ..Handshake::pty_default()
        };
        write_frame(&mut ctx, FrameKind::Handshake, &hs.encode().unwrap()).unwrap();
        let mut fr = FrameReader::new();
        read_until_marker(&mut crx, &mut fr);
        tx_h.send(open_grandchild(&pidfile)).unwrap();
        match ending {
            Ending::Disconnect => {
                if flood {
                    flood_input(&mut ctx, if mode == Mode::Pty { Stream::Pty } else { Stream::Stdin });
                    client_parked.wait();
                }
                let _ = ctx.shutdown_both();
            }
            Ending::NormalExit => {
                set_event(go_raw); // the pin above is now provably ahead of any teardown
                let mut sink = TestSink::default();
                let outcome = pump_decode(&mut crx, &mut fr, &mut sink);
                // If the command failed to reach its wait at all (a mistyped event name would
                // do it), it exits early and silently restores the race this is here to remove.
                // Its exit code is what makes that loud instead.
                assert_eq!(
                    outcome.unwrap(),
                    Outcome::Exited(0),
                    "the relayed command should have blocked on the go event, then exited 0"
                );
            }
        }
    });

    let conn = listener.accept().unwrap();
    let hooks = Hooks {
        parked,
        ..Hooks::production()
    };
    super::handle_connection_with(conn, hooks).unwrap();
    client.join().expect("client thread");
    let raw = rx_h.recv().expect("client reported the grandchild handle");
    std::fs::remove_dir_all(&dir).ok();
    raw
}

/// Wait for a pinned process to exit. `INFINITE` on purpose: a regression hangs
/// deterministically rather than flaking, and a timeout would be a guess about how long a
/// kill "should" take.
fn assert_exits(raw: isize, who: &str) {
    use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
    use windows::Win32::System::Threading::{INFINITE, WaitForSingleObject};
    let rc = unsafe { WaitForSingleObject(HANDLE(raw as *mut core::ffi::c_void), INFINITE) };
    close_handle(raw); // before the assert, so a failure does not also leak the handle
    // Checking the result is the difference between a gate and a decoration: an unusable
    // handle makes the wait return WAIT_FAILED *immediately*, which an ignored return value
    // reports as a pass — every test here would go green while verifying nothing.
    assert_eq!(
        rc, WAIT_OBJECT_0,
        "waiting on {who} failed instead of observing it exit"
    );
}

/// Disconnect: the session is gone, so everything it spawned goes with it.
///
/// Regression gate for the teardown defect — terminating the direct child alone left
/// descendants running with no session left to reach them.
#[test]
fn exec_disconnect_kills_the_whole_process_tree() {
    let raw = run_tree_session("tree-exec-disc", Mode::Exec, false, Ending::Disconnect, false);
    assert_exits(raw, "the grandchild after an EXEC disconnect");
}

/// The same, for a grandchild left on the command's own console and standard handles.
///
/// This is the realistic shape (`start /b`, a daemon launched from a script) and the one where
/// getting teardown wrong hangs the session instead of merely leaking a process.
#[test]
fn exec_disconnect_reaps_a_descendant_holding_stdout() {
    let raw = run_tree_session("tree-exec-inherit", Mode::Exec, true, Ending::Disconnect, false);
    assert_exits(raw, "the stdout-holding grandchild after an EXEC disconnect");
}

/// The same case on the PTY path, where the grandchild is attached to the pseudoconsole
/// rather than to a plain stdout pipe.
#[test]
fn pty_disconnect_reaps_a_descendant_holding_the_pseudoconsole() {
    let raw = run_tree_session("tree-pty-inherit", Mode::Pty, true, Ending::Disconnect, false);
    assert_exits(raw, "the pty-holding grandchild after a PTY disconnect");
}

/// The PTY path reaps at its own teardown site, separately from EXEC.
#[test]
fn pty_disconnect_kills_the_whole_process_tree() {
    let raw = run_tree_session("tree-pty-disc", Mode::Pty, false, Ending::Disconnect, false);
    assert_exits(raw, "the grandchild after a PTY disconnect");
}

/// Normal exit reaps descendants too — Windows OpenSSH does, so we do.
///
/// Measured parity, not a guess — `agent::reap_tree` records what stock Windows OpenSSH does
/// and how it was established. A normal exit is not a special case here.
///
/// The grandchild here does NOT inherit stdout, so this is purely about the reap decision; the
/// inherited-pipe case is covered by `exec_disconnect_reaps_a_descendant_holding_stdout`.
#[test]
fn exec_normal_exit_reaps_descendants_like_windows_sshd() {
    let raw = run_tree_session("tree-exec-exit", Mode::Exec, false, Ending::NormalExit, false);
    assert_exits(raw, "the grandchild after a normal EXEC exit");
}

/// Same, at the PTY teardown site.
#[test]
fn pty_normal_exit_reaps_descendants_like_windows_sshd() {
    let raw = run_tree_session("tree-pty-exit", Mode::Pty, false, Ending::NormalExit, false);
    assert_exits(raw, "the grandchild after a normal PTY exit");
}

/// A disconnect is noticed when the command is silent and the input pump is parked (nothing reads
/// the socket, no output write fails). The pinned grandchild must die too, so the whole tree is
/// reaped.
#[test]
fn exec_disconnect_with_a_parked_input_pump_reaps_the_tree_of_a_silent_command() {
    let raw = run_tree_session("tree-exec-flood", Mode::Exec, false, Ending::Disconnect, true);
    assert_exits(
        raw,
        "the grandchild after an EXEC disconnect with the input pump parked",
    );
}

/// The same on the PTY path, which shares `HandleWriter`.
#[test]
fn pty_disconnect_with_a_parked_input_pump_reaps_the_tree_of_a_silent_command() {
    let raw = run_tree_session("tree-pty-flood", Mode::Pty, false, Ending::Disconnect, true);
    assert_exits(raw, "the grandchild after a PTY disconnect with the input pump parked");
}

/// An anonymous pipe `(read, write)`.
fn anonymous_pipe() -> (crate::winutil::OwnedHandle, crate::winutil::OwnedHandle) {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Pipes::CreatePipe;
    let (mut read, mut write) = (HANDLE::default(), HANDLE::default());
    unsafe { CreatePipe(&mut read, &mut write, None, 0) }.expect("create a pipe");
    (crate::winutil::OwnedHandle(read), crate::winutil::OwnedHandle(write))
}

/// A writer whose queue is full reports it: the signal is what lets a test know the input pump is
/// about to park in the send, without guessing how long that takes.
#[test]
fn handle_writer_reports_a_full_queue() {
    let (read, write) = anonymous_pipe();
    let parked = ParkSignal::default();
    let writer = HandleWriter::spawn(write.raw(), Some(write), parked.clone());
    // Nobody reads the pipe: the big chunk stalls the writer thread, then the queue fills and the
    // feeder parks in a send.
    let feeder = thread::spawn(move || {
        if writer.write(&vec![b'x'; 64 * 1024]).is_err() {
            return;
        }
        while writer.write(b"x").is_ok() {}
    });
    parked.wait();
    // Closing the read end fails the stalled write, which ends the writer thread and, with it,
    // the feeder's send.
    drop(read);
    feeder.join().unwrap();
}

/// The wait on a hangup watcher ends in an `Err` only when the poll itself failed. That says
/// nothing about the peer, so it must not reap the command; a hangup or a wake does.
#[test]
fn a_failed_hangup_wait_does_not_reap_and_a_finished_one_does() {
    let mut reaped = false;
    end_of_watch(Err(std::io::Error::other("the poll failed")), || reaped = true);
    assert!(!reaped, "a failed poll reaped the tree");
    end_of_watch(Ok(()), || reaped = true);
    assert!(reaped, "a finished wait did not reap the tree");
}

/// A connected session's server-side halves and its client socket, for building a watcher over.
fn session_halves(tag: &str) -> (afunix::ConnTx, afunix::ConnRx, socket2::Socket, std::path::PathBuf) {
    let dir = hardened_dir(tag);
    let sock = dir.join("s");
    let listener = Listener::bind(&sock).unwrap();
    let client = afunix::connect(&sock).unwrap();
    let conn = listener.accept().unwrap();
    let (rx, tx) = afunix::split(conn).unwrap();
    (tx, rx, client, dir)
}

/// Ending the hangup watch wakes the watcher and waits for its thread, so no thread outlives the
/// session while the peer is still connected.
#[test]
fn finishing_the_hangup_watch_wakes_and_joins_the_watcher_thread() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let (tx, _rx, client, dir) = session_halves("finish-joins");
    let (watcher, waker) = HangupWatcher::new(&tx).unwrap();
    let ended = std::sync::Arc::new(AtomicBool::new(false));
    let flag = std::sync::Arc::clone(&ended);
    let thread = thread::spawn(move || {
        watcher.wait().unwrap();
        flag.store(true, Ordering::Release);
    });
    HangupGuard { waker, thread }.finish();
    // `client` is still connected: only the wake can have ended the watcher before this point.
    assert!(
        ended.load(Ordering::Acquire),
        "finish returned before the watcher ended"
    );
    drop(client);
    std::fs::remove_dir_all(&dir).ok();
}

/// A wake that fails leaves the watcher possibly unable to end until the peer closes, so ending
/// the watch must not wait for it.
#[test]
fn finishing_the_hangup_watch_does_not_wait_when_the_wake_fails() {
    let (tx, _rx, client, dir) = session_halves("finish-detaches");
    let (watcher, waker) = HangupWatcher::new(&tx).unwrap();
    // With the watcher gone the wake channel's far end is closed, so wakes start failing once the
    // reset reaches us.
    drop(watcher);
    while waker.wake().is_ok() {}
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let thread = thread::spawn(move || {
        let _ = release_rx.recv();
    });
    // Returns although the thread is still blocked; a join here would never return.
    HangupGuard { waker, thread }.finish();
    release_tx.send(()).unwrap();
    drop(client);
    std::fs::remove_dir_all(&dir).ok();
}

/// The teardown warning fires exactly when the reap failed.
///
/// Split out as a pure function so the decision is testable at all: as an inline `if` around a
/// `tracing::error!` it had no observable behaviour, so a regression that silenced it — the
/// operator's only clue that the agent is about to block rather than wedge — would have failed
/// nothing.
#[test]
fn teardown_warns_only_when_the_reap_failed() {
    assert!(super::teardown_warning(true).is_none(), "a clean reap needs no warning");
    let w = super::teardown_warning(false).expect("a failed reap must warn");
    assert!(
        w.contains("block"),
        "the warning must say what is about to happen: {w:?}"
    );
}
