//! Windows-only integration tests for the agent (run on a real Windows host via the cross-compile
//! -> scp -> run loop). They drive `handle_connection` over a real AF_UNIX socket.
use crate::afunix::{self, Listener};
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
        let hs = Handshake {
            mode: Mode::Exec,
            command: Some(
                "pwsh.exe -NoLogo -NoProfile -Command \"Start-Sleep -Seconds 99999\"".into(),
            ),
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

#[test]
fn single_instance_blocks_a_second_acquire() {
    let first = super::SingleInstance::acquire().unwrap();
    assert!(
        super::SingleInstance::acquire().is_err(),
        "a second acquire must fail while the first guard is held"
    );
    drop(first);
    // Once released, the name is free again.
    let _again = super::SingleInstance::acquire().unwrap();
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
