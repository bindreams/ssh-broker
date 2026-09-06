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
        // A sentinel the child holds until teardown kills it — not a wait for anything.
        let never_exits = r#"pwsh.exe -NoLogo -NoProfile -Command "Start-Sleep -Seconds 99999""#; // sleep-ok: sentinel the test kills
        let hs = Handshake {
            mode: Mode::Exec,
            command: Some(never_exits.into()),
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

// ── process-tree teardown ────────────────────────────────────────────────────────────────

/// A command that never returns on its own, so teardown is what ends it.
const SLEEP_FOREVER: &str = "Start-Sleep -Seconds 99999"; // sleep-ok: a sentinel the tests reap

/// A command that launches a background grandchild, records its pid, then announces itself.
///
/// The ordering is what makes the tests deterministic rather than timed: the pid file is
/// complete *before* the marker is printed, so a client that has read the marker can always
/// read a valid pid and the grandchild is guaranteed to exist.
///
/// `window` selects whether the grandchild inherits this process's stdio. `-NoNewWindow`
/// inherits (the case that actually matters, and the one a naive test misses); the default
/// opens a new console and inherits nothing.
fn grandchild_cmd(pidfile: &std::path::Path, tail: &str, inherit_stdio: bool) -> String {
    let window = if inherit_stdio { "-NoNewWindow " } else { "" };
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

/// Drive one relayed command to its marker, hand back the pinned grandchild handle, then run
/// `finish` (disconnect, or wait for a normal exit).
fn run_tree_session(tag: &str, mode: Mode, tail: &str, inherit_stdio: bool, disconnect: bool) -> isize {
    let dir = hardened_dir(tag);
    let sock = dir.join("s");
    let pidfile = dir.join("grandchild.pid");
    let listener = Listener::bind(&sock).unwrap();
    let cmd = grandchild_cmd(&pidfile, tail, inherit_stdio);

    let (tx_h, rx_h) = std::sync::mpsc::channel::<isize>();
    let client_path = sock.clone();
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
        if disconnect {
            let _ = ctx.shutdown_both();
        } else {
            // Let the session end because the command finished, not because we left.
            let mut sink = TestSink::default();
            let _ = pump_decode(&mut crx, &mut fr, &mut sink);
        }
    });

    let conn = listener.accept().unwrap();
    super::handle_connection(conn).unwrap();
    let _ = client.join();
    let raw = rx_h.recv().expect("client reported the grandchild handle");
    std::fs::remove_dir_all(&dir).ok();
    raw
}

/// Wait for a pinned process to exit. `INFINITE` on purpose: a regression hangs
/// deterministically rather than flaking, and a timeout would be a guess about how long a
/// kill "should" take.
fn assert_exits(raw: isize, who: &str) {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Threading::{INFINITE, WaitForSingleObject};
    let _ = who;
    unsafe { WaitForSingleObject(HANDLE(raw as *mut core::ffi::c_void), INFINITE) };
    close_handle(raw);
}

/// Disconnect: the session is gone, so everything it spawned goes with it.
///
/// Regression gate for the teardown defect — terminating the direct child alone left
/// descendants running with no session left to reach them.
#[test]
fn exec_disconnect_kills_the_whole_process_tree() {
    let raw = run_tree_session("tree-exec-disc", Mode::Exec, SLEEP_FOREVER, false, true);
    assert_exits(raw, "the grandchild after an EXEC disconnect");
}

/// The same, for a grandchild that **inherits the command's stdout**.
///
/// This is the case a `Start-Process` default misses: a new console inherits no handles, so a
/// test built on it proves only the easy half. Here the descendant holds the pipe the output
/// pump reads, which is both the realistic shape (`start /b`, a daemon launched from a script)
/// and the one where getting teardown wrong hangs the session instead of merely leaking.
#[test]
fn exec_disconnect_reaps_a_descendant_holding_stdout() {
    let raw = run_tree_session("tree-exec-inherit", Mode::Exec, SLEEP_FOREVER, true, true);
    assert_exits(raw, "the stdout-holding grandchild after an EXEC disconnect");
}

/// The PTY path has its own teardown and its own decision point.
#[test]
fn pty_disconnect_kills_the_whole_process_tree() {
    let raw = run_tree_session("tree-pty-disc", Mode::Pty, SLEEP_FOREVER, false, true);
    assert_exits(raw, "the grandchild after a PTY disconnect");
}

/// Normal exit: the command finished on its own, so its descendants are left alone.
///
/// This is the contract that keeps `ssh host "start-a-daemon"` working, and it is not free —
/// both teardown paths shut the socket down to unblock the input pump, and because `split`
/// hands out duplicates of one socket that EOF is indistinguishable from a peer disconnect.
/// The pump resolves it by asking whether the child already exited.
///
/// **Deliberately uses a non-inheriting grandchild.** With `-NoNewWindow` the descendant would
/// hold the command's stdout, the output pump would never see EOF, and the session would not
/// end at all — which is what sshd does too, and is therefore accepted behaviour rather than a
/// bug this test should assert around. Covering it here would hang, not fail.
#[test]
fn exec_normal_exit_leaves_descendants_running() {
    use windows::Win32::Foundation::{HANDLE, WAIT_TIMEOUT};
    use windows::Win32::System::Threading::{TerminateProcess, WaitForSingleObject};

    let raw = run_tree_session("tree-exec-exit", Mode::Exec, "exit 0", false, false);
    let h = HANDLE(raw as *mut core::ffi::c_void);
    // sleep-ok: zero timeout is a state query — WAIT_TIMEOUT means "still running"
    let alive = unsafe { WaitForSingleObject(h, 0) } == WAIT_TIMEOUT; // sleep-ok: state query, not a wait
    unsafe {
        let _ = TerminateProcess(h, 1); // do not leak it into the rest of the run
    }
    close_handle(raw);
    assert!(alive, "a normally-exited command must not take its descendants with it");
}
