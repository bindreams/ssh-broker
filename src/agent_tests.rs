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

/// A disconnect must be noticed even when the input pump is stuck inside its own sink.
///
/// The regression this pins is one that reached review: the output pumps' reap was deleted as
/// "redundant", on the premise that the input pump is always parked in a socket read and would
/// see the same disconnect. It is not. `pump_decode` dispatches inline, and `ExecInputSink`
/// writes to the child's stdin with a blocking `WriteFile` on a default-sized pipe — so a
/// command that ignores its stdin fills that pipe within a few KiB and parks the input pump in
/// the sink, blind to the socket. The output pumps are then the only detector left.
///
/// The payload is far larger than the pipe buffer but well under `MAX_FRAME`, so the agent
/// reads the whole frame before dispatching it and the client never blocks writing it.
/// A regression hangs here rather than failing, which the runner surfaces.
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
        write_data(&mut ctx, Stream::Stdin, &vec![b'x'; 256 * 1024]).unwrap();
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
/// `window` selects how the grandchild is attached: `-NoNewWindow` keeps it on the parent's
/// console and standard handles, the default gives it a fresh console. Exactly which handles
/// each variant inherits was NOT verified here — .NET's `Process.Start` sets
/// `bInheritHandles` either way — so treat the pair as two attachment shapes that must both be
/// reaped, not as a claim about handle inheritance.
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

/// Drive one relayed command to its marker, pin the grandchild, then end the session the way
/// `ending` says and hand back the pinned handle.
fn run_tree_session(tag: &str, mode: Mode, inherit_stdio: bool, ending: Ending) -> isize {
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
    super::handle_connection(conn).unwrap();
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
    let raw = run_tree_session("tree-exec-disc", Mode::Exec, false, Ending::Disconnect);
    assert_exits(raw, "the grandchild after an EXEC disconnect");
}

/// The same, for a grandchild left on the command's own console and standard handles.
///
/// This is the realistic shape (`start /b`, a daemon launched from a script) and the one where
/// getting teardown wrong hangs the session instead of merely leaking a process.
#[test]
fn exec_disconnect_reaps_a_descendant_holding_stdout() {
    let raw = run_tree_session("tree-exec-inherit", Mode::Exec, true, Ending::Disconnect);
    assert_exits(raw, "the stdout-holding grandchild after an EXEC disconnect");
}

/// The same case on the PTY path, where the grandchild is attached to the pseudoconsole
/// rather than to a plain stdout pipe.
#[test]
fn pty_disconnect_reaps_a_descendant_holding_the_pseudoconsole() {
    let raw = run_tree_session("tree-pty-inherit", Mode::Pty, true, Ending::Disconnect);
    assert_exits(raw, "the pty-holding grandchild after a PTY disconnect");
}

/// The PTY path reaps at its own teardown site, separately from EXEC.
#[test]
fn pty_disconnect_kills_the_whole_process_tree() {
    let raw = run_tree_session("tree-pty-disc", Mode::Pty, false, Ending::Disconnect);
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
    let raw = run_tree_session("tree-exec-exit", Mode::Exec, false, Ending::NormalExit);
    assert_exits(raw, "the grandchild after a normal EXEC exit");
}

/// Same, at the PTY teardown site.
#[test]
fn pty_normal_exit_reaps_descendants_like_windows_sshd() {
    let raw = run_tree_session("tree-pty-exit", Mode::Pty, false, Ending::NormalExit);
    assert_exits(raw, "the grandchild after a normal PTY exit");
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
