//! shim_pty: the Windows interactive PTY path of the shim + the `run()` wiring.
//!
//! Windows-only: it drives the real ssh-shellhost console. `run_on` connects to the agent,
//! decides fail-open, and dispatches; `run_pty` puts the console into raw VT mode (RAII
//! restore), spawns ONE `ReadConsoleInputW` worker that re-encodes keys/mouse/resize toward
//! the agent, and pumps the agent's filtered output to stdout on the main thread.
//!
//! Teardown model (mirrors `agent::handle_pty`'s discipline, inverted): MAIN owns `rx`, the
//! `ConsoleModes` RAII guard, and the worker's `JoinHandle`; it runs `pump_decode` (the
//! deterministic completion signal) and coordinates teardown. The worker owns `tx` (the sole
//! frame producer post-handshake) and runs the un-cancellable `ReadConsoleInputW` loop. On
//! EXIT, MAIN sets a `stopping` flag, wakes the parked read by injecting a benign console
//! record (`WriteConsoleInputW` — reliable for console reads where `CancelSynchronousIo` is
//! not), JOINS the worker, then the guard restores modes AFTER the join — so the worker can
//! never read with a half-restored mode (the use-after-close hazard the agent review found).

use crate::protocol::{FrameKind, FrameReader, Handshake, Stream, write_frame};
use crate::relay::{FrameSink, pump_decode, write_data};
use crate::shim::{
    FailOpen, Fallback, MouseModeSniffer, XtwinopsFilter, decide_fail_open, decide_fallback, make_handshake,
    map_outcome, run_exec_on, size_to_resize,
};
use crate::{afunix, conpty, vtinput};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Console::{
    CONSOLE_MODE, CONSOLE_SCREEN_BUFFER_INFO, DISABLE_NEWLINE_AUTO_RETURN, ENABLE_EXTENDED_FLAGS, ENABLE_MOUSE_INPUT,
    ENABLE_PROCESSED_OUTPUT, ENABLE_VIRTUAL_TERMINAL_PROCESSING, ENABLE_WINDOW_INPUT, GetConsoleMode,
    GetConsoleScreenBufferInfo, GetStdHandle, INPUT_RECORD, ReadConsoleInputW, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    SetConsoleCtrlHandler, SetConsoleMode, WriteConsoleInputW,
};

// INPUT_RECORD.EventType values (processthreadsapi/consoleapi). windows-rs 0.62 does not
// export them as usable typed consts, so name them with their documented `u16` values.
const EVT_KEY: u16 = 0x0001;
const EVT_MOUSE: u16 = 0x0002;
const EVT_WINDOW_BUFFER_SIZE: u16 = 0x0004;
const EVT_FOCUS: u16 = 0x0010;

/// stdin raw-input mode: window + mouse events as records, extended flags (disables
/// quick-edit). The absolute store implicitly clears PROCESSED/LINE/ECHO input, so Ctrl-C
/// arrives as a KEY record (uc=0x03) rather than a signal. VT-input is intentionally omitted
/// — we read raw `INPUT_RECORD`s and re-encode them ourselves.
const RAW_IN: CONSOLE_MODE = CONSOLE_MODE(ENABLE_WINDOW_INPUT.0 | ENABLE_MOUSE_INPUT.0 | ENABLE_EXTENDED_FLAGS.0);
/// stdout bits OR-ed onto the inherited mode: render the agent's VT, and stop CR injection
/// on LF (the agent's stream already carries explicit CR/LF).
const VT_OUT: CONSOLE_MODE =
    CONSOLE_MODE(ENABLE_PROCESSED_OUTPUT.0 | ENABLE_VIRTUAL_TERMINAL_PROCESSING.0 | DISABLE_NEWLINE_AUTO_RETURN.0);

// ── run() wiring + fail-open ───────────────────────────────────────────────────────

/// Windows shim entrypoint. Connect to the agent; on a completed relay exit with the child's
/// code. On agent-unreachable, no-console, or ANY pre-spawn setup error, fail open to a local
/// shell — never let an error reach `main()` (which would exit 1 and print to the terminal,
/// corrupting an interactive PTY). The log guard is flushed before every `process::exit`,
/// since `process::exit` runs no destructors and the log is the only PTY-mode diagnostic.
pub fn run_on(exec: Option<String>) -> anyhow::Result<()> {
    let log = init_file_logging();

    // EVERY command relays. There is deliberately no local route for file transfers.
    //
    // Routing them locally required deciding, from a string the CLIENT chose, whether a command
    // was a transfer — and that decision is not reliably derivable: sshd rewrites commands before
    // `DefaultShell` sees them, and its config serialisation differs from Windows' own quoting.
    // The justification for routing was that relaying would corrupt a binary stream; that turned
    // out to be untrue — `exec_relay_is_byte_clean_*` covers the framing in both directions, and
    // `verify`'s probe covers a real child, real pipes and a real socket in both directions too.
    // What remains is a throughput difference, which does not earn a classifier.
    match try_relay(&exec) {
        Ok(Some(code)) => {
            drop(log); // flush the appender before process::exit
            // Bypass main()'s Result→0/1 collapse; the i32→u32 cast is bit-preserving.
            std::process::exit(code)
        }
        Ok(None) => {} // fail-open reason (unreachable / no console) already logged
        Err(e) => {
            // A pre-spawn setup failure: the agent ran nothing, so re-running locally is
            // safe and far better than dying with an error to the user's terminal.
            tracing::warn!("shim relay setup failed: {e:?}; falling back to a local shell");
        }
    }
    // Fail open. An EXEC command runs through the contained passthrough, NOT a shell: `pwsh
    // -Command` reinterprets quoting, and an `sftp` session on a box with no interactive session
    // to relay into lands exactly here — a shell would mangle its binary stream. That also matches
    // the relay path, itself a bare `CreateProcessW`, so fail-open and relay no longer disagree
    // about whether a command gets shell semantics. An interactive session carries no command, so
    // it gets a plain `pwsh` instead — but through the SAME contained passthrough, not a separate
    // uncontained spawn: see `run_local_passthrough` for why that used to be a real containment
    // gap, not just an inaccurate claim in prose. `decide_fail_open` is where the exec/interactive
    // choice is made and tested, and `fail_open_command` maps it to the single spawn below — ONE
    // call site, so neither arm can regain shell semantics or lose containment on its own.
    //
    // The log guard deliberately stays ALIVE until each exit. Dropping it here (as this once did)
    // shuts the `tracing-appender` worker down, and its lossy writer then silently discards every
    // later line — so the `tracing::error!` below, the only PTY-mode diagnostic for a failed
    // fallback, went nowhere at all.
    let decision = decide_fail_open(exec);
    let command = fail_open_command(&decision);
    match run_local_passthrough(command) {
        Ok(code) => {
            drop(log); // flush: `process::exit` runs no destructors
            // Bypass main()'s Result→0/1 collapse; the i32→u32 cast is bit-preserving.
            std::process::exit(code)
        }
        Err(e) => {
            // A spawn failure must NOT escape to `main()`: that exits 1, the one code this crate
            // forbids for a broker-side failure because it is indistinguishable from the command
            // itself failing (`shim::map_outcome`). The relay reports the identical failure as
            // 255, so this does too — the `Err` is never propagated out of this function.
            tracing::error!("fail-open spawn of {command:?} failed: {e:?}");
            // EXEC has a clean stderr channel; in PTY mode a stderr write would corrupt the
            // terminal stream, so there the reason goes only to the log (README's "Limits").
            if matches!(decision, FailOpen::Passthrough(_)) {
                eprintln!("ssh-broker: could not run the command locally: {e}");
            }
            drop(log); // flush before exiting
            std::process::exit(255)
        }
    }
}

/// The command each fail-open outcome runs. Pure, so the interactive arm's program is pinned by a
/// test rather than by reading `run_on`: an interactive session has nothing of its own to run, so
/// it gets `pwsh`, while an EXEC command is passed through untouched.
fn fail_open_command(decision: &FailOpen) -> &str {
    match decision {
        FailOpen::Passthrough(cmd) => cmd.as_str(),
        FailOpen::LocalShell => "pwsh -NoLogo",
    }
}

/// Attempt the relay. `Ok(Some(code))` = a relay completed (PTY or EXEC). `Ok(None)` = the
/// shim should fail open (agent unreachable, or no interactive console). Any `Err` is a
/// pre-spawn setup failure (connect/split/handshake/console) — the agent spawned nothing, so
/// the caller can safely fail open without a double-execution or an orphaned shell.
fn try_relay(exec: &Option<String>) -> anyhow::Result<Option<i32>> {
    let path = afunix::socket_path();
    let conn = afunix::connect(&path);
    if decide_fallback(conn.is_err()) == Fallback::LocalShellWithWarning {
        let msg = "ssh-broker: agent unavailable — falling back to a local shell";
        tracing::warn!("{msg} (path={path:?}, err={:?})", conn.as_ref().err());
        // EXEC has a clean stderr channel; in PTY mode a stderr write would corrupt the
        // terminal stream, so there the warning goes only to the log file.
        if exec.is_some() {
            eprintln!("{msg}");
        }
        return Ok(None);
    }
    let (rx, tx) = afunix::split(conn?)?;

    match exec {
        Some(cmd) => {
            let hs = make_handshake(&Some(cmd.clone()), term(), 80, 24); // EXEC ignores cols/rows
            Ok(Some(run_exec_on(
                rx,
                tx,
                &hs,
                std::io::stdout(),
                std::io::stderr(),
                std::io::stdin(),
            )?))
        }
        None => {
            // Interactive: a real console is required to capture input. No handshake has been
            // sent yet, so a missing console fails open without orphaning an agent shell.
            let modes = ConsoleModes::enter()?;
            if !modes.is_console {
                drop(modes); // restore is a no-op when !is_console
                tracing::warn!("no interactive console (redirected stdio) — local shell");
                return Ok(None);
            }
            let (cols, rows) = console_size(modes.stdout);
            let hs = make_handshake(&None, term(), cols, rows);
            Ok(Some(run_pty(modes, rx, FrameReader::new(), tx, &hs)?))
        }
    }
}

/// `$TERM` from the SSH environment, defaulting to a sane 256-colour terminal.
fn term() -> String {
    std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".into())
}

/// Run `command` locally (in the session sshd launched us in), inheriting our stdio directly, and
/// return its exit code.
///
/// It deliberately RETURNS the code rather than calling `process::exit` itself. Exiting here forced
/// the caller to drop the log guard before this ran, which shut the appender down and silently
/// discarded every diagnostic logged afterwards — including the one explaining a failed fallback.
/// Returning leaves the caller owning both the exit and the flush that must precede it.
///
/// This is the fail-open path for BOTH shim modes — the agent was unreachable, so the command
/// runs here rather than not at all. For EXEC (`ssh host "cmd"`) `command` is the command itself;
/// for an interactive session it is a literal `pwsh -NoLogo`, since that session carries nothing
/// else to run (see the `FailOpen::LocalShell` arm in `run_on`). Either way it deliberately does
/// not go through an EXTRA shell: `pwsh -Command <cmd>` would reinterpret quoting and mangle a
/// binary stream, which is what an `sftp` session landing on the EXEC arm would be. The child
/// writes raw to sshd's pipes, exactly as the original DefaultShell did.
///
/// **Deliberate behaviour change** (do not "simplify" this back): the EXEC arm used to run
/// `exec_local_shell(Some(cmd))`, i.e. `pwsh -Command <cmd>`, so `ssh host "a | b"` piped and
/// `ssh host "cd x && y"` chained even during an agent outage. That shell hop is gone on purpose:
/// EXEC fail-open now matches the relay path's own bare `CreateProcessW` exactly, so during an
/// outage those shell operators stop working — they become the client's business, same as they
/// already are on the working (relayed) path, rather than an outage-only convenience the relay
/// never offered.
///
/// The interactive arm changed too, and for a correctness reason rather than a behavioural one:
/// it used to run through a plain, uncontained `std::process::Command` (`exec_local_shell`),
/// so its children did NOT die with the session — contradicting the README. Routing it through
/// this same contained spawn closes that gap; see `spawn_contained`.
fn run_local_passthrough(command: &str) -> anyhow::Result<i32> {
    use windows::Win32::Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation};
    use windows::Win32::System::Console::STD_ERROR_HANDLE;
    use windows::Win32::System::Threading::{GetExitCodeProcess, INFINITE, WaitForSingleObject};
    unsafe {
        let stdin = GetStdHandle(STD_INPUT_HANDLE)?;
        let stdout = GetStdHandle(STD_OUTPUT_HANDLE)?;
        let stderr = GetStdHandle(STD_ERROR_HANDLE)?;
        // STARTF_USESTDHANDLES only passes handles the child can inherit; make sure they are.
        for h in [stdin, stdout, stderr] {
            let _ = SetHandleInformation(h, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT);
        }
        // `_job` must outlive the wait: `cosca::Job` sets KILL_ON_JOB_CLOSE, so dropping it early
        // would terminate the very child we are waiting on.
        let (process, _job) = spawn_contained(command, Some([stdin, stdout, stderr]))?;
        WaitForSingleObject(process.0, INFINITE);
        let mut code = 0u32;
        if GetExitCodeProcess(process.0, &mut code).is_err() {
            // A failed query must not read as SUCCESS. `code` is still 0 here, so returning it
            // would be indistinguishable from the command having succeeded — the exact confusion
            // `shim::map_outcome` exists to prevent. Reporting it as an error routes it to the
            // caller's 255, this crate's "the broker failed" code, which is what the relay reports
            // for the same class of failure. Erroring rather than exiting here is also what lets
            // the caller LOG it: exiting inside this function is why that diagnostic was lost.
            anyhow::bail!("GetExitCodeProcess failed for the fail-open child");
        }
        Ok(code as i32)
    }
}

/// Spawn `command` suspended and contain it in a job object before it runs a single instruction.
///
/// This exists as its own function so the containment is *testable* in isolation. `run_on` still
/// ends in `process::exit` (so nothing in-process can observe its wiring — that is gated end to
/// end by `tests/fail_open_windows.rs`), but the spawn itself can be asserted against here.
///
/// Containment is the point. A child spawned here must die with the session exactly as a relayed
/// one does (`pipes.rs`, `conpty.rs` both contain theirs) — otherwise reaching the fail-open path
/// would be a way to leave a process running after disconnect, and the README promises the
/// opposite. `CREATE_SUSPENDED` is load-bearing: assignment has to win the race against the child
/// spawning anything, or a descendant is born outside the job. `contain_and_resume` kills rather
/// than resumes if assignment fails, so a failure here never yields an uncontained process.
///
/// The caller MUST keep the returned `Job` alive for as long as the child should live.
///
/// # Safety
/// Any handles named in `stdio` must be valid and inheritable.
unsafe fn spawn_contained(
    command: &str,
    stdio: Option<[windows::Win32::Foundation::HANDLE; 3]>,
) -> anyhow::Result<(crate::winutil::OwnedHandle, cosca::Job)> {
    use anyhow::Context;
    use windows::Win32::System::Threading::{
        CREATE_SUSPENDED, CreateProcessW, PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW,
    };
    use windows::core::PWSTR;

    let mut si = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    if let Some([i, o, e]) = stdio {
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = i;
        si.hStdOutput = o;
        si.hStdError = e;
    }
    let mut cmd: Vec<u16> = command.encode_utf16().chain(std::iter::once(0)).collect();
    let mut pi = PROCESS_INFORMATION::default();
    unsafe {
        CreateProcessW(
            None,
            Some(PWSTR(cmd.as_mut_ptr())),
            None,
            None,
            stdio.is_some(), // inherit → the child gets sshd's stdio directly (binary-clean)
            CREATE_SUSPENDED,
            None,
            None,
            &si,
            &mut pi,
        )
        .with_context(|| format!("spawn the fail-open local command: {command}"))?;
        let process = crate::winutil::OwnedHandle(pi.hProcess);
        let thread = crate::winutil::OwnedHandle(pi.hThread);
        let job = crate::winutil::contain_and_resume(process.0, thread.0, "shim fail-open")?;
        Ok((process, job))
    }
}

// ── PTY relay ──────────────────────────────────────────────────────────────────────

/// Relay an interactive PTY session. Owns `modes` so the console is restored (the guard's
/// Drop) BEFORE this returns — `run_on` then `process::exit`s, which would skip Drop, so the
/// restore must happen here on the normal return path.
fn run_pty(
    modes: ConsoleModes,
    mut rx: afunix::ConnRx,
    mut fr: FrameReader,
    mut tx: afunix::ConnTx,
    hs: &Handshake,
) -> anyhow::Result<i32> {
    let stdin_raw = modes.stdin.0 as isize;
    let stdout_raw = modes.stdout.0 as isize;

    // Handshake first (MAIN owns tx until the worker spawn consumes it), so the agent has
    // spawned + sized the shell before the first keystroke/resize frame arrives.
    write_frame(&mut tx, FrameKind::Handshake, &hs.encode()?)?;

    let gate = Arc::new(MouseGate::default());
    let stopping = Arc::new(AtomicBool::new(false));

    let worker = {
        let gate = Arc::clone(&gate);
        let stopping = Arc::clone(&stopping);
        std::thread::spawn(move || input_worker(stdin_raw, stdout_raw, tx, gate, stopping))
    };

    // MAIN: pump agent output → sniff/filter → console stdout. Capture the result WITHOUT `?`
    // so teardown always runs (mirrors agent.rs's deferred wait_result handling).
    let mut sink = StdoutSink {
        out: stdout_raw,
        filter: XtwinopsFilter::new(),
        sniffer: MouseModeSniffer::new(),
        gate,
    };
    let outcome = pump_decode(&mut rx, &mut fr, &mut sink);

    // Ordered teardown: stop, wake the parked ReadConsoleInputW, join. Console modes are
    // restored by `modes` dropping at scope end — AFTER the join, so the worker is provably
    // done before the restore.
    stopping.store(true, Ordering::Relaxed);
    wake_console_input(stdin_raw);
    let _ = worker.join();

    let code = map_outcome(outcome);
    drop(modes); // explicit: restore console modes before we return into run_on's process::exit
    Ok(code)
}

/// Routes the agent's output to the real console: observe mouse-mode changes (publishing the
/// gate), strip XTWINOPS, then write the raw VT bytes straight to the console handle (the
/// proven short-write loop, not buffered Rust stdout).
struct StdoutSink {
    out: isize,
    filter: XtwinopsFilter,
    sniffer: MouseModeSniffer,
    gate: Arc<MouseGate>,
}

impl FrameSink for StdoutSink {
    fn on_data(&mut self, _stream: Stream, bytes: &[u8]) -> anyhow::Result<()> {
        self.sniffer.observe(bytes);
        // The AND (tracking && SGR) is computed here on the single writer, so the worker
        // reads one self-consistent flag rather than two it would have to combine.
        self.gate.forward.store(self.sniffer.forward_mouse(), Ordering::Relaxed);
        self.gate.focus.store(self.sniffer.focus_on(), Ordering::Relaxed);
        let filtered = self.filter.filter(bytes);
        anyhow::ensure!(
            conpty::write_all_handle(self.out, &filtered),
            "failed to write relayed output to the console"
        );
        Ok(())
    }
    // on_resize: no-op — RESIZE flows shim→agent only.
}

/// Shared input gate: MAIN (the output sink) publishes whether the brokered shell wants SGR
/// mouse events (`forward`) and focus in/out reports (`focus`); the input worker reads them.
/// Each is an independent scalar, so atomics (not a mutex) suffice with no compound invariant
/// to tear.
#[derive(Default)]
struct MouseGate {
    forward: AtomicBool,
    focus: AtomicBool,
}

/// The single input thread: owns `tx`, reads `ReadConsoleInputW`, re-encodes keys/mouse and
/// re-queries the window size on resize. On any exit it FINs the socket so the agent (and the
/// MAIN pump) observe the disconnect.
fn input_worker(
    stdin_raw: isize,
    stdout_raw: isize,
    mut tx: afunix::ConnTx,
    gate: Arc<MouseGate>,
    stopping: Arc<AtomicBool>,
) {
    unsafe { input_loop(stdin_raw, stdout_raw, &mut tx, &gate, &stopping) };
    // FIN: in the disconnect-first case this makes the agent kill the brokered shell and
    // unblocks MAIN's pump; in the EXIT case it is harmless (the agent already closed).
    let _ = tx.shutdown_both();
}

/// # Safety
/// `stdin_raw`/`stdout_raw` must be the live console handles set up by `ConsoleModes::enter`,
/// valid for the duration of the call (guaranteed: MAIN joins this thread before the guard
/// drops).
unsafe fn input_loop(
    stdin_raw: isize,
    stdout_raw: isize,
    tx: &mut afunix::ConnTx,
    gate: &MouseGate,
    stopping: &AtomicBool,
) {
    let stdin = HANDLE(stdin_raw as *mut core::ffi::c_void);
    let stdout = HANDLE(stdout_raw as *mut core::ffi::c_void);
    let mut enc = vtinput::MouseEncoder::default();
    let mut recs: [INPUT_RECORD; 64] = unsafe { std::mem::zeroed() };
    loop {
        if stopping.load(Ordering::Relaxed) {
            return;
        }
        let mut n = 0u32;
        if unsafe { ReadConsoleInputW(stdin, &mut recs, &mut n) }.is_err() {
            return; // console input closed (SSH side gone)
        }
        // The wake record (or a real one) returns the read; re-check before processing so the
        // teardown signal is honored without forwarding the synthetic record.
        if stopping.load(Ordering::Relaxed) {
            return;
        }
        for rec in &recs[..n as usize] {
            match rec.EventType {
                EVT_KEY => {
                    let k = unsafe { rec.Event.KeyEvent };
                    let ke = vtinput::KeyEvent {
                        virtual_key_code: k.wVirtualKeyCode,
                        virtual_scan_code: k.wVirtualScanCode,
                        unicode_char: unsafe { k.uChar.UnicodeChar },
                        key_down: k.bKeyDown.as_bool(),
                        control_key_state: k.dwControlKeyState,
                        repeat_count: k.wRepeatCount,
                    };
                    if write_data(tx, Stream::Pty, &vtinput::encode_key_event(&ke)).is_err() {
                        return;
                    }
                }
                EVT_WINDOW_BUFFER_SIZE => {
                    // The record carries only the scrollback buffer size; the agent needs the
                    // visible window, so re-query it.
                    let (cols, rows) = console_size(stdout);
                    let r = size_to_resize(cols, rows);
                    if write_frame(tx, FrameKind::Resize, &r.encode()).is_err() {
                        return;
                    }
                }
                EVT_MOUSE => {
                    let m = unsafe { rec.Event.MouseEvent };
                    let mev = vtinput::MouseEvent {
                        x: m.dwMousePosition.X,
                        y: m.dwMousePosition.Y,
                        button_state: m.dwButtonState,
                        control_key_state: m.dwControlKeyState,
                        event_flags: m.dwEventFlags,
                    };
                    if gate.forward.load(Ordering::Relaxed) {
                        let sgr = enc.encode_sgr(&mev);
                        if !sgr.is_empty() && write_data(tx, Stream::Pty, &sgr).is_err() {
                            return;
                        }
                    } else {
                        // Forwarding off: keep the encoder's view clean so a later enable
                        // starts fresh (no unmatched release for a button held across the
                        // enable boundary).
                        enc.reset();
                    }
                }
                // Forward focus in/out as `CSI I`/`CSI O`, but ONLY when the shell enabled
                // ?1004 — else focus-naive programs would see stray `ESC[I`/`ESC[O`. A focus
                // record arriving while the gate is closed falls through to the `_` arm. The
                // teardown wake record (also a FOCUS) never reaches here: the worker returns
                // on the post-read `stopping` re-check above, before this loop.
                EVT_FOCUS if gate.focus.load(Ordering::Relaxed) => {
                    let focused = unsafe { rec.Event.FocusEvent }.bSetFocus.as_bool();
                    let seq: &[u8] = if focused { b"\x1b[I" } else { b"\x1b[O" };
                    if write_data(tx, Stream::Pty, seq).is_err() {
                        return;
                    }
                }
                _ => {} // MENU: ignored (internal)
            }
        }
    }
}

/// Wake a parked `ReadConsoleInputW` by injecting one benign FOCUS record. The worker, having
/// observed `stopping`, returns without forwarding it. More reliable for console reads than
/// `CancelSynchronousIo` (which may not cancel a parked console wait).
fn wake_console_input(stdin_raw: isize) {
    unsafe {
        let stdin = HANDLE(stdin_raw as *mut core::ffi::c_void);
        let mut rec: INPUT_RECORD = std::mem::zeroed();
        rec.EventType = EVT_FOCUS;
        let mut written = 0u32;
        let _ = WriteConsoleInputW(stdin, std::slice::from_ref(&rec), &mut written);
    }
}

/// Current visible window size (cols, rows) from the console, or an 80×24 default if the
/// query fails (e.g. a redirected handle).
fn console_size(stdout: HANDLE) -> (u16, u16) {
    unsafe {
        let mut sbi = CONSOLE_SCREEN_BUFFER_INFO::default();
        if GetConsoleScreenBufferInfo(stdout, &mut sbi).is_ok() {
            let w = sbi.srWindow;
            vtinput::win_size(w.Left, w.Top, w.Right, w.Bottom)
        } else {
            (80, 24)
        }
    }
}

// ── console raw-mode RAII ──────────────────────────────────────────────────────────

/// The Win32 calls `ConsoleModes` drives to apply/restore raw mode, behind a trait so the
/// guard's rollback-on-partial-failure behavior is host-testable without a real console via a
/// fake that fails the SECOND `set_mode` call (`src/shim_pty_tests.rs`). `Win32ConsoleOps` is
/// the real implementation the `ConsoleModes` alias below is backed by at runtime.
trait ConsoleOps {
    fn set_mode(&self, handle: HANDLE, mode: CONSOLE_MODE) -> windows::core::Result<()>;
    fn set_ctrl_suppressed(&self, suppress: bool) -> windows::core::Result<()>;
}

struct Win32ConsoleOps;

impl ConsoleOps for Win32ConsoleOps {
    fn set_mode(&self, handle: HANDLE, mode: CONSOLE_MODE) -> windows::core::Result<()> {
        unsafe { SetConsoleMode(handle, mode) }
    }

    fn set_ctrl_suppressed(&self, suppress: bool) -> windows::core::Result<()> {
        unsafe { SetConsoleCtrlHandler(None, suppress) }
    }
}

/// Saves and restores the stdin/stdout console modes (and the Ctrl handler). `is_console` is
/// false when stdin/stdout are not consoles (redirected pipes) — then nothing is changed and
/// Drop is a no-op, and the caller fails open (a non-console can't drive `ReadConsoleInputW`).
///
/// Generic over `ConsoleOps` purely for testability; real callers use the `ConsoleModes` alias
/// below, which is always `Win32ConsoleOps`-backed.
struct ConsoleModesState<Ops: ConsoleOps> {
    ops: Ops,
    stdin: HANDLE,
    stdout: HANDLE,
    in_orig: CONSOLE_MODE,
    out_orig: CONSOLE_MODE,
    is_console: bool,
    // Whether `set_ctrl_suppressed(true)` actually SUCCEEDED. Unlike the two `SetConsoleMode`
    // restores below (writing back a captured value is a harmless no-op even on a path where
    // that particular handle's mode was never actually changed), `SetConsoleCtrlHandler` is an
    // ABSOLUTE state change inherited by child processes, not a value restore — unconditionally
    // clearing it on Drop, on a path where the corresponding suppress call never ran (or
    // failed), would clear an attribute this guard never set (e.g. one the process inherited
    // from sshd). Gating the restore on this flag keeps Drop symmetric with what actually changed.
    ctrl_suppressed: bool,
}

type ConsoleModes = ConsoleModesState<Win32ConsoleOps>;

impl<Ops: ConsoleOps> ConsoleModesState<Ops> {
    /// Applies raw mode via `ops`, constructing the guard NOW, holding the ORIGINAL modes,
    /// before either is changed below. `modes` is then a local variable in scope for the rest of
    /// this function, so if the stdout `set_mode` fails via `?` after the stdin one already
    /// succeeded, Rust drops every local on that early return — running `modes`'s `Drop` and
    /// restoring stdin's mode before this function returns the error.
    fn enter_with(
        ops: Ops,
        stdin: HANDLE,
        stdout: HANDLE,
        in_orig: CONSOLE_MODE,
        out_orig: CONSOLE_MODE,
        is_console: bool,
    ) -> windows::core::Result<Self> {
        let mut modes = ConsoleModesState {
            ops,
            stdin,
            stdout,
            in_orig,
            out_orig,
            is_console,
            ctrl_suppressed: false,
        };
        if is_console {
            modes.ops.set_mode(stdin, RAW_IN)?;
            modes.ops.set_mode(stdout, CONSOLE_MODE(out_orig.0 | VT_OUT.0))?;
            // Suppress Ctrl events as signals to the shim (insurance; the primary path is the
            // cleared ENABLE_PROCESSED_INPUT delivering Ctrl-C as a KEY record). Best-effort:
            // failure here does not fail `enter_with`, it just leaves `ctrl_suppressed` false so
            // Drop does not try to undo a change that never happened — but it must not be silent,
            // for the same reason the Drop-side restores below are logged.
            modes.ctrl_suppressed = match modes.ops.set_ctrl_suppressed(true) {
                Ok(()) => true,
                Err(e) => {
                    tracing::error!("failed to suppress the console Ctrl handler: {e:?}");
                    false
                }
            };
        }
        Ok(modes)
    }
}

impl ConsoleModesState<Win32ConsoleOps> {
    fn enter() -> windows::core::Result<ConsoleModes> {
        unsafe {
            let stdin = GetStdHandle(STD_INPUT_HANDLE)?;
            let stdout = GetStdHandle(STD_OUTPUT_HANDLE)?;
            let mut in_orig = CONSOLE_MODE(0);
            let mut out_orig = CONSOLE_MODE(0);
            let is_console =
                GetConsoleMode(stdin, &mut in_orig).is_ok() && GetConsoleMode(stdout, &mut out_orig).is_ok();
            Self::enter_with(Win32ConsoleOps, stdin, stdout, in_orig, out_orig, is_console)
        }
    }
}

impl<Ops: ConsoleOps> Drop for ConsoleModesState<Ops> {
    fn drop(&mut self) {
        if self.is_console {
            // Restoring a captured value is a harmless no-op even if that particular call never
            // actually changed anything, so these two stay unconditional. A failure here can
            // leave the session in a corrupted terminal state (raw mode, no echo/line input)
            // with nothing left to do about it from this function — but it must not be silent,
            // or that corruption has zero diagnostic trail in the log.
            if let Err(e) = self.ops.set_mode(self.stdin, self.in_orig) {
                tracing::error!("failed to restore stdin console mode: {e:?}");
            }
            if let Err(e) = self.ops.set_mode(self.stdout, self.out_orig) {
                tracing::error!("failed to restore stdout console mode: {e:?}");
            }
            if self.ctrl_suppressed
                && let Err(e) = self.ops.set_ctrl_suppressed(false)
            {
                tracing::error!("failed to restore the console Ctrl handler: {e:?}");
            }
        }
    }
}

// ── logging ────────────────────────────────────────────────────────────────────────

/// Initialise a rolling file log under ProgramData. Best-effort: returns `None` (logging
/// disabled) on any failure so the shim still works. NEVER logs to stdout/stderr in PTY mode.
fn init_file_logging() -> Option<tracing_appender::non_blocking::WorkerGuard> {
    let dir = log_dir();
    std::fs::create_dir_all(&dir).ok()?;
    let appender = tracing_appender::rolling::daily(&dir, "shim.log");
    let (nb, guard) = tracing_appender::non_blocking(appender);
    let _ = tracing_subscriber::fmt().with_writer(nb).with_ansi(false).try_init();
    Some(guard)
}

fn log_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(r"C:\ProgramData\ssh-broker\logs")
}

#[cfg(test)]
#[path = "shim_pty_tests.rs"]
mod shim_pty_tests;
