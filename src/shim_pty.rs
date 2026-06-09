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
    Fallback, MouseModeSniffer, XtwinopsFilter, decide_fallback, make_handshake, map_outcome,
    run_exec_on, size_to_resize,
};
use crate::{afunix, conpty, vtinput};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Console::{
    CONSOLE_MODE, CONSOLE_SCREEN_BUFFER_INFO, DISABLE_NEWLINE_AUTO_RETURN, ENABLE_EXTENDED_FLAGS,
    ENABLE_MOUSE_INPUT, ENABLE_PROCESSED_OUTPUT, ENABLE_VIRTUAL_TERMINAL_PROCESSING,
    ENABLE_WINDOW_INPUT, GetConsoleMode, GetConsoleScreenBufferInfo, GetStdHandle, INPUT_RECORD,
    ReadConsoleInputW, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, SetConsoleCtrlHandler, SetConsoleMode,
    WriteConsoleInputW,
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
const RAW_IN: CONSOLE_MODE =
    CONSOLE_MODE(ENABLE_WINDOW_INPUT.0 | ENABLE_MOUSE_INPUT.0 | ENABLE_EXTENDED_FLAGS.0);
/// stdout bits OR-ed onto the inherited mode: render the agent's VT, and stop CR injection
/// on LF (the agent's stream already carries explicit CR/LF).
const VT_OUT: CONSOLE_MODE = CONSOLE_MODE(
    ENABLE_PROCESSED_OUTPUT.0 | ENABLE_VIRTUAL_TERMINAL_PROCESSING.0 | DISABLE_NEWLINE_AUTO_RETURN.0,
);

// ── run() wiring + fail-open ───────────────────────────────────────────────────────

/// Windows shim entrypoint. Connect to the agent; on a completed relay exit with the child's
/// code. On agent-unreachable, no-console, or ANY pre-spawn setup error, fail open to a local
/// shell — never let an error reach `main()` (which would exit 1 and print to the terminal,
/// corrupting an interactive PTY). The log guard is flushed before every `process::exit`,
/// since `process::exit` runs no destructors and the log is the only PTY-mode diagnostic.
pub fn run_on(exec: Option<String>) -> anyhow::Result<()> {
    let log = init_file_logging();
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
    drop(log); // flush before exec_local_shell's own process::exit
    exec_local_shell(exec)
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

/// Exec a local shell, inheriting the current stdio (behaviour == today's thin shell), and
/// exit with its code. The last resort when the agent is unreachable or there is no console.
fn exec_local_shell(exec: Option<String>) -> anyhow::Result<()> {
    let mut cmd = std::process::Command::new("pwsh");
    cmd.arg("-NoLogo");
    if let Some(c) = &exec {
        cmd.args(["-Command", c]);
    }
    let status = cmd.status()?;
    std::process::exit(status.code().unwrap_or(1));
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
        self.gate
            .forward
            .store(self.sniffer.forward_mouse(), Ordering::Relaxed);
        let filtered = self.filter.filter(bytes);
        anyhow::ensure!(
            conpty::write_all_handle(self.out, &filtered),
            "failed to write relayed output to the console"
        );
        Ok(())
    }
    // on_resize: no-op — RESIZE flows shim→agent only.
}

/// Shared mouse-mode gate: MAIN (the output sink) publishes whether the brokered shell wants
/// SGR mouse events; the input worker reads it. A single scalar, so an atomic (not a mutex)
/// suffices and there is no compound invariant to tear.
#[derive(Default)]
struct MouseGate {
    forward: AtomicBool,
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
                _ => {} // FOCUS / MENU: ignored in v1 (the wake record lands here)
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

/// Saves and restores the stdin/stdout console modes (and the Ctrl handler). `is_console` is
/// false when stdin/stdout are not consoles (redirected pipes) — then nothing is changed and
/// Drop is a no-op, and the caller fails open (a non-console can't drive `ReadConsoleInputW`).
struct ConsoleModes {
    stdin: HANDLE,
    stdout: HANDLE,
    in_orig: CONSOLE_MODE,
    out_orig: CONSOLE_MODE,
    is_console: bool,
}

impl ConsoleModes {
    fn enter() -> windows::core::Result<ConsoleModes> {
        unsafe {
            let stdin = GetStdHandle(STD_INPUT_HANDLE)?;
            let stdout = GetStdHandle(STD_OUTPUT_HANDLE)?;
            let mut in_orig = CONSOLE_MODE(0);
            let mut out_orig = CONSOLE_MODE(0);
            let is_console = GetConsoleMode(stdin, &mut in_orig).is_ok()
                && GetConsoleMode(stdout, &mut out_orig).is_ok();
            if is_console {
                SetConsoleMode(stdin, RAW_IN)?;
                SetConsoleMode(stdout, CONSOLE_MODE(out_orig.0 | VT_OUT.0))?;
                // Suppress Ctrl events as signals to the shim (insurance; the primary path is
                // the cleared ENABLE_PROCESSED_INPUT delivering Ctrl-C as a KEY record).
                let _ = SetConsoleCtrlHandler(None, true);
            }
            Ok(ConsoleModes { stdin, stdout, in_orig, out_orig, is_console })
        }
    }
}

impl Drop for ConsoleModes {
    fn drop(&mut self) {
        if self.is_console {
            unsafe {
                let _ = SetConsoleMode(self.stdin, self.in_orig);
                let _ = SetConsoleMode(self.stdout, self.out_orig);
                let _ = SetConsoleCtrlHandler(None, false);
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
    let _ = tracing_subscriber::fmt()
        .with_writer(nb)
        .with_ansi(false)
        .try_init();
    Some(guard)
}

fn log_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(r"C:\ProgramData\ssh-broker\logs")
}
