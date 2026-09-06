//! shim: the SSH `DefaultShell` (default action). Relays the terminal/streams to
//! the agent over AF_UNIX; fails open to a local shell if the agent is unreachable.

use crate::protocol::{FrameKind, FrameReader, Handshake, Mode, Resize, Stream, write_frame};
use crate::relay::{FrameSink, Outcome, pump_decode, write_data};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

/// Shim entrypoint. `exec` is `Some(command)` for the `-c "cmd"` EXEC path, `None`
/// for an interactive PTY session. The Windows path connects to the agent and relays;
/// elsewhere there is no session-1 console to relay.
pub fn run(exec: Option<String>) -> anyhow::Result<()> {
    #[cfg(windows)]
    return crate::shim_pty::run_on(exec);

    #[cfg(not(windows))]
    {
        let _ = exec;
        anyhow::bail!("the shim relays the session-1 console and runs only on Windows")
    }
}

// ── EXEC relay ───────────────────────────────────────────────────────────────────────

/// Relay an EXEC session over an already-connected, split transport: send the handshake,
/// forward `stdin` as `DATA(Stdin)` frames, and write the agent's `Stdout`/`Stderr` (kept
/// separate) to `out`/`err`, returning the child's exit code.
///
/// The write half (`tx`) is held by this function until AFTER the `EXIT` frame arrives, so
/// it is not closed mid-run. That matters because of the EXEC convention (see
/// `protocol::Stream`): the agent treats a full socket close as a *disconnect* and kills the
/// child, whereas stdin-EOF is signalled by an empty `DATA(Stdin)` marker. Closing `tx` at
/// stdin EOF would therefore kill a child that is still producing output.
pub fn run_exec_on<R, W, O, E, I>(mut rx: R, tx: W, hs: &Handshake, out: O, err: E, stdin: I) -> anyhow::Result<i32>
where
    R: Read,
    W: Write + Send + 'static,
    O: Write,
    E: Write,
    I: Read + Send + 'static,
{
    let tx = Arc::new(Mutex::new(tx));
    // Handshake first, so the agent spawns the child before any stdin/output flows.
    {
        let mut g = tx.lock().unwrap();
        write_frame(&mut *g, FrameKind::Handshake, &hs.encode()?)?;
    }
    // Detached stdin forwarder: it holds its own `tx` clone, but it is THIS scope's `tx`
    // (dropped only after EXIT, below) that keeps the write half open past stdin EOF. A
    // blocking stdin read cannot be portably cancelled, so the thread is not joined; the
    // shim process exit reaps it.
    {
        let tx = Arc::clone(&tx);
        std::thread::spawn(move || forward_stdin(stdin, tx));
    }

    let mut sink = ExecOutSink { out, err };
    let mut fr = FrameReader::new();
    let outcome = pump_decode(&mut rx, &mut fr, &mut sink);
    // `tx` drops at the end of this scope — after the relay finished, never at stdin EOF.
    // Route the outcome through the shared exit-code policy so a dead agent (PeerClosed) is
    // 255 and a protocol error is 254 — never the in-band exit 1 that would be
    // indistinguishable from a real command's failure (e.g. `findstr`/`grep` no-match).
    Ok(map_outcome(outcome))
}

/// Forward `stdin` to `DATA(Stdin)` frames; on EOF (or a read error, treated as EOF) send
/// the empty-`Stdin` EOF marker so a reader like `sort`/`findstr` finishes — WITHOUT closing
/// the connection. Best-effort: a write failure means the peer is gone, so just stop.
fn forward_stdin<I: Read, W: Write>(mut stdin: I, tx: Arc<Mutex<W>>) {
    let mut buf = [0u8; 32 * 1024];
    loop {
        match stdin.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let mut g = tx.lock().unwrap();
                if write_data(&mut *g, Stream::Stdin, &buf[..n]).is_err() {
                    return;
                }
            }
        }
    }
    let mut g = tx.lock().unwrap();
    let _ = write_data(&mut *g, Stream::Stdin, b""); // stdin-EOF marker
}

/// Routes the agent's decoded output streams to the EXEC writers, keeping stderr separate.
struct ExecOutSink<O: Write, E: Write> {
    out: O,
    err: E,
}

impl<O: Write, E: Write> FrameSink for ExecOutSink<O, E> {
    fn on_data(&mut self, stream: Stream, bytes: &[u8]) -> anyhow::Result<()> {
        // Flush after each frame: `std::io::stdout()` is a LineWriter, so newline-less or binary
        // output (e.g. a streaming command, or a relayed sftp protocol) would otherwise sit in
        // the buffer until a newline or process exit — hanging the client.
        match stream {
            Stream::Stderr => {
                self.err.write_all(bytes)?;
                self.err.flush()?;
            }
            _ => {
                self.out.write_all(bytes)?; // Stdout (Pty/Stdin not expected in EXEC)
                self.out.flush()?;
            }
        }
        Ok(())
    }
}

/// Whether an EXEC command is an sftp/scp FILE TRANSFER that the shim should run locally rather
/// than relay to the agent. File transfer needs raw binary stdio and gains nothing from session-1
/// parity, so relaying its long-lived binary protocol is pure downside (latency + a buffering
/// failure surface). Detected by the subsystem helper (`sftp-server`/`internal-sftp`) or the
/// rcp protocol's internal `-t`/`-f` flags — markers a human would never type, so no real
/// session-1 command is misrouted.
pub fn is_transfer_command(cmd: &str) -> bool {
    let tokens = split_command(cmd);
    let Some(prog) = tokens.first() else {
        return false;
    };
    match program_basename(prog).as_str() {
        "sftp-server" | "internal-sftp" => true,
        // The rcp protocol always emits `scp <opts> -t <path>` / `-f <path>` with the flag
        // immediately before the single trailing path operand (never combined like `-rt`).
        // Require that position so a legitimate `scp … -t …`-to-a-third-host is not misrouted.
        "scp" => tokens.len() >= 2 && matches!(tokens[tokens.len() - 2].as_str(), "-t" | "-f"),
        _ => false,
    }
}

/// Split a command line into tokens, respecting double quotes (so a program path containing
/// spaces stays one token). Quote characters are stripped. Good enough for the transfer-detection
/// heuristic; not a full Win32 `CommandLineToArgvW` (no backslash-escaping of quotes).
fn split_command(cmd: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut has_token = false;
    for ch in cmd.chars() {
        match ch {
            '"' => {
                has_token = {
                    in_quotes = !in_quotes;
                    true
                }
            }
            c if c.is_whitespace() && !in_quotes => {
                if has_token {
                    tokens.push(std::mem::take(&mut cur));
                    has_token = false;
                }
            }
            c => {
                cur.push(c);
                has_token = true;
            }
        }
    }
    if has_token {
        tokens.push(cur);
    }
    tokens
}

/// The program's lowercase basename without a `.exe` suffix (path separators stripped).
fn program_basename(prog: &str) -> String {
    let base = prog.rsplit(['\\', '/']).next().unwrap_or(prog).to_ascii_lowercase();
    base.strip_suffix(".exe").unwrap_or(&base).to_string()
}

// ── PTY relay helpers (pure; the live console path is Windows-only, Phase 8) ───────────

/// Map a console size to a `RESIZE` frame — the seam between the Windows
/// `WINDOW_BUFFER_SIZE_EVENT` watcher and the wire, isolated so it is testable off-Windows.
pub fn size_to_resize(cols: u16, rows: u16) -> Resize {
    Resize { cols, rows }
}

/// Strips XTWINOPS window-manipulation sequences (`CSI <params> t`) from a VT byte stream.
/// The agent's ConPTY emits these (e.g. resize reports); relayed verbatim to a real client
/// terminal they trigger spurious window queries/prompts (iTerm2 prompts on every resize).
/// Stateful so a sequence split across reads is handled; every other byte — including all
/// non-`t` CSI sequences (colours, cursor moves) and non-CSI escapes (OSC/DCS) — passes
/// through byte-for-byte.
#[derive(Default)]
pub struct XtwinopsFilter {
    state: FilterState,
    /// Bytes of an in-progress `ESC [ … ` sequence whose final byte is not yet seen.
    pending: Vec<u8>,
}

#[derive(Default, PartialEq)]
enum FilterState {
    #[default]
    Normal,
    Esc, // saw ESC, awaiting '['
    Csi, // inside `ESC [ …`, accumulating until the final byte
}

impl XtwinopsFilter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter one chunk, returning the bytes to forward downstream.
    pub fn filter(&mut self, input: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(input.len());
        for &b in input {
            match self.state {
                FilterState::Normal => self.begin(b, &mut out),
                FilterState::Esc => {
                    if b == b'[' {
                        self.state = FilterState::Csi;
                        self.pending.push(b);
                    } else {
                        // Not a CSI: release the held ESC, then reconsider this byte fresh.
                        out.extend_from_slice(&self.pending);
                        self.pending.clear();
                        self.state = FilterState::Normal;
                        self.begin(b, &mut out);
                    }
                }
                FilterState::Csi => match b {
                    0x20..=0x3F => self.pending.push(b), // parameter / intermediate bytes
                    0x40..=0x7E => {
                        // Final byte: the sequence is complete. Drop it iff it is XTWINOPS.
                        self.pending.push(b);
                        if b != b't' {
                            out.extend_from_slice(&self.pending);
                        }
                        self.pending.clear();
                        self.state = FilterState::Normal;
                    }
                    _ => {
                        // A byte outside the CSI grammar aborts it: emit what we held, then
                        // reconsider this byte (it may itself start a new escape).
                        out.extend_from_slice(&self.pending);
                        self.pending.clear();
                        self.state = FilterState::Normal;
                        self.begin(b, &mut out);
                    }
                },
            }
        }
        out
    }

    /// Process a byte from the `Normal` state: an ESC starts buffering, anything else passes.
    fn begin(&mut self, b: u8, out: &mut Vec<u8>) {
        if b == 0x1B {
            self.state = FilterState::Esc;
            self.pending.push(b);
        } else {
            out.push(b);
        }
    }
}

// ── mode selection + fail-open ─────────────────────────────────────────────────────

/// What the shim should do once it has tried to reach the agent.
#[derive(Debug, PartialEq, Eq)]
pub enum Fallback {
    /// The agent answered — relay this session to it.
    Relay,
    /// The agent is unreachable — run a local shell so the box is never locked out, and
    /// warn (to a log in PTY mode, to stderr in EXEC) that parity is unavailable.
    LocalShellWithWarning,
}

/// Decide the shim's action from whether connecting to the agent failed. Isolated as a pure
/// function so the fail-open policy is unit-tested without a live socket.
pub fn decide_fallback(connect_err: bool) -> Fallback {
    if connect_err {
        Fallback::LocalShellWithWarning
    } else {
        Fallback::Relay
    }
}

/// Map the relay outcome to the shim's process exit code. A clean exit propagates the child's
/// code verbatim (the later `i32`→`u32` at `process::exit` is bit-preserving, so an NTSTATUS
/// like `0xC0000142` survives); a peer that closed with no EXIT frame, or a protocol error,
/// map to distinct nonzero codes — never 0, so a dead agent can't masquerade as success.
pub fn map_outcome(outcome: Result<Outcome, crate::relay::PumpError>) -> i32 {
    match outcome {
        Ok(Outcome::Exited(code)) => code,
        Ok(Outcome::PeerClosed) => {
            tracing::error!("agent closed the connection before sending an exit code");
            255
        }
        Err(e) => {
            tracing::error!("relay error: {e:?}");
            254
        }
    }
}

/// Build the handshake from the shim's inputs (pure; the Windows caller supplies `term` from
/// `$TERM` and `cols`/`rows` from the live console). EXEC mode iff a command is present; `cwd`
/// and `env` are empty in v1 — the agent supplies the session-1 working dir and profile env.
pub fn make_handshake(exec: &Option<String>, term: String, cols: u16, rows: u16) -> Handshake {
    Handshake {
        mode: if exec.is_some() { Mode::Exec } else { Mode::Pty },
        cols,
        rows,
        term,
        cwd: String::new(),
        command: exec.clone(),
        env: Vec::new(),
        ..Handshake::pty_default()
    }
}

// ── mouse-mode sniffer (pure; gates mouse forwarding) ──────────────────────────────

/// Observes the agent→client output stream for the shell enabling/disabling mouse tracking
/// and focus reporting, so the input side forwards those events ONLY when the shell wants them
/// (an ungated stream injects `ESC[<…M` / `ESC[I`/`ESC[O` bytes into naive programs).
/// Recognizes the DEC private modes `CSI ? <params> h|l`: tracking 1000/1002/1003, SGR encoding
/// 1006, and focus reporting 1004. Stateful, so a sequence split across reads is handled.
/// Observe-only — it never alters the bytes (the client terminal still receives and honors the
/// same sequences via `XtwinopsFilter`).
#[derive(Default)]
pub struct MouseModeSniffer {
    state: SniffState,
    private: bool,
    params: Vec<u32>,
    cur: u32,
    cur_has_digits: bool,
    tracking: u8, // bitset: 1000 → bit0, 1002 → bit1, 1003 → bit2
    sgr: bool,    // mode 1006 (SGR extended coordinates)
    focus: bool,  // mode 1004 (focus in/out reporting)
}

#[derive(Default, PartialEq)]
enum SniffState {
    #[default]
    Normal,
    Esc,
    Csi,
}

impl MouseModeSniffer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed a chunk of output bytes (does not modify or consume them).
    pub fn observe(&mut self, bytes: &[u8]) {
        for &b in bytes {
            match self.state {
                SniffState::Normal => {
                    if b == 0x1B {
                        self.state = SniffState::Esc;
                    }
                }
                SniffState::Esc => {
                    if b == b'[' {
                        self.reset_csi_accum();
                        self.state = SniffState::Csi;
                    } else if b != 0x1B {
                        self.state = SniffState::Normal;
                    }
                }
                SniffState::Csi => self.csi_byte(b),
            }
        }
    }

    fn csi_byte(&mut self, b: u8) {
        match b {
            b'?' => self.private = true,
            b'0'..=b'9' => {
                self.cur = self.cur.saturating_mul(10).saturating_add(u32::from(b - b'0'));
                self.cur_has_digits = true;
            }
            b';' => {
                self.params.push(self.cur);
                self.cur = 0;
                self.cur_has_digits = false;
            }
            0x40..=0x7E => {
                // Final byte. Apply only DEC-private set/reset (`?` … h|l).
                if self.cur_has_digits {
                    self.params.push(self.cur);
                }
                if self.private && (b == b'h' || b == b'l') {
                    let set = b == b'h';
                    for p in std::mem::take(&mut self.params) {
                        self.apply_mode(p, set);
                    }
                }
                self.end_csi();
            }
            0x20..=0x2F => {} // intermediate bytes: ignore
            _ => {
                // A control byte (or stray ESC) aborts the malformed sequence.
                self.end_csi();
                if b == 0x1B {
                    self.state = SniffState::Esc;
                }
            }
        }
    }

    fn apply_mode(&mut self, mode: u32, set: bool) {
        let bit = match mode {
            1000 => Some(0u8),
            1002 => Some(1),
            1003 => Some(2),
            1006 => {
                self.sgr = set;
                return;
            }
            1004 => {
                self.focus = set;
                return;
            }
            _ => None, // 1005/1015 etc. recognized-but-unsupported → leave SGR off (gate stays closed)
        };
        if let Some(bit) = bit {
            if set {
                self.tracking |= 1 << bit;
            } else {
                self.tracking &= !(1 << bit);
            }
        }
    }

    fn reset_csi_accum(&mut self) {
        self.private = false;
        self.params.clear();
        self.cur = 0;
        self.cur_has_digits = false;
    }

    fn end_csi(&mut self) {
        self.reset_csi_accum();
        self.state = SniffState::Normal;
    }

    /// Any of the tracking modes (1000/1002/1003) is enabled.
    pub fn tracking_on(&self) -> bool {
        self.tracking != 0
    }
    /// SGR extended coordinate mode (1006) is enabled.
    pub fn sgr_on(&self) -> bool {
        self.sgr
    }
    /// Focus-reporting mode (1004) is enabled — gate focus `CSI I`/`CSI O` events on this.
    pub fn focus_on(&self) -> bool {
        self.focus
    }
    /// Forward mouse events only when the shell enabled tracking AND SGR encoding — the only
    /// encoding `MouseEncoder` emits; sending SGR to a shell that asked for legacy X10 would
    /// corrupt it just as badly as unsolicited events.
    pub fn forward_mouse(&self) -> bool {
        self.tracking != 0 && self.sgr
    }
}

#[cfg(test)]
#[path = "shim_tests.rs"]
mod shim_tests;
