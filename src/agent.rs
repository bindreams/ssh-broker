//! agent: resident in session 1 (started by the auto-login logon task). Per AF_UNIX
//! connection it hosts the shell — in a ConPTY for interactive (PTY) sessions, or with
//! redirected pipes for EXEC (`ssh host "cmd"`) — inheriting the session-1 token (working
//! DPAPI/profile + no RedirectionGuard) and relays it to the SSH-side shim.

/// `agent` subcommand entrypoint. Windows-only: the agent must run in the interactive
/// session-1 console to confer RDP parity.
pub fn run() -> anyhow::Result<()> {
    #[cfg(windows)]
    return run_on(&crate::afunix::socket_path());

    #[cfg(not(windows))]
    return Err(anyhow::anyhow!(
        "the agent runs only on Windows (it hosts the shell in the session-1 console)"
    ));
}

#[cfg(windows)]
use crate::afunix::{self, ConnRx, ConnTx, Listener};
#[cfg(windows)]
use crate::conpty::{self, PtySession};
#[cfg(windows)]
use crate::pipes::ExecChild;
#[cfg(windows)]
use crate::protocol::{ExitCode, FrameKind, FrameReader, Handshake, Mode, Resize, Stream, read_one_frame, write_frame};
#[cfg(windows)]
use crate::relay::{FrameSink, pump_until_peer_gone, write_data};
#[cfg(windows)]
use crate::winutil::OwnedHandle;
#[cfg(windows)]
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::sync::{Arc, Mutex};

/// Bind the hardened socket and serve connections, one handler thread each. Single-instance
/// is enforced by a named mutex acquired before binding.
#[cfg(windows)]
fn run_on(path: &Path) -> anyhow::Result<()> {
    let _instance = SingleInstance::acquire()?;
    let listener = Listener::bind(path)?;
    loop {
        let conn = listener.accept()?;
        std::thread::spawn(move || {
            if let Err(e) = handle_connection(conn) {
                tracing::warn!("connection handler error: {e:?}");
            }
        });
    }
}

/// Default shell when the handshake carries no command (config-driven shell is Phase 7).
#[cfg(windows)]
fn default_shell() -> String {
    "pwsh.exe -NoLogo".to_string()
}

/// The session-1 user's home directory (`%USERPROFILE%`), if it exists. The agent runs AS that
/// user, so its own environment carries the correct profile path.
#[cfg(windows)]
fn home_dir() -> Option<PathBuf> {
    let p = PathBuf::from(std::env::var_os("USERPROFILE")?);
    p.is_dir().then_some(p)
}

/// The working directory to start the child in: the handshake's explicit `cwd` if any, else the
/// user's home directory. This mirrors what a normal SSH login does — sshd's `do_child()` runs
/// `chdir(pw->pw_dir)` to the user's home before exec'ing the shell — so `ssh host` lands you in
/// your home, not wherever the agent task happened to start (`C:\Windows\System32`).
pub fn child_cwd(handshake_cwd: &str, home: Option<std::path::PathBuf>) -> Option<std::path::PathBuf> {
    if handshake_cwd.is_empty() {
        home
    } else {
        Some(std::path::PathBuf::from(handshake_cwd))
    }
}

/// Read the handshake, then dispatch to the PTY or EXEC relay.
#[cfg(windows)]
fn handle_connection(conn: socket2::Socket) -> anyhow::Result<()> {
    let (mut rx, tx) = afunix::split(conn)?;
    let mut fr = FrameReader::new();
    let frame = read_one_frame(&mut rx, &mut fr)?;
    anyhow::ensure!(frame.kind == FrameKind::Handshake, "first frame was not a handshake");
    let hs = Handshake::decode(&frame.payload)?;
    let command = hs.command.clone().unwrap_or_else(default_shell);
    let cwd_buf = child_cwd(&hs.cwd, home_dir());
    let cwd = cwd_buf.as_deref();
    match hs.mode {
        Mode::Pty => handle_pty(rx, fr, tx, &command, hs.cols, hs.rows, cwd),
        Mode::Exec => handle_exec(rx, fr, tx, &command, cwd),
    }
}

#[cfg(test)]
#[path = "agent_cwd_tests.rs"]
mod agent_cwd_tests;

// ── PTY relay ────────────────────────────────────────────────────────────────────────

/// Interactive PTY relay: spawn the shell in a ConPTY and bridge it with three threads and
/// an ordered, race-free teardown (criterion 2).
#[cfg(windows)]
fn handle_pty(
    mut rx: ConnRx,
    mut fr: FrameReader,
    tx: ConnTx,
    command: &str,
    cols: u16,
    rows: u16,
    cwd: Option<&Path>,
) -> anyhow::Result<()> {
    let mut session = PtySession::spawn(command, cols, rows, cwd)?;

    let out_raw = session.out_read_raw();
    let in_raw = session.in_write_raw();
    // HPCON shared behind a mutex: the input thread resizes under the lock; teardown takes
    // it (→ None) and closes it under the lock, so resize can never touch a closed HPCON.
    let hpc_cell = Arc::new(Mutex::new(Some(session.take_hpc_raw())));
    let tx_arc = Arc::new(Mutex::new(tx));
    let job = session.job();

    // Output pump: ConPTY output -> DATA(Pty). It deliberately does NOT emit EXIT.
    // `read_handle` returns 0 for a read *error* as well as for EOF, so this thread cannot
    // tell "the shell finished" from "the pipe broke" — emitting the code from here raced the
    // waiter that produces it, and a failed session could report EXIT(0).
    let out_thread = {
        let tx = Arc::clone(&tx_arc);
        let job = Arc::clone(&job);
        std::thread::spawn(move || {
            let mut buf = [0u8; 32 * 1024];
            loop {
                let n = conpty::read_handle(out_raw, &mut buf);
                if n == 0 {
                    break; // pseudoconsole closed (teardown) -> drained to EOF
                }
                let ok = {
                    let mut g = tx.lock().unwrap();
                    write_data(&mut *g, Stream::Pty, &buf[..n]).is_ok()
                };
                if !ok {
                    reap_tree(&job); // the socket is gone; see `spawn_stream_pump`
                    break;
                }
            }
        })
    };

    let in_thread = {
        let hpc_cell = Arc::clone(&hpc_cell);
        let job = Arc::clone(&job);
        std::thread::spawn(move || {
            let mut sink = PtyInputSink {
                writer: HandleWriter::spawn(in_raw, None),
                hpc_cell,
            };
            pump_until_peer_gone(&mut rx, &mut fr, &mut sink);
            // Reap before dropping the sink: dropping joins the writer thread, which may be
            // parked in a write that only a dead shell releases.
            reap_tree(&job);
            drop(sink);
        })
    };

    // Waiter + ordered teardown. Do NOT `?` on wait(): even if it errors we must still tear
    // down (close the HPCON, join the threads) before returning, or the threads would
    // outlive `session` and touch closed handles, and the (forgotten) HPCON would leak.
    let wait_result = session.wait();
    if let Some(w) = teardown_warning(reap_tree(&job)) {
        tracing::error!("{w}");
    }
    let code = *wait_result.as_ref().unwrap_or(&1);
    {
        // Close the pseudoconsole while HOLDING the lock, so a concurrent resize cannot
        // copy the raw HPCON out and then race this close (use-after-close).
        let mut hpc = hpc_cell.lock().unwrap();
        if let Some(raw) = hpc.take() {
            conpty::close_pty_raw(raw); // → output pipe EOF → out_thread drains, emits EXIT, FINs
        }
    }
    let _ = out_thread.join();
    {
        // The shell is gone and the output is drained, so the code is final and nothing else
        // can still be writing frames.
        let mut g = tx_arc.lock().unwrap();
        let _ = write_frame(&mut *g, FrameKind::Exit, &ExitCode(code).encode());
        let _ = g.shutdown_both(); // FIN + unblock the input pump's read
    }
    let _ = in_thread.join();
    // Threads joined; `session` now drops and closes the process/thread + pipe handles.
    wait_result?;
    Ok(())
}

/// Routes decoded input frames into the pseudoconsole.
#[cfg(windows)]
struct PtyInputSink {
    writer: HandleWriter,
    hpc_cell: Arc<Mutex<Option<isize>>>,
}

#[cfg(windows)]
impl FrameSink for PtyInputSink {
    fn on_data(&mut self, _stream: Stream, bytes: &[u8]) -> anyhow::Result<()> {
        // PTY input arrives pre-encoded (win32-input-mode); hand it straight to ConPTY#2.
        self.writer.write(bytes)
    }
    fn on_resize(&mut self, r: Resize) -> anyhow::Result<()> {
        // Hold the lock across the OS call (bound guard, not a temporary) so teardown
        // cannot close the HPCON mid-resize.
        let hpc = self.hpc_cell.lock().unwrap();
        if let Some(raw) = *hpc {
            let _ = conpty::resize_pty(raw, r.cols, r.rows);
        }
        Ok(())
    }
}

// ── EXEC relay ───────────────────────────────────────────────────────────────────────

/// Non-interactive EXEC relay (`ssh host "cmd"`): spawn the child with redirected pipes,
/// relay stdout/stderr as SEPARATE streams, feed stdin, and propagate the exit code.
#[cfg(windows)]
fn handle_exec(
    mut rx: ConnRx,
    mut fr: FrameReader,
    tx: ConnTx,
    command: &str,
    cwd: Option<&Path>,
) -> anyhow::Result<()> {
    let mut child = ExecChild::spawn(command, cwd)?;
    let out_raw = child.stdout_read_raw();
    let err_raw = child.stderr_read_raw();
    let stdin_owned = child.take_stdin_write();
    let stdin_raw = stdin_owned.as_ref().map_or(0, |h| h.raw());
    // stdout, stderr, and the EXIT frame all share tx → serialize with a mutex.
    let tx_arc = Arc::new(Mutex::new(tx));
    let job = child.job();

    let t_out = spawn_stream_pump(out_raw, Stream::Stdout, Arc::clone(&tx_arc), Arc::clone(&job));
    let t_err = spawn_stream_pump(err_raw, Stream::Stderr, Arc::clone(&tx_arc), Arc::clone(&job));

    // stdin pump owns the child's stdin-write handle. A half-close mid-session (empty
    // DATA(Stdin) marker) closes only the child's stdin so a reader like sort/findstr
    // finishes; a FULL socket close means the SSH side is gone, so after the pump returns we
    // kill the child unconditionally. Without this, a silent, stdin-ignoring command that
    // sleeps indefinitely would never exit, and the output pumps — blocked in read with
    // nothing to write — would never detect the dead socket, hanging the waiter.
    let t_in = {
        let job = Arc::clone(&job);
        std::thread::spawn(move || {
            let mut sink = ExecInputSink {
                writer: HandleWriter::spawn(stdin_raw, stdin_owned),
            };
            pump_until_peer_gone(&mut rx, &mut fr, &mut sink);
            // Reap before dropping the sink: dropping joins the writer thread, which may be
            // parked in a write that only a dead child releases. The drop then closes the
            // child's stdin if the EOF marker never arrived.
            reap_tree(&job);
            drop(sink);
        })
    };

    let wait_result = child.wait();
    // The command is gone, so the session is over. Reaping now takes its descendants with it
    // and closes the pipes, which is what lets the output pumps below be joined at all.
    if let Some(w) = teardown_warning(reap_tree(&job)) {
        tracing::error!("{w}");
    }
    let code = *wait_result.as_ref().unwrap_or(&1);
    let _ = t_out.join();
    let _ = t_err.join();
    {
        let mut g = tx_arc.lock().unwrap();
        let _ = write_frame(&mut *g, FrameKind::Exit, &ExitCode(code).encode());
        let _ = g.shutdown_both(); // FIN + unblock the stdin pump's read
    }
    let _ = t_in.join();
    wait_result?;
    Ok(())
}

/// Pump one child output stream (stdout/stderr) into `DATA(stream)` frames on the shared
/// connection. On EOF the child is exiting; on a write failure the SSH side is gone, so
/// kill the child to unblock the waiter.
#[cfg(windows)]
fn spawn_stream_pump(
    raw: isize,
    stream: Stream,
    tx: Arc<Mutex<ConnTx>>,
    job: std::sync::Arc<cosca::Job>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut buf = [0u8; 32 * 1024];
        loop {
            let n = conpty::read_handle(raw, &mut buf);
            if n == 0 {
                break; // child's stream closed (exiting)
            }
            let ok = {
                let mut g = tx.lock().unwrap();
                write_data(&mut *g, stream, &buf[..n]).is_ok()
            };
            if !ok {
                // The socket is gone. Reaping here is NOT redundant with the input pump: that
                // pump dispatches inline, and `ExecInputSink` writes to the child's stdin with
                // a blocking `WriteFile` on a default-sized pipe. A command that ignores its
                // stdin fills that pipe in a few KiB and parks the input pump *in the sink*,
                // where it can no longer see the socket at all. These pumps are then the only
                // thing left that can notice, so they must act rather than defer.
                reap_tree(&job);
                break;
            }
        }
    })
}

/// Routes decoded input frames into the EXEC child's stdin. Owns the stdin-write handle so
/// it can close it on the stdin-EOF marker (below) or when the pump thread ends.
#[cfg(windows)]
struct ExecInputSink {
    writer: HandleWriter,
}

#[cfg(windows)]
impl FrameSink for ExecInputSink {
    fn on_data(&mut self, _stream: Stream, bytes: &[u8]) -> anyhow::Result<()> {
        if bytes.is_empty() {
            // The shim's stdin-EOF marker: close the child's stdin so a reader like
            // sort/findstr finishes, WITHOUT tearing down the connection — stdout, stderr and
            // EXIT still flow. A full socket close is the separate disconnect signal.
            self.writer.close();
            Ok(())
        } else {
            self.writer.write(bytes)
        }
    }

    // on_resize: default no-op (EXEC has no pseudoconsole).
}

/// Writes to a blocking handle from a thread of its own.
///
/// The frame reader must never park in a sink. `pump_decode` dispatches inline, and a pipe
/// write blocks as soon as the pipe fills and the child stops reading it — so a reader parked
/// there has stopped watching the socket, and a disconnect becomes invisible. If the command
/// also produces no output, nothing is left that can notice, and the session hangs for the
/// lifetime of the agent. Moving the write off this thread is what sshd gets from a select
/// loop over non-blocking descriptors.
///
/// The queue is unbounded. Bounding it would reintroduce exactly the block it removes, and it
/// would buy nothing: the peer is a user the socket ACL already admits, who can exhaust memory
/// directly.
#[cfg(windows)]
struct HandleWriter {
    tx: Option<std::sync::mpsc::Sender<Option<Vec<u8>>>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(windows)]
impl HandleWriter {
    /// `owned` is the handle to close on the stdin-EOF marker; the PTY path passes `None`
    /// because the pseudoconsole's input handle belongs to the session.
    fn spawn(raw: isize, owned: Option<OwnedHandle>) -> Self {
        let (tx, rx) = std::sync::mpsc::channel::<Option<Vec<u8>>>();
        let thread = std::thread::spawn(move || {
            let _owned = owned; // dropped on the way out, closing the child's stdin
            for msg in rx {
                match msg {
                    Some(bytes) if conpty::write_all_handle(raw, &bytes) => {}
                    _ => break, // the write failed, or the peer signalled stdin-EOF
                }
            }
        });
        Self {
            tx: Some(tx),
            thread: Some(thread),
        }
    }

    /// Queue bytes. Fails only once the writer thread has stopped, which is a genuine
    /// [`crate::relay::PumpError::Sink`]: local, and no evidence about the peer.
    fn write(&self, bytes: &[u8]) -> anyhow::Result<()> {
        let Some(tx) = &self.tx else {
            return Ok(()); // stdin already closed by the marker; further input is discarded
        };
        tx.send(Some(bytes.to_vec()))
            .map_err(|_| anyhow::anyhow!("the handle writer stopped"))
    }

    /// Close the underlying handle without ending the session.
    fn close(&mut self) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(None);
        }
    }
}

#[cfg(windows)]
impl Drop for HandleWriter {
    fn drop(&mut self) {
        self.tx = None; // end the channel so the thread finishes
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// The warning teardown owes an operator when a failed reap means the joins can block.
///
/// Pure so the decision is testable; the caller does the logging. Proceeding with the join is
/// deliberate — detaching would let those threads read handles the session is about to close —
/// but it must not be silent, or the agent looks wedged for no stated reason.
#[cfg(windows)]
fn teardown_warning(reaped: bool) -> Option<&'static str> {
    (!reaped).then_some(
        "the process tree survived teardown; joining the output pumps will block until whatever still holds the session's pipes exits",
    )
}

/// Reap the child and everything it spawned. Idempotent.
///
/// This is what Windows OpenSSH does, measured rather than assumed: it ends the session when
/// the direct child exits, does not wait for a descendant holding the pipe, and terminates the
/// descendant tree — including one whose stdout was redirected to a file and never touched the
/// session's pipe. There is no `nohup` equivalent on that platform, so preserving descendants
/// would be a divergence from the shell this replaces, not parity with it. (Unix OpenSSH does
/// the opposite: it waits for pipe EOF, which is why `nohup cmd >/dev/null 2>&1 &` exists.)
///
/// Reaping is also what unblocks teardown: killing the tree closes the pipes, so an output pump
/// parked in `ReadFile` on a handle a descendant was holding returns instead of hanging the
/// handler thread forever in a resident agent.
#[cfg(windows)]
fn reap_tree(job: &cosca::Job) -> bool {
    match job.kill_tree() {
        Ok(()) => true,
        Err(e) => {
            tracing::warn!("tearing down the process tree failed: {e}");
            false
        }
    }
}

// ── single-instance ────────────────────────────────────────────────────────────────

/// Single-instance guard: a named mutex so only one agent binds the socket (the real fix
/// for a concurrent double-launch, which the bind probe-connect alone can't close).
#[cfg(windows)]
struct SingleInstance {
    handle: windows::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
impl SingleInstance {
    fn acquire() -> anyhow::Result<SingleInstance> {
        use windows::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, GetLastError};
        use windows::Win32::System::Threading::CreateMutexW;
        use windows::core::PCWSTR;
        let name: Vec<u16> = "Global\\ssh-broker-agent"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        unsafe {
            let handle = CreateMutexW(None, true, PCWSTR(name.as_ptr()))?;
            if GetLastError() == ERROR_ALREADY_EXISTS {
                let _ = CloseHandle(handle);
                anyhow::bail!("another ssh-broker agent is already running");
            }
            Ok(SingleInstance { handle })
        }
    }
}

#[cfg(windows)]
impl Drop for SingleInstance {
    fn drop(&mut self) {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::ReleaseMutex;
        unsafe {
            let _ = ReleaseMutex(self.handle);
            let _ = CloseHandle(self.handle);
        }
    }
}

#[cfg(all(windows, test))]
#[path = "agent_tests.rs"]
mod agent_tests;
