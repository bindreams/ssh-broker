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
use crate::relay::{FrameSink, Outcome, pump_decode, write_data};
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
    let code_cell = Arc::new(Mutex::new(0i32));

    // Output pump (owns tx): ConPTY output → DATA(Pty); on EOF emit EXIT + shut down.
    let out_thread = {
        let code_cell = Arc::clone(&code_cell);
        let mut tx = tx;
        std::thread::spawn(move || {
            let mut buf = [0u8; 32 * 1024];
            loop {
                let n = conpty::read_handle(out_raw, &mut buf);
                if n == 0 {
                    break; // pseudoconsole closed (teardown) → drained to EOF
                }
                if write_data(&mut tx, Stream::Pty, &buf[..n]).is_err() {
                    break; // SSH side gone
                }
            }
            let code = *code_cell.lock().unwrap();
            let _ = write_frame(&mut tx, FrameKind::Exit, &ExitCode(code).encode());
            let _ = tx.shutdown_both(); // FIN + unblock the input pump's read
        })
    };

    // Input pump: socket → ConPTY input + resize. On return the socket is gone; if the shell
    // is still running that means the SSH side dropped, so its tree is reaped to unblock the
    // waiter. If the shell already exited, this return is just the normal-exit teardown
    // reaching us, and its descendants are left alone.
    let job_claim: JobClaim = Arc::new(Mutex::new(Some(session.job())));
    let in_thread = {
        let hpc_cell = Arc::clone(&hpc_cell);
        let job = Arc::clone(&job_claim);
        std::thread::spawn(move || {
            let mut sink = PtyInputSink { in_raw, hpc_cell };
            // Only a closed socket means the peer is gone. A sink error is a local failure
            // (a broken pseudoconsole write), not a disconnect, and must not reap a session
            // whose peer is still there.
            if matches!(pump_decode(&mut rx, &mut fr, &mut sink), Ok(Outcome::PeerClosed)) {
                reap_if_peer_vanished(&job);
            }
        })
    };

    // Waiter + ordered teardown. Do NOT `?` on wait(): even if it errors we must still tear
    // down (close the HPCON, join the threads) before returning, or the threads would
    // outlive `session` and touch closed handles, and the (forgotten) HPCON would leak.
    let wait_result = session.wait();
    // Only a clean exit means the shell finished on its own. If `wait` failed the state is
    // unknown, so the claim is left alone and the `Job`'s drop reaps the tree — the safe
    // default. Winning the claim is also what proves no pump has already reaped.
    if wait_result.is_ok()
        && let Some(job) = claim_job(&job_claim)
    {
        job.disarm();
    }
    let code = *wait_result.as_ref().unwrap_or(&1);
    *code_cell.lock().unwrap() = code;
    {
        // Close the pseudoconsole while HOLDING the lock, so a concurrent resize cannot
        // copy the raw HPCON out and then race this close (use-after-close).
        let mut hpc = hpc_cell.lock().unwrap();
        if let Some(raw) = hpc.take() {
            conpty::close_pty_raw(raw); // → output pipe EOF → out_thread drains, emits EXIT, FINs
        }
    }
    let _ = out_thread.join();
    let _ = in_thread.join();
    // Threads joined; `session` now drops and closes the process/thread + pipe handles.
    wait_result?;
    Ok(())
}

/// Routes decoded input frames into the pseudoconsole.
#[cfg(windows)]
struct PtyInputSink {
    in_raw: isize,
    hpc_cell: Arc<Mutex<Option<isize>>>,
}

#[cfg(windows)]
impl FrameSink for PtyInputSink {
    fn on_data(&mut self, _stream: Stream, bytes: &[u8]) -> anyhow::Result<()> {
        // PTY input arrives pre-encoded (win32-input-mode); write it straight to ConPTY#2.
        anyhow::ensure!(
            conpty::write_all_handle(self.in_raw, bytes),
            "failed to write to the pseudoconsole input"
        );
        Ok(())
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
    // stdout, stderr, and the EXIT frame all share tx → serialize with a mutex.
    let tx_arc = Arc::new(Mutex::new(tx));
    let job_claim: JobClaim = Arc::new(Mutex::new(Some(child.job())));

    let t_out = spawn_stream_pump(out_raw, Stream::Stdout, Arc::clone(&tx_arc), Arc::clone(&job_claim));
    let t_err = spawn_stream_pump(err_raw, Stream::Stderr, Arc::clone(&tx_arc), Arc::clone(&job_claim));

    // stdin pump owns the child's stdin-write handle. A half-close mid-session (empty
    // DATA(Stdin) marker) closes only the child's stdin so a reader like sort/findstr
    // finishes; a FULL socket close means the SSH side is gone, so after the pump returns we
    // kill the child unconditionally. Without this, a silent, stdin-ignoring command that
    // sleeps indefinitely would never exit, and the output pumps — blocked in read with
    // nothing to write — would never detect the dead socket, hanging the waiter.
    let t_in = {
        let job = Arc::clone(&job_claim);
        std::thread::spawn(move || {
            let mut sink = ExecInputSink { stdin: stdin_owned };
            // Only a closed socket means the peer is gone. A sink error is a local failure —
            // notably a broken stdin pipe when the command closed its own stdin, which
            // `ssh host "prog" < file` produces routinely — and must not reap a live session.
            let peer_closed = matches!(pump_decode(&mut rx, &mut fr, &mut sink), Ok(Outcome::PeerClosed));
            drop(sink); // close the child's stdin if the EOF marker never arrived
            if peer_closed {
                reap_if_peer_vanished(&job);
            }
        })
    };

    let wait_result = child.wait();
    // Only a clean exit means the command finished on its own. If `wait` failed the state is
    // unknown, so the claim is left alone and the `Job`'s drop reaps the tree — the safe
    // default. Winning the claim is also what proves no pump has already reaped.
    if wait_result.is_ok()
        && let Some(job) = claim_job(&job_claim)
    {
        job.disarm();
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
fn spawn_stream_pump(raw: isize, stream: Stream, tx: Arc<Mutex<ConnTx>>, job: JobClaim) -> std::thread::JoinHandle<()> {
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
                // A failed write is unambiguous: the socket is gone.
                reap_if_peer_vanished(&job);
                break;
            }
        }
    })
}

/// Routes decoded input frames into the EXEC child's stdin. Owns the stdin-write handle so
/// it can close it on the stdin-EOF marker (below) or when the pump thread ends.
#[cfg(windows)]
struct ExecInputSink {
    stdin: Option<OwnedHandle>,
}

#[cfg(windows)]
impl FrameSink for ExecInputSink {
    fn on_data(&mut self, _stream: Stream, bytes: &[u8]) -> anyhow::Result<()> {
        if bytes.is_empty() {
            // An empty DATA(Stdin) frame is the shim's stdin-EOF marker: close the child's
            // stdin (→ readers like sort/findstr see EOF and finish) WITHOUT tearing down the
            // connection, so stdout/stderr/EXIT still flow. A full socket close is the
            // separate disconnect signal, handled by the pump thread (kill).
            self.stdin = None;
        } else if let Some(h) = &self.stdin {
            anyhow::ensure!(
                conpty::write_all_handle(h.raw(), bytes),
                "failed to write to the exec child's stdin"
            );
        }
        Ok(())
    }
    // on_resize: default no-op (EXEC has no pseudoconsole).
}

/// The containment handle, claimable exactly once.
///
/// Teardown and the relay pumps race to decide the tree's fate, and the decision cannot be
/// made by *observing* anything: both paths end with the socket shut down, and because
/// `split` hands out duplicates of one socket that EOF is identical whether the peer vanished
/// or the agent closed up after a normal exit. Asking whether the child exited is wrong too —
/// a descendant holding the child's stdout keeps the output pumps blocked long after the child
/// is gone, so "child exited" and "peer still there" are simultaneously true.
///
/// So the decision is made by *ownership*. Whoever takes the handle first decides, and the
/// loser does nothing:
///
/// - Teardown takes it after a clean `wait()` and disarms — the command finished on its own,
///   so what it launched is not ours to reap (sshd leaves such processes running).
/// - A pump that still finds it present knows teardown has not begun, so the peer is what went
///   away, and it reaps unconditionally. That also unblocks the output pumps: reaping the tree
///   closes the pipe a descendant was holding.
///
/// Nobody claiming it is also correct — the `Job` drops with the session and
/// `KILL_ON_JOB_CLOSE` reaps the tree, which is the right default when `wait()` failed and the
/// state is unknown.
#[cfg(windows)]
type JobClaim = Arc<Mutex<Option<Arc<cosca::Job>>>>;

/// Take the containment handle if it is still unclaimed.
#[cfg(windows)]
fn claim_job(claim: &JobClaim) -> Option<Arc<cosca::Job>> {
    claim.lock().unwrap_or_else(|e| e.into_inner()).take()
}

/// Reap the tree because the peer went away — unless teardown already claimed it.
#[cfg(windows)]
fn reap_if_peer_vanished(claim: &JobClaim) {
    let Some(job) = claim_job(claim) else {
        return; // teardown got there first: the command exited on its own
    };
    if let Err(e) = job.kill_tree() {
        tracing::warn!("tearing down the process tree after a disconnect failed: {e}");
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
