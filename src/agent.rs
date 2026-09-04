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
use crate::relay::{FrameSink, pump_decode, write_data};
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
mod cwd_logic_tests {
    use super::child_cwd;
    use std::path::PathBuf;

    #[test]
    fn empty_handshake_cwd_falls_back_to_home() {
        let home = Some(PathBuf::from(r"C:\Users\me"));
        assert_eq!(child_cwd("", home.clone()), home);
    }

    #[test]
    fn explicit_handshake_cwd_wins_over_home() {
        assert_eq!(
            child_cwd(r"C:\work", Some(PathBuf::from(r"C:\Users\me"))),
            Some(PathBuf::from(r"C:\work"))
        );
    }

    #[test]
    fn empty_cwd_and_no_home_is_none() {
        // No worse than today's behaviour (inherit the agent's cwd) when home is unresolvable.
        assert_eq!(child_cwd("", None), None);
    }
}

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
    let child_pid = session.pid();
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

    // Input pump: socket → ConPTY input + resize; on return, kill the child so the waiter
    // unblocks even if the SSH side dropped first.
    let in_thread = {
        let hpc_cell = Arc::clone(&hpc_cell);
        std::thread::spawn(move || {
            let mut sink = PtyInputSink { in_raw, hpc_cell };
            let _ = pump_decode(&mut rx, &mut fr, &mut sink);
            kill_tree(child_pid);
        })
    };

    // Waiter + ordered teardown. Do NOT `?` on wait(): even if it errors we must still tear
    // down (close the HPCON, join the threads) before returning, or the threads would
    // outlive `session` and touch closed handles, and the (forgotten) HPCON would leak.
    let wait_result = session.wait();
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
    let child_pid = child.pid();
    let stdin_owned = child.take_stdin_write();
    // stdout, stderr, and the EXIT frame all share tx → serialize with a mutex.
    let tx_arc = Arc::new(Mutex::new(tx));

    let t_out = spawn_stream_pump(out_raw, Stream::Stdout, Arc::clone(&tx_arc), child_pid);
    let t_err = spawn_stream_pump(err_raw, Stream::Stderr, Arc::clone(&tx_arc), child_pid);

    // stdin pump owns the child's stdin-write handle. A half-close mid-session (empty
    // DATA(Stdin) marker) closes only the child's stdin so a reader like sort/findstr
    // finishes; a FULL socket close means the SSH side is gone, so after the pump returns we
    // kill the child unconditionally. Without this, a silent, stdin-ignoring command
    // (e.g. `ssh host "Start-Sleep 99999"`) would never exit and the output pumps — blocked
    // in read with nothing to write — would never detect the dead socket, hanging the waiter.
    let t_in = std::thread::spawn(move || {
        let mut sink = ExecInputSink { stdin: stdin_owned };
        let _ = pump_decode(&mut rx, &mut fr, &mut sink);
        drop(sink); // close the child's stdin if the EOF marker never arrived
        kill_tree(child_pid);
    });

    let wait_result = child.wait();
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
    child_pid: u32,
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
                kill_tree(child_pid); // SSH side gone → unblock the waiter
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

/// Terminate the child **and everything it spawned**.
///
/// Terminating the child alone leaves its descendants running, so a relayed shell that
/// launched anything in the background leaked it past the end of the SSH session.
///
/// Descendants are enumerated before the root is killed: once the root dies its children
/// are orphaned and the parent links the walk relies on no longer lead anywhere.
///
/// Deliberate limitation: without a job object this is a treewalk, so a process created
/// *during* the walk can still escape. Pid reuse is not a hazard — cosca's `Process`
/// identity is `(pid, start_token)`, so a recycled pid resolves as a different process.
/// A job object is the complete fix and is tracked separately.
#[cfg(windows)]
fn kill_tree(pid: u32) {
    use cosca::identity::Resolved;
    use cosca::process::{Process, Recursive};

    let Resolved::Found(root) = Process::from_pid(pid) else {
        return; // already gone, or the OS refused the query
    };
    for descendant in root.children(Recursive::Yes) {
        let _ = descendant.kill();
    }
    let _ = root.kill();
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
