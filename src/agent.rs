//! agent: resident in session 1 (started by the auto-login logon task). Per AF_UNIX
//! connection it hosts the shell in a ConPTY (inheriting the session-1 token → working
//! DPAPI/profile + no RedirectionGuard) and relays it to the SSH-side shim.
//!
//! The PTY relay uses three threads with an ordered, race-free teardown (criterion 2):
//!   - **waiter** (the calling thread): blocks on the child, then records the exit code,
//!     closes the pseudoconsole (→ output pipe EOF), and joins the two pump threads;
//!   - **output**: `PtySession` output → `DATA(Pty)` frames; on EOF emits the `EXIT` frame
//!     and shuts the connection down (which unblocks the input pump);
//!   - **input**: `pump_decode` → ConPTY input + `ResizePseudoConsole`, and on return kills
//!     the child so the waiter unblocks even when the SSH side drops first.
//! The HPCON is shared behind a mutex so a resize can never race the teardown's close.

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
use crate::afunix::{self, Listener};
#[cfg(windows)]
use crate::conpty::{self, PtySession};
#[cfg(windows)]
use crate::protocol::{
    ExitCode, FrameKind, FrameReader, Handshake, Mode, Resize, Stream, read_one_frame, write_frame,
};
#[cfg(windows)]
use crate::relay::{FrameSink, pump_decode, write_data};
#[cfg(windows)]
use std::sync::{Arc, Mutex};

/// Bind the hardened socket and serve connections, one handler thread each. Single-instance
/// is enforced by a named mutex acquired before binding.
#[cfg(windows)]
fn run_on(path: &std::path::Path) -> anyhow::Result<()> {
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

/// Drive one PTY connection: handshake → spawn shell in a ConPTY → relay both directions →
/// exit code → ordered teardown.
#[cfg(windows)]
fn handle_connection(conn: socket2::Socket) -> anyhow::Result<()> {
    let (mut rx, tx) = afunix::split(conn)?;

    // Handshake (reuse the FrameReader so any pipelined input survives for the pump).
    let mut fr = FrameReader::new();
    let frame = read_one_frame(&mut rx, &mut fr)?;
    anyhow::ensure!(frame.kind == FrameKind::Handshake, "first frame was not a handshake");
    let hs = Handshake::decode(&frame.payload)?;
    anyhow::ensure!(hs.mode == Mode::Pty, "the agent PTY handler requires Mode::Pty");

    let command = hs.command.clone().unwrap_or_else(default_shell);
    let cwd = if hs.cwd.is_empty() { None } else { Some(std::path::Path::new(&hs.cwd)) };
    let mut session = PtySession::spawn(&command, hs.cols, hs.rows, cwd)?;

    let out_raw = session.out_read_raw();
    let in_raw = session.in_write_raw();
    let proc_raw = session.process_raw();
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
            unsafe {
                let _ = windows::Win32::System::Threading::TerminateProcess(
                    windows::Win32::Foundation::HANDLE(proc_raw as *mut core::ffi::c_void),
                    1,
                );
            }
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
        // copy the raw HPCON out and then race this close (use-after-close). Binding the
        // guard to a variable keeps it alive across `close_pty_raw`.
        let mut hpc = hpc_cell.lock().unwrap();
        if let Some(raw) = hpc.take() {
            conpty::close_pty_raw(raw); // → output pipe EOF → out_thread drains, emits EXIT, FINs
        }
    }
    let _ = out_thread.join();
    let _ = in_thread.join();
    // Threads joined; `session` now drops and closes the process/thread + pipe handles.
    // Propagate a wait() error only AFTER teardown (converts windows::core::Error -> anyhow).
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
