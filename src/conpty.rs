//! conpty: hand-rolled ConPTY#2 host for the agent's PTY path (Windows-only).
//!
//! `PtySession` creates a pseudoconsole, spawns the configured shell into it (inheriting
//! the agent's session-1 token → working DPAPI/profile + no RedirectionGuard), and
//! exposes its input/output pipes + resize + exit code to the agent's relay.
//!
//! Productionized from the feasibility spike with these hard requirements met:
//!  - `UpdateProcThreadAttribute` lpValue is the **HPCON value** (`hpc.0 as *const c_void`),
//!    never `&hpc` — the root cause of the 0xC0000142 DLL-init failure (microsoft/terminal
//!    diff). Std handles are nulled + `STARTF_USESTDHANDLES` set (microsoft/terminal#4380),
//!    since over SSH the agent's stdio are pipes that must not bleed into the child.
//!  - **RAII on every path:** `OwnedHandle`/`OwnedHpcon`/`OwnedAttrList` free pipes, the
//!    pseudoconsole (a conhost process), and the attribute list on every `?` early return.
//!  - **`write_all` loops** on the returned byte count (a short write drops VT tail bytes).
//!  - Decomposed (pipe / pseudoconsole / attribute-list / spawn).
//!
//! Relay threading + cancellation + the close-then-drain teardown ordering live in the
//! agent (it owns the pump threads); `PtySession` provides the cancelable primitive
//! (`close_pty` makes the output pipe hit EOF) and the raw handles for those threads.
//!
//! Session placement is NOT a ConPTY constraint. A pseudoconsole created in session 0 can
//! host a child launched into a *different* (interactive) session: with a SYSTEM process
//! using `WTSQueryUserToken` + `CreateProcessAsUserW`, the child landed in the console
//! session (confirmed parent-side via `ProcessIdToSessionId`), exited 0, and its VT came
//! back through the session-0 pseudoconsole byte-identical to a same-session control.
//! The agent still runs *inside* the target session, but by choice, not necessity: that
//! keeps the relay at the user's privilege instead of SYSTEM's, and inherits the real
//! profile/environment for free (`CreateProcessAsUserW` with a null environment block
//! hands the child SYSTEM's environment, not the user's).

use std::path::Path;

use crate::winutil::{AttrList, OwnedHandle};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows::Win32::System::Console::{COORD, ClosePseudoConsole, CreatePseudoConsole, HPCON, ResizePseudoConsole};
use windows::Win32::System::Pipes::CreatePipe;
use windows::Win32::System::Threading::{
    CreateProcessW, EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess, INFINITE, PROCESS_INFORMATION,
    STARTF_USESTDHANDLES, STARTUPINFOEXW, TerminateProcess, WaitForSingleObject,
};
use windows::core::{PCWSTR, PWSTR};

// windows-rs 0.62 does not export these as plain flag values usable with the `u32`/`usize`
// FFI parameters, so they are named here with their documented winnt/consoleapi values.
/// `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` (processthreadsapi.h) — the attribute key that
/// binds a pseudoconsole to a process being created.
const PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE: usize = 0x0002_0016;
/// `PSEUDOCONSOLE_RESIZE_QUIRK` (consoleapi.h) — fixes resize-reflow artifacts.
const PSEUDOCONSOLE_RESIZE_QUIRK: u32 = 0x0002;
/// `PSEUDOCONSOLE_WIN32_INPUT_MODE` — accept win32-input-mode CSI input sequences.
const PSEUDOCONSOLE_WIN32_INPUT_MODE: u32 = 0x0004;
/// `PSEUDOCONSOLE_PASSTHROUGH_MODE` (build ≥ 22621) — relay the child's VT directly.
const PSEUDOCONSOLE_PASSTHROUGH_MODE: u32 = 0x0008;

// ── RAII guard (pipe/process handles use winutil::OwnedHandle) ───────────────────────

/// `ClosePseudoConsole` on drop (no-op once taken/closed). Closing the pseudoconsole is
/// what makes the output pipe deliver its buffered tail and then EOF.
struct OwnedHpcon(HPCON);
impl Drop for OwnedHpcon {
    fn drop(&mut self) {
        if self.0.0 != 0 {
            unsafe {
                ClosePseudoConsole(self.0);
            }
        }
    }
}

// ── decomposed steps ─────────────────────────────────────────────────────────────────

/// Create an anonymous pipe, returning (read end, write end) as owned handles.
unsafe fn create_pipe_pair() -> windows::core::Result<(OwnedHandle, OwnedHandle)> {
    let mut read = HANDLE::default();
    let mut write = HANDLE::default();
    unsafe { CreatePipe(&mut read, &mut write, None, 0)? };
    Ok((OwnedHandle(read), OwnedHandle(write)))
}

/// Create the pseudoconsole, trying the full modern flag set and falling back to the base
/// flags if passthrough is unavailable.
unsafe fn create_pty(size: COORD, in_read: HANDLE, out_write: HANDLE) -> windows::core::Result<OwnedHpcon> {
    let full = PSEUDOCONSOLE_RESIZE_QUIRK | PSEUDOCONSOLE_WIN32_INPUT_MODE | PSEUDOCONSOLE_PASSTHROUGH_MODE;
    let hpc = match unsafe { CreatePseudoConsole(size, in_read, out_write, full) } {
        Ok(h) => h,
        Err(_) => {
            let base = PSEUDOCONSOLE_RESIZE_QUIRK | PSEUDOCONSOLE_WIN32_INPUT_MODE;
            unsafe { CreatePseudoConsole(size, in_read, out_write, base)? }
        }
    };
    Ok(OwnedHpcon(hpc))
}

/// Write the whole buffer to `handle`, looping on the returned byte count. Returns false
/// on a write failure or a 0-byte write (broken pipe), so the relay stops cleanly rather
/// than dropping the tail of a VT sequence.
pub fn write_all_handle(handle: isize, mut buf: &[u8]) -> bool {
    let h = HANDLE(handle as *mut core::ffi::c_void);
    while !buf.is_empty() {
        let mut written = 0u32;
        if unsafe { WriteFile(h, Some(buf), Some(&mut written), None) }.is_err() || written == 0 {
            return false;
        }
        buf = &buf[written as usize..];
    }
    true
}

/// Read up to `buf.len()` bytes from `handle`; returns 0 on EOF or error (the relay treats
/// a closed/broken output pipe as end-of-stream).
pub fn read_handle(handle: isize, buf: &mut [u8]) -> usize {
    let h = HANDLE(handle as *mut core::ffi::c_void);
    let mut n = 0u32;
    if unsafe { ReadFile(h, Some(buf), Some(&mut n), None) }.is_err() {
        return 0;
    }
    n as usize
}

/// Resize a pseudoconsole by raw HPCON value (for the agent's input thread). A `0` handle
/// (already closed/taken) is a no-op, symmetric with [`close_pty_raw`].
pub fn resize_pty(hpc_raw: isize, cols: u16, rows: u16) -> windows::core::Result<()> {
    if hpc_raw == 0 {
        return Ok(());
    }
    let size = COORD {
        X: cols.max(1) as i16,
        Y: rows.max(1) as i16,
    };
    unsafe { ResizePseudoConsole(HPCON(hpc_raw), size) }
}

/// Close a pseudoconsole by raw HPCON value (the agent's teardown owns this once it has
/// taken the HPCON via [`PtySession::take_hpc_raw`]). Makes the output pipe hit EOF.
pub fn close_pty_raw(hpc_raw: isize) {
    if hpc_raw != 0 {
        unsafe {
            ClosePseudoConsole(HPCON(hpc_raw));
        }
    }
}

// ── PtySession ─────────────────────────────────────────────────────────────────────

/// A shell hosted in a pseudoconsole. Holds the pseudoconsole, the child process/thread,
/// and the parent's input-write / output-read pipe ends.
pub struct PtySession {
    hpc: Option<OwnedHpcon>,
    process: OwnedHandle,
    _thread: OwnedHandle,
    in_write: OwnedHandle,
    out_read: OwnedHandle,
}

impl PtySession {
    /// Spawn `command` in a fresh pseudoconsole of `cols`x`rows`, optionally in `cwd`. The
    /// child inherits the agent's (session-1) token and environment.
    pub fn spawn(command: &str, cols: u16, rows: u16, cwd: Option<&Path>) -> windows::core::Result<PtySession> {
        let size = COORD {
            X: cols.max(1) as i16,
            Y: rows.max(1) as i16,
        };
        unsafe {
            let (in_read, in_write) = create_pipe_pair()?;
            let (out_read, out_write) = create_pipe_pair()?;

            // The pseudoconsole owns the child-side ends; the parent keeps in_write+out_read.
            let hpc = create_pty(size, in_read.0, out_write.0)?;
            drop(in_read);
            drop(out_write);

            // lpValue for PSEUDOCONSOLE is the HPCON VALUE itself, not a pointer to it —
            // the root cause of the 0xC0000142 DLL-init failure in the spike.
            let attr = AttrList::single(
                PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
                hpc.0.0 as *const core::ffi::c_void,
                std::mem::size_of::<HPCON>(),
            )?;

            let mut si = STARTUPINFOEXW::default();
            si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
            si.StartupInfo.hStdInput = HANDLE::default();
            si.StartupInfo.hStdOutput = HANDLE::default();
            si.StartupInfo.hStdError = HANDLE::default();
            si.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
            si.lpAttributeList = attr.as_ptr();

            let mut cmd: Vec<u16> = command.encode_utf16().chain(std::iter::once(0)).collect();
            let cwd_wide: Option<Vec<u16>> = cwd.map(|c| {
                use std::os::windows::ffi::OsStrExt;
                c.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
            });
            let cwd_ptr = cwd_wide.as_ref().map(|w| PCWSTR(w.as_ptr())).unwrap_or(PCWSTR::null());

            let mut pi = PROCESS_INFORMATION::default();
            CreateProcessW(
                PCWSTR::null(),
                Some(PWSTR(cmd.as_mut_ptr())),
                None,
                None,
                false,
                EXTENDED_STARTUPINFO_PRESENT,
                None,
                cwd_ptr,
                &si.StartupInfo,
                &mut pi,
            )?;
            // `attr` drops here (DeleteProcThreadAttributeList) — the child is created.
            drop(attr);

            Ok(PtySession {
                hpc: Some(hpc),
                process: OwnedHandle(pi.hProcess),
                _thread: OwnedHandle(pi.hThread),
                in_write,
                out_read,
            })
        }
    }

    /// Raw output-read handle (as `isize`) for the agent's reader thread.
    pub fn out_read_raw(&self) -> isize {
        self.out_read.0.0 as isize
    }

    /// Raw input-write handle (as `isize`) for forwarding decoded input.
    pub fn in_write_raw(&self) -> isize {
        self.in_write.0.0 as isize
    }

    /// Raw child-process handle (as `isize`) — e.g. for `TerminateProcess` from a relay
    /// thread on mid-session teardown.
    pub fn process_raw(&self) -> isize {
        self.process.0.0 as isize
    }

    /// Hand the pseudoconsole's raw handle to the caller, who then owns closing it (via
    /// [`close_pty_raw`]); `PtySession`'s own Drop no longer closes it. Used by the agent
    /// so the HPCON can be shared (behind a mutex) between the resize and teardown paths.
    pub fn take_hpc_raw(&mut self) -> isize {
        match self.hpc.take() {
            Some(owned) => {
                let raw = owned.0.0;
                std::mem::forget(owned); // ownership transferred; don't ClosePseudoConsole here
                raw
            }
            None => 0,
        }
    }

    /// Resize the pseudoconsole.
    pub fn resize(&self, cols: u16, rows: u16) -> windows::core::Result<()> {
        let size = COORD {
            X: cols.max(1) as i16,
            Y: rows.max(1) as i16,
        };
        unsafe { ResizePseudoConsole(self.hpc_handle(), size) }
    }

    /// Block until the child exits and return its exit code (bit-preserving `u32`→`i32`).
    pub fn wait(&self) -> windows::core::Result<i32> {
        unsafe {
            WaitForSingleObject(self.process.0, INFINITE);
            let mut code = 0u32;
            GetExitCodeProcess(self.process.0, &mut code)?;
            Ok(code as i32)
        }
    }

    /// Force-terminate the child (mid-session teardown when the SSH side drops).
    pub fn kill(&self) -> windows::core::Result<()> {
        unsafe { TerminateProcess(self.process.0, 1) }
    }

    /// Close the pseudoconsole. This makes the output pipe deliver its buffered tail and
    /// then hit EOF, so the agent's reader thread ends and can be joined. Idempotent.
    pub fn close_pty(&mut self) {
        self.hpc = None; // OwnedHpcon::drop -> ClosePseudoConsole
    }

    fn hpc_handle(&self) -> HPCON {
        self.hpc.as_ref().map(|h| h.0).unwrap_or(HPCON(0))
    }
}

#[cfg(test)]
#[path = "conpty_tests.rs"]
mod conpty_tests;
