//! pipes: redirected-pipe EXEC child (Windows-only). Spawns the configured shell with
//! stdin/stdout/stderr wired to anonymous pipes, inheriting the agent's session-1 token.
//!
//! Inheritance is restricted to EXACTLY the three std-handle pipe ends via
//! `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`, so the listening socket and other connections'
//! handles are never leaked into the child — even under concurrent EXEC spawns, where a
//! global inheritable-flag approach would race.

use crate::winutil::{AttrList, OwnedHandle};
use std::os::windows::io::BorrowedHandle;
use std::path::Path;
use windows::Win32::Foundation::{ERROR_INVALID_HANDLE, HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation};
use windows::Win32::System::Pipes::CreatePipe;
use windows::Win32::System::Threading::{
    CREATE_SUSPENDED, CreateProcessW, EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess, INFINITE, PROCESS_INFORMATION,
    ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOEXW, TerminateProcess, WaitForSingleObject,
};
use windows::core::{PCWSTR, PWSTR};

/// `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` (processthreadsapi.h) — restrict the child's
/// inherited handles to exactly those listed. (windows-rs 0.62 doesn't export it as a
/// usable `usize` FFI value; named here with its documented value.)
const PROC_THREAD_ATTRIBUTE_HANDLE_LIST: usize = 0x0002_0002;

/// A child process with redirected stdin/stdout/stderr (the EXEC path).
pub struct ExecChild {
    process: OwnedHandle,
    /// Kernel-enforced containment for the command and everything it spawns. Teardown is
    /// `kill_tree` (the session is gone, reap it all) or `disarm` (the command exited on its
    /// own, so leave whatever it launched running, as sshd does).
    job: std::sync::Arc<cosca::Job>,
    _thread: OwnedHandle,
    stdin_write: Option<OwnedHandle>,
    stdout_read: OwnedHandle,
    stderr_read: OwnedHandle,
}

/// Create an anonymous pipe (read, write) as owned handles.
unsafe fn create_pipe() -> windows::core::Result<(OwnedHandle, OwnedHandle)> {
    let mut read = HANDLE::default();
    let mut write = HANDLE::default();
    unsafe { CreatePipe(&mut read, &mut write, None, 0)? };
    Ok((OwnedHandle(read), OwnedHandle(write)))
}

/// Mark a handle inheritable.
unsafe fn set_inheritable(h: HANDLE) -> windows::core::Result<()> {
    unsafe { SetHandleInformation(h, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT) }
}

impl ExecChild {
    /// Spawn `command` with redirected std streams, optionally in `cwd`.
    pub fn spawn(command: &str, cwd: Option<&Path>) -> windows::core::Result<ExecChild> {
        unsafe {
            let (stdin_read, stdin_write) = create_pipe()?;
            let (stdout_read, stdout_write) = create_pipe()?;
            let (stderr_read, stderr_write) = create_pipe()?;
            // Only the child-side ends are inheritable; the parent-side ends stay private.
            set_inheritable(stdin_read.0)?;
            set_inheritable(stdout_write.0)?;
            set_inheritable(stderr_write.0)?;

            // Inherit EXACTLY these three handles (the array must outlive CreateProcessW —
            // the attribute list stores a pointer to it, not a copy).
            let handles: [HANDLE; 3] = [stdin_read.0, stdout_write.0, stderr_write.0];
            let attr = AttrList::single(
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                handles.as_ptr() as *const core::ffi::c_void,
                std::mem::size_of_val(&handles),
            )?;

            let mut si = STARTUPINFOEXW::default();
            si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
            si.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
            si.StartupInfo.hStdInput = stdin_read.0;
            si.StartupInfo.hStdOutput = stdout_write.0;
            si.StartupInfo.hStdError = stderr_write.0;
            si.lpAttributeList = attr.as_ptr();

            let mut cmd: Vec<u16> = command.encode_utf16().chain(std::iter::once(0)).collect();
            let cwd_wide: Option<Vec<u16>> = cwd.map(|c| {
                use std::os::windows::ffi::OsStrExt;
                c.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
            });
            let cwd_ptr = cwd_wide.as_ref().map(|w| PCWSTR(w.as_ptr())).unwrap_or(PCWSTR::null());

            // CREATE_SUSPENDED is required, not an optimisation: the command must be inside
            // the job before it runs a single instruction, or anything it forks first escapes
            // containment permanently. Sequence fixed by `cosca::Job`: create suspended,
            // assign, and only then resume.
            let mut pi = PROCESS_INFORMATION::default();
            CreateProcessW(
                PCWSTR::null(),
                Some(PWSTR(cmd.as_mut_ptr())),
                None,
                None,
                true, // bInheritHandles — restricted to the 3 handles above
                EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED,
                None,
                cwd_ptr,
                &si.StartupInfo,
                &mut pi,
            )?;
            drop(attr);
            // The parent keeps stdin_write/stdout_read/stderr_read; close the child-side ends
            // so the parent's reads see EOF when the child exits.
            drop(stdin_read);
            drop(stdout_write);
            drop(stderr_write);

            let process = OwnedHandle(pi.hProcess);
            let thread = OwnedHandle(pi.hThread);

            // Borrowed for the call only; `process` owns the handle and outlives it.
            let job = match cosca::Job::assign(BorrowedHandle::borrow_raw(
                process.0.0 as std::os::windows::io::RawHandle,
            )) {
                Ok(job) => job,
                Err(e) => {
                    // Uncontained AND still suspended. Resuming now would let it fork
                    // descendants nothing can reach, so kill it and propagate.
                    let _ = TerminateProcess(process.0, 1);
                    return Err(windows::core::Error::new(
                        windows::core::HRESULT::from_win32(ERROR_INVALID_HANDLE.0),
                        format!("assign the command to a job object: {e}"),
                    ));
                }
            };

            // Contained: safe to run.
            if ResumeThread(thread.0) == u32::MAX {
                let err = windows::core::Error::from_thread();
                let _ = job.kill_tree();
                return Err(err);
            }

            Ok(ExecChild {
                process,
                _thread: thread,
                job: std::sync::Arc::new(job),
                stdin_write: Some(stdin_write),
                stdout_read,
                stderr_read,
            })
        }
    }

    /// Raw stdout-read handle (`isize`) for the relay's reader thread.
    pub fn stdout_read_raw(&self) -> isize {
        self.stdout_read.raw()
    }
    /// Raw stderr-read handle (`isize`) for the relay's reader thread.
    pub fn stderr_read_raw(&self) -> isize {
        self.stderr_read.raw()
    }

    /// Raw child-process handle (`isize`) — for `TerminateProcess` from a relay thread.
    pub fn process_raw(&self) -> isize {
        self.process.raw()
    }

    /// Take ownership of the stdin-write handle. The relay's stdin thread holds it and
    /// drops it (→ the child's stdin sees EOF) when the SSH side stops sending — so a
    /// reader like `sort`/`findstr` finishes instead of hanging.
    pub fn take_stdin_write(&mut self) -> Option<OwnedHandle> {
        self.stdin_write.take()
    }

    /// Reap the command and everything it spawned — the peer is gone, so nothing it started
    /// has anyone left to talk to.
    /// A share of the containment handle, for a relay thread that must tear the tree down
    /// without owning the session.
    pub fn job(&self) -> std::sync::Arc<cosca::Job> {
        std::sync::Arc::clone(&self.job)
    }

    /// Whether the command has already exited. A zero timeout is an instantaneous state query,
    /// not a wait for anything.
    pub fn has_exited(&self) -> bool {
        crate::winutil::has_exited(self.process.0.0 as isize)
    }

    pub fn kill_tree(&self) {
        if let Err(e) = self.job.kill_tree() {
            tracing::warn!("exec: killing the command's process tree failed: {e}");
        }
    }

    /// Leave the tree running: the command exited on its own, so anything it launched in the
    /// background outlives the session, exactly as it would under sshd. Clears
    /// `KILL_ON_JOB_CLOSE`, so dropping this child no longer reaps them.
    pub fn disarm(&self) {
        self.job.disarm();
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
}

#[cfg(test)]
#[path = "pipes_tests.rs"]
mod pipes_tests;
