//! pipes: redirected-pipe EXEC child (Windows-only). Spawns the configured shell with
//! stdin/stdout/stderr wired to anonymous pipes, inheriting the agent's session-1 token.
//!
//! Inheritance is restricted to EXACTLY the three std-handle pipe ends via
//! `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`, so the listening socket and other connections'
//! handles are never leaked into the child — even under concurrent EXEC spawns, where a
//! global inheritable-flag approach would race.

use crate::shell::StartError;
use crate::winutil::{ChildConsole, OwnedHandle, spawn_suspended};
use std::path::Path;
use windows::Win32::Foundation::{HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation};
use windows::Win32::System::Pipes::CreatePipe;
use windows::Win32::System::Threading::{GetExitCodeProcess, INFINITE, WaitForSingleObject};

/// A child process with redirected stdin/stdout/stderr (the EXEC path).
pub struct ExecChild {
    process: OwnedHandle,
    /// Kernel-enforced containment for the command and everything it spawns. Teardown always
    /// reaps the whole tree; a normal exit is no different from a disconnect here, for the
    /// measured reason in `agent::reap_tree`.
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
    /// Spawn `command` with redirected std streams, optionally in `cwd`. `CreateProcessW` cannot run
    /// leading whitespace, which [`crate::shim::spawn_line`] trims.
    pub fn spawn(command: &str, cwd: Option<&Path>) -> Result<ExecChild, StartError> {
        unsafe {
            let (stdin_read, stdin_write) = create_pipe()?;
            let (stdout_read, stdout_write) = create_pipe()?;
            let (stderr_read, stderr_write) = create_pipe()?;
            // Only the child-side ends are inheritable; the parent-side ends stay private.
            set_inheritable(stdin_read.0)?;
            set_inheritable(stdout_write.0)?;
            set_inheritable(stderr_write.0)?;

            // Inherit EXACTLY these three handles, so the listening socket and other connections'
            // handles never reach the command.
            let handles: [HANDLE; 3] = [stdin_read.0, stdout_write.0, stderr_write.0];
            // The command has a console of its own with no window (see `agent::console`), which also keeps a
            // Ctrl+C it raises for its console (`GenerateConsoleCtrlEvent`, group 0) from reaching the agent
            // or other sessions' commands.
            let (process, thread) = spawn_suspended(
                crate::shim::spawn_line(command),
                cwd,
                ChildConsole::NoWindow,
                handles,
                &handles,
            )?;
            // The parent keeps stdin_write/stdout_read/stderr_read; close the child-side ends
            // so the parent's reads see EOF when the child exits.
            drop(stdin_read);
            drop(stdout_write);
            drop(stderr_write);

            let job = crate::winutil::contain_and_resume(process.0, thread.0, "command")?;

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

    /// Take ownership of the stdin-write handle. The relay's stdin thread holds it and
    /// drops it (→ the child's stdin sees EOF) when the SSH side stops sending — so a
    /// reader like `sort`/`findstr` finishes instead of hanging.
    pub fn take_stdin_write(&mut self) -> Option<OwnedHandle> {
        self.stdin_write.take()
    }

    /// A share of the containment handle, for a relay thread that must tear the tree down
    /// without owning the session.
    pub fn job(&self) -> std::sync::Arc<cosca::Job> {
        std::sync::Arc::clone(&self.job)
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
