//! agent_lock: what keeps one user's agents from fighting over one socket.
//!
//! Two guards, because there are two questions:
//!
//! - [`SessionSlot`]: is there already an agent in *this session*? `apply` and the boot
//!   self-heal start an agent per logged-on session each time they run; the logon task starts
//!   one per logon. A second agent in a session that has one has nothing to add, so it exits.
//!   The name is in the `Local\` namespace, which is per session: another user's session has a
//!   namespace of its own, so one user cannot hold, or squat, another's slot.
//! - [`UserLock`]: is there already an agent for *this user* in another session? One user can be
//!   logged on twice (console and RDP). Only one agent can own the socket, and the other must not
//!   leave: the owner lives and dies with its session, and the user may still be logged on in the
//!   other one. So the second agent waits on the lock and takes over when the first dies. The lock
//!   file lives in the user's verified private folder, so no other account can create it first.

use std::fs::File;
use std::os::windows::io::AsRawHandle;
use std::path::Path;

use anyhow::Context;
use windows::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, ERROR_LOCK_VIOLATION, GetLastError, HANDLE};
use windows::Win32::Storage::FileSystem::{
    LOCK_FILE_FLAGS, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx,
};
use windows::Win32::System::IO::OVERLAPPED;
use windows::Win32::System::Threading::CreateMutexW;
use windows::core::{HRESULT, PCWSTR};

/// The per-session slot's name.
pub const SESSION_SLOT_NAME: &str = r"Local\ssh-broker-agent";

/// Whether an agent may run in session `id`. Session 0 is the services session, where a logon
/// task's agent would have the very environment this project exists to leave: the shell would be
/// a child of a session-0 process and a user's socket would be served from there.
pub fn session_allows_agent(id: u32) -> bool {
    id != 0
}

/// The right to be the one agent of this session. Held until dropped.
#[derive(Debug)]
pub struct SessionSlot(HANDLE);

// SAFETY: the handle is a kernel object owned by this value alone and is only closed on drop.
unsafe impl Send for SessionSlot {}

impl SessionSlot {
    /// Take this session's slot. `None` if another agent in this session holds it.
    pub fn try_acquire() -> anyhow::Result<Option<SessionSlot>> {
        Self::try_acquire_named(SESSION_SLOT_NAME)
    }

    fn try_acquire_named(name: &str) -> anyhow::Result<Option<SessionSlot>> {
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: `wide` is NUL-terminated and outlives the call. Ownership of the mutex is not
        // taken (`false`): the name existing is the whole signal, so a crash releases it.
        let handle = unsafe { CreateMutexW(None, false, PCWSTR(wide.as_ptr())) }
            .with_context(|| format!("create the session slot {name}"))?;
        // SAFETY: read straight after the call it describes, on the same thread.
        if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            // SAFETY: `handle` is the one just opened, closed once.
            let _ = unsafe { CloseHandle(handle) };
            return Ok(None);
        }
        Ok(Some(SessionSlot(handle)))
    }
}

impl Drop for SessionSlot {
    fn drop(&mut self) {
        // SAFETY: `self.0` is the handle this value owns, closed once.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

/// An exclusive lock on the user's `agent.lock`. Held until dropped, and released by the system
/// if the process dies, which is what lets a waiting agent take over.
#[derive(Debug)]
pub struct UserLock {
    _file: File,
}

impl UserLock {
    /// Take the lock if nobody holds it. `None` only when another handle holds the lock: any
    /// other failure, including a sharing violation from a handle that does not hold it (a
    /// scanner, the indexer), is an error, not proof that someone else serves.
    pub fn try_acquire(path: &Path) -> anyhow::Result<Option<UserLock>> {
        let file = open(path)?;
        match lock(&file, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY) {
            Ok(()) => Ok(Some(UserLock { _file: file })),
            Err(e) if e.code() == HRESULT::from_win32(ERROR_LOCK_VIOLATION.0) => Ok(None),
            Err(e) => Err(e).with_context(|| format!("lock {}", path.display())),
        }
    }

    /// Wait for the lock, however long that takes. The holder is another agent that exists, so
    /// there is nothing to time out on: the wait ends when it dies.
    pub fn acquire(path: &Path) -> anyhow::Result<UserLock> {
        let file = open(path)?;
        lock(&file, LOCKFILE_EXCLUSIVE_LOCK).with_context(|| format!("lock {}", path.display()))?;
        Ok(UserLock { _file: file })
    }
}

/// Open (creating) the lock file with the default sharing, so that another handle on it is a
/// contender and not an error.
fn open(path: &Path) -> anyhow::Result<File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .with_context(|| format!("open {}", path.display()))
}

fn lock(file: &File, flags: LOCK_FILE_FLAGS) -> windows::core::Result<()> {
    let mut overlapped = OVERLAPPED::default();
    // SAFETY: the handle is open for the life of `file`; one byte at offset 0, and a synchronous
    // handle makes the exclusive form block until the range is free.
    unsafe { LockFileEx(HANDLE(file.as_raw_handle()), flags, None, 1, 0, &mut overlapped) }
}

#[cfg(test)]
#[path = "agent_lock_tests.rs"]
mod agent_lock_tests;
