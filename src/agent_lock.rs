//! agent_lock: what keeps one user's agents from fighting over one socket.
//!
//! Two guards, because there are two questions:
//!
//! - [`SessionSlot`]: is there already an agent in *this session*? `apply` and the boot
//!   self-heal start an agent per logged-on session each time they run; the logon task starts
//!   one per logon. A second agent in a session that has one has nothing to add, so it exits.
//!   The slot is a lock on a per-session file in the user's verified private folder, not a named
//!   kernel object: any process in the session could create such an object first, whatever
//!   account it runs as, and only the user, SYSTEM and Administrators can create a file here.
//! - [`UserLock`]: is there already an agent for *this user* in another session? One user can be
//!   logged on twice (console and RDP). Only one agent can own the socket, and the other must not
//!   leave: the owner lives and dies with its session, and the user may still be logged on in the
//!   other one. So the second agent waits on the lock and takes over when the first dies. The lock
//!   file lives in the user's verified private folder, so no other account can create it first.

use std::fs::File;
use std::os::windows::io::AsRawHandle;
use std::path::Path;

use anyhow::Context;
use windows::Win32::Foundation::{ERROR_LOCK_VIOLATION, HANDLE};
use windows::Win32::Storage::FileSystem::{
    LOCK_FILE_FLAGS, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx,
};
use windows::Win32::System::IO::OVERLAPPED;
use windows::core::HRESULT;

/// Whether an agent may run in session `id`. Session 0 is the services session, where a logon
/// task's agent would have the very environment this project exists to leave: the shell would be
/// a child of a session-0 process and a user's socket would be served from there.
pub fn session_allows_agent(id: u32) -> bool {
    id != 0
}

/// The right to be the one agent of this session. Held until dropped.
#[derive(Debug)]
pub struct SessionSlot {
    _lock: UserLock,
}

impl SessionSlot {
    /// Take the slot, a lock on `path`, the session's file in the user's folder. `None` if another
    /// agent in this session holds it.
    pub fn try_acquire(path: &Path) -> anyhow::Result<Option<SessionSlot>> {
        Ok(UserLock::try_acquire(path)?.map(|_lock| SessionSlot { _lock }))
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

    /// Take the lock, waiting for it if another handle holds it. `on_wait` runs once, after the
    /// lock was found held and before the wait begins, so a caller can say it is waiting and a
    /// test can tell "held, about to block" from "free". The wait has no limit: the holder is
    /// another agent that exists, so there is nothing to time out on; it ends when the holder dies.
    pub fn acquire(path: &Path, on_wait: impl FnOnce()) -> anyhow::Result<UserLock> {
        let file = open(path)?;
        match lock(&file, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY) {
            Ok(()) => return Ok(UserLock { _file: file }),
            Err(e) if e.code() == HRESULT::from_win32(ERROR_LOCK_VIOLATION.0) => on_wait(),
            Err(e) => return Err(e).with_context(|| format!("lock {}", path.display())),
        }
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
