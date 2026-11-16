//! starting_agent: telling an agent that is starting from no agent.
//!
//! A connect to the agent's socket is refused (`WSAECONNREFUSED`) both in the window between the
//! agent creating the socket file and calling `listen()`, and when the file is left over from an
//! agent that ended. The code cannot tell them apart. The user's lock can: an agent takes
//! `agent.lock` before it binds and keeps it until it ends, and the system releases it if the agent
//! dies. A refused connect with the lock held is a starting agent; with the lock free it is none.

use std::sync::Arc;

use anyhow::Context;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::{FILE_ACCESS_RIGHTS, FILE_READ_DATA, FILE_WRITE_DATA};
use windows::Win32::System::Threading::{CreateEventW, SetEvent};
use windows::core::PCWSTR;

use crate::acl::{self, DirHandle};
use crate::agent_lock::UserLock;
use crate::socket_loc::LOCK_FILE_NAME;
use crate::winutil::OwnedHandle;

/// The lock file, open by handle in the user's private folder: `None` if there is none, and never
/// made by looking. A link at the name is refused. The access is what locking a byte takes.
fn open_lock(dir: &DirHandle) -> anyhow::Result<Option<std::fs::File>> {
    let access = FILE_ACCESS_RIGHTS(FILE_READ_DATA.0 | FILE_WRITE_DATA.0);
    acl::open_existing_file(dir, LOCK_FILE_NAME, access)
}

/// Whether an agent holds `agent.lock` in `dir`, the user's private folder. A lock file that does
/// not exist is no agent's, and looking never creates it. The lock is taken to look and released
/// at once, which an agent waiting for it (`UserLock::acquire`) does not notice.
pub fn is_held(dir: &DirHandle) -> anyhow::Result<bool> {
    let Some(file) = open_lock(dir)? else {
        return Ok(false);
    };
    Ok(UserLock::try_acquire_open(file, &dir.path().join(LOCK_FILE_NAME))?.is_none())
}

/// A kernel event that threads may signal and wait on.
struct Signal(OwnedHandle);

// SAFETY: signalling and waiting on an event handle from several threads is what events are for,
// and the handle is closed once, when the last `Arc` goes.
unsafe impl Sync for Signal {}

/// Signals when the holder of `agent.lock` in a folder has ended. Nothing is polled: a thread waits for
/// the lock itself, so the signal is the system's release of it.
pub struct HolderWatch {
    signal: Arc<Signal>,
}

impl HolderWatch {
    /// Start watching the lock in `dir`, the user's private folder, which is opened here and never
    /// made. The thread takes the lock when its holder ends, releases it at once and then
    /// signals, so whoever sees the signal finds the lock free. A lock file that is gone is no
    /// holder: the signal is set at once. If the thread cannot take the lock it signals too: the
    /// holder can no longer be told apart from none, and the waiter would otherwise sleep forever.
    pub fn start(dir: &DirHandle) -> anyhow::Result<HolderWatch> {
        let file = open_lock(dir)?;
        let name = dir.path().join(LOCK_FILE_NAME);
        // SAFETY: an unnamed manual-reset event, not signalled.
        let event = unsafe { CreateEventW(None, true, false, PCWSTR::null()) }.context("CreateEventW")?;
        let signal = Arc::new(Signal(OwnedHandle(event)));
        let thread_signal = Arc::clone(&signal);
        let Some(file) = file else {
            // SAFETY: the event just made.
            unsafe { SetEvent(signal.0.0) }.context("signal that the agent's lock is gone")?;
            return Ok(HolderWatch { signal });
        };
        std::thread::Builder::new()
            .name("holder-watch".into())
            .spawn(move || {
                match UserLock::acquire_open(file, &name, || {}) {
                    Ok(lock) => drop(lock),
                    Err(e) => tracing::warn!("cannot wait for the agent's lock: {e:#}"),
                }
                // SAFETY: the event lives as long as `thread_signal`.
                if let Err(e) = unsafe { SetEvent(thread_signal.0.0) } {
                    tracing::warn!("cannot signal that the agent's lock is free: {e}");
                }
            })
            .context("start the thread that waits for the agent's lock")?;
        Ok(HolderWatch { signal })
    }

    /// The event to wait on. Owned by `self`.
    pub fn handle(&self) -> HANDLE {
        self.signal.0.0
    }
}

#[cfg(test)]
#[path = "starting_agent_tests.rs"]
mod starting_agent_tests;
