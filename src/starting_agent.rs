//! starting_agent: telling an agent that is starting from no agent.
//!
//! A connect to the agent's socket is refused (`WSAECONNREFUSED`) both in the window between the
//! agent creating the socket file and calling `listen()`, and when the file is left over from an
//! agent that ended. The code cannot tell them apart. The user's lock can: an agent takes
//! `agent.lock` before it binds and keeps it until it ends, and the system releases it if the agent
//! dies. A refused connect with the lock held is a starting agent; with the lock free it is none.

use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Threading::{CreateEventW, SetEvent};
use windows::core::PCWSTR;

use crate::agent_lock::UserLock;
use crate::winutil::OwnedHandle;

/// Whether an agent holds the lock at `path`. A lock file that does not exist is no agent's, and
/// looking never creates it. The lock is taken to look and released at once, which an agent
/// waiting for it (`UserLock::acquire`) does not notice.
pub fn is_held(path: &Path) -> anyhow::Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    Ok(UserLock::try_acquire(path)?.is_none())
}

/// A kernel event that threads may signal and wait on.
struct Signal(OwnedHandle);

// SAFETY: signalling and waiting on an event handle from several threads is what events are for,
// and the handle is closed once, when the last `Arc` goes.
unsafe impl Sync for Signal {}

/// Signals when the holder of the lock at a path has ended. Nothing is polled: a thread waits for
/// the lock itself, so the signal is the system's release of it.
pub struct HolderWatch {
    signal: Arc<Signal>,
}

impl HolderWatch {
    /// Start watching. The thread takes the lock when its holder ends, releases it at once and
    /// then signals, so whoever sees the signal finds the lock free. If the thread cannot take the
    /// lock it signals too: the holder can no longer be told apart from none, and the waiter would
    /// otherwise sleep forever. The thread outlives the watch if the holder does; it ends with the
    /// process.
    pub fn start(path: &Path) -> anyhow::Result<HolderWatch> {
        // SAFETY: an unnamed manual-reset event, not signalled.
        let event = unsafe { CreateEventW(None, true, false, PCWSTR::null()) }.context("CreateEventW")?;
        let signal = Arc::new(Signal(OwnedHandle(event)));
        let thread_signal = Arc::clone(&signal);
        let path = path.to_path_buf();
        std::thread::Builder::new()
            .name("holder-watch".into())
            .spawn(move || {
                match UserLock::acquire(&path, || {}) {
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
