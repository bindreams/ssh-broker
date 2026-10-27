//! provision::apply_lock — one `apply` at a time on a machine.
//!
//! `apply` disables tasks, waits for agents, replaces the exe and enables the tasks again, and the
//! boot self-heal task runs `apply` by itself, so two can overlap. The second would see the
//! first's disabled tasks and its record of them ([`super::pending_sessions`]) as the leftovers of
//! a killed run and undo them under it. The lock is held for the whole run, so a record found
//! under it is from a run that was killed: the system releases the lock with its process.

use std::path::Path;

use crate::agent_lock::UserLock;

use super::pending_sessions;

/// The right to be the one running `apply`. Held until dropped.
#[derive(Debug)]
pub struct ApplyLock {
    _lock: UserLock,
}

/// Take the lock in `lock_path`, waiting for it if another `apply` holds it, then read the record
/// at `pending_path`. The record is read only after the lock is held, so it cannot be one a
/// running `apply` is about to change.
///
/// `on_wait` runs once, after the lock was found held and before the wait begins. The wait has no
/// limit: the holder is an `apply` that exists, and the system ends the lock if it dies.
pub fn acquire_and_load(
    lock_path: &Path,
    pending_path: &Path,
    on_wait: impl FnOnce(),
) -> anyhow::Result<(ApplyLock, Vec<String>)> {
    let lock = ApplyLock {
        _lock: UserLock::acquire(lock_path, on_wait)?,
    };
    let owed = pending_sessions::load(pending_path)?;
    Ok((lock, owed))
}

#[cfg(test)]
#[path = "apply_lock_tests.rs"]
mod apply_lock_tests;
