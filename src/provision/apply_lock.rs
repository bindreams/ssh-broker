//! provision::apply_lock — one `apply` at a time on a machine, and no `auto-login on|off` during one.
//!
//! `apply` stops agents and sessions, waits for them, replaces the exe and starts them again, and
//! the boot self-heal task runs `apply` by itself, so two can overlap; an `auto-login` command that
//! registers a task, or deletes one, in the middle of an `apply` would have it stop or start a
//! session that command is changing. The lock is held for the whole run of each; the system
//! releases it with its process.

use std::path::Path;

use crate::agent_lock::UserLock;

/// The right to be the one running `apply` (or `auto-login on|off`). Held until dropped.
#[derive(Debug)]
pub struct ApplyLock {
    _lock: UserLock,
}

/// Take the lock in `lock_path`, waiting for it if another holds it.
///
/// The lock file is private to SYSTEM and Administrators ([`crate::acl::ensure_admin_only_file`]),
/// made so or checked to be so before the lock is asked for: a lock any local user could open could
/// be held by one for ever, and `apply` and the boot self-heal would wait on it without end.
///
/// `on_wait` runs once, after the lock was found held and before the wait begins. The wait has no
/// limit: the holder is a command that exists, and the system ends the lock if it dies.
pub fn acquire(lock_path: &Path, on_wait: impl FnOnce()) -> anyhow::Result<ApplyLock> {
    acquire_with(crate::acl::ensure_admin_only_file, lock_path, on_wait)
}

/// [`acquire`] with the making of the lock file as a parameter, so a test can see that it comes
/// first and needs no elevation.
fn acquire_with(
    make_private: impl FnOnce(&Path) -> anyhow::Result<()>,
    lock_path: &Path,
    on_wait: impl FnOnce(),
) -> anyhow::Result<ApplyLock> {
    make_private(lock_path)?;
    Ok(ApplyLock {
        _lock: UserLock::acquire(lock_path, on_wait)?,
    })
}

#[cfg(test)]
#[path = "apply_lock_tests.rs"]
mod apply_lock_tests;
