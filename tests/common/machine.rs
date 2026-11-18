//! Machine-wide exclusion between the Elevated tests, across processes.
//!
//! A test that logs an account on, registers a task or starts an agent holds [`shared`]; a test that
//! stops or disables `seclogon`, replaces the machine install, runs `apply`, or otherwise changes what
//! the other tests depend on holds [`exclusive`]. CI runs nextest, one process per test, so the
//! exclusion is a lock on a file in the temp directory, which the kernel gives to a reader or to one
//! writer across processes (and across handles in one process, so `cargo test` is covered too) and
//! takes back when the holder ends, however it ends.
//!
//! The waits here have no bound: a holder is a test, and a test that hangs is ended by nextest's
//! bound, which releases its lock.
//!
//! CI also keeps the `exclusive` tests out of the parallel run (`.config/nextest.toml`, profile
//! `ci-exclusive`), because a writer waits for every reader and the lock is not fair: that split is only
//! so that they do not wait out the whole run. A new `exclusive` test missing from it is still correct,
//! only slow.
#![allow(dead_code)]

use fd_lock::{RwLock, RwLockReadGuard, RwLockWriteGuard};

/// The lock's file. The same path in every test process of a run.
fn lock() -> &'static mut RwLock<std::fs::File> {
    let path = std::env::temp_dir().join("ssh-broker-tests-machine.lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .unwrap_or_else(|e| panic!("open the machine lock {}: {e}", path.display()));
    // One handle per holder, kept for the life of the process: the guard borrows the lock.
    Box::leak(Box::new(RwLock::new(file)))
}

pub struct MachineShared(#[allow(dead_code)] RwLockReadGuard<'static, std::fs::File>);
pub struct MachineExclusive(#[allow(dead_code)] RwLockWriteGuard<'static, std::fs::File>);

/// Hold the machine alongside other shared holders.
pub fn shared() -> MachineShared {
    MachineShared(lock().read().expect("take the machine lock shared"))
}

/// Hold the machine alone: no shared holder, in any process, runs while this lives.
pub fn exclusive() -> MachineExclusive {
    MachineExclusive(lock().write().expect("take the machine lock exclusively"))
}
