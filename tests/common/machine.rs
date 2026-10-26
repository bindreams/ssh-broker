//! Machine-wide exclusion between the Elevated tests of one test binary.
//!
//! libtest runs the tests of a binary on parallel threads. A test that logs an account on,
//! registers a task or starts an agent holds [`shared`]; a test that stops or disables `seclogon`,
//! replaces the machine install, runs `apply`, or otherwise changes what the other tests depend on
//! holds [`exclusive`]. The lock is per process: CI runs `cargo test`, not one process per test.
#![allow(dead_code)]

use std::sync::{PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

static MACHINE: RwLock<()> = RwLock::new(());

pub struct MachineShared(RwLockReadGuard<'static, ()>);
pub struct MachineExclusive(RwLockWriteGuard<'static, ()>);

/// Hold the machine alongside other shared holders. A panicked holder does not poison it.
pub fn shared() -> MachineShared {
    MachineShared(MACHINE.read().unwrap_or_else(PoisonError::into_inner))
}

/// Hold the machine alone: no shared holder runs while this lives.
pub fn exclusive() -> MachineExclusive {
    MachineExclusive(MACHINE.write().unwrap_or_else(PoisonError::into_inner))
}
