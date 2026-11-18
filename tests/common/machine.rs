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

/// Hold the machine alongside other shared holders, with `seclogon` running.
///
/// The shared holders start processes through Secondary Logon at the same moment, as they are released
/// together by an exclusive holder that ends. Against a stopped service each call starts it, and one of
/// two that start it at once is answered "An instance of the service is already running" (0x80070420) and
/// fails its test. So the service is made running here, before any holder uses it, by a wait on its real
/// state. No exclusive holder stops it while a shared one lives.
pub fn shared() -> MachineShared {
    let held = lock().read().expect("take the machine lock shared");
    seclogon_running();
    MachineShared(held)
}

/// Return when the `seclogon` service is running: start it if it is stopped, take another caller's start
/// that wins as ours, and wait out a start or a stop in progress. Each wait is on the service's own state,
/// with no bound of ours; a start that fails for a reason of its own (a disabled service) fails here.
fn seclogon_running() {
    const SCRIPT: &str = "$s = Get-Service -Name seclogon; \
        while ($s.Status -ne 'Running') { \
            if ($s.Status -eq 'Stopped') { \
                try { $s.Start() } catch { $s.Refresh(); if ($s.Status -eq 'Stopped') { throw } } \
            } elseif ($s.Status -eq 'StopPending') { $s.WaitForStatus('Stopped') } \
            else { $s.WaitForStatus('Running') }; \
            $s.Refresh() \
        }";
    let out = crate::desktop::output(std::process::Command::new("powershell").args([
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        SCRIPT,
    ]))
    .unwrap_or_else(|e| panic!("powershell did not run: {e}"));
    assert!(
        out.status.success(),
        "making sure seclogon is running failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Hold the machine alone: no shared holder, in any process, runs while this lives.
pub fn exclusive() -> MachineExclusive {
    MachineExclusive(lock().write().expect("take the machine lock exclusively"))
}
