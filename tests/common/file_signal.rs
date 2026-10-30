//! Files as signals between a test and the stand-in processes it starts as other accounts. A network
//! token cannot use a named kernel object (see `socket_watch`), and a file in a directory both can
//! reach needs none. Included by the test crates and by `examples/session_stand_in`.
#![allow(dead_code)]

use std::path::Path;
use std::time::{Duration, Instant};

use ssh_broker::socket_watch::DirWatch;
use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::System::Threading::{GetExitCodeProcess, INFINITE, WaitForMultipleObjects};

/// What ended a wait for a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileWaited {
    /// The file exists.
    Appeared,
    /// The process ended first, with this exit code, and the file does not exist.
    ProcessEnded(u32),
}

/// Write `text` to `path` so that a reader who sees `path` sees all of `text`: it is written to a
/// sibling and renamed.
pub fn publish(path: &Path, text: &str) {
    let staging = path.with_extension("staging");
    std::fs::write(&staging, text).unwrap_or_else(|e| panic!("write {}: {e}", staging.display()));
    std::fs::rename(&staging, path).unwrap_or_else(|e| panic!("rename to {}: {e}", path.display()));
}

/// Block until `path` exists or `process` (a process handle, if any) ends. The directory watch is
/// armed before the file is looked for, so a file made in between is not missed. With a `bound`, a
/// file that neither appears nor is made by a process that ends is an external event that may never
/// come: expiry fails the wait, naming `what`. Without one the wait has no limit (for a stand-in that
/// the test ends).
pub fn wait_for_file(path: &Path, process: Option<HANDLE>, bound: Option<Duration>, what: &str) -> FileWaited {
    let dir = path.parent().expect("a signal file has a directory");
    let watch = DirWatch::arm(dir).unwrap_or_else(|e| panic!("{e:#}"));
    // One deadline for the whole wait: every change in the directory wakes it, and none restarts the bound.
    let deadline = bound.map(|b| Instant::now() + b);
    loop {
        if path.is_file() {
            return FileWaited::Appeared;
        }
        let millis = time_left(deadline).unwrap_or_else(|| {
            panic!("{what}: {} did not appear within {bound:?}", path.display());
        });
        let handles: Vec<HANDLE> = std::iter::once(watch.handle()).chain(process).collect();
        // SAFETY: every handle is valid for the call.
        let woke = unsafe { WaitForMultipleObjects(&handles, false, millis) }; // sleep-ok: failure bound on a process that may never write the file; expiry fails the wait and is not read as state
        if woke == WAIT_OBJECT_0 {
            watch.rearm().unwrap_or_else(|e| panic!("{e:#}"));
        } else if woke.0 == WAIT_OBJECT_0.0 + 1 {
            if path.is_file() {
                return FileWaited::Appeared;
            }
            let mut code = 0u32;
            // SAFETY: a valid process handle and out-pointer.
            unsafe { GetExitCodeProcess(process.expect("two handles mean a process"), &mut code) }
                .unwrap_or_else(|e| panic!("read the exit code while waiting for {what}: {e}"));
            return FileWaited::ProcessEnded(code);
        } else if woke == WAIT_TIMEOUT {
            // The loop looks once more and then reports the expiry.
        } else {
            panic!("waiting for {what} ({}) failed: {woke:?}", path.display());
        }
    }
}

/// The milliseconds of `deadline` that are left for a wait (`INFINITE` without a deadline), or `None` when
/// it has passed.
pub fn time_left(deadline: Option<Instant>) -> Option<u32> {
    let Some(deadline) = deadline else {
        return Some(INFINITE);
    };
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return None;
    }
    Some(u32::try_from(left.as_millis().max(1)).map_or(INFINITE - 1, |ms| ms.min(INFINITE - 1)))
}
