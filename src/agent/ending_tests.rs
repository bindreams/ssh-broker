//! Unit tests for the one way the agent's process ends. In-process: nothing here ends the process.
use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Barrier, Once};

/// Threads that all begin to end the process at once (the logout handler once its drain is over, the
/// accept loop once it has stopped, the main thread on an error) end it by one path: the end runs once,
/// and no caller gets past the guard before it is done. Two threads in `ExitProcess` together (or one
/// in the C runtime's `exit`) are what this keeps the agent out of.
#[test]
fn threads_that_begin_to_end_the_process_together_end_it_once() {
    const THREADS: usize = 8;
    let once = Once::new();
    let ends = AtomicUsize::new(0);
    let done = AtomicBool::new(false);
    let at_start = Barrier::new(THREADS);
    std::thread::scope(|scope| {
        for _ in 0..THREADS {
            scope.spawn(|| {
                at_start.wait();
                end_once(&once, || {
                    ends.fetch_add(1, Ordering::SeqCst);
                    done.store(true, Ordering::SeqCst);
                });
                assert!(
                    done.load(Ordering::SeqCst),
                    "a caller got past the guard before the end was done"
                );
            });
        }
    });
    assert_eq!(ends.load(Ordering::SeqCst), 1);
}
