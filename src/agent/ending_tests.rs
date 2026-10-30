//! Unit tests for the one way the agent's process ends. In-process: nothing here ends the process.
use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};

/// Threads that all begin to end the process at once (the logout handler once its drain is over, the
/// accept loop once it has stopped, the main thread on an error) end it by one path: the end runs once,
/// and no caller gets past the guard before it is done. Two threads in `ExitProcess` together (or one
/// in the C runtime's `exit`) are what this keeps the agent out of.
#[test]
fn threads_that_begin_to_end_the_process_together_end_it_once() {
    const THREADS: usize = 8;
    let ending = Ending::new();
    let ends = AtomicUsize::new(0);
    let done = AtomicBool::new(false);
    let at_start = Barrier::new(THREADS);
    std::thread::scope(|scope| {
        for _ in 0..THREADS {
            scope.spawn(|| {
                at_start.wait();
                ending.end(|| {
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

/// Stands in for the log's guard: dropping the real one writes out what is queued, so what matters is
/// that it is dropped, and before the process is left.
struct DropFlag(Arc<AtomicBool>);

impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// The thread that ends the process is not the one that opened the log (the `logout` handler runs on
/// a connection's thread; the log belongs to the thread that started the agent). The guard is dropped
/// by the time the process is left: the process's exit runs no destructor, so nothing else would flush
/// the writer's queue. This fails if the drop is taken out, whatever the writer's timing.
#[test]
fn the_log_is_flushed_before_the_process_is_left_by_whichever_thread_ends_it() {
    let ending = Ending::new();
    let dropped = Arc::new(AtomicBool::new(false));
    ending.keep_log(DropFlag(dropped.clone()));
    assert!(!dropped.load(Ordering::SeqCst), "keeping the guard must not drop it");

    let dropped_when_left = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let mut seen = None;
                ending.end(|| seen = Some(dropped.load(Ordering::SeqCst)));
                seen
            })
            .join()
            .unwrap()
    });
    assert_eq!(
        dropped_when_left,
        Some(true),
        "the guard was still alive when the process was left"
    );
}

/// What the agent holds for its successor to wait on (its session slot and user lock) is still held
/// when the process is left, and is never dropped by the end: the system releases it with the
/// process, which is what keeps a successor from starting while the old agent is still ending.
#[test]
fn what_is_held_until_the_end_is_still_held_when_the_process_is_left() {
    let ending = Ending::new();
    let dropped = Arc::new(AtomicBool::new(false));
    ending.hold_until_end(DropFlag(dropped.clone()));

    let mut dropped_when_left = None;
    ending.end(|| dropped_when_left = Some(dropped.load(Ordering::SeqCst)));

    assert_eq!(dropped_when_left, Some(false), "released before the process was left");
    assert!(!dropped.load(Ordering::SeqCst), "released by the end itself");
}
