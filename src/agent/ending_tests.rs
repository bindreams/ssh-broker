//! Unit tests for the one way the agent's process ends. In-process: nothing here ends the process.
use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Barrier, Mutex};

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

/// A file the log writes to, readable by the test while the log still holds it.
struct SharedBuffer(std::sync::Arc<Mutex<Vec<u8>>>);

impl std::io::Write for SharedBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The thread that ends the process is not the one that opened the log (the `logout` handler runs on
/// a connection's thread; the log belongs to the thread that started the agent). The lines written
/// before the end are in the log by the time the process is left: the process's exit runs no
/// destructor, so nothing else would flush the writer's queue.
#[test]
fn the_log_is_flushed_before_the_process_is_left_by_whichever_thread_ends_it() {
    let ending = Ending::new();
    let written = std::sync::Arc::new(Mutex::new(Vec::new()));
    let (mut writer, guard) = tracing_appender::non_blocking(SharedBuffer(written.clone()));
    ending.keep_log(guard);
    std::io::Write::write_all(&mut writer, b"the background session has ended\n").unwrap();

    let seen_when_left = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let mut seen = Vec::new();
                ending.end(|| seen = written.lock().unwrap().clone());
                seen
            })
            .join()
            .unwrap()
    });
    assert_eq!(
        String::from_utf8(seen_when_left).unwrap(),
        "the background session has ended\n"
    );
}
