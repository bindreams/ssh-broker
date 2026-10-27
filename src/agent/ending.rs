//! The one way the agent's process ends.
//!
//! The agent has several threads that end the process: the `logout` handler once the shells'
//! output is delivered, the accept loop once it has stopped, and the main thread when the agent
//! fails. Each of them used to end it on its own (`process::exit` from one, a return from `main`
//! into the C runtime's `exit` from another), so two could be inside the process's exit at once.
//! Every end goes through [`end_process`] now, and the first one in is the only one that ends it.
//!
//! The log's guard lives here too, because the thread that ends the process is not the one that
//! opened the log, and the exit runs no destructor: [`end_process`] drops the guard, which writes out
//! what is queued, before it leaves.

use std::sync::{Mutex, Once};

use tracing_appender::non_blocking::WorkerGuard;

static ENDING: Ending = Ending::new();

/// Hand the log's guard over, to be flushed when the process ends. Until then it keeps the writer
/// alive: dropping a guard stops the writer and later lines are lost.
pub fn keep_log(guard: WorkerGuard) {
    ENDING.keep_log(guard);
}

/// End the process with `code`. The first caller ends it; a caller that comes while that is in
/// progress waits for it, and the process is gone before that wait is over.
pub fn end_process(code: i32) -> ! {
    ENDING.end(|| std::process::exit(code));
    unreachable!("the process has ended")
}

struct Ending {
    once: Once,
    log: Mutex<Option<WorkerGuard>>,
}

impl Ending {
    const fn new() -> Self {
        Self {
            once: Once::new(),
            log: Mutex::new(None),
        }
    }

    fn keep_log(&self, guard: WorkerGuard) {
        *self.log.lock().unwrap_or_else(|e| e.into_inner()) = Some(guard);
    }

    /// Flush the log and run `leave`, if no caller has begun to; otherwise wait until the one that
    /// did has finished.
    fn end(&self, leave: impl FnOnce()) {
        self.once.call_once(|| {
            drop(self.log.lock().unwrap_or_else(|e| e.into_inner()).take());
            leave();
        });
    }
}

#[cfg(test)]
#[path = "ending_tests.rs"]
mod ending_tests;
