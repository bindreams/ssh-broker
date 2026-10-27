//! The one way the agent's process ends.
//!
//! The agent has several threads that end the process: the `logout` handler once the shells'
//! output is delivered, the accept loop once it has stopped, and the main thread when the agent
//! fails. Each of them used to end it on its own (`process::exit` from one, a return from `main`
//! into the C runtime's `exit` from another), so two could be inside the process's exit at once.
//! Every end goes through [`end_process`] now, and the first one in is the only one that ends it.

use std::sync::Once;

static ENDING: Once = Once::new();

/// End the process with `code`. The first caller ends it; a caller that comes while that is in
/// progress waits for it, and the process is gone before that wait is over.
pub fn end_process(code: i32) -> ! {
    end_once(&ENDING, || std::process::exit(code));
    unreachable!("the process has ended")
}

/// Run `end` if no caller has begun to; otherwise wait until the one that did has finished.
fn end_once(once: &Once, end: impl FnOnce()) {
    once.call_once(end);
}

#[cfg(test)]
#[path = "ending_tests.rs"]
mod ending_tests;
