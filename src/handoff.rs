//! What the agent writes into the pipe it hands the hidden `console-fallback` verb: the notice to
//! print and the line to start.
//!
//! A pseudoconsole clears the screen after anything written ahead of the shell, so the agent starts
//! the verb, which prints the notice from inside the console and then starts the line. The line can be
//! as long as `CreateProcessW` takes, which leaves no room for it in the verb's own command line;
//! the verb reads both from an inherited pipe until the agent closes its end.

use anyhow::Context;

/// The bytes to write into the pipe for `notice` and `line`.
pub fn encode(notice: &str, line: &str) -> anyhow::Result<Vec<u8>> {
    postcard::to_stdvec(&(notice, line)).context("encode the notice and the line")
}

/// The notice and the line in `bytes`, everything the pipe held up to its end. A pipe cut short
/// (the agent died while writing) is an error, never a shorter line, and so are bytes left over.
pub fn decode(bytes: &[u8]) -> anyhow::Result<(String, String)> {
    let (handed, rest) = postcard::take_from_bytes(bytes).context("the agent's hand-off is not a notice and a line")?;
    anyhow::ensure!(
        rest.is_empty(),
        "the agent's hand-off has {} bytes after the line",
        rest.len()
    );
    Ok(handed)
}

#[cfg(test)]
#[path = "handoff_tests.rs"]
mod handoff_tests;
