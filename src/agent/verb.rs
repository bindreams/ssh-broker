//! Starting the hidden `console-fallback` verb with the notice and the line in an inherited pipe.

use std::path::Path;

use crate::cmdline::join_args;
use crate::handoff;
use crate::shell::StartError;
use crate::winutil::{Handoff, OwnedHandle};

/// Start the verb of the program at `exe` with `start`, which gets the verb's command line and the
/// read end of the pipe the verb inherits, and returns what it started. The verb's argument is that
/// handle's value, the same in the child. Once the verb runs, `notice` and `line` are written into the
/// pipe, which is sized to hold them, and it is closed; a write that fails is logged, and the verb
/// reports the short read on its console.
///
/// Only a failure of `start` or of the pipe is an error, and then nothing runs.
pub(super) fn start<T>(
    exe: &Path,
    notice: &str,
    line: &str,
    login: bool,
    start: impl FnOnce(&str, &OwnedHandle) -> Result<T, StartError>,
) -> Result<T, StartError> {
    let bytes = handoff::encode(notice, line).map_err(StartError::Other)?;
    // Holds the whole message, so the write below does not wait for a verb that has not read yet.
    let capacity = u32::try_from(bytes.len())
        .map_err(|_| StartError::Other(anyhow::anyhow!("the fallback shell's hand-off is larger than 4 GiB")))?;
    let pipe = Handoff::new(capacity)?;
    let value = (pipe.read().0.0 as usize).to_string();
    let exe = exe.to_string_lossy();
    let mut args: Vec<&str> = vec![&exe, "console-fallback"];
    if login {
        args.push("--login");
    }
    args.push(&value);
    let started = start(&join_args(&args), pipe.read())?;
    if let Err(e) = pipe.send(&bytes) {
        tracing::warn!("could not hand the fallback shell to its verb: {e}");
    }
    Ok(started)
}

#[cfg(test)]
#[path = "verb_tests.rs"]
mod verb_tests;
