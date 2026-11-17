//! filelog: the daily log file the shim and the agent write into the user's own folder.
//!
//! The folder is `logs` inside the socket's private directory ([`socket_loc`]), so a log is readable and
//! writable by exactly the account that produced it (and SYSTEM and Administrators).
//!
//! Setting the log up can fail (no profile, a link or a foreign owner where the folder should be,
//! a full disk). Every setup function returns the cause; whether the caller can say it, and where,
//! is the caller's to decide, because a PTY stream must not be written to.

use anyhow::Context;
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};

use crate::acl::DirHandle;

mod daily;

/// A log file writer and the guard that flushes it.
type Sink = (NonBlocking, WorkerGuard);

/// Open the daily file log in `dir`, named `<prefix>.<date>`, without installing it. The folder
/// is the handle's: the files are opened under it and never by a path.
fn open_in(dir: &DirHandle, prefix: &str) -> anyhow::Result<Sink> {
    let log = daily::daily(dir.try_clone()?, prefix)
        .with_context(|| format!("create the log file {prefix} in {}", dir.path().display()))?;
    Ok(tracing_appender::non_blocking(log))
}

/// Make `sink` the process's log.
fn install((writer, guard): Sink) -> anyhow::Result<WorkerGuard> {
    tracing_subscriber::fmt()
        .with_writer(writer)
        .with_ansi(false)
        .try_init()
        .map_err(|e| anyhow::anyhow!("a log subscriber is already installed in this process: {e}"))?;
    Ok(guard)
}

/// Initialise a daily file log in `dir`, named `<prefix>.<date>`. NEVER logs to stdout/stderr,
/// which would corrupt a PTY stream. Keep the guard alive until the process exits: dropping it
/// shuts the writer down and later lines are discarded. The error says why there is no log; the
/// caller carries on without one.
pub fn init_in(dir: &DirHandle, prefix: &str) -> anyhow::Result<WorkerGuard> {
    install(open_in(dir, prefix)?)
}

#[cfg(test)]
#[path = "filelog_tests.rs"]
mod filelog_tests;
