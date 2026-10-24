//! filelog: the rolling log file the shim and the agent write into the user's own folder.
//!
//! The folder is `<profile>\AppData\Local\ssh-broker\logs`, inside the same private directory as
//! the socket, so a log is readable and writable by exactly the account that produced it (and
//! SYSTEM and Administrators), and an ordinary user can log at all.
//!
//! Setting the log up can fail (no profile, a link or a foreign owner where the folder should be,
//! a full disk). Every setup function returns the cause; whether the caller can say it, and where,
//! is the caller's to decide, because a PTY stream must not be written to.

use std::path::Path;

use anyhow::Context;
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};

use crate::acl::Sid;
use crate::socket_loc::SocketLocation;

/// A log file writer and the guard that flushes it.
type Sink = (NonBlocking, WorkerGuard);

/// Open the rolling file log in `dir`, named `<prefix>.<date>`, without installing it.
fn open_in(dir: &Path, prefix: &str) -> anyhow::Result<Sink> {
    std::fs::create_dir_all(dir).with_context(|| format!("create the log folder {}", dir.display()))?;
    // `rolling::daily` panics when the first log file cannot be created; the builder returns the
    // error instead.
    let appender = tracing_appender::rolling::RollingFileAppender::builder()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix(prefix)
        .build(dir)
        .with_context(|| format!("create the log file {prefix} in {}", dir.display()))?;
    Ok(tracing_appender::non_blocking(appender))
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

/// Initialise a rolling file log in `dir`, named `<prefix>.<date>`. NEVER logs to stdout/stderr,
/// which would corrupt a PTY stream. Keep the guard alive until the process exits: dropping it
/// shuts the writer down and later lines are discarded. The error says why there is no log; the
/// caller carries on without one.
pub fn init_in(dir: &Path, prefix: &str) -> anyhow::Result<WorkerGuard> {
    install(open_in(dir, prefix)?)
}

fn open_for_location(loc: &SocketLocation, user: &Sid, prefix: &str) -> anyhow::Result<Sink> {
    crate::userdir::ensure_socket_dir(loc, user)?;
    open_in(&loc.logs_dir(), prefix)
}

/// Log into the logs folder of `loc`, making the private folder first if it is missing. The error
/// says why not: no profile, a link in the way, a foreign owner.
pub fn init_for_location(loc: &SocketLocation, user: &Sid, prefix: &str) -> anyhow::Result<WorkerGuard> {
    install(open_for_location(loc, user, prefix)?)
}

/// [`init_for_location`] for the account this process runs as.
pub fn init_for_current_user(prefix: &str) -> anyhow::Result<WorkerGuard> {
    let loc = crate::userdir::current_socket_location()?;
    init_for_location(&loc, &Sid::current_user()?, prefix)
}

#[cfg(test)]
#[path = "filelog_tests.rs"]
mod filelog_tests;
