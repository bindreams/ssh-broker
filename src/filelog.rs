//! filelog: the daily log file the shim and the agent write into the user's own folder.
//!
//! The folder is `<profile>\AppData\Local\ssh-broker\logs`, inside the same private directory as
//! the socket, so a log is readable and writable by exactly the account that produced it (and
//! SYSTEM and Administrators), and an ordinary user can log at all.
//!
//! Setting the log up can fail (no profile, a link or a foreign owner where the folder should be,
//! a full disk). Every setup function returns the cause; whether the caller can say it, and where,
//! is the caller's to decide, because a PTY stream must not be written to.

use anyhow::Context;
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};

use crate::acl::{self, DirHandle, Sid};
use crate::socket_loc::SocketLocation;

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

/// Why a log could not be set up. Its text is the cause's, whole.
#[derive(Debug, thiserror::Error)]
#[error("{cause:#}")]
pub struct NoLog {
    pub cause: anyhow::Error,
    /// The private folder itself (or the way to it) was refused, not only its `logs` folder: no agent
    /// can serve it either, which a caller that offers a session needs to know.
    pub folder_refused: bool,
}

impl NoLog {
    fn other(cause: anyhow::Error) -> NoLog {
        NoLog {
            cause,
            folder_refused: false,
        }
    }
}

fn open_for_location(loc: &SocketLocation, user: &Sid, prefix: &str) -> Result<Sink, NoLog> {
    let folders = crate::userdir::open_socket_dir(loc, user).map_err(|cause| NoLog {
        folder_refused: cause.is::<acl::Refused>(),
        cause,
    })?;
    open_in(&folders.logs.map_err(NoLog::other)?, prefix).map_err(NoLog::other)
}

/// Log into the logs folder of `loc`, making the private folder first if it is missing. The error
/// says why not: no profile, a link in the way, a foreign owner.
pub fn init_for_location(loc: &SocketLocation, user: &Sid, prefix: &str) -> Result<WorkerGuard, NoLog> {
    install(open_for_location(loc, user, prefix)?).map_err(NoLog::other)
}

/// [`init_for_location`] for the account this process runs as.
pub fn init_for_current_user(prefix: &str) -> Result<WorkerGuard, NoLog> {
    let loc = crate::userdir::current_socket_location().map_err(NoLog::other)?;
    init_for_location(&loc, &Sid::current_user().map_err(NoLog::other)?, prefix)
}

#[cfg(test)]
#[path = "filelog_tests.rs"]
mod filelog_tests;
