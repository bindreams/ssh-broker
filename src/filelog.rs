//! filelog: the rolling log file the shim and the agent write into the user's own folder.
//!
//! The folder is `<profile>\AppData\Local\ssh-broker\logs`, inside the same private directory as
//! the socket, so a log is readable and writable by exactly the account that produced it (and
//! SYSTEM and Administrators), and an ordinary user can log at all. (It used to be an
//! administrator-only folder under `ProgramData`, where an unprivileged shim logged nothing.)

use std::path::Path;

use tracing_appender::non_blocking::WorkerGuard;

use crate::acl::Sid;
use crate::socket_loc::SocketLocation;

/// Initialise a rolling file log in `dir`, named `<prefix>.<date>`. Best-effort: `None` (logging
/// disabled) on any failure so the caller still works. NEVER logs to stdout/stderr, which would
/// corrupt a PTY stream. Keep the guard alive until the process exits: dropping it shuts the
/// writer down and later lines are discarded.
pub fn init_in(dir: &Path, prefix: &str) -> Option<WorkerGuard> {
    std::fs::create_dir_all(dir).ok()?;
    // `rolling::daily` panics when the first log file cannot be created; the builder returns the
    // error instead.
    let appender = tracing_appender::rolling::RollingFileAppender::builder()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix(prefix)
        .build(dir)
        .ok()?;
    let (writer, guard) = tracing_appender::non_blocking(appender);
    let _ = tracing_subscriber::fmt()
        .with_writer(writer)
        .with_ansi(false)
        .try_init();
    Some(guard)
}

/// Log into the logs folder of `loc`, making the private folder first if it is missing. `None` if
/// the folder cannot be made or trusted (no profile, a link in the way, a foreign owner).
pub fn init_for_location(loc: &SocketLocation, user: &Sid, prefix: &str) -> Option<WorkerGuard> {
    crate::userdir::ensure_socket_dir(loc, user).ok()?;
    init_in(&loc.logs_dir(), prefix)
}

/// [`init_for_location`] for the account this process runs as.
pub fn init_for_current_user(prefix: &str) -> Option<WorkerGuard> {
    let loc = crate::userdir::current_socket_location().ok()?;
    init_for_location(&loc, &Sid::current_user().ok()?, prefix)
}

#[cfg(test)]
#[path = "filelog_tests.rs"]
mod filelog_tests;
