//! socket_loc: where a user's agent socket lives, and the length rule it must satisfy.
//!
//! Pure path arithmetic, so it is testable on every host. The agent and the shim both derive
//! the location from a profile directory and from nothing else: there is no override, because a
//! location the caller can choose is a location another account can point the shim at.

use std::path::{Path, PathBuf};

/// The longest socket path `afunix` accepts, in bytes: `sockaddr_un.sun_path` is 108 bytes and
/// `socket2` keeps one for the NUL. On Windows the count is WTF-8 bytes, which is what
/// `OsStr::len` returns, so non-ASCII profile names count for what they cost.
pub const MAX_SOCKET_PATH_BYTES: usize = 107;

/// The per-user folder under `AppData\Local`. The only place the name is written.
pub const SOCKET_DIR_NAME: &str = "ssh-broker";
pub const SOCKET_FILE_NAME: &str = "agent.sock";
pub const LOCK_FILE_NAME: &str = "agent.lock";
pub const LOGS_DIR_NAME: &str = "logs";

/// A user's socket directory and the socket inside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketLocation {
    pub dir: PathBuf,
    pub path: PathBuf,
}

impl SocketLocation {
    /// The lock file the agent holds while it serves.
    pub fn lock_path(&self) -> PathBuf {
        self.dir.join(LOCK_FILE_NAME)
    }

    /// The folder the shim and the agent log into.
    pub fn logs_dir(&self) -> PathBuf {
        self.dir.join(LOGS_DIR_NAME)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SocketLocationError {
    #[error(
        "the socket path {} is {bytes} bytes; the AF_UNIX limit is {max}. ssh-broker keeps the socket inside \
         your profile so that only you can reach it and will not move it; use a shorter profile path",
        path.display()
    )]
    TooLong { path: PathBuf, bytes: usize, max: usize },
}

/// The socket location inside `profile`, or why it cannot be used.
pub fn for_profile(profile: &Path) -> Result<SocketLocation, SocketLocationError> {
    let dir = profile.join("AppData").join("Local").join(SOCKET_DIR_NAME);
    let path = dir.join(SOCKET_FILE_NAME);
    let bytes = path.as_os_str().len();
    if bytes > MAX_SOCKET_PATH_BYTES {
        return Err(SocketLocationError::TooLong {
            path,
            bytes,
            max: MAX_SOCKET_PATH_BYTES,
        });
    }
    Ok(SocketLocation { dir, path })
}

#[cfg(test)]
#[path = "socket_loc_tests.rs"]
mod socket_loc_tests;
