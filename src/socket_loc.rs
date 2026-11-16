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
pub const SESSIONS_LOCK_FILE_NAME: &str = "sessions.lock";
pub const LOGS_DIR_NAME: &str = "logs";
pub const SERVING_MARKER_NAME: &str = "serving";

/// The folders between the profile directory and the private folder, in the order a walk opens them.
/// [`SocketLocation::dir`] is built from these, so a walk over them reaches that folder and no other.
pub const FOLDERS_IN_PROFILE: [&str; 2] = ["AppData", "Local"];

/// A user's socket directory and the socket inside it. Made from a profile directory and nothing
/// else, so `dir` and `path` are always inside `profile`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketLocation {
    /// The profile directory `dir` is in.
    profile: PathBuf,
    /// `<profile>\AppData\Local\ssh-broker`.
    dir: PathBuf,
    path: PathBuf,
}

impl SocketLocation {
    fn in_profile(profile: &Path) -> SocketLocation {
        let dir = FOLDERS_IN_PROFILE
            .iter()
            .fold(profile.to_path_buf(), |path, name| path.join(name))
            .join(SOCKET_DIR_NAME);
        let path = dir.join(SOCKET_FILE_NAME);
        SocketLocation {
            profile: profile.to_path_buf(),
            dir,
            path,
        }
    }

    /// The private folder: the one the agent makes, the shim looks in and the socket is inside.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The socket the agent listens on.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The lock file the agent holds while it serves.
    pub fn lock_path(&self) -> PathBuf {
        self.dir.join(LOCK_FILE_NAME)
    }

    /// The one file in which each session of the user locks its own byte, which makes an agent the
    /// one agent of its session.
    pub fn sessions_lock_path(&self) -> PathBuf {
        self.dir.join(SESSIONS_LOCK_FILE_NAME)
    }

    /// The file every agent rewrites once its listener is up. Its content means nothing and it is
    /// never read: the change in the folder is the signal a waiting shim watches for.
    pub fn serving_marker_path(&self) -> PathBuf {
        self.dir.join(SERVING_MARKER_NAME)
    }

    /// The profile directory this location was made from: where a walk to the folder starts.
    pub fn profile_dir(&self) -> &Path {
        &self.profile
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
    let location = SocketLocation::in_profile(profile);
    let bytes = location.path.as_os_str().len();
    if bytes > MAX_SOCKET_PATH_BYTES {
        return Err(SocketLocationError::TooLong {
            path: location.path,
            bytes,
            max: MAX_SOCKET_PATH_BYTES,
        });
    }
    Ok(location)
}

#[cfg(test)]
#[path = "socket_loc_tests.rs"]
mod socket_loc_tests;
