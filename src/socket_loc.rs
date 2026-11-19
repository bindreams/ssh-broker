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

/// The per-user folder under `AppData\Local` of an agent below High. The only place the name is written.
pub const SOCKET_DIR_NAME: &str = "ssh-broker";
/// The per-user folder of an agent at High or above: born with the High mandatory label, so that a process
/// of the account below High cannot connect to what is in it. The only place the name is written.
pub const ELEVATED_SOCKET_DIR_NAME: &str = "ssh-broker-elevated";
pub const SOCKET_FILE_NAME: &str = "agent.sock";
/// The socket an agent at High keeps in the plain folder for requests (`logout`) from the processes of its
/// account below High. The only place the name is written.
pub const REQUEST_SOCKET_FILE_NAME: &str = "request.sock";
pub const LOCK_FILE_NAME: &str = "agent.lock";
pub const SESSIONS_LOCK_FILE_NAME: &str = "sessions.lock";
pub const LOGS_DIR_NAME: &str = "logs";
pub const SERVING_MARKER_NAME: &str = "serving";

/// The folders between the profile directory and the private folder, in the order a walk opens them.
/// [`SocketLocation::dir`] is built from these, so a walk over them reaches that folder and no other.
pub const FOLDERS_IN_PROFILE: [&str; 2] = ["AppData", "Local"];

/// The integrity level of the processes a location serves: the agent that keeps its socket there, and the
/// processes that connect to it. An agent at High or above (an administrator's elevated session) keeps
/// its socket in a folder of its own, labelled High.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Integrity {
    Medium,
    High,
}

impl Integrity {
    pub fn dir_name(self) -> &'static str {
        match self {
            Integrity::Medium => SOCKET_DIR_NAME,
            Integrity::High => ELEVATED_SOCKET_DIR_NAME,
        }
    }
}

/// How much of an administrator's power a token carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Elevation {
    /// An administrator's full token: `Administrators` enabled, integrity High or above.
    Full,
    /// An administrator account's token cut down, as UAC gives a non-elevated process: the
    /// `Administrators` group is deny-only or disabled, or the integrity level is below High.
    Filtered,
    /// A token of an account that is not an administrator.
    Standard,
}

/// What a session of a login is started with: the answer of [`crate::account::step_down`].
#[derive(Debug, PartialEq, Eq)]
pub enum StepDown<K> {
    /// The stepped-down token, in place of this process's own.
    Token(K),
    /// This process's own token: at High the login asked for an elevated session, below High what a
    /// process starts is unelevated anyway.
    Own,
    /// No session: the login asked for an elevated one and this process is below High.
    Refused,
    /// A login that set nothing could not be stepped down; the error is why, formatted with its context. The
    /// agent hosts no such session and hands it back (`FrameKind::HandBack`); in the shim's fail-open shell it
    /// runs with sshd's token, after a notice. A login that asked for a level is refused instead.
    Fallback(String),
}

/// What is said of a socket file at `path` that is not as the agent made it (`acl::verify_file_acl` is
/// false): it must grant exactly `grantee`, SYSTEM and Administrators and, for [`Integrity::High`], carry
/// the High label. One wording for the agent's refusal to bind and `verify`'s row.
pub fn file_acl_refusal(path: &Path, grantee: &str, integrity: Integrity) -> String {
    format!(
        "{} does not grant exactly {grantee}, SYSTEM and Administrators{}",
        path.display(),
        match integrity {
            Integrity::Medium => "",
            Integrity::High => ", or lacks the High integrity label",
        }
    )
}

/// A user's socket directory and the socket inside it. Made from a profile directory and an integrity
/// level and nothing else, so `dir` and `path` are always inside `profile`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketLocation {
    /// The profile directory `dir` is in.
    profile: PathBuf,
    integrity: Integrity,
    dir: PathBuf,
    path: PathBuf,
}

impl SocketLocation {
    fn in_profile(profile: &Path, integrity: Integrity) -> SocketLocation {
        let dir = FOLDERS_IN_PROFILE
            .iter()
            .fold(profile.to_path_buf(), |path, name| path.join(name))
            .join(integrity.dir_name());
        let path = dir.join(SOCKET_FILE_NAME);
        SocketLocation {
            profile: profile.to_path_buf(),
            integrity,
            dir,
            path,
        }
    }

    pub fn integrity(&self) -> Integrity {
        self.integrity
    }

    /// The private folder: the one the agent makes, the shim looks in and the socket is inside.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The socket the agent listens on.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The request socket: where an agent at High takes requests from the processes of its account below High.
    /// Inside [`SocketLocation::dir`], so it is as private as `path`; only a location at [`Integrity::Medium`]
    /// is where it is kept.
    pub fn request_path(&self) -> PathBuf {
        self.dir.join(REQUEST_SOCKET_FILE_NAME)
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

/// The path of `request.sock` is over the limit. [`for_profile`] measures `agent.sock` only, and where that fits and
/// this does not, no agent at High can exist for the profile: its own `agent.sock` is 7 bytes longer than this path.
/// Nothing is there to connect to, which is what a caller that looks for an agent takes this error for
/// ([`crate::console_prompt::is_no_agent`]).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{} is over the socket path limit, so no agent at High can exist for this profile", path.display())]
pub struct RequestPathTooLong {
    pub path: PathBuf,
}

/// The socket location inside `profile` for processes at `integrity`, or why it cannot be used. Only `agent.sock`
/// is measured: `request.sock` is bound by an agent at High in the plain folder, where its path is 7 bytes
/// shorter than that agent's own `agent.sock`, so it fits whenever the agent can start.
pub fn for_profile(profile: &Path, integrity: Integrity) -> Result<SocketLocation, SocketLocationError> {
    let location = SocketLocation::in_profile(profile, integrity);
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
