//! provision::user_rows — the rows of the `verify` report about the invoking user's own agent.
//!
//! Every agent is per user, so `verify` reports on the account that runs it and says so. It does
//! not enumerate other profiles: reading another user's folder is not something an unprivileged
//! check should do, and each user can run `verify` for themselves.

use crate::acl::{self, Sid};
use crate::afunix;
use crate::socket_loc::SocketLocation;

use super::report::Check;

/// `socket location`: where this account's agent socket lives, or why there is none (no profile,
/// or a profile path too long for a socket).
pub fn socket_location_row(location: &anyhow::Result<SocketLocation>) -> Check {
    const NAME: &str = "socket location";
    match location {
        Ok(loc) => Check::new(NAME, true, loc.path.display().to_string()),
        Err(e) => Check::new(NAME, false, format!("{e:#}")),
    }
}

/// `socket dir ACL`: the socket folder grants exactly this account, SYSTEM and Administrators.
pub fn socket_dir_row(location: &anyhow::Result<SocketLocation>, user: &Sid) -> Check {
    let Ok(loc) = location else {
        return Check::new("socket dir ACL", false, "no socket location");
    };
    dir_row("socket dir ACL", &loc.dir, "no agent has made it yet", user)
}

/// `log folder`: the folder the shim and the agent log into grants exactly this account, SYSTEM
/// and Administrators. If it is missing or wrong, the shim and the agent run without a log, and
/// nothing else says so.
pub fn log_folder_row(location: &anyhow::Result<SocketLocation>, user: &Sid) -> Check {
    let Ok(loc) = location else {
        return Check::new("log folder", false, "no socket location");
    };
    dir_row("log folder", &loc.logs_dir(), "no log is being written", user)
}

fn dir_row(name: &'static str, dir: &std::path::Path, absent_means: &str, user: &Sid) -> Check {
    if !dir.exists() {
        return Check::new(name, false, format!("{} does not exist: {absent_means}", dir.display()));
    }
    match acl::verify_dir_acl(dir, user) {
        Ok(true) => Check::new(name, true, format!("grantee={}", user.describe())),
        Ok(false) => Check::new(
            name,
            false,
            format!(
                "{} does not grant exactly {}, SYSTEM and Administrators",
                dir.display(),
                user.describe()
            ),
        ),
        Err(e) => Check::new(name, false, format!("{e:#}")),
    }
}

/// `socket file ACL`: the socket file itself, which is what decides who can connect.
pub fn socket_file_row(location: &anyhow::Result<SocketLocation>, user: &Sid) -> Check {
    const NAME: &str = "socket file ACL";
    let Ok(loc) = location else {
        return Check::new(NAME, false, "no socket location");
    };
    if loc.path.symlink_metadata().is_err() {
        return Check::new(NAME, false, "no socket: no agent is serving this account");
    }
    match acl::verify_file_acl(&loc.path, user) {
        Ok(true) => Check::new(NAME, true, format!("grantee={}", user.describe())),
        Ok(false) => Check::new(
            NAME,
            false,
            format!(
                "{} does not grant exactly {}, SYSTEM and Administrators",
                loc.path.display(),
                user.describe()
            ),
        ),
        Err(e) => Check::new(NAME, false, format!("{e:#}")),
    }
}

/// What to do when the agent is not there. The logon task discards the agent's stderr, and an error
/// before its log opens goes nowhere else; run by hand it prints that error.
const AGENT_HINT: &str = " (to see why, run `ssh-broker agent` in your desktop session)";

/// `socket reachable`: this account's agent answers on its socket.
pub fn socket_reachable_row(location: &anyhow::Result<SocketLocation>) -> Check {
    const NAME: &str = "socket reachable";
    match location {
        Ok(loc) => match afunix::connect(&loc.path) {
            Ok(_) => Check::new(NAME, true, String::new()),
            Err(e) => Check::new(NAME, false, format!("{e:#}{AGENT_HINT}")),
        },
        Err(_) => Check::new(NAME, false, "no socket location"),
    }
}

/// `other users (info)`: says what `verify` covers. Never fails.
pub fn other_users_row() -> Check {
    Check::new(
        "other users (info)",
        true,
        "each user runs their own agent; run verify as that user",
    )
}

#[cfg(test)]
#[path = "user_rows_tests.rs"]
mod user_rows_tests;
