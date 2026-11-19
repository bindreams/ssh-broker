//! provision::user_rows — the rows of the `verify` report about the invoking user's own agent.
//!
//! Every agent is per user, so `verify` reports on the account that runs it and says so. It does
//! not enumerate other profiles: reading another user's folder is not something an unprivileged
//! check should do, and each user can run `verify` for themselves.

use crate::account::Elevation;
use crate::acl::{self, Sid};
use crate::socket_loc::{self, SocketLocation};
use crate::userdir::{self, SocketDir};

use super::report::Check;

/// `socket location`: where this account's agent socket lives, or why there is none (no profile,
/// or a profile path too long for a socket).
pub fn socket_location_row(location: &anyhow::Result<SocketLocation>) -> Check {
    const NAME: &str = "socket location";
    match location {
        Ok(loc) => Check::new(NAME, true, loc.path().display().to_string()),
        Err(e) => Check::new(NAME, false, format!("{e:#}")),
    }
}

/// `socket dir ACL`: the socket folder is reached the way the agent reaches it (by handle from the
/// profile directory, no link below it) and grants exactly this account, SYSTEM and Administrators.
/// Nothing is made or changed: a folder that is not right is for the user to remove.
pub fn socket_dir_row(location: &anyhow::Result<SocketLocation>, user: &Sid) -> Check {
    let Ok(loc) = location else {
        return Check::new("socket dir ACL", false, "no socket location");
    };
    dir_row(
        "socket dir ACL",
        loc.dir(),
        "no agent has made it yet",
        user,
        loc,
        |folder| Ok(folder.dir),
    )
}

/// `log folder`: the folder the shim and the agent log into is judged the same way. If it is missing
/// or wrong, the shim and the agent run without a log, and nothing else says so.
pub fn log_folder_row(location: &anyhow::Result<SocketLocation>, user: &Sid) -> Check {
    let Ok(loc) = location else {
        return Check::new("log folder", false, "no socket location");
    };
    dir_row(
        "log folder",
        &loc.logs_dir(),
        "no log is being written",
        user,
        loc,
        |folder| folder.logs,
    )
}

/// The row for the folder `pick` takes out of the agent's walk: it passes when the folder is a real
/// directory with exactly the private ACL, and fails with the folder named when it is missing
/// (`absent_means` says what that costs) or refused (the text says why and what to do).
fn dir_row(
    name: &'static str,
    dir: &std::path::Path,
    absent_means: &str,
    user: &Sid,
    loc: &SocketLocation,
    pick: impl FnOnce(SocketDir) -> anyhow::Result<acl::DirHandle>,
) -> Check {
    match userdir::inspect_socket_dir(loc, user).and_then(pick) {
        Ok(_) => Check::new(name, true, format!("grantee={}", user.describe())),
        Err(e) if e.is::<acl::Missing>() => {
            Check::new(name, false, format!("{} does not exist: {absent_means}", dir.display()))
        }
        Err(e) => Check::new(name, false, format!("{e:#}")),
    }
}

/// `socket file ACL`: the socket file itself, which is what decides who can connect.
pub fn socket_file_row(location: &anyhow::Result<SocketLocation>, user: &Sid) -> Check {
    const NAME: &str = "socket file ACL";
    let Ok(loc) = location else {
        return Check::new(NAME, false, "no socket location");
    };
    if loc.path().symlink_metadata().is_err() {
        return Check::new(NAME, false, "no socket: no agent is serving this account");
    }
    match acl::verify_file_acl(loc.path(), user, loc.integrity()) {
        Ok(true) => Check::new(NAME, true, format!("grantee={}", user.describe())),
        Ok(false) => Check::new(
            NAME,
            false,
            socket_loc::file_acl_refusal(loc.path(), &user.describe(), loc.integrity()),
        ),
        Err(e) => Check::new(NAME, false, format!("{e:#}")),
    }
}

/// What to do when the agent is not there. The logon task discards the agent's stderr, and an error
/// before its log opens goes nowhere else; run by hand it prints that error. An administrator's agent
/// exits 68 at an ordinary prompt, so for them the hand run needs an elevated one.
const AGENT_HINT: &str = " (to see why, run `ssh-broker agent` in your desktop session; an administrator runs it \
                          from an elevated prompt)";

/// `socket reachable`: this account's agent answers on its socket, which is connected to through
/// the folder as the agent's own walk judges it: a folder that is refused is not connected through.
pub fn socket_reachable_row(location: &anyhow::Result<SocketLocation>, user: &Sid) -> Check {
    const NAME: &str = "socket reachable";
    match location {
        Ok(loc) => match userdir::inspect_socket_dir(loc, user).and_then(|folder| folder.connect()) {
            Ok(_) => Check::new(NAME, true, String::new()),
            Err(e) => Check::new(NAME, false, format!("{e:#}{AGENT_HINT}")),
        },
        Err(_) => Check::new(NAME, false, "no socket location"),
    }
}

/// What `verify` shows an administrator's unelevated process in place of the rows about the agent
/// (the explanation is `offer::text::ELEVATED_AGENT_LOOKS_ELSEWHERE`). Fails, because nothing was proven.
pub fn filtered_row() -> Check {
    Check::new(
        "socket reachable",
        false,
        crate::offer::text::ELEVATED_AGENT_LOOKS_ELSEWHERE,
    )
}

/// What `verify` shows for the account, chosen by the elevation of this process's token.
pub enum AccountRows {
    /// The rows about the agent.
    Agent,
    /// [`filtered_row`] in place of them.
    Filtered,
    /// The rows about the agent, after this failing row: the elevation could not be read, so they may be
    /// about the wrong folder.
    AgentAfter(Check),
}

/// Which rows the account gets, given the elevation of this process's token.
pub fn account_rows(elevation: &anyhow::Result<Elevation>) -> AccountRows {
    match elevation {
        Ok(Elevation::Filtered) => AccountRows::Filtered,
        Ok(Elevation::Full | Elevation::Standard) => AccountRows::Agent,
        Err(e) => AccountRows::AgentAfter(Check::new(
            "elevation",
            false,
            crate::offer::text::elevation_unreadable_clause(&format!("{e:#}")),
        )),
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
