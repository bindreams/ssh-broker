//! agent_background: what differs when the agent runs as a background session.
//!
//! A background agent is started by `CreateProcessWithLogonW` (the password prompt) or by a Task
//! Scheduler boot task (`auto-login`), not by the logon task in the user's desktop session. It has
//! no console and no stderr, and before its log opens it cannot say why it stopped, so **the exit
//! code is the record**: the shim maps [`Refusal`]'s codes to fixed sentences.

use std::io::Write as _;

use crate::agent_lock::session_allows_agent;
use crate::route::BackgroundArgs;
use crate::socket_loc::SocketLocation;

/// Why an agent refused to start. The discriminant is the process exit code; any other failure
/// exits 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// The agent's token is not the account it was started for.
    #[error("this agent runs as a different account than the one it was started for")]
    WrongUser = 64,
    /// A desktop agent in session 0.
    #[error(
        "the agent will not run in session 0: a shell hosted there has the limited environment this tool \
         exists to avoid. It belongs in the user's interactive session; the logon task starts it there"
    )]
    SessionRefused = 65,
    /// No profile, or a profile path too long for a socket.
    #[error("the agent cannot place its socket in this account's profile")]
    NoSocketLocation = 66,
    /// The private socket folder is missing or is not safe to use.
    #[error("the agent's private socket folder cannot be used")]
    SocketFolderRefused = 67,
}

impl Refusal {
    pub fn code(self) -> i32 {
        self as i32
    }
}

/// The checks that come before the agent touches a file or a socket. `mode` is `None` for the
/// desktop agent (the logon task's) and `Some` for `agent --background`; `current_sid` is the SID
/// text of the agent's own token.
///
/// A background agent is allowed in any session including 0, because Task Scheduler's batch logon
/// puts the auto-login agent there (spike M5(d)); a desktop agent in session 0 is a mis-registered
/// task and is refused.
pub fn check_start(mode: Option<&BackgroundArgs>, session: u32, current_sid: &str) -> Result<(), Refusal> {
    let Some(background) = mode else {
        return if session_allows_agent(session) {
            Ok(())
        } else {
            Err(Refusal::SessionRefused)
        };
    };
    match background.expect_user.as_deref() {
        Some(expected) if expected != current_sid => Err(Refusal::WrongUser),
        _ => Ok(()),
    }
}

/// Rewrite the `serving` marker in the socket folder. Every agent calls this after its listener
/// is up: `bind` creates the socket file before it calls `listen`, a connect in that gap is
/// refused, and nothing in the folder changes at `listen`. The write is the change a waiting shim
/// can rely on coming after it.
pub fn mark_listening(location: &SocketLocation) -> std::io::Result<()> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let mut marker = std::fs::File::create(location.serving_marker_path())?;
    writeln!(marker, "{} {stamp}", std::process::id())
}

#[cfg(test)]
#[path = "agent_background_tests.rs"]
mod agent_background_tests;
