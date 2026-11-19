//! logout: `ssh-broker logout`, the client side. Asks the invoking user's agent to end its
//! background session.
//!
//! The usual place to type it is a shell hosted by that very agent, so the client is inside the
//! tree the agent ends. The agent therefore waits for the client to close the connection before it
//! ends anything, and the client never closes the connection itself: it fixes its exit code, and
//! the kernel closes the socket when the process exits.
//!
//! Which socket it asks is [`connect_in`]'s rule. The reason: an agent at High keeps `agent.sock` in a folder with
//! the High label, which a process below High cannot connect to, and `request.sock` in the plain folder, which it
//! can.

use std::io::{Read, Write};

use crate::account::Elevation;
use crate::console_prompt::is_no_agent;
use crate::protocol::{FrameKind, Launch, Mode};
use crate::request::{Asked, ask_at, ask_with};
use crate::shim::make_handshake;
use crate::socket_loc::Integrity;

/// What `logout` says when there is no agent to ask.
pub const NO_SESSION: &str = "ssh-broker: no session to end.";

/// The line for "no agent to ask". An unelevated process of an account whose agent runs at High (`Filtered`, or a
/// split account like Backup Operators that reads `Standard`) gets the elevated-agent line when
/// `elevated_folder` ([`elevated_folder_exists`]) says the account has the folder of an agent at High, since it
/// can reach that agent only on `request.sock`. An unreadable elevation, or a `Standard` process that could not
/// look for the folder, gets the plain line plus the cause.
pub fn no_session_line(elevation: &anyhow::Result<Elevation>, elevated_folder: &anyhow::Result<bool>) -> String {
    let unchecked = match (elevation, elevated_folder) {
        (Ok(Elevation::Filtered), _) | (Ok(Elevation::Standard), Ok(true)) => return where_to_run_line(),
        (Ok(Elevation::Standard), Err(e)) => crate::offer::text::elevated_session_unchecked_clause(&format!("{e:#}")),
        (Ok(Elevation::Full | Elevation::Standard), _) => return NO_SESSION.to_owned(),
        (Err(e), _) => crate::offer::text::elevation_unreadable_clause(&format!("{e:#}")),
    };
    format!("{NO_SESSION} Note: {unchecked}, so the session may be elsewhere.")
}

/// What an unelevated process of an account whose agent runs at High is told when neither socket it can reach is served.
fn where_to_run_line() -> String {
    format!(
        "ssh-broker: no session to end that this process can reach: {}.",
        crate::offer::text::ELEVATED_AGENT_LOOKS_ELSEWHERE
    )
}

/// Whether the profile `profile` has the folder of an agent at High: one has been here. The folder is
/// made by an agent at High and by nothing else, so its presence is what an unelevated process can see of that
/// agent when it serves no socket it can reach. A profile too long for an agent at High has none; a folder that
/// cannot be looked at is an error, which is not "absent".
fn elevated_folder_exists(profile: &std::path::Path) -> anyhow::Result<bool> {
    use anyhow::Context;
    match crate::socket_loc::for_profile(profile, Integrity::High) {
        Ok(location) => location
            .dir()
            .try_exists()
            .with_context(|| format!("look at {}", location.dir().display())),
        Err(crate::socket_loc::SocketLocationError::TooLong { .. }) => Ok(false),
    }
}

/// Send the `Logout` handshake over a connected transport and relay the reply to `err`: the reply of `logout` is
/// stderr only. The transport is borrowed, not consumed: the caller keeps it open until the process exits.
pub fn logout_on<R: Read, W: Write>(rx: &mut R, tx: &mut W, err: &mut dyn Write) -> Asked {
    let mut handshake = make_handshake(&None, false, Launch::Direct, String::new(), 0, 0, None);
    handshake.mode = Mode::Logout;
    ask_with(
        rx,
        tx,
        &mut std::io::stdout(),
        err,
        FrameKind::Handshake,
        handshake.encode(),
        "ask the agent to end the session",
    )
}

/// Connect to the agent that serves a process at `integrity`: `agent` is the connect to `agent.sock` of its
/// folder and `request` the connect to `request.sock` of it. A process at High asks `agent.sock` only. One below
/// High asks `agent.sock` of the plain folder, and `request.sock` there when `no_agent` says nothing serves the
/// first: an agent at High keeps only the second in that folder. A failure that is not the absence of an agent
/// (a socket that refuses this process, say) is the answer as it is, and the second socket is not tried.
fn connect_in<S>(
    integrity: Integrity,
    agent: impl FnOnce() -> anyhow::Result<S>,
    request: impl FnOnce() -> anyhow::Result<S>,
    no_agent: impl Fn(&anyhow::Error) -> bool,
) -> anyhow::Result<S> {
    match agent() {
        Err(e) if integrity == Integrity::Medium && no_agent(&e) => request(),
        asked => asked,
    }
}

/// `ssh-broker logout`: ask the invoking user's agent, found by the same rule as the shim's (the
/// profile of this process's token), to end its background session.
pub fn run() -> anyhow::Result<()> {
    let connect = || {
        let folder = crate::userdir::inspect_current_socket_dir()?;
        let conn = connect_in(
            folder.location().integrity(),
            || folder.connect(),
            || folder.connect_request(),
            is_no_agent,
        )?;
        crate::afunix::split(conn)
    };
    // No profile, no folder and nothing listening all mean there is no session; anything else is not
    // that.
    let no_session = |e: &anyhow::Error| e.downcast_ref::<crate::userdir::NoProfile>().is_some() || is_no_agent(e);
    let elevated_folder = match crate::userdir::current_profile_dir() {
        Ok(profile) => elevated_folder_exists(&profile),
        Err(e) if e.is::<crate::userdir::NoProfile>() => Ok(false),
        Err(e) => Err(e),
    };
    let line = no_session_line(&crate::account::elevation(), &elevated_folder);
    ask_at(connect, logout_on, no_session, &line, &mut std::io::stderr(), |code| {
        std::process::exit(code)
    })
}

#[cfg(test)]
#[path = "logout_tests.rs"]
mod logout_tests;
