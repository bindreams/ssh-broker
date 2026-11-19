//! logout: `ssh-broker logout`, the client side. Asks the invoking user's agent to end its
//! background session.
//!
//! The usual place to type it is a shell hosted by that very agent, so the client is inside the
//! tree the agent ends. The agent therefore waits for the client to close the connection before it
//! ends anything, and the client never closes the connection itself: it fixes its exit code, and
//! the kernel closes the socket when the process exits.
//!
//! The socket it asks on depends on who it is. An agent at High keeps `agent.sock` in a folder with the High
//! label, which a process below High cannot connect to, and `request.sock` in the plain folder, which it can.
//! A process at High asks `agent.sock` of the elevated folder. A process below High looks in the plain folder:
//! `agent.sock` there is the account's agent (a standard account's, below High, keeps only that), and where
//! there is none, `request.sock` is the agent at High's.

use std::io::{Read, Write};

use crate::account::Elevation;
use crate::console_prompt::is_no_agent;
use crate::protocol::{FrameKind, FrameReader, Launch, Mode, Stream, write_frame};
use crate::relay::{FrameSink, Outcome};
use crate::request::{Asked, ask_at};
use crate::shim::{make_handshake, peer_gone, pump_heard};
use crate::socket_loc::Integrity;

/// What `logout` says when there is no agent to ask.
pub const NO_SESSION: &str = "ssh-broker: no session to end.";

/// The line for "there is no agent to ask". An elevation that cannot be read gets the plain line with the
/// cause after it, since the token may be a filtered one and the session may be elsewhere. Any other gets the
/// plain line: an administrator's unelevated process reaches an agent at High as any other does, so none
/// found is none.
pub fn no_session_line(elevation: &anyhow::Result<Elevation>) -> String {
    match elevation {
        Ok(Elevation::Filtered | Elevation::Full | Elevation::Standard) => NO_SESSION.to_owned(),
        Err(e) => format!(
            "{NO_SESSION} Note: {}, so the session may be elsewhere.",
            crate::offer::text::elevation_unreadable_clause(&format!("{e:#}"))
        ),
    }
}

/// Writes the agent's stderr to `err`.
struct ReplySink<'a> {
    err: &'a mut dyn Write,
}

impl FrameSink for ReplySink<'_> {
    fn on_data(&mut self, _stream: Stream, bytes: &[u8]) -> anyhow::Result<()> {
        self.err.write_all(bytes)?;
        self.err.flush()?;
        Ok(())
    }
}

/// Send the `Logout` handshake over a connected transport and relay the reply to `err`. The transport
/// is borrowed, not consumed: the caller keeps it open until the process exits.
pub fn logout_on<R: Read, W: Write>(rx: &mut R, tx: &mut W, err: &mut dyn Write) -> Asked {
    let mut handshake = make_handshake(&None, false, Launch::Direct, String::new(), 0, 0, None);
    handshake.mode = Mode::Logout;
    let sent = handshake
        .encode()
        .and_then(|bytes| write_frame(tx, FrameKind::Handshake, &bytes))
        .and_then(|()| tx.flush().map_err(Into::into));
    if let Err(e) = sent {
        if peer_gone(&e).is_some() {
            return Asked::Unanswered;
        }
        let _ = writeln!(err, "ssh-broker: could not ask the agent to end the session: {e:#}");
        return Asked::Code(crate::shim::map_outcome(Ok(Outcome::PeerClosed)));
    }
    let pumped = pump_heard(rx, &mut FrameReader::new(), &mut ReplySink { err });
    if pumped.no_answer() {
        Asked::Unanswered
    } else {
        Asked::Code(pumped.code())
    }
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
    let line = no_session_line(&crate::account::elevation());
    ask_at(connect, logout_on, no_session, &line, &mut std::io::stderr(), |code| {
        std::process::exit(code)
    })
}

#[cfg(test)]
#[path = "logout_tests.rs"]
mod logout_tests;
