//! logout: `ssh-broker logout`, the client side. Asks the invoking user's agent to end its
//! background session.
//!
//! The usual place to type it is a shell hosted by that very agent, so the client is inside the
//! tree the agent ends. The agent therefore waits for the client to close the connection before it
//! ends anything, and the client never closes the connection itself: it fixes its exit code, and
//! the kernel closes the socket when the process exits.

use std::io::{Read, Write};

use crate::protocol::{FrameKind, FrameReader, Launch, Mode, Stream, write_frame};
use crate::relay::{FrameSink, Outcome};
use crate::shim::{PROTOCOL_VIOLATION_CODE, closed_twice_message, make_handshake, peer_gone, pump_heard};

/// What `logout` says when there is no agent to ask.
pub const NO_SESSION: &str = "ssh-broker: no session to end.";
/// The exit code when the agent could not be reached for a reason other than not being there.
pub const UNREACHABLE_CODE: i32 = 4;

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

/// How asking the agent to end the session went.
#[derive(Debug)]
pub enum Asked {
    /// The agent answered, or the connection failed after it had: the exit code.
    Code(i32),
    /// The connection ended before the agent's first byte. An agent that is alive answers every
    /// connection, so this one is ending or gone.
    Unanswered,
}

/// Send the `Logout` handshake over a connected transport and relay the reply to `err`. The transport
/// is borrowed, not consumed: the caller keeps it open until the process exits.
pub fn logout_on<R: Read, W: Write>(rx: &mut R, tx: &mut W, err: &mut dyn Write) -> Asked {
    let mut handshake = make_handshake(&None, false, Launch::Direct, String::new(), 0, 0);
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

/// Connect with `connect`, run [`logout_on`], and hand its exit code to `exit` **while the
/// connection is still open**. A connect that fails because there is no agent (`no_session` says
/// so) is `NO_SESSION` and exit code 1; any other failure is reported with its cause and exits
/// with [`UNREACHABLE_CODE`], since an agent may well serve this user.
///
/// A connection that ends before the agent's first byte means the agent is ending (its listener closed
/// with this request queued) or gone: the session the user asked to end is ending already. It connects
/// again, and the next connect finds no agent (the outcome of running `logout` a moment later) or an
/// agent that answers. A second connection in a row that ends before the first byte breaks the
/// protocol (an agent that follows it closes without a byte only while its listener closes, as an
/// older agent that does not know the request does not): it is reported and exits with
/// [`PROTOCOL_VIOLATION_CODE`](crate::shim::PROTOCOL_VIOLATION_CODE).
pub fn logout_at<R: Read, W: Write, T>(
    mut connect: impl FnMut() -> anyhow::Result<(R, W)>,
    no_session: impl Fn(&anyhow::Error) -> bool,
    err: &mut dyn Write,
    exit: impl FnOnce(i32) -> T,
) -> T {
    let mut closed_before = false;
    loop {
        let (mut rx, mut tx) = match connect() {
            Ok(connection) => connection,
            Err(e) if no_session(&e) => {
                let _ = writeln!(err, "{NO_SESSION}");
                return exit(1);
            }
            Err(e) => {
                let _ = writeln!(err, "ssh-broker: could not reach your session: {e:#}");
                return exit(UNREACHABLE_CODE);
            }
        };
        match logout_on(&mut rx, &mut tx, err) {
            Asked::Code(code) => return exit(code),
            Asked::Unanswered if closed_before => {
                let _ = writeln!(err, "{}", closed_twice_message(None));
                return exit(PROTOCOL_VIOLATION_CODE);
            }
            Asked::Unanswered => closed_before = true,
        }
    }
}

/// `ssh-broker logout`: ask the invoking user's agent, found by the same rule as the shim's (the
/// profile of this process's token), to end its background session.
pub fn run() -> anyhow::Result<()> {
    let connect = || {
        let location = crate::userdir::current_socket_location()?;
        let conn = crate::afunix::connect(&location.path)?;
        crate::afunix::split(conn)
    };
    // No profile and nothing listening both mean there is no session; anything else is not that.
    let no_session = |e: &anyhow::Error| {
        e.downcast_ref::<crate::userdir::NoProfile>().is_some() || crate::console_prompt::is_no_agent(e)
    };
    logout_at(connect, no_session, &mut std::io::stderr(), |code| {
        std::process::exit(code)
    })
}

#[cfg(test)]
#[path = "logout_tests.rs"]
mod logout_tests;
