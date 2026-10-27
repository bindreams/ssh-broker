//! logout: `ssh-broker logout`, the client side. Asks the invoking user's agent to end its
//! background session.
//!
//! The usual place to type it is a shell hosted by that very agent, so the client is inside the
//! tree the agent ends. The agent therefore waits for the client to close the connection before it
//! ends anything, and the client never closes the connection itself: it fixes its exit code, and
//! the kernel closes the socket when the process exits.

use std::io::{Read, Write};

use crate::protocol::{FrameKind, FrameReader, Mode, Stream, write_frame};
use crate::relay::{FrameSink, Outcome, pump_decode};
use crate::shim::{make_handshake, map_outcome};

/// What `logout` says when there is no agent to ask.
pub const NO_SESSION: &str = "ssh-broker: no session to end.";
/// The exit code when the agent closed the connection without a single frame.
pub const NO_ANSWER_CODE: i32 = 3;
/// The exit code when the agent could not be reached for a reason other than not being there.
pub const UNREACHABLE_CODE: i32 = 4;

/// The one sentence for an agent that closed without answering. An agent of a build before
/// `logout` cannot decode the request and drops the connection without a reply; a crashed or
/// hung-up agent looks the same, and the sentence says so.
pub fn no_answer_notice(exe: &str) -> String {
    format!("ssh-broker: the agent did not answer. If your agent is older than this ssh-broker, run {exe} apply.")
}

/// Writes the agent's stderr to `err` and notes that a frame arrived.
struct ReplySink<'a> {
    err: &'a mut dyn Write,
    frames: usize,
}

impl FrameSink for ReplySink<'_> {
    fn on_data(&mut self, _stream: Stream, bytes: &[u8]) -> anyhow::Result<()> {
        self.frames += 1;
        self.err.write_all(bytes)?;
        self.err.flush()?;
        Ok(())
    }
}

/// Send the `Logout` handshake over a connected transport, relay the reply to `err`, and return the
/// exit code. The transport is borrowed, not consumed: the caller keeps it open until the process
/// exits.
pub fn logout_on<R: Read, W: Write>(rx: &mut R, tx: &mut W, err: &mut dyn Write, exe: &str) -> i32 {
    let mut handshake = make_handshake(&None, String::new(), 0, 0);
    handshake.mode = Mode::Logout;
    let sent = handshake
        .encode()
        .and_then(|bytes| write_frame(tx, FrameKind::Handshake, &bytes))
        .and_then(|()| tx.flush().map_err(Into::into));
    if let Err(e) = sent {
        let _ = writeln!(err, "ssh-broker: could not ask the agent to end the session: {e:#}");
        return crate::shim::map_outcome(Ok(Outcome::PeerClosed));
    }
    let mut sink = ReplySink { err, frames: 0 };
    let outcome = pump_decode(rx, &mut FrameReader::new(), &mut sink);
    match outcome {
        Ok(Outcome::Exited(code)) => code,
        Ok(Outcome::PeerClosed) if sink.frames == 0 => {
            let _ = writeln!(sink.err, "{}", no_answer_notice(exe));
            NO_ANSWER_CODE
        }
        other => map_outcome(other),
    }
}

/// Connect with `connect`, run [`logout_on`], and hand its exit code to `exit` **while the
/// connection is still open**. A connect that fails because there is no agent (`no_session` says
/// so) is `NO_SESSION` and exit code 1; any other failure is reported with its cause and exits
/// with [`UNREACHABLE_CODE`], since an agent may well serve this user.
pub fn logout_at<R: Read, W: Write, T>(
    connect: impl FnOnce() -> anyhow::Result<(R, W)>,
    no_session: impl FnOnce(&anyhow::Error) -> bool,
    err: &mut dyn Write,
    exe: &str,
    exit: impl FnOnce(i32) -> T,
) -> T {
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
    let code = logout_on(&mut rx, &mut tx, err, exe);
    exit(code)
}

/// `ssh-broker logout`: ask the invoking user's agent, found by the same rule as the shim's (the
/// profile of this process's token), to end its background session.
pub fn run() -> anyhow::Result<()> {
    let exe = crate::provision::canonical_exe();
    let connect = || {
        let location = crate::userdir::current_socket_location()?;
        let conn = crate::afunix::connect(&location.path)?;
        crate::afunix::split(conn)
    };
    // No profile and nothing listening both mean there is no session; anything else is not that.
    let no_session = |e: &anyhow::Error| {
        e.downcast_ref::<crate::userdir::NoProfile>().is_some() || crate::console_prompt::is_no_agent(e)
    };
    logout_at(connect, no_session, &mut std::io::stderr(), &exe.to_string_lossy(), |code| {
        std::process::exit(code)
    })
}

#[cfg(test)]
#[path = "logout_tests.rs"]
mod logout_tests;
