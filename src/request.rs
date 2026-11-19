//! request: the client loop of the verbs that ask the invoking user's agent for something (`logout`): connect,
//! ask, retry once if the agent was ending, and report when there is no agent.

use std::io::{Read, Write};

use crate::protocol::{FrameKind, FrameReader, Stream, write_frame};
use crate::relay::{FrameSink, Outcome};
use crate::shim::{PROTOCOL_VIOLATION_CODE, closed_twice_message, map_outcome, peer_gone, pump_heard};

/// The exit code when the agent could not be reached for a reason other than not being there.
pub const UNREACHABLE_CODE: i32 = 4;

/// How asking the agent went.
#[derive(Debug)]
pub enum Asked {
    /// The agent answered, or the connection failed after it had: the exit code.
    Code(i32),
    /// The connection ended before the agent's first byte. An agent that is alive answers every
    /// connection, so this one is ending or gone.
    Unanswered,
}

/// Writes the reply of a request: the agent's stdout to `out` and everything else (its stderr) to `err`, then an exit
/// code. A reply is stderr only, except the output of a command the agent ran for `elevate`.
pub struct ReplySink<'a> {
    pub out: &'a mut dyn Write,
    pub err: &'a mut dyn Write,
}

impl FrameSink for ReplySink<'_> {
    fn on_data(&mut self, stream: Stream, bytes: &[u8]) -> anyhow::Result<()> {
        let to = match stream {
            Stream::Stdout => &mut *self.out,
            _ => &mut *self.err,
        };
        to.write_all(bytes)?;
        to.flush()?;
        Ok(())
    }
}

/// Send the request `payload` as a frame of `kind` over a connected transport and relay the reply to `out` and `err`
/// (see [`ReplySink`]): the ask of every verb, which `ask_at` runs. `payload` is what encoding the request gave, and
/// `what` says what was asked, for a request that cannot be sent. The transport is borrowed, not consumed: the caller
/// keeps it open until the process exits.
pub fn ask_with<R: Read, W: Write>(
    rx: &mut R,
    tx: &mut W,
    out: &mut dyn Write,
    err: &mut dyn Write,
    kind: FrameKind,
    payload: anyhow::Result<Vec<u8>>,
    what: &str,
) -> Asked {
    let sent = payload
        .and_then(|bytes| write_frame(tx, kind, &bytes))
        .and_then(|()| tx.flush().map_err(Into::into));
    if let Err(e) = sent {
        if peer_gone(&e).is_some() {
            return Asked::Unanswered;
        }
        let _ = writeln!(err, "ssh-broker: could not {what}: {e:#}");
        return Asked::Code(map_outcome(Ok(Outcome::PeerClosed)));
    }
    let pumped = pump_heard(rx, &mut FrameReader::new(), &mut ReplySink { out, err });
    if pumped.no_answer() {
        Asked::Unanswered
    } else {
        Asked::Code(pumped.code())
    }
}

/// Connect with `connect`, run `ask` on the connection, and hand its exit code to `exit` **while the
/// connection is still open**. A connect that fails because there is no agent (`no_session` says so) is
/// `no_session_line` and exit code 1; any other failure is reported with its cause and exits with
/// [`UNREACHABLE_CODE`], since an agent may well serve this user.
///
/// `ask` sends the verb's request over the connection and relays the answer to `err`; the connection is
/// borrowed, not consumed, and the caller keeps it open until the process exits (the agent may wait for the
/// client to close before it acts, and the client may be inside the tree it ends).
///
/// A connection that ends before the agent's first byte means the agent is ending or gone; connect once more,
/// which finds no agent or an agent that answers. A second such connection in a row breaks the protocol:
/// reported, exit [`PROTOCOL_VIOLATION_CODE`](crate::shim::PROTOCOL_VIOLATION_CODE).
pub fn ask_at<R, W, T>(
    mut connect: impl FnMut() -> anyhow::Result<(R, W)>,
    mut ask: impl FnMut(&mut R, &mut W, &mut dyn Write) -> Asked,
    no_session: impl Fn(&anyhow::Error) -> bool,
    no_session_line: &str,
    err: &mut dyn Write,
    exit: impl FnOnce(i32) -> T,
) -> T {
    let mut closed_before = false;
    loop {
        let (mut rx, mut tx) = match connect() {
            Ok(connection) => connection,
            Err(e) if no_session(&e) => {
                let _ = writeln!(err, "{no_session_line}");
                return exit(1);
            }
            Err(e) => {
                let _ = writeln!(err, "ssh-broker: could not reach your session: {e:#}");
                return exit(UNREACHABLE_CODE);
            }
        };
        match ask(&mut rx, &mut tx, err) {
            Asked::Code(code) => return exit(code),
            Asked::Unanswered if closed_before => {
                let _ = writeln!(err, "{}", closed_twice_message(None));
                return exit(PROTOCOL_VIOLATION_CODE);
            }
            Asked::Unanswered => closed_before = true,
        }
    }
}

#[cfg(test)]
#[path = "request_tests.rs"]
mod request_tests;
