//! request: the client loop of the verbs that ask the invoking user's agent for something (`logout`; `elevate`
//! next), over whichever socket reaches it.
//!
//! What is asked is the verb's own (`ask`); this is how the agent is found again once, what is said when
//! there is none, and the exit codes.

use std::io::Write;

use crate::shim::{PROTOCOL_VIOLATION_CODE, closed_twice_message};

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

/// Connect with `connect`, run `ask` on the connection, and hand its exit code to `exit` **while the
/// connection is still open**. A connect that fails because there is no agent (`no_session` says so) is
/// `no_session_line` and exit code 1; any other failure is reported with its cause and exits with
/// [`UNREACHABLE_CODE`], since an agent may well serve this user.
///
/// `ask` sends the verb's request over the connection and relays the answer to `err`; the connection is
/// borrowed, not consumed, and the caller keeps it open until the process exits (the agent may wait for the
/// client to close before it acts, and the client may be inside the tree it ends).
///
/// A connection that ends before the agent's first byte means the agent is ending (its listener closed
/// with this request queued) or gone: the session the user asked about is ending already. It connects
/// again, and the next connect finds no agent (the outcome of asking a moment later) or an agent that
/// answers. A second connection in a row that ends before the first byte breaks the protocol (an agent
/// that follows it closes without a byte only while its listener closes, as an older agent that does not
/// know the request does not): it is reported and exits with
/// [`PROTOCOL_VIOLATION_CODE`](crate::shim::PROTOCOL_VIOLATION_CODE).
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
