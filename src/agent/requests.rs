//! The request socket: what an agent at High answers on `request.sock`, in the plain folder.
//!
//! A process of the account below High cannot connect to the agent's `agent.sock` (its folder carries the High
//! label), and an administrator's sessions are unelevated by default. The request socket is the way to the
//! agent for those: it takes requests only (`logout` now), and no session ever starts on it.
//!
//! Everything on it is input from a lower integrity level. It is read through the frame reader every
//! connection uses, whose frames are bounded; a first frame that is not a well-formed handshake is answered
//! as a failed request; and nothing read from it is used as a path. Any program of the account can connect
//! and say nothing, which holds a handler thread and delays the agent's end by up to the drain's bound
//! (`DRAIN_BOUND`): it is the same as holding `agent.sock` on a standard account, and the unelevated
//! session is a consent step, not a boundary.

use super::{Control, Opened, logout, read_request};
use crate::afunix;
use crate::protocol::Mode;

/// What a session handshake on the request socket is told.
pub const REQUESTS_ONLY: &str = "this socket takes requests only";

/// Serve one connection of the request socket: [`handle`], with the agent's own end, and with a reply to a handler
/// that panics (see [`logout::PanicReply`]).
pub(super) fn serve(conn: socket2::Socket, control: &Control) -> anyhow::Result<()> {
    let _answer_a_panic = logout::PanicReply::new(&conn, control);
    handle(conn, control, logout::end_the_agent)
}

/// Serve one connection of the request socket. A `Logout` handshake is answered exactly as on `agent.sock` (the
/// reply, then the end of a background agent through `end_process`); any other handshake is answered with
/// [`REQUESTS_ONLY`] and the connection ends. The agent never closes a connection without a byte while it is
/// alive (see [`super::handle_connection_in`]): a connection it cannot read is answered, and the error comes
/// back for the log.
pub(super) fn handle(conn: socket2::Socket, control: &Control, end_process: impl FnOnce()) -> anyhow::Result<()> {
    let Some(Opened { mut rx, mut tx, hs, .. }) = read_request(afunix::try_split, conn, control)? else {
        return Ok(());
    };
    match hs.mode {
        Mode::Logout => logout::handle_logout(&mut rx, &mut tx, control, end_process),
        Mode::Pty | Mode::Exec => Err(logout::fail_connection(
            &mut rx,
            &mut tx,
            control,
            "the agent could not serve the request",
            anyhow::anyhow!(REQUESTS_ONLY),
            logout::BAD_REQUEST_EXIT_CODE,
        )),
    }
}

#[cfg(test)]
#[path = "requests_tests.rs"]
mod requests_tests;
