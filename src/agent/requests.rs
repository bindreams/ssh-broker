//! The request socket: what an agent at High answers on `request.sock`, in the plain folder.
//!
//! A process of the account below High cannot connect to the agent's `agent.sock` (its folder carries the High
//! label), and an administrator's sessions are unelevated by default. The request socket is the way to the
//! agent for those: it takes requests only (`logout`), and no session ever starts on it.
//!
//! Input here comes from a lower integrity level: frames are bounded, a malformed first frame is answered as a
//! failed request, nothing read is used as a path. A client that connects and stays silent holds a handler
//! thread, as it can on `agent.sock` of a standard account; the unelevated session is a consent step, not a
//! boundary.

use super::{Control, Opened, logout, read_request};
use crate::afunix::Conn;
use crate::protocol::Mode;

/// What a session handshake on the request socket is told.
pub const REQUESTS_ONLY: &str = "this socket takes requests only";

/// [`handle`] with the agent's own end and a panic reply (see [`logout::PanicReply`]).
pub(super) fn serve(sock: socket2::Socket, control: &Control) -> anyhow::Result<()> {
    let conn = logout::admit(sock)?;
    let _answer_a_panic = logout::PanicReply::new(conn.clone(), control);
    handle(conn, control, |outcome| super::finish_settled(outcome))
}

/// Serve one connection of the request socket. A `Logout` handshake is answered exactly as on `agent.sock` (the
/// reply, then the end of a background agent through `end_process`, given how that end went); any other handshake is answered with
/// [`REQUESTS_ONLY`] and the connection ends. The error of a connection it cannot read comes back for the log.
pub(super) fn handle(
    conn: Conn,
    control: &Control,
    end_process: impl FnOnce(anyhow::Result<()>),
) -> anyhow::Result<()> {
    let Some(Opened { mut rx, mut tx, hs, .. }) = read_request(conn, control)? else {
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
