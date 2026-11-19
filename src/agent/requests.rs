//! The request socket: what an agent at High answers on `request.sock`, in the plain folder.
//!
//! A process of the account below High cannot connect to the agent's `agent.sock` (its folder carries the High
//! label), and an administrator's sessions are unelevated by default. The request socket is the way to the
//! agent for those: it takes requests only (`logout`, `elevate`), and no session ever starts on it.
//!
//! Input here comes from a lower integrity level: frames are bounded, a malformed first frame is answered as a
//! failed request, nothing read is used as a path but the working directory of an `elevate`, which is checked to be
//! an existing directory. A client that connects and stays silent holds a handler thread, as it can on `agent.sock`
//! of a standard account; the unelevated session is a consent step, not a boundary.

use std::path::Path;

use super::elevation::{Verdict, decide, run_hosted};
use super::{Control, Opened, child_cwd, home_dir, logout, read_opening};
use crate::afunix::{Conn, ConnRx, ConnTx};
use crate::elevate::REFUSED_EXIT_CODE;
use crate::offer::text;
use crate::protocol::{ElevationRequest, Frame, FrameKind, Handshake, Mode, SessionId};

/// What a session handshake on the request socket is told.
pub const REQUESTS_ONLY: &str = "this socket takes requests only";

/// What opens a connection to the request socket.
enum Opening {
    /// `logout`, which `agent.sock` takes as well, or a session's handshake, which this socket refuses.
    Handshake(Handshake),
    /// `elevate`.
    Request(ElevationRequest),
}

fn decode_opening(frame: Frame) -> anyhow::Result<Opening> {
    match frame.kind {
        FrameKind::Handshake => Ok(Opening::Handshake(Handshake::decode(&frame.payload)?)),
        FrameKind::Request => Ok(Opening::Request(ElevationRequest::decode(&frame.payload)?)),
        _ => anyhow::bail!("first frame was not a handshake or a request"),
    }
}

/// [`handle`] with the agent's own end and a panic reply (see [`logout::PanicReply`]).
pub(super) fn serve(sock: socket2::Socket, control: &Control) -> anyhow::Result<()> {
    let conn = logout::admit(sock)?;
    let _answer_a_panic = logout::PanicReply::new(conn.clone(), control);
    handle(conn, control, |outcome| super::finish_settled(outcome))
}

/// Serve one connection of the request socket. A `Logout` handshake is answered exactly as on `agent.sock` (the
/// reply, then the end of a background agent through `end_process`, given how that end went); any other handshake is answered with
/// [`REQUESTS_ONLY`] and the connection ends; a request to elevate is [`elevate`]'s. The error of a connection it
/// cannot read comes back for the log.
pub(super) fn handle(
    conn: Conn,
    control: &Control,
    end_process: impl FnOnce(anyhow::Result<()>),
) -> anyhow::Result<()> {
    let Some(Opened {
        mut rx, mut tx, first, ..
    }) = read_opening(conn, control, decode_opening)?
    else {
        return Ok(());
    };
    match first {
        Opening::Handshake(hs) => match hs.mode {
            Mode::Logout => logout::handle_logout(&mut rx, &mut tx, control, end_process),
            Mode::Pty | Mode::Exec => Err(logout::fail_connection(
                &mut rx,
                &mut tx,
                control,
                "the agent could not serve the request",
                anyhow::anyhow!(REQUESTS_ONLY),
                logout::BAD_REQUEST_EXIT_CODE,
            )),
        },
        Opening::Request(request) => elevate(&mut rx, &mut tx, control, &request),
    }
}

/// Answer a refusal: the sentence, then [`REFUSED_EXIT_CODE`].
fn refuse(rx: &mut ConnRx, tx: &mut ConnTx, control: &Control, sentence: &str) -> anyhow::Result<()> {
    logout::reply_and_wait(rx, tx, control, sentence, REFUSED_EXIT_CODE)
}

/// Run the command of an `elevate` request, if its session's login allows it, and answer with its exit code, or
/// refuse. The command's output goes back on this connection, and the connection is watched while it runs (see
/// [`run_hosted`]). The session is found by the id in the request: that routes the request and proves nothing (a
/// process of the account can read another's environment), and what it routes is something the login already
/// allowed.
fn elevate(rx: &mut ConnRx, tx: &mut ConnTx, control: &Control, request: &ElevationRequest) -> anyhow::Result<()> {
    let Some(id) = SessionId::parse(&request.session) else {
        return refuse(rx, tx, control, &text::elevation_not_hosted());
    };
    if let Err(cause) = request.check() {
        return Err(logout::fail_connection(
            rx,
            tx,
            control,
            "the agent could not serve the request",
            cause,
            logout::BAD_REQUEST_EXIT_CODE,
        ));
    }
    if control.is_ending() {
        return logout::refuse_while_ending(rx, tx, control);
    }
    // A session that is being started waits here until its link exists; one this agent never gave out, or that is
    // over, is not there.
    let Some(hosted) = control.await_hosted(&id) else {
        return refuse(rx, tx, control, &text::elevation_not_hosted());
    };
    if let Verdict::Refuse(sentence) = decide(hosted.policy(), hosted.has_terminal(), request.terminal) {
        return refuse(rx, tx, control, &sentence);
    }
    let Some(_slot) = hosted.slot().try_take() else {
        return refuse(rx, tx, control, &text::elevation_in_progress());
    };
    // The working directory is the one path the agent acts on: it is the command's folder, which must be one.
    let cwd = child_cwd(&request.cwd, home_dir());
    if !request.cwd.is_empty() && !Path::new(&request.cwd).is_dir() {
        let cause = format!("{} is not an existing directory", request.cwd);
        return refuse(rx, tx, control, &text::elevation_cannot_start(&cause));
    }
    match run_hosted(hosted.link(), tx, request, cwd.as_deref(), hosted.starts(), &id) {
        Ok(code) => logout::reply_and_wait(rx, tx, control, "", code),
        Err(cause) => refuse(rx, tx, control, &text::elevation_cannot_start(&format!("{cause:#}"))),
    }
}

#[cfg(test)]
#[path = "requests_tests.rs"]
mod requests_tests;

#[cfg(test)]
#[path = "requests_elevate_tests.rs"]
mod requests_elevate_tests;
