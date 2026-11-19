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

use super::elevation::{HostedSession, RunOutcome, Verdict, decide, run_hosted};
use super::{Control, Opened, child_cwd, home_dir, logout, read_opening};
use crate::afunix::{self, ConnRx, ConnTx};
use crate::elevate::{REFUSED_EXIT_CODE, UNKNOWN_END_EXIT_CODE};
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
pub(super) fn serve(conn: socket2::Socket, control: &Control) -> anyhow::Result<()> {
    let _answer_a_panic = logout::PanicReply::new(&conn, control);
    handle(conn, control, |outcome| super::finish_settled(outcome))
}

/// Serve one connection of the request socket. A `Logout` handshake is answered exactly as on `agent.sock` (the
/// reply, then the end of a background agent through `end_process`, given how that end went); any other handshake is answered with
/// [`REQUESTS_ONLY`] and the connection ends; a request to elevate is [`elevate`]'s. The error of a connection it
/// cannot read comes back for the log.
pub(super) fn handle(
    conn: socket2::Socket,
    control: &Control,
    end_process: impl FnOnce(anyhow::Result<()>),
) -> anyhow::Result<()> {
    let Some(Opened {
        mut rx, mut tx, first, ..
    }) = read_opening(afunix::try_split, conn, control, decode_opening)?
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
    let id = match request.check() {
        Ok(id) => id,
        Err(cause) => {
            return Err(logout::fail_connection(
                rx,
                tx,
                control,
                "the agent could not serve the request",
                cause,
                logout::BAD_REQUEST_EXIT_CODE,
            ));
        }
    };
    if control.is_ending() {
        return logout::refuse_while_ending(rx, tx, control);
    }
    // A session that is being started waits here until its link exists; one this agent never gave out, or that is
    // over, is not there.
    let Some(hosted) = control.await_hosted(&id) else {
        return refuse(rx, tx, control, &text::elevation_not_hosted());
    };
    if let Verdict::Refuse(sentence) = decide(hosted.policy, hosted.link.has_terminal(), request.terminal) {
        return refuse(rx, tx, control, &sentence);
    }
    // The slot is held while the command runs, and not while the client is waited for: the reply is written, and its
    // client waited for, with the slot free, so that the next `elevate` of the session is not refused for it.
    let answer = {
        let Some(_slot) = hosted.slot.try_take() else {
            return refuse(rx, tx, control, &text::elevation_in_progress());
        };
        run_elevated(&hosted, tx, request, &id)
    };
    // A client that could not be told its command had started: nothing more is written to it.
    let Some((sentence, code)) = answer else {
        return Ok(());
    };
    logout::reply_and_wait(rx, tx, control, &sentence, code)
}

/// Run the command of `request` for `hosted`, whose slot the caller holds, and say what to answer: the sentence (empty
/// for a command that ran and ended) and the exit code, or `None` when the client could not be told that the command
/// had started ([`RunOutcome::Unserved`]). Nothing is written to the client but `Serving` and the command's own
/// output.
fn run_elevated(
    hosted: &HostedSession,
    tx: &mut ConnTx,
    request: &ElevationRequest,
    id: &SessionId,
) -> Option<(String, i32)> {
    // The working directory is the one path the agent acts on: it is the command's folder, which must be one.
    let cwd = child_cwd(&request.cwd, home_dir());
    if !request.cwd.is_empty() && !Path::new(&request.cwd).is_dir() {
        let cause = format!("{} is not an existing directory", request.cwd);
        return Some((text::elevation_cannot_start(&cause), REFUSED_EXIT_CODE));
    }
    match run_hosted(&hosted.link, tx, request, cwd.as_deref(), &hosted.starts, id) {
        RunOutcome::Exited(code) => Some((String::new(), code)),
        RunOutcome::NotStarted(cause) => Some((text::elevation_cannot_start(&format!("{cause:#}")), REFUSED_EXIT_CODE)),
        RunOutcome::Unserved => None,
        RunOutcome::EndUnread(cause) => {
            Some((text::elevation_end_unread(&format!("{cause:#}")), UNKNOWN_END_EXIT_CODE))
        }
    }
}

#[cfg(test)]
#[path = "requests_tests.rs"]
mod requests_tests;

#[cfg(test)]
#[path = "requests_elevate_tests.rs"]
mod requests_elevate_tests;
