//! The agent's side of `ssh-broker logout`: what a background agent shares among its connections
//! so that one of them can end the whole session, and how it answers.
//!
//! Ending is ordered. The reply goes out first. Then the agent waits until the client has closed
//! its connection (the usual client is `logout` typed in a shell that is a child of this agent,
//! inside its job, so ending the tree earlier could cut the reply and the exit code off), ends
//! every session's shell tree, waits until every other connection has finished relaying (so each
//! shell's last output reaches its client the way it does when a shell exits by itself), stops
//! accepting and closes the listener, and only then ends the process. Every wait on a client (the
//! logout request's, a refused login's, the drain's) is on a client that may never read or close, so
//! each has the bound `DRAIN_BOUND`: past it the process goes on without the client, and the log says
//! so. A refused login counts as live for the drain until its wait on the client returns, so the
//! process does not end with the client's input unread, which would reset the connection and lose
//! the reply.
//!
//! The listener stays open through the drain, and a login that arrives meanwhile is refused with
//! [`ENDING_REFUSAL`]. Once the drain is over the accept loop stops, after counting the connection it
//! is accepting, and the listener is closed; then the drain judges again, so every connection the
//! loop took gets its refusal. That includes a connection kept for want of a thread when the end is
//! decided: it is served once more. Only if that has no thread either is it closed without a reply. A
//! connection that was queued and never accepted is reset with the listener, and its shim treats that
//! as an agent that is gone. The session slot and the user lock
//! stay held until the process ends, so a successor agent starts only after this one is gone.

use std::io::{Read, Write};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use super::{Connections, Drained, HalfClose};
use crate::afunix::{ConnRx, Whole};
use crate::protocol::{ExitCode, FrameKind, Stream, write_frame};
use crate::relay::write_data;

/// The reply of a background agent, before it ends.
pub const ENDING_REPLY: &str = "ssh-broker: ending your background session.\r\n";
/// The reply of an agent that runs in the desktop session: signing out of Windows ends it.
pub const DESKTOP_REPLY: &str =
    "ssh-broker: your agent runs in your desktop session; signing out of Windows ends it.\r\n";
/// What `logout` exits with when the agent runs in the desktop session.
pub const DESKTOP_EXIT_CODE: i32 = 2;
/// What a login is told when it reached the agent after the end began: it got no shell.
pub const ENDING_REFUSAL: &str = "ssh-broker: your background session is ending; reconnect in a moment.\r\n";
/// What that login exits with. 255 is ssh's code for a failed connection and the shim's for a dead
/// agent; 1 would look like the command's own failure (`grep` found nothing).
pub const ENDING_REFUSED_EXIT_CODE: i32 = 255;

/// What an agent shares among its connections.
pub(super) struct Control {
    background: bool,
    state: Mutex<State>,
    connections: Arc<Connections>,
    /// Makes the accept loop look at the flag that closes it (see [`Connections::settle`]): a loop
    /// blocked in `accept` does not otherwise notice it.
    waker: Box<dyn Fn() + Send + Sync>,
}

type Killer = Arc<dyn Fn() + Send + Sync>;

#[derive(Default)]
struct State {
    ending: bool,
    next_id: u64,
    sessions: Vec<(u64, Killer)>,
}

impl Control {
    pub(super) fn new(background: bool, connections: Arc<Connections>) -> Control {
        Control {
            background,
            state: Mutex::new(State::default()),
            connections,
            waker: Box::new(|| {}),
        }
    }

    /// Call `waker` to make the accept loop return from `accept`, once the end is decided.
    pub(super) fn with_waker(mut self, waker: impl Fn() + Send + Sync + 'static) -> Control {
        self.waker = Box::new(waker);
        self
    }

    /// A control for a connection handled outside the accept loop: a desktop agent that nobody
    /// will ask to end.
    #[cfg(test)]
    pub(super) fn standalone() -> Control {
        Control::new(false, Connections::new())
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether the agent has begun to end: no session may start.
    pub(super) fn is_ending(&self) -> bool {
        self.lock().ending
    }

    /// Record a running session, with the means to end its shell tree. The registration lasts
    /// while the returned guard does. `None` means the agent is already ending: the caller must
    /// end the session itself, at once.
    pub(super) fn register(&self, kill: Killer) -> Option<Registration<'_>> {
        let mut state = self.lock();
        if state.ending {
            return None;
        }
        let id = state.next_id;
        state.next_id += 1;
        state.sessions.push((id, kill));
        Some(Registration { control: self, id })
    }

    /// Begin to end: from now on no session registers, and every registered one is ended. A login
    /// that comes now is refused (`refuse_while_ending`).
    pub(super) fn end_all(&self) {
        let killers: Vec<Killer> = {
            let mut state = self.lock();
            state.ending = true;
            state.sessions.iter().map(|(_, kill)| Arc::clone(kill)).collect()
        };
        for kill in killers {
            kill();
        }
    }

    /// Wait until the shells' output is delivered, then stop the accept loop and close the listener
    /// (see [`Connections::settle`]). The process may end when this returns.
    pub(super) fn settle(&self) -> Drained {
        self.connections.settle(&*self.waker)
    }
}

/// A session recorded by [`Control::register`]; dropped when the session is over.
pub(super) struct Registration<'a> {
    control: &'a Control,
    id: u64,
}

impl Drop for Registration<'_> {
    fn drop(&mut self) {
        self.control.lock().sessions.retain(|(id, _)| *id != self.id);
    }
}

/// Answer a `Logout` handshake on a connection whose handshake has been read.
///
/// `end_process` ends the process; it is a parameter so a test can see when it is called. A
/// desktop agent answers and keeps serving.
pub(super) fn handle_logout<R: LimitedRead, W: std::io::Write>(
    rx: &mut R,
    tx: &mut W,
    control: &Control,
    end_process: impl FnOnce(),
) -> anyhow::Result<()> {
    if !control.background {
        reply(tx, DESKTOP_REPLY, DESKTOP_EXIT_CODE)?;
        return Ok(());
    }
    // Every logout ends the agent, also one whose client has gone before the reply: it asked.
    if let Err(e) = reply(tx, ENDING_REPLY, 0) {
        tracing::warn!("could not deliver the logout reply: {e:#}");
    }
    wait_for_client(rx, control, "the logout request");
    tracing::info!("ending the background session at the user's request");
    let _logout = control.connections.begin_logout();
    control.end_all();
    control.settle();
    end_process();
    Ok(())
}

/// Answer a login that reached the agent after the end began: it is told, and exits with
/// [`ENDING_REFUSED_EXIT_CODE`], instead of being dropped without a word.
///
/// The reply is followed by a FIN and a read until the client closes, as every reply that must
/// arrive is: the client has sent its handshake and goes on sending input (an exec shim always ends
/// with the stdin EOF marker), and closing with that unread would reset the connection and lose the
/// reply. The read has the drain's bound ([`wait_for_client`]). The connection stays live for the
/// drain until the read returns, so the process does not end under it.
pub(super) fn refuse_while_ending<R: LimitedRead, W: Write + HalfClose>(
    rx: &mut R,
    tx: &mut W,
    control: &Control,
) -> anyhow::Result<()> {
    answer_and_wait(
        rx,
        tx,
        control,
        ENDING_REFUSAL,
        ENDING_REFUSED_EXIT_CODE,
        "a refused login",
    )
}

/// What the shim exits with when the agent could not read the request.
pub const BAD_REQUEST_EXIT_CODE: i32 = 254;
/// What the shim exits with when the agent could not serve a request it read.
pub const FAILED_EXIT_CODE: i32 = 255;

/// Tell a client the agent could not serve its connection, which is a fault of the agent's or the
/// request's and not the end: `what` says what could not be done, `cause` why, and the client exits
/// with `code`. The connection is answered like a refusal (see [`refuse_while_ending`]), because the
/// shim treats a connection that ends without a byte as an agent that is going away. Returns `cause`,
/// for the caller to log, with `what` as its context.
pub(super) fn fail_connection<R: LimitedRead, W: Write + HalfClose>(
    rx: &mut R,
    tx: &mut W,
    control: &Control,
    what: &str,
    cause: anyhow::Error,
    code: i32,
) -> anyhow::Error {
    let text = format!("ssh-broker: {what}: {cause:#}\r\n");
    // A client that has gone cannot be told; the caller logs the cause either way.
    if let Err(e) = answer_and_wait(rx, tx, control, &text, code, "a failed connection") {
        tracing::debug!("could not tell the client why its connection failed: {e:#}");
    }
    cause.context(what.to_owned())
}

/// Answers a connection whose handler thread panics. A panic closes the connection without a byte,
/// which a client takes for an agent that is going away; this writes the failure reply
/// ([`FAILED_EXIT_CODE`]) first, on a second handle to the same socket, and waits for the client to
/// close like any other failure reply. Dropped without a panic, it does nothing.
pub(super) struct PanicReply<'a> {
    conn: Option<socket2::Socket>,
    control: &'a Control,
}

impl<'a> PanicReply<'a> {
    pub(super) fn new(conn: &socket2::Socket, control: &'a Control) -> Self {
        let conn = match conn.try_clone() {
            Ok(conn) => Some(conn),
            Err(e) => {
                tracing::warn!("a panic of this connection's handler will not be answered: {e}");
                None
            }
        };
        PanicReply { conn, control }
    }
}

impl Drop for PanicReply<'_> {
    fn drop(&mut self) {
        let Some(conn) = self.conn.take() else { return };
        if !std::thread::panicking() {
            return;
        }
        let cause = anyhow::anyhow!("the handler panicked");
        let failure = fail_socket(
            conn,
            self.control,
            "the agent failed while serving this connection",
            cause,
        );
        tracing::error!("{failure:#}");
    }
}

/// [`fail_connection`] with [`FAILED_EXIT_CODE`] on a connection that nothing has split yet. The split
/// also makes the socket non-inheritable; if it fails, the reply goes on the whole socket.
pub(super) fn fail_socket(conn: socket2::Socket, control: &Control, what: &str, cause: anyhow::Error) -> anyhow::Error {
    match crate::afunix::try_split(conn) {
        Ok((mut rx, mut tx)) => fail_connection(&mut rx, &mut tx, control, what, cause, FAILED_EXIT_CODE),
        Err((whole, _)) => {
            let (mut rx, mut tx) = (&whole, &whole);
            fail_connection(&mut rx, &mut tx, control, what, cause, FAILED_EXIT_CODE)
        }
    }
}

/// Send `text` and `code`, FIN the write half and wait for the client to close (see
/// [`wait_for_client`]).
fn answer_and_wait<R: LimitedRead, W: Write + HalfClose>(
    rx: &mut R,
    tx: &mut W,
    control: &Control,
    text: &str,
    code: i32,
    who: &str,
) -> anyhow::Result<()> {
    reply(tx, text, code)?;
    tx.shutdown_write()?;
    wait_for_client(rx, control, who);
    Ok(())
}

fn reply<W: std::io::Write>(tx: &mut W, text: &str, code: i32) -> anyhow::Result<()> {
    write_data(tx, Stream::Stderr, text.as_bytes())?;
    write_frame(tx, FrameKind::Exit, &ExitCode(code).encode())?;
    tx.flush()?;
    Ok(())
}

/// A connection whose blocking reads can be given a limit.
pub(super) trait LimitedRead: Read {
    /// Make a read that finds nothing fail with `TimedOut` or `WouldBlock` once `limit` has passed.
    fn limit_reads(&mut self, limit: Duration) -> std::io::Result<()>;
}

impl LimitedRead for ConnRx {
    fn limit_reads(&mut self, limit: Duration) -> std::io::Result<()> {
        self.set_read_timeout(Some(limit))
    }
}

impl LimitedRead for &Whole {
    fn limit_reads(&mut self, limit: Duration) -> std::io::Result<()> {
        self.set_read_timeout(Some(limit))
    }
}

/// How [`wait_for_close_within`] ended.
#[derive(Debug, PartialEq, Eq)]
enum Waited {
    /// The client closed, or the connection failed.
    Closed,
    /// The bound passed with the client still connected.
    Abandoned,
}

/// Wait until a client, which may never read or close, has closed its end of the connection `rx`.
/// Every wait of the agent on a client goes through here: the bound is the drain's, and when it
/// passes the agent goes on without the client and logs that `who` was left. The bound is the
/// failure bound on an external client, never proof that the client has read the reply.
fn wait_for_client<R: LimitedRead>(rx: &mut R, control: &Control, who: &str) {
    let bound = control.connections.drain_bound();
    if wait_for_close_within(rx, bound) == Waited::Abandoned {
        tracing::warn!(
            "the client of {who} had not closed its connection {} s after the reply; not waiting for it any longer",
            bound.as_secs_f32()
        );
    }
}

/// Block until the client has closed its end (or the connection has failed), or `bound` has passed.
/// Any duration works as the bound: the limit on each read is the time left, which the connection
/// rounds up to whole milliseconds (see [`ConnRx::set_read_timeout`]).
fn wait_for_close_within<R: LimitedRead>(rx: &mut R, bound: Duration) -> Waited {
    let deadline = Instant::now() + bound;
    let mut buf = [0u8; 256];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Waited::Abandoned;
        }
        if let Err(e) = rx.limit_reads(left) {
            tracing::warn!("could not limit the wait for the client to close: {e}; not waiting for it");
            return Waited::Closed;
        }
        match rx.read(&mut buf) {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            // The deadline is looked at again at the top.
            Err(e) if matches!(e.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock) => {}
            Ok(0) | Err(_) => return Waited::Closed,
            Ok(_) => {}
        }
    }
}

#[cfg(test)]
#[path = "logout_tests.rs"]
mod logout_tests;
