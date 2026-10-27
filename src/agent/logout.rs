//! The agent's side of `ssh-broker logout`: what a background agent shares among its connections
//! so that one of them can end the whole session, and how it answers.
//!
//! Ending is ordered. The reply goes out first. Then the agent waits until the client has closed
//! its connection (the usual client is `logout` typed in a shell that is a child of this agent,
//! inside its job, so ending the tree earlier could cut the reply and the exit code off), ends
//! every session's shell tree, waits until every other connection has finished relaying (so each
//! shell's last output reaches its client the way it does when a shell exits by itself), and only
//! then ends the process. A connection waits on its client, which may never read or close, so that
//! wait has a bound (`DRAIN_BOUND`): past it the process ends with the connections left, and the log
//! says how many.

use std::io::Read;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use super::Connections;
use crate::afunix::{ConnRx, ConnTx};
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
    /// Makes the accept loop look at [`Control::is_ending`]: a loop blocked in `accept` does not
    /// otherwise notice the flag.
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

    /// Call `waker` when the end begins, after [`Control::is_ending`] has become true.
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

    /// Begin to end: from now on no session registers, and every registered one is ended.
    pub(super) fn end_all(&self) {
        let (first, killers): (bool, Vec<Killer>) = {
            let mut state = self.lock();
            let first = !state.ending;
            state.ending = true;
            (first, state.sessions.iter().map(|(_, kill)| Arc::clone(kill)).collect())
        };
        // Before the shells end: a user who sees one end and logs in again should find no listener,
        // not an agent that is on its way out.
        if first {
            (self.waker)();
        }
        for kill in killers {
            kill();
        }
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
pub(super) fn handle_logout<R: Read, W: std::io::Write>(
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
    wait_for_close(rx);
    tracing::info!("ending the background session at the user's request");
    let _logout = control.connections.begin_logout();
    control.end_all();
    control.connections.wait_until_only_logouts_live();
    end_process();
    Ok(())
}

/// Answer a login that reached the agent after the end began: it is told, and exits with
/// [`ENDING_REFUSED_EXIT_CODE`], instead of being dropped without a word.
///
/// The reply is followed by a FIN and a read until the client closes, as every reply that must
/// arrive is: the client has sent its handshake and goes on sending input (an exec shim always ends
/// with the stdin EOF marker), and closing with that unread would reset the connection and lose the
/// reply.
pub(super) fn refuse_while_ending(rx: &mut ConnRx, tx: &mut ConnTx) -> anyhow::Result<()> {
    reply(tx, ENDING_REFUSAL, ENDING_REFUSED_EXIT_CODE)?;
    tx.shutdown_write()?;
    wait_for_close(rx);
    Ok(())
}

fn reply<W: std::io::Write>(tx: &mut W, text: &str, code: i32) -> anyhow::Result<()> {
    write_data(tx, Stream::Stderr, text.as_bytes())?;
    write_frame(tx, FrameKind::Exit, &ExitCode(code).encode())?;
    tx.flush()?;
    Ok(())
}

/// Block until the client has closed its end (or the connection has failed).
fn wait_for_close<R: Read>(rx: &mut R) {
    let mut buf = [0u8; 256];
    loop {
        match rx.read(&mut buf) {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
    }
}

#[cfg(test)]
#[path = "logout_tests.rs"]
mod logout_tests;
