//! A connection, and whom it carries.
//!
//! A session's connection to its client is written by the session's own output pumps. While `ssh-broker
//! elevate --terminal` runs a command, the agent hosts that command itself and the same connection carries ITS
//! output instead, and the client's keys go to it ([`Link::host_elevated`]). The [`Link`] is the one place that
//! owns the connection's write half, so there is exactly one place that decides whose bytes it carries. A link
//! without a terminal gates nothing: the output of a command that runs without `--terminal` is written to the
//! request's own connection through one of those.
//!
//! **Input and screen return at different times.** The keys go back to the session as soon as the command has
//! exited and its tree is reaped ([`Link::return_input`]), so what is typed while the command's pseudoconsole is
//! closed and drained is the session's. The screen (the output) returns when the guard drops, after the drain.
//!
//! **Two locks.** The state (whom the connection carries, where input goes, the size) is under one lock that is
//! never held across a write to the connection. Writes are serialised by a second lock of their own, which holds
//! the write half. Input and resize take only the state lock and the target's own handle, so they are routed while
//! an output write is blocked on a full connection. The order, where both are taken, is writer then state.

use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};

use super::HalfClose;
use super::logout::Killer;
use crate::protocol::{Resize, Stream};
use crate::relay::write_data;

/// Whose output the connection carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Carrier {
    /// The session's own program.
    Session,
    /// The command `ssh-broker elevate` runs, hosted by the agent.
    Elevated,
}

/// Where the client's keys and size go: the session's pseudoconsole, or the elevated command's.
pub(super) trait InputTarget: Send + Sync {
    /// Keys, as the client encoded them (win32 input mode).
    fn input(&self, bytes: &[u8]) -> anyhow::Result<()>;
    /// The client's size changed (or the target is new and takes the size the link holds).
    fn resize(&self, cols: u16, rows: u16);
}

/// What the elevated command's keys and size go to while it runs.
pub(super) type ElevatedTarget = Arc<dyn InputTarget>;

/// The elevated command the connection carries: where its input goes, and the means to end it.
struct Hosted {
    /// `None` once the command's input has gone back to the session ([`Link::return_input`]).
    target: Option<ElevatedTarget>,
    end: Killer,
}

struct State {
    carrier: Carrier,
    /// The session is over: nothing waits any more, and nothing new is waited for.
    ended: bool,
    /// The session's shell is gone ([`Link::end_hosting`]): the command hosted now is ended, and none is hosted after.
    hosting_ended: bool,
    /// The client's size, as it last reported it.
    size: (u16, u16),
    /// Set while the connection carries the elevated command.
    elevated: Option<Hosted>,
}

impl State {
    /// Whether a deliver for `carrier` can never go on: the link is over, or the session's end left the elevated
    /// command it is for unhosted.
    fn over_for(&self, carrier: Carrier) -> bool {
        self.ended || (carrier == Carrier::Elevated && self.hosting_ended && self.elevated.is_none())
    }
}

/// A session's connection. See the module.
pub(super) struct Link {
    /// Whether the session has a terminal. Without one the session's streams and the command's are separate
    /// pipes and nothing waits for a carrier: a gate there could deadlock a pipeline that waits on what it gates.
    terminal: bool,
    session: Option<Arc<dyn InputTarget>>,
    state: Mutex<State>,
    changed: Condvar,
    /// Held while a size is applied, so that two sizes are applied in the order they were taken.
    resizing: Mutex<()>,
    writer: Mutex<Box<dyn HalfClose + Send>>,
}

/// What a deliver found when it looked.
enum Admit {
    Go,
    Wait,
    Ended,
}

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Link {
    /// The link of a session whose client is the write half `tx`, with a terminal or not, of `size` (columns,
    /// rows), whose own input goes to `session` (`None` for a session that routes its input itself).
    pub(super) fn new(
        tx: impl HalfClose + Send + 'static,
        terminal: bool,
        size: (u16, u16),
        session: Option<Arc<dyn InputTarget>>,
    ) -> Arc<Link> {
        Arc::new(Link {
            terminal,
            session,
            state: Mutex::new(State {
                carrier: Carrier::Session,
                ended: false,
                hosting_ended: false,
                size,
                elevated: None,
            }),
            changed: Condvar::new(),
            resizing: Mutex::new(()),
            writer: Mutex::new(Box::new(tx)),
        })
    }

    pub(super) fn has_terminal(&self) -> bool {
        self.terminal
    }

    /// The size the client last reported (columns, rows).
    pub(super) fn size(&self) -> (u16, u16) {
        locked(&self.state).size
    }

    /// Write `bytes` to the client as `stream`, for `carrier`. With a terminal this waits until `carrier` is the one
    /// the connection carries, on a condition that is re-checked (no timeout), or the link has ended, which is an
    /// error. The carrier is looked at again once the write is ours, and a switch that came between repeats the
    /// wait.
    pub(super) fn deliver(&self, carrier: Carrier, stream: Stream, bytes: &[u8]) -> anyhow::Result<()> {
        self.deliver_observed(carrier, stream, bytes, || {})
    }

    /// [`Link::deliver`], calling `waiting` each time it is about to wait for its carrier (with the state locked,
    /// so a switch cannot slip in before the wait begins), so that a test can tell that it is waiting.
    pub(super) fn deliver_observed(
        &self,
        carrier: Carrier,
        stream: Stream,
        bytes: &[u8],
        mut waiting: impl FnMut(),
    ) -> anyhow::Result<()> {
        loop {
            self.await_carrier(carrier, &mut waiting)?;
            let mut writer = locked(&self.writer);
            match self.admit(carrier) {
                Admit::Go => return write_data(&mut *writer, stream, bytes),
                Admit::Ended => anyhow::bail!("the session has ended"),
                // A switch came between the wait and the write: the write lock goes, and the wait is repeated.
                Admit::Wait => {}
            }
        }
    }

    fn admit(&self, carrier: Carrier) -> Admit {
        let state = locked(&self.state);
        if state.over_for(carrier) {
            Admit::Ended
        } else if !self.terminal || state.carrier == carrier {
            Admit::Go
        } else {
            Admit::Wait
        }
    }

    fn await_carrier(&self, carrier: Carrier, waiting: &mut impl FnMut()) -> anyhow::Result<()> {
        if !self.terminal {
            return Ok(());
        }
        let mut state = locked(&self.state);
        loop {
            if state.over_for(carrier) {
                anyhow::bail!("the session has ended");
            }
            if state.carrier == carrier {
                return Ok(());
            }
            waiting();
            state = self.changed.wait(state).unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// Send the session's exit code and FIN the write half (see [`super::send_exit`]).
    pub(super) fn send_exit(&self, code: i32) {
        super::send_exit(&mut *locked(&self.writer), code);
    }

    /// Send the client's keys to whichever target is current: the elevated command's while its input is its, else
    /// the session's. Takes no lock the connection's writes hold, and none while it writes to the target.
    ///
    /// An error is the session's own target's. The elevated command's input fails when the command is ending (its
    /// pseudoconsole is closed while it is still current), which is no fault of the session: the keys are dropped,
    /// and the caller, which stops delivering input for good on an error, goes on.
    pub(super) fn route_input(&self, bytes: &[u8]) -> anyhow::Result<()> {
        let elevated = locked(&self.state)
            .elevated
            .as_ref()
            .and_then(|hosted| hosted.target.clone());
        match (elevated, &self.session) {
            (Some(target), _) => {
                if let Err(e) = target.input(bytes) {
                    tracing::debug!("the elevated command is ending; dropped its keys: {e:#}");
                }
                Ok(())
            }
            (None, Some(target)) => target.input(bytes),
            (None, None) => Ok(()),
        }
    }

    /// The hosted command has exited and its tree is reaped: from now on the client's keys and size go to the
    /// session's own target again, though the connection still carries the command's output until its guard drops
    /// (its screen is up until the output is drained). The keys typed in that window are the session's shell's, and
    /// its echo of them waits for the screen like all session output. Does nothing when nothing is hosted.
    pub(super) fn return_input(&self) {
        if let Some(hosted) = locked(&self.state).elevated.as_mut() {
            hosted.target = None;
        }
    }

    /// The client's size changed: remember it and apply it to the current target.
    pub(super) fn resize(&self, size: Resize) {
        let _applying = locked(&self.resizing);
        let target = {
            let mut state = locked(&self.state);
            state.size = (size.cols, size.rows);
            let elevated = state.elevated.as_ref().and_then(|hosted| hosted.target.clone());
            elevated.or_else(|| self.session.clone())
        };
        if let Some(target) = target {
            target.resize(size.cols, size.rows);
        }
    }

    /// From now on the connection carries the elevated command's output and `target` gets the client's keys and
    /// size, which it is given now, until [`Link::return_input`]; `end` ends the command, and [`Link::end_hosting`]
    /// calls it. Dropping the guard gives the output back. Only a link with a terminal has a screen to hand over: `decide` refuses the request that would
    /// come here for one without.
    ///
    /// `None` when the session's shell is gone already ([`Link::end_hosting`]): nothing is hosted, and this calls
    /// `end` itself, so a command that asks too late is ended as one hosted when the session ended is.
    pub(super) fn host_elevated(&self, target: ElevatedTarget, end: Killer) -> Option<ElevatedGuard<'_>> {
        debug_assert!(self.terminal, "a command was hosted on a link without a terminal");
        let applying = locked(&self.resizing);
        let (cols, rows) = {
            let mut state = locked(&self.state);
            if state.hosting_ended {
                drop(state);
                drop(applying);
                end();
                return None;
            }
            state.carrier = Carrier::Elevated;
            state.elevated = Some(Hosted {
                target: Some(Arc::clone(&target)),
                end,
            });
            state.size
        };
        self.changed.notify_all();
        target.resize(cols, rows);
        drop(applying);
        Some(ElevatedGuard { link: self })
    }

    /// The session's shell is gone: the command hosted now is ended, and none is hosted after (a command that asks
    /// is ended at once by [`Link::host_elevated`], and a deliver for it fails). It does not switch the connection
    /// back: dropping the guard is the one place that does.
    ///
    /// Returns once the connection is the session's again: after it has ended the hosted command, it waits, on a
    /// condition that is re-checked (no timeout), until the command's own teardown has dropped its guard, so that the
    /// command's last output is written before the session's `Exit`. Nothing is waited for when nothing was hosted.
    /// No lock is held across the wait but the state lock the wait releases.
    pub(super) fn end_hosting(&self) {
        let end = {
            let mut state = locked(&self.state);
            state.hosting_ended = true;
            state.elevated.as_ref().map(|hosted| Arc::clone(&hosted.end))
        };
        // A deliver of the command's that waits for the screen is told there is none.
        self.changed.notify_all();
        let Some(end) = end else { return };
        end();
        let mut state = locked(&self.state);
        while state.elevated.is_some() {
            state = self.changed.wait(state).unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// The session is over: every wait ends with an error and none begins.
    pub(super) fn end(&self) {
        locked(&self.state).ended = true;
        self.changed.notify_all();
    }
}

/// The connection carries the elevated command's output while this lives (its input goes back earlier, at
/// [`Link::return_input`]); dropping it switches the screen back to the session and wakes its output pump, before
/// whatever the caller writes next (the request's reply).
///
/// The switch back always gives the session's pseudoconsole its current size, even when it is the size it has:
/// resizing a pseudoconsole to its own size makes it repaint its whole screen. Never a different size and back:
/// that stream asks the person's terminal to resize its window.
pub(super) struct ElevatedGuard<'a> {
    link: &'a Link,
}

impl Drop for ElevatedGuard<'_> {
    fn drop(&mut self) {
        let link = self.link;
        let _applying = locked(&link.resizing);
        let (hosted, (cols, rows)) = {
            let mut state = locked(&link.state);
            state.carrier = Carrier::Session;
            (state.elevated.take(), state.size)
        };
        link.changed.notify_all();
        drop(hosted);
        if let Some(session) = &link.session {
            session.resize(cols, rows);
        }
    }
}

#[cfg(test)]
#[path = "link_tests.rs"]
mod link_tests;
