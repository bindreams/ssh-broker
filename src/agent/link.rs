//! The session's connection, and whom it carries.
//!
//! A session's connection to its client is written by the session's own output pumps. While `ssh-broker
//! elevate` runs a command with a terminal, the agent hosts that command itself and the same connection carries
//! ITS output instead, and the client's keys go to it ([`Link::host_elevated`]). The [`Link`] is the one place
//! that owns the connection's write half, so there is exactly one place that decides whose bytes it carries.
//!
//! **Two locks.** The state (whom the connection carries, where input goes, the size) is under one lock that is
//! never held across a write to the connection. Writes are serialised by a second lock of their own, which holds
//! the write half. Input and resize take only the state lock and the target's own handle, so they are routed while
//! an output write is blocked on a full connection. The order, where both are taken, is writer then state.

use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};

use super::HalfClose;
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

struct State {
    carrier: Carrier,
    /// The session is over: nothing waits any more, and nothing new is waited for.
    ended: bool,
    /// The trees were reaped ([`Link::reap_all`]): a job adopted now is ended at once.
    reaped: bool,
    /// The client's size, as it last reported it.
    size: (u16, u16),
    /// The size the session's own target was last given.
    session_size: (u16, u16),
    /// Set while the connection carries the elevated command.
    elevated: Option<ElevatedTarget>,
    jobs: Vec<Arc<cosca::Job>>,
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
                reaped: false,
                size,
                session_size: size,
                elevated: None,
                jobs: Vec::new(),
            }),
            changed: Condvar::new(),
            resizing: Mutex::new(()),
            writer: Mutex::new(Box::new(tx)),
        })
    }

    /// Whether the session has a terminal.
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
        if state.ended {
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
            if state.ended {
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

    /// Send the client's keys to whichever target is current: the elevated command's while it runs, else the
    /// session's. Takes no lock the connection's writes hold, and none while it writes to the target.
    pub(super) fn route_input(&self, bytes: &[u8]) -> anyhow::Result<()> {
        let target = {
            let state = locked(&self.state);
            state.elevated.clone().or_else(|| self.session.clone())
        };
        match target {
            Some(target) => target.input(bytes),
            None => Ok(()),
        }
    }

    /// The client's size changed: remember it and apply it to the current target.
    pub(super) fn resize(&self, size: Resize) {
        let _applying = locked(&self.resizing);
        let target = {
            let mut state = locked(&self.state);
            state.size = (size.cols, size.rows);
            match &state.elevated {
                Some(elevated) => Some(Arc::clone(elevated)),
                None => {
                    state.session_size = state.size;
                    self.session.clone()
                }
            }
        };
        if let Some(target) = target {
            target.resize(size.cols, size.rows);
        }
    }

    /// From now on the connection carries the elevated command's output and `target` gets the client's keys and
    /// size, which it is given now. Dropping the guard switches back.
    pub(super) fn host_elevated(&self, target: ElevatedTarget) -> ElevatedGuard<'_> {
        let _applying = locked(&self.resizing);
        let (cols, rows) = {
            let mut state = locked(&self.state);
            state.carrier = Carrier::Elevated;
            state.elevated = Some(Arc::clone(&target));
            state.size
        };
        self.changed.notify_all();
        target.resize(cols, rows);
        ElevatedGuard { link: self }
    }

    /// The session is over: every wait ends with an error and none begins.
    pub(super) fn end(&self) {
        locked(&self.state).ended = true;
        self.changed.notify_all();
    }

    /// Record the elevated command's job, so that [`Link::reap_all`] ends it with the session's. A job adopted after
    /// the link has ended or its trees were reaped is ended at once. The job is forgotten when the guard drops.
    pub(super) fn adopt_job(&self, job: Arc<cosca::Job>) -> AdoptedJob<'_> {
        let late = {
            let mut state = locked(&self.state);
            let late = state.ended || state.reaped;
            if !late {
                state.jobs.push(Arc::clone(&job));
            }
            late
        };
        if late {
            super::reap_tree(&job);
        }
        AdoptedJob { link: self, job }
    }

    /// End the session's tree and every adopted one. True when every tree was ended. Every place that reaps the
    /// session's tree comes here, so that the elevated command does not outlive its session.
    pub(super) fn reap_all(&self, session_job: &cosca::Job) -> bool {
        let adopted = {
            let mut state = locked(&self.state);
            state.reaped = true;
            state.jobs.clone()
        };
        let mut all = super::reap_tree(session_job);
        for job in adopted {
            all &= super::reap_tree(&job);
        }
        all
    }

    #[cfg(test)]
    fn adopted(&self) -> usize {
        locked(&self.state).jobs.len()
    }
}

/// The connection carries the elevated command while this lives; dropping it switches back to the session and
/// wakes its output pump, before whatever the caller writes next (the request's reply).
pub(super) struct ElevatedGuard<'a> {
    link: &'a Link,
}

impl Drop for ElevatedGuard<'_> {
    fn drop(&mut self) {
        let link = self.link;
        let _applying = locked(&link.resizing);
        let changed_size = {
            let mut state = locked(&link.state);
            state.carrier = Carrier::Session;
            state.elevated = None;
            let changed = state.size != state.session_size;
            state.session_size = state.size;
            changed.then_some(state.size)
        };
        link.changed.notify_all();
        if let (Some((cols, rows)), Some(session)) = (changed_size, &link.session) {
            session.resize(cols, rows);
        }
    }
}

/// A job recorded by [`Link::adopt_job`]; dropped when the command is over.
pub(super) struct AdoptedJob<'a> {
    link: &'a Link,
    job: Arc<cosca::Job>,
}

impl Drop for AdoptedJob<'_> {
    fn drop(&mut self) {
        locked(&self.link.state)
            .jobs
            .retain(|adopted| !Arc::ptr_eq(adopted, &self.job));
    }
}

#[cfg(test)]
#[path = "link_tests.rs"]
mod link_tests;
