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
//! **The question.** Before a command is run for a session whose login asks, the same connection carries the question
//! to the session's shim ([`Link::ask`]) and its answer comes back on it. While it is asked the session's output is
//! held, as it is while a command holds the screen. The shim writes the question and reads the answer from the console
//! itself and relays nothing while it does, so the agent drops no key: it keeps every one that arrives while the
//! question is asked, in two groups. A key that arrives before the answer (or the withdrawal) was relayed before the
//! shim began to ask, and is the session's always: it is delivered to the session's target, also when a command run
//! with `--terminal` takes the screen, where it waits in the session's own input queue as type-ahead does. A key that
//! arrives after it is ordered after it: it goes to the command that is hosted, else to the session after the first
//! group. The screen goes back to the session, repainted, when the question's hold on it is let go, unless a command
//! run with `--terminal` has taken it from the question by then.
//!
//! The kept keys have no bound. They last from the question to the command's start or the screen's return, hold one
//! person's typing, and the session's frame reader that routes them must never park: it is the one that sees the
//! client hang up (see `HandleWriter`).
//!
//! **Locks.** The state (whom the connection carries, where input goes, the size) is under one lock that is never
//! held across a write to the connection. Writes are serialised by a second lock of their own, which holds the write
//! half. Input and resize take only the state lock and the target's own handle, so they are routed while an output
//! write is blocked on a full connection. The order, where both are taken, is writer then state. Two small locks keep
//! the order of what is applied to a target: sizes (`resizing`) and keys (`inputting`); they come before the state
//! lock, `resizing` first. Delivering the kept keys can park in a full target queue, so it holds `inputting` alone,
//! never `resizing`: a resize does not wait for it.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};

use super::HalfClose;
use super::logout::Killer;
use crate::protocol::{
    ConsentAnswer, ConsentReply, ConsentRequest, ConsentWithdrawal, FrameKind, PROTOCOL_VERSION, Resize, Stream,
    write_frame,
};
use crate::relay::write_data;

/// Whose output the connection carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Carrier {
    /// The session's own program.
    Session,
    /// The command `ssh-broker elevate` runs, hosted by the agent.
    Elevated,
    /// Nobody's: the shim has the screen, to ask the person a question ([`Link::ask`]).
    Asking,
}

/// Where the one question a session may have at a time is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Question {
    None,
    /// The `Consent` frame, numbered so, is written or being written, and the answer has not come.
    Asked(u32),
    Answered(ConsentAnswer),
}

/// The question was not answered, because the session is over, the shim can no longer be written to, or the client of
/// the request it was asked for has gone: nothing is to be run for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Ended;

/// Whether the client of the request a question is asked for has hung up. Set by [`Link::client_gone`], from the
/// watch of the request's connection; a pending [`Link::ask`] given it ends with [`Ended`].
#[derive(Debug, Default)]
pub(super) struct ClientGone(AtomicBool);

impl ClientGone {
    pub(super) fn is_gone(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
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
    question: Question,
    /// The number the last question was given: the link numbers its questions from 1 ([`ConsentRequest::id`]).
    last_question: u32,
    /// The keys that arrived while the question was asked and before its answer or withdrawal, in order. They were
    /// relayed before the shim began to ask, so they are the session's whoever gets the screen.
    early: Vec<Vec<u8>>,
    /// The keys that arrived after the question's answer or withdrawal, in order: `None` until one has come. They
    /// wait here until the question's outcome is known, then go to the command hosted ([`Link::host_elevated`]) or
    /// to the session ([`Link::switch_back`]), after the early ones.
    kept: Option<Vec<Vec<u8>>>,
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
    /// Held while keys are delivered to a target, so that the kept keys ([`State::early`], [`State::kept`]) reach it
    /// before a later one.
    inputting: Mutex<()>,
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
                question: Question::None,
                last_question: 0,
                early: Vec::new(),
                kept: None,
            }),
            changed: Condvar::new(),
            resizing: Mutex::new(()),
            inputting: Mutex::new(()),
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
    /// the session's. Takes no lock the connection's writes hold.
    ///
    /// While the question is asked the keys are kept ([`State::early`] before its answer or withdrawal,
    /// [`State::kept`] after), in order and without bound, until the question's outcome is known: the caller is the
    /// session's frame reader, which never parks here.
    ///
    /// An error is the session's own target's. The elevated command's input fails when the command is ending (its
    /// pseudoconsole is closed while it is still current), which is no fault of the session: the keys are dropped,
    /// and the caller, which stops delivering input for good on an error, goes on.
    pub(super) fn route_input(&self, bytes: &[u8]) -> anyhow::Result<()> {
        // Held until the keys are delivered, so that what the switch back of a question delivers (its kept keys)
        // is ahead of them.
        let _ordered = locked(&self.inputting);
        let mut state = locked(&self.state);
        let elevated = if state.carrier == Carrier::Asking {
            let state = &mut *state;
            state.kept.as_mut().unwrap_or(&mut state.early).push(bytes.to_vec());
            return Ok(());
        } else {
            state.elevated.as_ref().and_then(|hosted| hosted.target.clone())
        };
        drop(state);
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

    /// Deliver the keys kept for a question to `target`, in order. An error (the target is ending, as in
    /// [`Link::route_input`]) is logged and does not stop the rest. The caller holds `inputting`, and not `resizing`:
    /// a delivery can park in the target's full queue.
    fn deliver_kept(kept: Vec<Vec<u8>>, target: &dyn InputTarget) {
        for chunk in kept {
            if let Err(e) = target.input(&chunk) {
                tracing::debug!("the keys kept for a question could not be delivered: {e:#}");
            }
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
    /// calls it. Dropping the guard gives the output back. Only a link with a terminal has a screen to hand over:
    /// `decide` refuses the request that would come here for one without.
    ///
    /// The keys kept while a question was asked go first: those from before its answer ([`State::early`]) to the
    /// session's own target, the others ([`State::kept`]) to `target`, both ahead of any later key. They are delivered
    /// holding `inputting` alone, after the size is applied.
    ///
    /// `None` when the session's shell is gone already ([`Link::end_hosting`]): nothing is hosted, and this calls
    /// `end` itself, so a command that asks too late is ended as one hosted when the session ended is.
    pub(super) fn host_elevated(&self, target: ElevatedTarget, end: Killer) -> Option<ElevatedGuard<'_>> {
        debug_assert!(self.terminal, "a command was hosted on a link without a terminal");
        let applying = locked(&self.resizing);
        let ordered = locked(&self.inputting);
        let (cols, rows, early, kept) = {
            let mut state = locked(&self.state);
            if state.hosting_ended {
                drop(state);
                drop(ordered);
                drop(applying);
                end();
                return None;
            }
            state.carrier = Carrier::Elevated;
            state.elevated = Some(Hosted {
                target: Some(Arc::clone(&target)),
                end,
            });
            (
                state.size.0,
                state.size.1,
                std::mem::take(&mut state.early),
                state.kept.take().unwrap_or_default(),
            )
        };
        self.changed.notify_all();
        target.resize(cols, rows);
        // The size is applied; what is delivered next can park in a full queue, and a resize must not wait for that.
        // `inputting` stays held, which keeps these keys ahead of later ones.
        drop(applying);
        if let Some(session) = &self.session {
            Self::deliver_kept(early, &**session);
        }
        Self::deliver_kept(kept, &*target);
        drop(ordered);
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

    /// Ask the session's shim the question `request` and wait for its answer, on a condition that is re-checked (no
    /// timeout): it ends with the answer, or with [`Ended`] when the session's shell is gone ([`Link::end_hosting`])
    /// or the session is over ([`Link::end`]). A link on which either has happened is [`Ended`] at once, with
    /// nothing written. Only a link with a terminal has a shim that can ask: `decide` asks no other.
    ///
    /// The carrier is [`Carrier::Asking`] BEFORE the frame is written, and a deliver takes the write lock and looks at
    /// the carrier again, so no output frame follows the `Consent` frame. No lock the keys or the size need is held
    /// across the write. The screen stays the question's, held by the returned [`AskGuard`], and goes back to the
    /// session when that drops: a command hosted before then takes it from the question instead.
    ///
    /// `gone` says the client of the request the question is for has hung up ([`Link::client_gone`]): the question
    /// is [`Ended`] at once if it has, and is ended at the moment it does. A question that was written and ends
    /// without an answer (whatever the cause) is withdrawn to the shim before the screen goes back to the session; one
    /// that was never written is not. An answer that was already on its way is dropped ([`Link::answer`]).
    pub(super) fn ask(
        &self,
        command: &str,
        cwd: &str,
        gone: &ClientGone,
    ) -> Result<(ConsentAnswer, AskGuard<'_>), Ended> {
        self.ask_observed(command, cwd, gone, || {})
    }

    /// [`Link::ask`], calling `waiting` each time it is about to wait for the answer (with the state locked, so
    /// that the answer cannot slip in before the wait begins), so that a test can tell that it is waiting.
    pub(super) fn ask_observed(
        &self,
        command: &str,
        cwd: &str,
        gone: &ClientGone,
        mut waiting: impl FnMut(),
    ) -> Result<(ConsentAnswer, AskGuard<'_>), Ended> {
        debug_assert!(self.terminal, "a question was asked on a link without a terminal");
        let id = {
            let mut state = locked(&self.state);
            if state.over_for(Carrier::Session) || state.hosting_ended || gone.is_gone() {
                return Err(Ended);
            }
            debug_assert!(
                state.carrier == Carrier::Session
                    && state.question == Question::None
                    && state.elevated.is_none()
                    && state.early.is_empty()
                    && state.kept.is_none(),
                "a question was asked while the screen was not the session's, or another was open"
            );
            state.last_question = state.last_question.wrapping_add(1);
            state.carrier = Carrier::Asking;
            state.question = Question::Asked(state.last_question);
            state.last_question
        };
        // From here the screen goes back to the session whenever this returns without handing the guard on.
        let hold = AskGuard { link: self };
        let request = ConsentRequest {
            version: PROTOCOL_VERSION,
            id,
            command: command.to_owned(),
            cwd: cwd.to_owned(),
        };
        let written = request
            .encode()
            .and_then(|payload| write_frame(&mut *locked(&self.writer), FrameKind::Consent, &payload));
        if let Err(e) = written {
            tracing::debug!("the consent question could not be put to the shim: {e:#}");
            locked(&self.state).question = Question::None;
            return Err(Ended);
        }
        let mut state = locked(&self.state);
        loop {
            if let Question::Answered(answer) = state.question {
                state.question = Question::None;
                drop(state);
                return Ok((answer, hold));
            }
            if state.over_for(Carrier::Session) || state.hosting_ended || gone.is_gone() {
                state.question = Question::None;
                // The shim leaves the question when it reads the withdrawal, and relays keys again: those come
                // after it, as the keys after an answer do.
                state.kept = Some(Vec::new());
                drop(state);
                self.withdraw(id);
                return Err(Ended);
            }
            waiting();
            state = self.changed.wait(state).unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// Tell the shim the question numbered `id` it was put is withdrawn ([`FrameKind::ConsentWithdrawn`]), so that it
    /// comes off the console and takes no more keys. Written under the write lock, as the question was, and before
    /// the hold on the screen drops and the session is repainted. A connection that cannot be written is one the shim
    /// has left.
    fn withdraw(&self, id: u32) {
        let written = ConsentWithdrawal { id }
            .encode()
            .and_then(|payload| write_frame(&mut *locked(&self.writer), FrameKind::ConsentWithdrawn, &payload));
        if let Err(e) = written {
            tracing::debug!("the consent withdrawal could not be put to the shim: {e:#}");
        }
    }

    /// The client of the request `gone` belongs to has hung up: a question asked for it ends. The flag is set before
    /// the state lock is taken and the waiter is woken under it, so a question that is about to wait sees the flag.
    pub(super) fn client_gone(&self, gone: &ClientGone) {
        gone.0.store(true, Ordering::Release);
        let _state = locked(&self.state);
        self.changed.notify_all();
    }

    /// The shim's answer to the question that is asked. An answer that is not for the question asked now (none is
    /// asked: it ended, and the shim answered it late; or another is: the answer is to one that ended before it) is
    /// dropped: it must not answer another.
    pub(super) fn answer(&self, reply: ConsentReply) {
        let mut state = locked(&self.state);
        if state.question != Question::Asked(reply.id) {
            tracing::debug!(
                "the answer to question {} was dropped: the question open is {:?}",
                reply.id,
                state.question
            );
            return;
        }
        state.question = Question::Answered(reply.answer);
        state.kept = Some(Vec::new());
        drop(state);
        self.changed.notify_all();
    }

    /// Hand the screen back to the session if the connection still carries `from` (a command's guard clears what it
    /// hosted either way): the session's output goes on, and
    /// its pseudoconsole is given its current size, even when unchanged, which makes it repaint its whole screen
    /// (the clear that began the question, or the command's own screen, wiped what it had). Never a different size
    /// and back: that stream asks the person's terminal to resize its window.
    ///
    /// The keys kept for a question are delivered first, holding `inputting` alone; the size is applied after, under
    /// `resizing`, at the size the client has by then. A resize that comes between goes to the session as it comes.
    fn switch_back(&self, from: Carrier) {
        // Only a question's screen has kept keys (a command hosted since took them).
        let ordered = (from == Carrier::Asking).then(|| locked(&self.inputting));
        let (hosted, early, kept, ours) = {
            let mut state = locked(&self.state);
            let ours = state.carrier == from;
            if ours {
                state.carrier = Carrier::Session;
            }
            // The command's guard clears what it set whoever carries the connection by now: `end_hosting` waits for
            // nothing to be hosted.
            let hosted = if ours || from == Carrier::Elevated {
                state.elevated.take()
            } else {
                None
            };
            let (early, kept) = if ours {
                (std::mem::take(&mut state.early), state.kept.take().unwrap_or_default())
            } else {
                (Vec::new(), Vec::new())
            };
            (hosted, early, kept, ours)
        };
        self.changed.notify_all();
        drop(hosted);
        if !ours {
            return;
        }
        let Some(session) = &self.session else { return };
        Self::deliver_kept(early, &**session);
        Self::deliver_kept(kept, &**session);
        drop(ordered);
        let _applying = locked(&self.resizing);
        let (cols, rows) = locked(&self.state).size;
        session.resize(cols, rows);
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
        self.link.switch_back(Carrier::Elevated);
    }
}

/// The question's hold on the screen: the connection carries nobody's output while this lives, and dropping it gives
/// the screen back to the session ([`Link::switch_back`]), unless a command has taken it since.
pub(super) struct AskGuard<'a> {
    link: &'a Link,
}

impl Drop for AskGuard<'_> {
    fn drop(&mut self) {
        self.link.switch_back(Carrier::Asking);
    }
}

#[cfg(test)]
#[path = "link_tests.rs"]
mod link_tests;
