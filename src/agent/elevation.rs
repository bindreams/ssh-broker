//! The agent's side of `ssh-broker elevate`: whether a session's login allows it, and running the command.
//!
//! The unelevated session is a convenience and a consent step, like an ordinary prompt beside "Run as
//! administrator"; it is not a security boundary, and nothing here claims one. The command runs with the agent's
//! own token (elevated), directly (no configured shell: what runs is the line the person typed), and only when
//! [`decide`] says the session's login allowed it. Everything in the request is input from a lower integrity
//! level: see [`crate::protocol::ElevationRequest`].

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use super::link::{Carrier, Link};
use super::logout::Killer;
use super::{
    ExecStarter, HangupGuard, ParkSignal, PtyStarter, PtyTarget, answer_serving, close_unserved_pty, end_pty,
    prepare_hangup_watch, reap_tree, spawn_stream_pump, start_hangup_watch, teardown_warning,
};
use crate::afunix::ConnTx;
use crate::hangup::HangupWatcher;
use crate::offer::text;
use crate::protocol::{ElevationPolicy, ElevationRequest, SESSION_VARIABLE, SessionId, Stream};

// Whether a request is allowed =====

/// What a session's login allows of a request to elevate.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Verdict {
    /// Run the command.
    Run,
    /// Do not: say this, exit 126.
    Refuse(String),
}

/// What `policy` allows when a program of the session asks to run a command elevated, in a session with or without
/// a terminal (`has_terminal`), with a screen of its own or not (`terminal`: `elevate --terminal`). `Never` and
/// `Always` refuse (the second because a session that asked for `always` runs at High, where `elevate` runs the
/// command in place and asks nobody: a request for it that reaches the agent comes from a process below High
/// somewhere else in the account). A command that wants a terminal in a session that has none is refused next:
/// there is no screen to give it. `AutoApprove` runs it; `Prompt` is refused, with a sentence that says the consent
/// question does not exist yet.
pub(super) fn decide(policy: ElevationPolicy, has_terminal: bool, terminal: bool) -> Verdict {
    match policy {
        ElevationPolicy::Never => Verdict::Refuse(text::elevation_never()),
        ElevationPolicy::Always => Verdict::Refuse(text::elevation_already_elevated()),
        _ if terminal && !has_terminal => Verdict::Refuse(text::elevation_needs_a_terminal()),
        ElevationPolicy::AutoApprove => Verdict::Run,
        ElevationPolicy::Prompt => Verdict::Refuse(text::elevation_consent_not_built()),
    }
}

// The session's entry =====

/// How a command is started: the starters of the session's hooks, so that a test can replace them as it does the
/// session's own.
#[derive(Clone, Copy)]
pub(super) struct Starts {
    pub pty: PtyStarter,
    pub exec: ExecStarter,
}

/// One elevation at a time per session: the slot is taken before the question is asked and held until the command
/// has ended.
#[derive(Default)]
pub(super) struct Slot(AtomicBool);

impl Slot {
    /// The slot, or `None` while another elevation of the session holds it.
    pub(super) fn try_take(&self) -> Option<SlotGuard<'_>> {
        self.0
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
            .then_some(SlotGuard(self))
    }
}

/// The slot, held; free again when this drops.
pub(super) struct SlotGuard<'a>(&'a Slot);

impl Drop for SlotGuard<'_> {
    fn drop(&mut self) {
        self.0.0.store(false, Ordering::Release);
    }
}

/// What a request needs of the session it is for. Published to `Control` once the session's [`Link`] exists
/// (`Registration::attach`).
pub(super) struct HostedSession {
    /// What the session's login asked of elevation.
    pub(super) policy: ElevationPolicy,
    /// The session's connection, which the output of a command run with `--terminal` is carried on.
    pub(super) link: Arc<Link>,
    /// How a command for this session is started.
    pub(super) starts: Starts,
    /// The slot of the one elevation the session may have at a time.
    pub(super) slot: Slot,
}

impl HostedSession {
    pub(super) fn new(policy: ElevationPolicy, link: Arc<Link>, starts: Starts) -> Self {
        HostedSession {
            policy,
            link,
            starts,
            slot: Slot::default(),
        }
    }
}

// Running the command =====

/// How running a hosted command ended.
pub(super) enum RunOutcome {
    /// The command did not start, and the client was not told it had: a refusal, with the cause.
    NotStarted(anyhow::Error),
    /// The command started, ended, and this is its exit code.
    Exited(i32),
    /// The command started and the client could not be told so: its tree was ended and `answer_serving` has logged
    /// why. Nothing more is written to the client.
    Unserved,
    /// The command started (the client was answered `Serving`) and its end could not be read: why.
    EndUnread(anyhow::Error),
}

/// Run the command of `request` elevated, hosted by the agent, for the session whose connection is `link` and whose
/// id is `id` (which its environment carries, so that the command can itself ask for what a program of the session
/// can), in `cwd`. `conn` is the write half of the request's own connection. Returns how it ended ([`RunOutcome`]).
///
/// Once the command has started, is contained and runs, and before any output of it is carried, the client is answered
/// `Serving` on `conn` (see [`FrameKind`](crate::protocol::FrameKind)), in both modes: it is how the client knows the
/// command ran. When that cannot be written the client is gone: the command's tree is ended as a session's is, and
/// the outcome is [`RunOutcome::Unserved`].
///
/// The command is started directly with the agent's own token, in the mode the REQUEST asks for, whatever the
/// session is:
///
/// - by default it runs on pipes, its stdin closed at once, and its stdout and stderr go back on `conn` as the
///   request's reply, for the `elevate` client to print. The session's connection is not touched;
/// - with `--terminal` it has a pseudoconsole of its own at the link's size: the session's connection carries its
///   output and it gets the client's keys while it runs ([`Link::host_elevated`]). When it ends, the client's keys
///   go back to the session at once ([`Link::return_input`]), and the pseudoconsole is closed and drained as a
///   session's is before the screen goes back to the session, which repaints it.
///
/// The command lives as long as the request that asked for it, and no longer: `conn` is watched, and a client that
/// has hung up ends the command's tree. A command with `--terminal` also ends with the session whose screen it
/// holds, whoever asked for it ([`Link::end_hosting`]).
pub(super) fn run_hosted(
    link: &Arc<Link>,
    conn: &mut ConnTx,
    request: &ElevationRequest,
    cwd: Option<&Path>,
    starts: &Starts,
    id: &SessionId,
) -> RunOutcome {
    let id = id.to_string();
    let env = [(SESSION_VARIABLE, id.as_str())];
    if request.terminal {
        on_a_pseudoconsole(link, conn, &request.command, cwd, starts, &env)
    } else {
        on_pipes(conn, &request.command, cwd, starts, &env)
    }
}

/// Watch `conn`, the request's connection, for the client going away, and end `job`'s tree when it does.
fn watch_request(conn: &ConnTx, job: &Arc<cosca::Job>) -> Option<HangupGuard> {
    start_hangup_watch(prepare_hangup_watch(conn, HangupWatcher::new), job)
}

fn on_a_pseudoconsole(
    link: &Arc<Link>,
    conn: &mut ConnTx,
    line: &str,
    cwd: Option<&Path>,
    starts: &Starts,
    env: &[(&str, &str)],
) -> RunOutcome {
    debug_assert!(
        link.has_terminal(),
        "decide refuses --terminal in a session without a terminal"
    );
    let (cols, rows) = link.size();
    let mut session = match (starts.pty)(line, cols, rows, cwd, None, None, env) {
        Ok(session) => session,
        Err(cause) => return RunOutcome::NotStarted(cause.into_cause()),
    };
    let job = session.job();
    let hangup = watch_request(conn, &job);
    if answer_serving(conn).is_err() {
        if let Some(w) = teardown_warning(reap_tree(&job)) {
            tracing::error!("{w}");
        }
        close_unserved_pty(session, &|_| {});
        if let Some(hangup) = hangup {
            hangup.finish();
        }
        return RunOutcome::Unserved;
    }
    let out_raw = session.out_read_raw();
    let target = Arc::new(PtyTarget::new(&mut session, ParkSignal::default()));
    // The session's end ends the command ([`Link::end_hosting`]); a command asked for after it is ended by the call.
    let end: Killer = {
        let job = Arc::clone(&job);
        Arc::new(move || {
            reap_tree(&job);
        })
    };
    let guard = link.host_elevated(target.clone(), end);
    if guard.is_none() {
        tracing::debug!("the session's shell is gone: the command was ended instead of hosted");
    }
    // A delivery that fails is a connection that has gone, and its command has no screen to run on: its tree ends,
    // as the session's own pump's does, and the pump goes on reading until the pseudoconsole is closed. The session's
    // own end is [`Link::end_hosting`]'s, and this is what ends the command when the session's hang-up watch could
    // not start and its input pump is parked in a send.
    let gone = {
        let job = Arc::clone(&job);
        move || {
            reap_tree(&job);
        }
    };
    let pump = spawn_stream_pump(out_raw, Stream::Pty, Arc::clone(link), Carrier::Elevated, gone);

    // The session's own teardown (see `handle_pty`), with nothing to end in the link: the command is the one being
    // ended. Once it has exited and its tree is reaped, the client's keys are the session's again; its screen is
    // back only when the guard drops below.
    let ended = end_pty(session, &target, pump, || link.return_input());
    // The connection goes back to the session before the reply is written.
    drop(guard);
    if let Some(hangup) = hangup {
        hangup.finish();
    }
    match ended {
        Ok(code) => RunOutcome::Exited(code),
        Err(cause) => RunOutcome::EndUnread(cause),
    }
}

/// The command on pipes, with its output written to `conn`. A [`Link`] without a terminal of the request's own
/// connection serialises the two streams' writes, so the pump is the session's own.
fn on_pipes(conn: &mut ConnTx, line: &str, cwd: Option<&Path>, starts: &Starts, env: &[(&str, &str)]) -> RunOutcome {
    let output = Link::new(conn.share(), false, (0, 0), None);
    let mut child = match (starts.exec)(line, cwd, None, env) {
        Ok(child) => child,
        Err(cause) => return RunOutcome::NotStarted(cause.into_cause()),
    };
    let job = child.job();
    let hangup = watch_request(conn, &job);
    if answer_serving(conn).is_err() {
        if let Some(w) = teardown_warning(reap_tree(&job)) {
            tracing::error!("{w}");
        }
        if let Some(hangup) = hangup {
            hangup.finish();
        }
        return RunOutcome::Unserved;
    }
    // The command's stdin is closed at once: it is never fed from the session, which is below it.
    drop(child.take_stdin_write());
    // A write that fails is a client that has gone: the command's tree ends, and the pump goes on reading.
    let gone = || {
        let job = Arc::clone(&job);
        move || {
            reap_tree(&job);
        }
    };
    let out = spawn_stream_pump(
        child.stdout_read_raw(),
        Stream::Stdout,
        Arc::clone(&output),
        Carrier::Elevated,
        gone(),
    );
    let err = spawn_stream_pump(
        child.stderr_read_raw(),
        Stream::Stderr,
        Arc::clone(&output),
        Carrier::Elevated,
        gone(),
    );
    let waited = child.wait();
    if let Some(w) = teardown_warning(reap_tree(&job)) {
        tracing::error!("{w}");
    }
    let (out, err) = (out.join(), err.join());
    let panicked = out.is_err() || err.is_err();
    if panicked {
        tracing::error!("an output pump panicked; the output the client printed may be cut");
    }
    if let Some(hangup) = hangup {
        hangup.finish();
    }
    match (waited, panicked) {
        (Err(cause), _) => RunOutcome::EndUnread(cause.into()),
        // The command's code must not be reported as a clean end.
        (Ok(_), true) => RunOutcome::EndUnread(anyhow::anyhow!("an output pump panicked; the output may be cut")),
        (Ok(code), false) => RunOutcome::Exited(code),
    }
}

#[cfg(test)]
#[path = "elevation_tests.rs"]
mod elevation_tests;
