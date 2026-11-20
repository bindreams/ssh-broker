//! The agent's side of `ssh-broker elevate`: whether a session's login allows it, and running the command.
//!
//! The unelevated session is a convenience and a consent step, like an ordinary prompt beside "Run as
//! administrator"; it is not a security boundary, and nothing here claims one. The command runs with the agent's
//! own token (elevated), directly (no configured shell: what runs is the line the person typed), and only when
//! [`decide`] says the session's login allowed it. Everything in the request is input from a lower integrity
//! level: see [`crate::protocol::ElevationRequest`].

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use super::link::{AskGuard, Carrier, ClientGone, Ended, Link, locked};
use super::logout::Killer;
use super::{
    ExecStarter, HangupGuard, PtyStarter, PtyTarget, answer_serving, close_unserved_pty, end_pty, prepare_hangup_watch,
    reap_tree, spawn_stream_pump, start_watch_with, teardown_warning,
};
use crate::afunix::ConnTx;
use crate::hangup::HangupWatcher;
use crate::offer::text;
use crate::protocol::{ConsentAnswer, ElevationPolicy, ElevationRequest, SESSION_VARIABLE, SessionId, Stream};

// Whether a request is allowed =====

/// What a session's login allows of a request to elevate.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Verdict {
    /// Run the command.
    Run,
    /// Ask the person at the session's terminal first ([`Link::ask`]); run it only if they allow it.
    Ask,
    /// Do not: say this, exit 126.
    Refuse(String),
}

/// What `policy` allows when a program of the session asks to run a command elevated, in a session with or without
/// a terminal (`has_terminal`), with a screen of its own or not (`terminal`: `elevate --terminal`). `Never` and
/// `Always` refuse (the second because a session that asked for `always` runs at High, where `elevate` runs the
/// command in place and asks nobody: a request for it that reaches the agent comes from a process below High
/// somewhere else in the account). A command that wants a terminal in a session that has none is refused next:
/// there is no screen to give it. `AutoApprove` runs it. `Prompt` asks the person at the terminal; a session without
/// one has nobody to ask and is refused, with the sentence that names the two levels that need no question.
pub(super) fn decide(policy: ElevationPolicy, has_terminal: bool, terminal: bool) -> Verdict {
    match policy {
        ElevationPolicy::Never => Verdict::Refuse(text::elevation_never()),
        ElevationPolicy::Always => Verdict::Refuse(text::elevation_already_elevated()),
        _ if terminal && !has_terminal => Verdict::Refuse(text::elevation_needs_a_terminal()),
        ElevationPolicy::AutoApprove => Verdict::Run,
        ElevationPolicy::Prompt if has_terminal => Verdict::Ask,
        ElevationPolicy::Prompt => Verdict::Refuse(text::elevation_no_terminal()),
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

// The question =====

/// Ask the person at the session's terminal whether `request`'s command may run, in `cwd` (the folder it would run
/// in: the request's, else the account's home), through the session's own shim ([`Link::ask`]). `Ok` is a yes, with
/// the question's hold on the screen, which the caller lets go of, or hands to the command it runs with `--terminal`
/// ([`run_hosted`]). Anything else is the sentence to refuse with: the answer was no (the screen is back with the
/// session by then, repainted), or the session ended while it was asked.
///
/// `gone` is set when the request's client hangs up ([`RequestWatch`]): the question ends then, and is not asked at
/// all if the client is gone already.
pub(super) fn consent<'a>(
    link: &'a Link,
    request: &ElevationRequest,
    cwd: Option<&Path>,
    gone: &ClientGone,
) -> Result<AskGuard<'a>, String> {
    let shown = folder_shown(cwd, std::env::current_dir)?;
    match link.ask(&request.command, &shown, gone) {
        Ok((ConsentAnswer::Allow, hold)) => Ok(hold),
        Ok((ConsentAnswer::Refuse, hold)) => {
            drop(hold);
            Err(text::elevation_declined())
        }
        Err(Ended) => Err(text::elevation_session_ended()),
    }
}

/// The one watch of an `elevate` request's connection, from before its question to the end of its command: when the
/// client hangs up, a question that is asked ends ([`Link::client_gone`]) and a command that has a tree to end
/// ([`RequestWatch::attach`]) has it ended. There is no moment of the request that nobody watches.
///
/// Finishing the watch ([`HangupGuard::finish`]) calls the same action, so [`RequestWatch::is_gone`] is read before it
/// is finished.
pub(super) struct RequestWatch {
    link: Arc<Link>,
    gone: ClientGone,
    /// How to end the command's tree, once it has one.
    command: Mutex<Option<Killer>>,
}

impl RequestWatch {
    /// Start watching `conn`, the request's connection, for the session whose link is `link`. The guard is `None`
    /// when the watcher could not be made: the request then loses only the hang-up protection, as the session's own
    /// does ([`prepare_hangup_watch`]).
    pub(super) fn start(link: &Arc<Link>, conn: &ConnTx) -> (Arc<RequestWatch>, Option<HangupGuard>) {
        let watch = Arc::new(RequestWatch {
            link: Arc::clone(link),
            gone: ClientGone::default(),
            command: Mutex::new(None),
        });
        let on_hangup = Arc::clone(&watch);
        let guard = start_watch_with(prepare_hangup_watch(conn, HangupWatcher::new), move || {
            on_hangup.on_hangup()
        });
        (watch, guard)
    }

    /// The session's link, which the question is asked on and the command's screen is handed over on.
    pub(super) fn link(&self) -> &Arc<Link> {
        &self.link
    }

    /// The flag [`Link::ask`] ends a question on.
    pub(super) fn gone(&self) -> &ClientGone {
        &self.gone
    }

    /// Whether the client has hung up.
    pub(super) fn is_gone(&self) -> bool {
        self.gone.is_gone()
    }

    /// The command has a tree that `end` ends: from now on a hang-up ends it, and one that came before ends it now.
    /// The command is published before the flag is read, and the hang-up sets the flag before it reads the command,
    /// so one of the two sees the other.
    pub(super) fn attach(&self, end: Killer) {
        *locked(&self.command) = Some(Arc::clone(&end));
        if self.gone.is_gone() {
            end();
        }
    }

    fn on_hangup(&self) {
        self.link.client_gone(&self.gone);
        let end = locked(&self.command).clone();
        if let Some(end) = end {
            end();
        }
    }
}

/// What ends `job`'s tree, and says so when it cannot.
fn tree_end(job: &Arc<cosca::Job>) -> Killer {
    let job = Arc::clone(job);
    Arc::new(move || {
        if let Some(w) = teardown_warning(reap_tree(&job)) {
            tracing::error!("{w}");
        }
    })
}

/// The folder the question shows: where the command starts, `cwd`, or, for a command with no folder, the agent's own
/// (`current`). `Err` is the sentence to refuse with when that cannot be told: a question that says nothing of where
/// the command runs is not asked.
fn folder_shown(cwd: Option<&Path>, current: impl FnOnce() -> std::io::Result<PathBuf>) -> Result<String, String> {
    match cwd {
        Some(dir) => Ok(dir.display().to_string()),
        None => current()
            .map(|dir| dir.display().to_string())
            .map_err(|e| text::elevation_cannot_start(&format!("the folder it would start in is not known: {e}"))),
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
/// The command lives as long as the request that asked for it, and no longer: `watch` watches `conn`, and a client
/// that has hung up ends the command's tree ([`RequestWatch::attach`]). A command with `--terminal` also ends with the
/// session whose screen it holds, whoever asked for it ([`Link::end_hosting`]).
///
/// `asked` is the question's hold on the screen when one was asked, and only for a command with `--terminal`, which
/// takes the screen from the question without giving it back to the session in between; the hold is let go once it
/// has. A command run by default is given none: the session's screen is back before it starts.
pub(super) fn run_hosted(
    watch: &RequestWatch,
    conn: &mut ConnTx,
    request: &ElevationRequest,
    cwd: Option<&Path>,
    starts: &Starts,
    id: &SessionId,
    asked: Option<AskGuard<'_>>,
) -> RunOutcome {
    let id = id.to_string();
    let env = [(SESSION_VARIABLE, id.as_str())];
    if request.terminal {
        on_a_pseudoconsole(watch, conn, &request.command, cwd, starts, &env, asked)
    } else {
        debug_assert!(
            asked.is_none(),
            "a command on pipes was given the question's hold on the screen"
        );
        on_pipes(watch, conn, &request.command, cwd, starts, &env)
    }
}

fn on_a_pseudoconsole(
    watch: &RequestWatch,
    conn: &mut ConnTx,
    line: &str,
    cwd: Option<&Path>,
    starts: &Starts,
    env: &[(&str, &str)],
    asked: Option<AskGuard<'_>>,
) -> RunOutcome {
    let link = watch.link();
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
    // The session's end ends the command ([`Link::end_hosting`]) and so does the client's hang-up; a command asked for
    // after the session's end is ended by the call.
    let end = tree_end(&job);
    watch.attach(Arc::clone(&end));
    if answer_serving(conn).is_err() {
        if let Some(w) = teardown_warning(reap_tree(&job)) {
            tracing::error!("{w}");
        }
        close_unserved_pty(session, &|_| {});
        return RunOutcome::Unserved;
    }
    let out_raw = session.out_read_raw();
    let target = Arc::new(PtyTarget::new(&mut session));
    let guard = link.host_elevated(target.clone(), end);
    if guard.is_none() {
        tracing::debug!("the session's shell is gone: the command was ended instead of hosted");
    }
    // The command has the screen now (or never will): the question's hold has nothing left to give back, or the
    // session's screen goes back, repainted, if the command was not hosted.
    drop(asked);
    // A delivery that fails is a connection that has gone, and its command has no screen to run on: its tree ends,
    // as the session's own pump's does, and the pump goes on reading until the pseudoconsole is closed. The session's
    // own end is [`Link::end_hosting`]'s, and this is what ends the command when the session's hang-up watch could
    // not start. The session's input pump does not park in a send on this path (a pseudoconsole's queue has no
    // bound), so it still sees the client go.
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
    match ended {
        Ok(code) => RunOutcome::Exited(code),
        Err(cause) => RunOutcome::EndUnread(cause),
    }
}

/// The command on pipes, with its output written to `conn`. A [`Link`] without a terminal of the request's own
/// connection serialises the two streams' writes, so the pump is the session's own.
fn on_pipes(
    watch: &RequestWatch,
    conn: &mut ConnTx,
    line: &str,
    cwd: Option<&Path>,
    starts: &Starts,
    env: &[(&str, &str)],
) -> RunOutcome {
    let output = Link::new(conn.share(), false, (0, 0), None);
    let mut child = match (starts.exec)(line, cwd, None, env) {
        Ok(child) => child,
        Err(cause) => return RunOutcome::NotStarted(cause.into_cause()),
    };
    let job = child.job();
    watch.attach(tree_end(&job));
    if answer_serving(conn).is_err() {
        if let Some(w) = teardown_warning(reap_tree(&job)) {
            tracing::error!("{w}");
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
    // A pump that panicked is the agent's fault, logged as `end_pty` logs it; the command's code is still its code.
    if out.join().is_err() || err.join().is_err() {
        tracing::error!("an output pump panicked; the output the client printed may be cut");
    }
    match waited {
        Ok(code) => RunOutcome::Exited(code),
        Err(cause) => RunOutcome::EndUnread(cause.into()),
    }
}

#[cfg(test)]
#[path = "elevation_tests.rs"]
mod elevation_tests;
