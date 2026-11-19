//! The agent's side of `ssh-broker elevate`: whether a session's login allows it, and running the command.
//!
//! The unelevated session is a convenience and a consent step, like an ordinary prompt beside "Run as
//! administrator"; it is not a security boundary, and nothing here claims one. The command runs with the agent's
//! own token (elevated), directly (no configured shell: what runs is the line the person typed), and only when
//! [`decide`] says the session's login allowed it. Everything in the request is input from a lower integrity
//! level: see [`crate::protocol::ElevationRequest`].

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use super::link::{Carrier, Link};
use super::{
    ExecStarter, HandleWriter, HangupGuard, ParkSignal, PtyStarter, PtyTarget, prepare_hangup_watch, reap_tree,
    spawn_stream_pump, start_hangup_watch, teardown_warning,
};
use crate::afunix::ConnTx;
use crate::conpty;
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
/// there is no screen to give it. `AutoApprove` runs it; `Prompt` is the question the next unit builds, and refuses
/// with a sentence that says so.
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
pub(super) trait Hosted: Send + Sync {
    /// What the session's login asked of elevation.
    fn policy(&self) -> ElevationPolicy;
    /// Whether the session has a terminal.
    fn has_terminal(&self) -> bool;
    /// The session's connection, which the output of a command run with `--terminal` is carried on.
    fn link(&self) -> &Arc<Link>;
    /// How a command for this session is started.
    fn starts(&self) -> &Starts;
    /// The slot of the one elevation the session may have at a time.
    fn slot(&self) -> &Slot;
}

/// The session the agent hosts, as a request sees it.
pub(super) struct HostedSession {
    policy: ElevationPolicy,
    link: Arc<Link>,
    starts: Starts,
    slot: Slot,
}

impl HostedSession {
    /// The entry of a session with `link`, shared as a request sees it.
    pub(super) fn shared(policy: ElevationPolicy, link: Arc<Link>, starts: Starts) -> Arc<dyn Hosted> {
        Arc::new(HostedSession {
            policy,
            link,
            starts,
            slot: Slot::default(),
        })
    }
}

impl Hosted for HostedSession {
    fn policy(&self) -> ElevationPolicy {
        self.policy
    }

    fn has_terminal(&self) -> bool {
        self.link.has_terminal()
    }

    fn link(&self) -> &Arc<Link> {
        &self.link
    }

    fn starts(&self) -> &Starts {
        &self.starts
    }

    fn slot(&self) -> &Slot {
        &self.slot
    }
}

// Running the command =====

/// Run the command of `request` elevated, hosted by the agent, for the session whose connection is `link` and whose
/// id is `id` (which its environment carries, so that the command can itself ask for what a program of the session
/// can), in `cwd`. `conn` is the write half of the request's own connection. Returns its exit code once it has ended.
///
/// The command is started directly with the agent's own token, in the mode the REQUEST asks for, whatever the
/// session is:
///
/// - by default it runs on pipes, its stdin closed at once, and its stdout and stderr go back on `conn` as the
///   request's reply, for the `elevate` client to print. The session's connection is not touched;
/// - with `--terminal` it has a pseudoconsole of its own at the link's size: the session's connection carries its
///   output and it gets the client's keys while it runs ([`Link::host_elevated`]), and when it ends the
///   pseudoconsole is closed and drained as a session's is before the connection goes back to the session, which
///   repaints its screen.
///
/// The command lives as long as the request that asked for it, and no longer: `conn` is watched, and a client that
/// has hung up ends the command's tree. `elevate` is a process of the session, so the session's own end ends it
/// first.
pub(super) fn run_hosted(
    link: &Arc<Link>,
    conn: &ConnTx,
    request: &ElevationRequest,
    cwd: Option<&Path>,
    starts: &Starts,
    id: &SessionId,
) -> anyhow::Result<i32> {
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
    conn: &ConnTx,
    line: &str,
    cwd: Option<&Path>,
    starts: &Starts,
    env: &[(&str, &str)],
) -> anyhow::Result<i32> {
    debug_assert!(
        link.has_terminal(),
        "decide refuses --terminal in a session without a terminal"
    );
    let (cols, rows) = link.size();
    let mut session =
        (starts.pty)(line, cols, rows, cwd, None, None, env).map_err(crate::shell::StartError::into_cause)?;
    let job = session.job();
    let hangup = watch_request(conn, &job);
    let out_raw = session.out_read_raw();
    let hpc = Arc::new(Mutex::new(Some(session.take_hpc_raw())));
    let target = Arc::new(PtyTarget::new(
        HandleWriter::spawn(session.in_write_raw(), None, ParkSignal::default()),
        Arc::clone(&hpc),
    ));
    let guard = link.host_elevated(target.clone());
    let pump = spawn_stream_pump(out_raw, Stream::Pty, Arc::clone(link), Carrier::Elevated, || {});

    // The session's own teardown, in the same order (see `handle_pty`): wait, reap the tree, close the
    // pseudoconsole while holding its lock (a resize cannot touch a closed one), which flushes conhost and ends
    // the output, then join the pump.
    let waited = session.wait();
    if let Some(w) = teardown_warning(reap_tree(&job)) {
        tracing::error!("{w}");
    }
    if let Some(raw) = hpc.lock().unwrap_or_else(PoisonError::into_inner).take() {
        conpty::close_pty_raw(raw);
    }
    let _ = pump.join();
    // The connection goes back to the session before the reply is written.
    drop(guard);
    // The writer's thread may be parked in the input pipe until the pseudoconsole is closed, which it now is; it
    // is joined before the pipe's handles are closed with `session`.
    target.shutdown();
    drop(session);
    if let Some(hangup) = hangup {
        hangup.finish();
    }
    Ok(waited?)
}

/// The command on pipes, with its output written to `conn`. A [`Link`] without a terminal of the request's own
/// connection serialises the two streams' writes, so the pump is the session's own.
fn on_pipes(
    conn: &ConnTx,
    line: &str,
    cwd: Option<&Path>,
    starts: &Starts,
    env: &[(&str, &str)],
) -> anyhow::Result<i32> {
    let output = Link::new(conn.try_clone()?, false, (0, 0), None);
    let mut child = (starts.exec)(line, cwd, None, env).map_err(crate::shell::StartError::into_cause)?;
    let job = child.job();
    let hangup = watch_request(conn, &job);
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
    let _ = out.join();
    let _ = err.join();
    if let Some(hangup) = hangup {
        hangup.finish();
    }
    Ok(waited?)
}

#[cfg(test)]
#[path = "elevation_tests.rs"]
mod elevation_tests;
