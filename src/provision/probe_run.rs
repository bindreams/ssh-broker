//! provision::probe_run — `doctor`'s probes through the agent: which are run, in what order, and what
//! is cleaned up after them.
//!
//! The probes run in the agent's session (see [`super::probe`]); this is the parent's side, which
//! connects to the agent, sends the handshake and reads the PROBE line back. What it found, whatever
//! became of each probe, is a [`Probes`] for [`super::session_rows`] to turn into rows.
//!
//! The directory of the junction is named here, under this process's temp directory, before any probe
//! runs, and no probe names one back, so a path a process below High wrote is never one `doctor` acts on.
//! It is removed here, through no link, whatever became of the probes: one whose child may still be
//! running may still create it, and a note says so. A directory left in the temp folder does not make the installation
//! wrong, so the `junction directory` row it gives passes.

use std::path::Path;
use std::time::Duration;

use anyhow::Context;

use super::bounded::WaitError;
use super::probe::{self, SymlinkState};
use super::session_rows::{Answer, Junction, ProbeOutcome, Probes, level};
use crate::account::integrity_class;
use crate::protocol::ElevationPolicy;
use crate::route::ProbeLink;
use crate::socket_loc::Integrity;
use crate::{afunix, shim};

/// How a probe is driven: asked for an `ElevationPolicy`, told what to do about the junction, and what became of
/// it. The one thing [`run_at`] is given in place of the agent.
type Drive<'a> = &'a dyn Fn(ElevationPolicy, ProbeLink) -> ProbeOutcome;

/// Run the probes through this account's agent and read what they found.
///
/// An agent at High integrity (an administrator's elevated one) is probed twice, and keyed on the
/// level of this process, which is the level of the folder the agent serves: first with the default
/// policy (`prompt`: an unelevated session), which makes a junction that a token below High made, and then
/// with `always` (an elevated one), which follows it. RedirectionGuard refuses only a link a
/// non-administrator made, so a junction the elevated probe made itself would be followed always and prove
/// nothing. Any other agent is probed once, and its probe, which asks for the default policy (`always` is
/// refused below High), makes and follows a junction.
///
/// Each probe is bounded by `timeout` ([`super::bounded`]), so an agent at High takes up to twice it, except
/// that a first probe that does not answer is not followed by a second.
pub fn run(exe: &Path, timeout: Option<Duration>) -> anyhow::Result<Probes> {
    let integrity = crate::account::integrity().context("read this process's integrity level")?;
    Ok(run_at(integrity, &std::env::temp_dir(), &|elevation, link| {
        drive_bounded(exe, elevation, link, timeout)
    }))
}

/// [`run`] for an agent at `integrity`, with `temp` as the place to name a directory in and `drive` to
/// run a probe. It has an answer for every outcome of every probe: nothing in it returns early.
fn run_at(integrity: Integrity, temp: &Path, drive: Drive) -> Probes {
    let dir = probe::link::unique_dir(temp);
    let mut probes = match integrity {
        Integrity::Medium => run_at_medium(&dir, drive),
        Integrity::High => run_at_high(&dir, drive),
    };
    probes.leftover = leftover(&dir, dir.to_str().is_some(), maker(&probes));
    probes
}

/// The probe of an agent below High: it makes the junction in `dir` and follows it.
fn run_at_medium(dir: &Path, drive: Drive) -> Probes {
    let default = drive(ElevationPolicy::DEFAULT, make_link(dir));
    let note = said(&default).to_owned();
    let junction = if dir.to_str().is_some() {
        read_by(&default, note)
    } else {
        Junction::Unavailable {
            cause: not_text(dir),
            note,
        }
    };
    Probes {
        unelevated: None,
        default,
        junction,
        leftover: None,
    }
}

/// The two probes of an agent at High, in the order [`run`] gives.
fn run_at_high(dir: &Path, drive: Drive) -> Probes {
    let unelevated = drive(ElevationPolicy::DEFAULT, make_link(dir));
    let source = source_of(dir, &unelevated);
    let default = match (&source, &unelevated) {
        (Source::FromBelowHigh(text), _) => drive(ElevationPolicy::Always, ProbeLink::Follow((*text).to_owned())),
        // An agent that did not answer is not waited on a second time.
        (_, ProbeOutcome::TimedOut(_)) => ProbeOutcome::NotRun("the agent did not answer the first probe".into()),
        // No junction from below High to follow, and one that the probe made itself tells nothing about
        // the first's token: the probe is given none.
        _ => drive(ElevationPolicy::Always, ProbeLink::NoJunction),
    };

    let note = [said(&unelevated), said(&default)]
        .into_iter()
        .filter(|said| !said.is_empty())
        .collect::<Vec<_>>()
        .join("; ");
    let junction = match source {
        Source::FromBelowHigh(_) => read_by(&default, note),
        Source::NoJunctionsOnVolume => Junction::Read {
            state: Some(SymlinkState::Skipped),
            note,
        },
        Source::Unavailable(cause) => Junction::Unavailable { cause, note },
    };
    Probes {
        unelevated: Some(unelevated),
        default,
        junction,
        leftover: None,
    }
}

/// What a probe is told to do about the directory `dir` that `doctor` named: make a junction in it, or
/// nothing when it cannot be told to a probe as text.
fn make_link(dir: &Path) -> ProbeLink {
    dir.to_str()
        .map_or(ProbeLink::NoJunction, |text| ProbeLink::Make(text.to_owned()))
}

/// The junction as the default probe, which follows it, found it; one that gave no answer found nothing, and
/// its own outcome says why.
fn read_by(default: &ProbeOutcome, note: String) -> Junction {
    match default.answer() {
        Ok(followed) => Junction::Read {
            state: followed.result.symlink,
            note,
        },
        Err(_) => Junction::Unread { note },
    }
}

fn not_text(dir: &Path) -> String {
    format!("the directory {} cannot be told to a probe as text", dir.display())
}

/// The probe that was to make the directory: the unelevated one of an agent at High, the only one below it.
fn maker(probes: &Probes) -> &ProbeOutcome {
    probes.unelevated.as_ref().unwrap_or(&probes.default)
}

/// Remove `dir` and say what is left of it: why it could not be removed, and that a `maker` whose child may
/// still be running may still create it. `told` is whether `maker` was given it.
fn leftover(dir: &Path, told: bool, maker: &ProbeOutcome) -> Option<String> {
    let may_come = told && maker.may_still_run();
    match (probe::link::remove(dir), may_come) {
        (Err(e), may_come) => Some(format!(
            "{} could not be removed: {e}{}; it can be deleted",
            dir.display(),
            if may_come {
                ", and the probe that did not answer may still create it"
            } else {
                ""
            }
        )),
        (Ok(()), true) => Some(format!(
            "the probe that did not answer may still create {}; it can be deleted",
            dir.display()
        )),
        (Ok(()), false) => None,
    }
}

/// Where the junction the default probe at High is judged on comes from.
enum Source<'a> {
    /// A token below High made it, in this directory: the default probe follows it.
    FromBelowHigh(&'a str),
    /// The volume holds no junctions: nothing was tested, and that fails nothing.
    NoJunctionsOnVolume,
    /// There is none from below High, and why.
    Unavailable(String),
}

/// Whether the unelevated probe made a junction from below High in `dir`. It did only when it answered,
/// reports its integrity as below High, and its junction was made.
fn source_of<'a>(dir: &'a Path, unelevated: &ProbeOutcome) -> Source<'a> {
    let Some(text) = dir.to_str() else {
        return Source::Unavailable(not_text(dir));
    };
    let asked = match unelevated.answer() {
        Ok(answer) => &answer.result,
        Err(cause) => return Source::Unavailable(cause.to_string()),
    };
    match (asked.integrity.map(integrity_class), asked.symlink) {
        (None, _) => {
            Source::Unavailable("the probe that asked for an unelevated session did not report its level".into())
        }
        (Some(Integrity::High), _) => Source::Unavailable(format!(
            "the probe that asked for an unelevated session ran at integrity {}, not below High",
            level(asked.integrity)
        )),
        (Some(Integrity::Medium), None) => {
            Source::Unavailable("the probe that asked for an unelevated session did not report its junction".into())
        }
        (Some(Integrity::Medium), Some(state)) if state.was_made() => Source::FromBelowHigh(text),
        (Some(Integrity::Medium), Some(SymlinkState::Skipped)) => Source::NoJunctionsOnVolume,
        (Some(Integrity::Medium), Some(_)) => {
            Source::Unavailable("the probe that asked for an unelevated session could not make the junction".into())
        }
    }
}

/// What a probe said about its junction: nothing, for one that did not answer.
fn said(outcome: &ProbeOutcome) -> &str {
    outcome.answer().map_or("", |answer| answer.junction_said.as_str())
}

/// Drive the probe on a worker thread, giving up after `timeout`.
///
/// The bound covers every way the probe can fail to answer (lost stdin-EOF marker, an agent that never
/// replies, a child that dies mid-write); bounding the read would cover one, and needs overlapped I/O in
/// the child.
///
/// On expiry the outcome is [`ProbeOutcome::TimedOut`], which becomes the `parity probe (via agent)` row
/// that an unreachable agent produces, so `doctor` still prints every local check and exits non-zero
/// instead of hanging with nothing on stdout.
fn drive_bounded(exe: &Path, elevation: ElevationPolicy, link: ProbeLink, timeout: Option<Duration>) -> ProbeOutcome {
    let (tx, rx) = std::sync::mpsc::channel();
    let exe = exe.to_path_buf();
    // The worker owns the whole relay conversation; on expiry it is left blocked on a socket that is not
    // delivering. `doctor` goes on without it and exits after printing, which collects it.
    std::thread::spawn(move || {
        let _ = tx.send(drive(&exe, elevation, &link));
    });
    outcome_of(super::bounded::await_bounded(&rx, timeout))
}

/// How [`drive`] stopped short of an answer, which says whether the probe's child may still be running.
enum Stop {
    /// Nothing reached the agent (no connection, no handshake sent): there is no child.
    NotStarted(anyhow::Error),
    /// The relay broke before the child's exit: whether it still runs is not known.
    RelayBroke(anyhow::Error),
    /// The relay ended with the child's exit, and what it printed has no PROBE line: the child is gone.
    Exited(anyhow::Error),
}

/// What became of a probe whose worker was waited for: a probe that could not be started is
/// [`ProbeOutcome::NotRun`]; a timeout is [`ProbeOutcome::TimedOut`]; a relay that failed and a worker that
/// stopped are [`ProbeOutcome::Failed`], whose child is gone only when the relay ended with its exit.
fn outcome_of(waited: Result<Result<Answer, Stop>, WaitError>) -> ProbeOutcome {
    let failed = |cause: String, may_still_run| ProbeOutcome::Failed { cause, may_still_run };
    match waited {
        Ok(Ok(answer)) => ProbeOutcome::Answered(answer),
        Ok(Err(Stop::NotStarted(cause))) => ProbeOutcome::NotRun(format!("{cause:#}")),
        Ok(Err(Stop::RelayBroke(cause))) => failed(format!("{cause:#}"), true),
        Ok(Err(Stop::Exited(cause))) => failed(format!("{cause:#}"), false),
        Err(timed_out @ WaitError::TimedOut { .. }) => ProbeOutcome::TimedOut(timed_out.to_string()),
        Err(stopped @ WaitError::WorkerStopped) => failed(stopped.to_string(), true),
    }
}

/// Drive `<exe> doctor-probe` as an EXEC command THROUGH the agent (so it runs in session 1), asking for
/// `elevation`, parse the PROBE line it prints, and check whether its binary payload survived intact.
///
/// The byte check reads the RAW stdout, before the lossy UTF-8 conversion the line parse
/// needs: the payload is deliberately not valid UTF-8, so converting first would destroy the
/// very property being measured. This is the end-to-end half of byte-transparency — a real
/// child, real pipes, a real socket — which the in-memory relay tests cannot reach.
fn drive(exe: &Path, elevation: ElevationPolicy, link: &ProbeLink) -> Result<Answer, Stop> {
    let sock = crate::userdir::inspect_current_socket_dir()
        .and_then(|folder| folder.connect())
        .context("connect to agent")
        .map_err(Stop::NotStarted)?;
    let (rx, tx) = afunix::split(sock).map_err(|e| Stop::NotStarted(e.into()))?;
    let hs = super::probe_handshake(exe, elevation, link);
    let mut out = Vec::new();
    let mut err = Vec::new();
    // Feed the same payload upstream that the child echoes downstream, so the client → child
    // (`sftp put`/`scp`) direction is checked too.
    let upstream = std::io::Cursor::new(probe::binary_probe_payload());
    let code = shim::run_exec_on(rx, tx, &hs, &mut out, &mut err, upstream).map_err(Stop::RelayBroke)?;
    if code == 254 || code == 255 {
        return Err(Stop::RelayBroke(anyhow::anyhow!(
            "probe relay failed (code {code}; stderr={})",
            String::from_utf8_lossy(&err).trim()
        )));
    }
    let binary_ok = probe::binary_probe_ok(&out);
    let result = probe::parse_probe_line(&String::from_utf8_lossy(&out)).map_err(Stop::Exited)?;
    let stderr = String::from_utf8_lossy(&err);
    Ok(Answer {
        result,
        binary_ok,
        junction_said: probe::notes(&stderr, probe::JUNCTION_SAID),
        token_said: probe::notes(&stderr, probe::TOKEN_SAID),
    })
}

#[cfg(test)]
#[path = "probe_run_tests.rs"]
mod probe_run_tests;
