//! provision::probe_run — `verify`'s probes through the agent: which are run, in what order, and what
//! is cleaned up after them.
//!
//! The probes run in the agent's session (see [`super::probe`]); this is the parent's side, which
//! connects to the agent, sends the handshake and reads the PROBE line back. What it found, whatever
//! became of each probe, is a [`Probes`] for [`super::session_rows`] to turn into rows.

use std::path::Path;
use std::time::Duration;

use anyhow::Context;

use super::bounded::WaitError;
use super::probe::{self, SymlinkState};
use super::session_rows::{Answer, Junction, ProbeOutcome, Probes, level};
use crate::account::integrity_class;
use crate::protocol::Privilege;
use crate::route::ProbeLink;
use crate::socket_loc::Integrity;
use crate::{afunix, shim};

/// How a probe is driven: asked for `Privilege`, told what to do about the junction, and what became of
/// it. The one thing [`run_at`] is given in place of the agent.
type Drive<'a> = &'a dyn Fn(Privilege, ProbeLink) -> ProbeOutcome;

/// Run the probes through this account's agent and read what they found.
///
/// An agent at High integrity (an administrator's elevated one) is probed twice, and keyed on the
/// level of this process, which is the level of the folder the agent serves: first with the unelevated
/// privilege, which makes a junction that a token below High made, and then as the account, which follows
/// it. RedirectionGuard refuses only a link a non-administrator made, so a junction the elevated probe
/// made itself would be followed always and prove nothing. Any other agent is probed once, and its
/// probe makes and follows a junction of its own.
///
/// The directory of the junction is named here, under this process's temp directory, before any probe
/// runs, and no probe names one back. It is removed here whatever became of the probes.
///
/// Each probe is bounded by `timeout` ([`super::bounded`]), so an agent at High takes up to twice it, except
/// that a first probe that does not answer is not followed by a second.
pub fn run(exe: &Path, timeout: Option<Duration>) -> anyhow::Result<Probes> {
    let integrity = crate::account::integrity().context("read this process's integrity level")?;
    Ok(run_at(integrity, &std::env::temp_dir(), &|privilege, link| {
        drive_bounded(exe, privilege, link, timeout)
    }))
}

/// [`run`] for an agent at `integrity`, with `temp` as the place to name a directory in and `drive` to
/// run a probe. It has an answer for every outcome of every probe: nothing in it returns early.
fn run_at(integrity: Integrity, temp: &Path, drive: Drive) -> Probes {
    match integrity {
        Integrity::Medium => {
            let default = drive(Privilege::Account, ProbeLink::Own);
            let junction = match &default {
                ProbeOutcome::Answered(own) => Junction::Read {
                    state: own.result.symlink,
                    note: own.said.clone(),
                },
                unanswered => no_junction(unanswered, String::new()),
            };
            Probes {
                unelevated: None,
                default,
                junction,
                leftover: None,
            }
        }
        Integrity::High => run_at_high(temp, drive),
    }
}

/// The two probes of an agent at High, in order. The directory is named, the unelevated probe makes the
/// junction in it, the default probe follows it, and the directory is removed.
fn run_at_high(temp: &Path, drive: Drive) -> Probes {
    let dir = probe::link::unique_dir(temp);
    let text = dir.to_str();
    let unelevated = drive(
        Privilege::Unelevated,
        text.map_or(ProbeLink::Own, |text| ProbeLink::Make(text.to_owned())),
    );
    let source = source_of(&dir, text, &unelevated);
    let default = match (&source, &unelevated) {
        (Source::FromBelowHigh(text), _) => drive(Privilege::Account, ProbeLink::Follow((*text).to_owned())),
        // An agent that did not answer is not waited on a second time.
        (_, ProbeOutcome::TimedOut(_)) => ProbeOutcome::NotRun("the agent did not answer the first probe".into()),
        // No junction from below High to follow: the probe makes one of its own, which tells nothing about
        // the first's token, and the junction is not judged from it.
        _ => drive(Privilege::Account, ProbeLink::Own),
    };

    let note = [said(&unelevated), said(&default)]
        .into_iter()
        .filter(|said| !said.is_empty())
        .collect::<Vec<_>>()
        .join("; ");
    let junction = match source {
        Source::FromBelowHigh(_) => match &default {
            ProbeOutcome::Answered(followed) => Junction::Read {
                state: followed.result.symlink,
                note,
            },
            unanswered => no_junction(unanswered, note),
        },
        Source::VolumeRefused => Junction::Read {
            state: SymlinkState::Skipped,
            note,
        },
        Source::Unavailable(cause) => Junction::Unavailable { cause, note },
    };

    // The one place the directory goes, whatever the probes did, through no link.
    let may_come = text.is_some() && matches!(unelevated, ProbeOutcome::TimedOut(_));
    let leftover = match (probe::link::remove(&dir), may_come) {
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
    };
    Probes {
        unelevated: Some(unelevated),
        default,
        junction,
        leftover,
    }
}

/// Where the junction the default probe is judged on comes from.
enum Source<'a> {
    /// A token below High made it, in this directory: the default probe follows it.
    FromBelowHigh(&'a str),
    /// The volume refused to make one: nothing was tested, and that fails nothing.
    VolumeRefused,
    /// There is none from below High, and why.
    Unavailable(String),
}

/// Whether the unelevated probe made a junction from below High in `dir`, which was told to it as `text`.
/// It did only when it answered, reports its integrity as below High, and its junction was made.
fn source_of<'a>(dir: &Path, text: Option<&'a str>, unelevated: &ProbeOutcome) -> Source<'a> {
    let Some(text) = text else {
        return Source::Unavailable(format!(
            "the directory {} cannot be told to a probe as text",
            dir.display()
        ));
    };
    let asked = match unelevated {
        ProbeOutcome::Answered(answer) => &answer.result,
        unanswered => return Source::Unavailable(unanswered.cause().unwrap_or_default().to_string()),
    };
    match asked.integrity.map(integrity_class) {
        None => Source::Unavailable("the probe that asked for an unelevated session did not report its level".into()),
        Some(Integrity::High) => Source::Unavailable(format!(
            "the probe that asked for an unelevated session ran at integrity {}, not below High",
            level(asked.integrity)
        )),
        Some(Integrity::Medium) if asked.symlink.was_made() => Source::FromBelowHigh(text),
        Some(Integrity::Medium) if asked.symlink == SymlinkState::Skipped => Source::VolumeRefused,
        Some(Integrity::Medium) => {
            Source::Unavailable("the probe that asked for an unelevated session could not make the directory".into())
        }
    }
}

/// What the probes said about their junctions: nothing, for one that did not answer.
fn said(outcome: &ProbeOutcome) -> &str {
    match outcome {
        ProbeOutcome::Answered(answer) => &answer.said,
        _ => "",
    }
}

/// The junction of a default probe that did not answer: there is none to judge.
fn no_junction(unanswered: &ProbeOutcome, note: String) -> Junction {
    Junction::Unavailable {
        cause: unanswered.cause().unwrap_or_default().to_string(),
        note,
    }
}

/// Drive the probe on a worker thread, giving up after `timeout`.
///
/// The bound is here rather than around the child's stdin read for two reasons. It covers
/// EVERY way the probe can fail to answer — a lost stdin-EOF marker, an agent that accepts the
/// connection and then never replies, a child that dies mid-write — where bounding the read
/// would cover only the first. And bounding a blocking `ReadFile` on a Windows pipe means
/// overlapped I/O inside the child, where this is a thread and a channel.
///
/// On expiry the outcome is [`ProbeOutcome::TimedOut`], which becomes the `parity probe (via agent)` row
/// that an unreachable agent produces, so `verify` still prints every local check and exits non-zero —
/// instead of hanging with nothing on stdout, which is what it did before.
fn drive_bounded(exe: &Path, privilege: Privilege, link: ProbeLink, timeout: Option<Duration>) -> ProbeOutcome {
    let (tx, rx) = std::sync::mpsc::channel();
    let exe = exe.to_path_buf();
    // The worker owns the whole relay conversation; on expiry it is left blocked on a socket that is not
    // delivering. `verify` goes on without it and exits after printing, which collects it.
    std::thread::spawn(move || {
        let _ = tx.send(drive(&exe, privilege, &link));
    });
    match super::bounded::await_bounded(&rx, timeout) {
        Ok(Ok(answer)) => ProbeOutcome::Answered(answer),
        Ok(Err(cause)) => ProbeOutcome::Failed(format!("{cause:#}")),
        Err(timed_out @ WaitError::TimedOut { .. }) => ProbeOutcome::TimedOut(timed_out.to_string()),
        Err(stopped @ WaitError::WorkerStopped) => ProbeOutcome::Failed(stopped.to_string()),
    }
}

/// Drive `<exe> verify-probe` as an EXEC command THROUGH the agent (so it runs in session 1), asking for
/// `privilege`, parse the PROBE line it prints, and check whether its binary payload survived intact.
///
/// The byte check reads the RAW stdout, before the lossy UTF-8 conversion the line parse
/// needs: the payload is deliberately not valid UTF-8, so converting first would destroy the
/// very property being measured. This is the end-to-end half of byte-transparency — a real
/// child, real pipes, a real socket — which the in-memory relay tests cannot reach.
fn drive(exe: &Path, privilege: Privilege, link: &ProbeLink) -> anyhow::Result<Answer> {
    let sock = crate::userdir::inspect_current_socket_dir()
        .and_then(|folder| folder.connect())
        .context("connect to agent")?;
    let (rx, tx) = afunix::split(sock)?;
    let hs = super::probe_handshake(exe, privilege, link);
    let mut out = Vec::new();
    let mut err = Vec::new();
    // Feed the SAME payload upstream that the child echoes downstream. Passing `io::empty()`
    // here left the client → child direction — the `sftp put` / `scp` upload direction —
    // completely unchecked, while the docs claimed `verify` covered both.
    let upstream = std::io::Cursor::new(probe::binary_probe_payload());
    let code = shim::run_exec_on(rx, tx, &hs, &mut out, &mut err, upstream)?;
    anyhow::ensure!(
        code != 254 && code != 255,
        "probe relay failed (code {code}; stderr={})",
        String::from_utf8_lossy(&err).trim()
    );
    let binary_ok = probe::binary_probe_ok(&out);
    let result = probe::parse_probe_line(&String::from_utf8_lossy(&out))?;
    Ok(Answer {
        result,
        binary_ok,
        said: probe::junction_notes(&String::from_utf8_lossy(&err)),
    })
}

#[cfg(test)]
#[path = "probe_run_tests.rs"]
mod probe_run_tests;
