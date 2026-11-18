//! provision::probe_run — `verify`'s probes through the agent: which are run, in what order, and what
//! is cleaned up after them.
//!
//! The probes run in the agent's session (see [`super::probe`]); this is the parent's side, which
//! connects to the agent, sends the handshake and reads the PROBE line back.

use std::path::Path;
use std::time::Duration;

use anyhow::Context;

use super::probe::{self, ProbeResult, SymlinkState};
use super::session_rows::{Junction, Probes};
use crate::protocol::Privilege;
use crate::route::ProbeLink;
use crate::socket_loc::Integrity;
use crate::{afunix, shim};

/// What one probe answered: its PROBE line, whether its binary payload survived, and what it said about
/// its junction on stderr ([`probe::junction_notes`]).
struct Answer {
    result: ProbeResult,
    binary_ok: bool,
    said: String,
}

/// How a probe is driven: asked for `Privilege`, told what to do about the junction. The one thing
/// [`run_at`] is given in place of the agent.
type Drive<'a> = &'a dyn Fn(Privilege, ProbeLink) -> anyhow::Result<Answer>;

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
/// Each probe is bounded by `timeout` ([`super::bounded`]), so an agent at High takes up to twice it.
pub fn run(exe: &Path, timeout: Option<Duration>) -> anyhow::Result<Probes> {
    let integrity = crate::account::integrity().context("read this process's integrity level")?;
    run_at(integrity, &std::env::temp_dir(), &|privilege, link| {
        drive_bounded(exe, privilege, link, timeout)
    })
}

/// [`run`] for an agent at `integrity`, with `temp` as the place to name a directory in and `drive` to
/// run a probe.
fn run_at(integrity: Integrity, temp: &Path, drive: Drive) -> anyhow::Result<Probes> {
    match integrity {
        Integrity::Medium => {
            let own = drive(Privilege::Account, ProbeLink::Own)?;
            Ok(Probes {
                junction: Junction {
                    state: own.result.symlink,
                    note: own.said,
                },
                default: own.result,
                binary_ok: own.binary_ok,
                unelevated: None,
                leftover: None,
            })
        }
        Integrity::High => {
            let dir = probe::link::unique_dir(temp);
            let probes = unelevated_then_default(drive, &dir);
            // The one exit: the directory goes whatever the probes did, through no link.
            let leftover = probe::link::remove(&dir)
                .err()
                .map(|e| format!("{}: {e}", dir.display()));
            probes.map(|probes| Probes { leftover, ..probes })
        }
    }
}

/// The two probes of an agent at High, the second always run: the first makes the junction in `dir`, and
/// the second follows it. When there is no junction to follow, because the first failed or could not make
/// one or `dir` cannot be told to a probe as text, the second makes one of its own, which tells nothing
/// about the first's token, and the junction is not judged from it.
fn unelevated_then_default(drive: Drive, dir: &Path) -> anyhow::Result<Probes> {
    let text = dir.to_str();
    let made = drive(
        Privilege::Unelevated,
        text.map_or(ProbeLink::Own, |text| ProbeLink::Make(text.to_owned())),
    );
    let was_made = matches!(&made, Ok(answer) if answer.result.symlink != SymlinkState::Skipped);
    let follow = match text {
        Some(text) if was_made => ProbeLink::Follow(text.to_owned()),
        _ => ProbeLink::Own,
    };
    let followed = drive(Privilege::Account, follow)?;

    let junction = match (&made, text) {
        (_, None) => Junction {
            state: SymlinkState::Skipped,
            note: format!("the directory {} cannot be told to a probe as text", dir.display()),
        },
        (Err(cause), _) => Junction {
            state: SymlinkState::Failed,
            note: format!("no junction from an unelevated session could be tested: {cause:#}"),
        },
        (Ok(made), _) if !was_made => Junction {
            state: SymlinkState::Skipped,
            note: made.said.clone(),
        },
        (Ok(made), _) => Junction {
            state: followed.result.symlink,
            note: [made.said.as_str(), followed.said.as_str()]
                .into_iter()
                .filter(|said| !said.is_empty())
                .collect::<Vec<_>>()
                .join("; "),
        },
    };
    Ok(Probes {
        default: followed.result,
        binary_ok: followed.binary_ok,
        unelevated: Some(made.map(|made| made.result).map_err(|cause| format!("{cause:#}"))),
        junction,
        leftover: None,
    })
}

/// Drive the probe on a worker thread, giving up after `timeout`.
///
/// The bound is here rather than around the child's stdin read for two reasons. It covers
/// EVERY way the probe can fail to answer — a lost stdin-EOF marker, an agent that accepts the
/// connection and then never replies, a child that dies mid-write — where bounding the read
/// would cover only the first. And bounding a blocking `ReadFile` on a Windows pipe means
/// overlapped I/O inside the child, where this is a thread and a channel.
///
/// On expiry the error flows into the same `parity probe (via agent)` row that an unreachable
/// agent produces, so `verify` still prints every local check and exits non-zero — instead of
/// hanging with nothing on stdout, which is what it did before.
fn drive_bounded(
    exe: &Path,
    privilege: Privilege,
    link: ProbeLink,
    timeout: Option<Duration>,
) -> anyhow::Result<Answer> {
    let (tx, rx) = std::sync::mpsc::channel();
    let exe = exe.to_path_buf();
    // The worker owns the whole relay conversation; on expiry it is left blocked on a socket
    // that is not delivering, and `verify` exits immediately after printing, which collects it.
    std::thread::spawn(move || {
        let _ = tx.send(drive(&exe, privilege, &link));
    });
    super::bounded::await_bounded(&rx, timeout)?
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
