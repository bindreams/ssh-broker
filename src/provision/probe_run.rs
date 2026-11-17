//! provision::probe_run — `verify`'s probes through the agent: which are run, in what order, and what
//! is cleaned up after them.
//!
//! The probes run in the agent's session (see [`super::probe`]); this is the parent's side, which
//! connects to the agent, sends the handshake and reads the PROBE line back.

use std::path::Path;
use std::time::Duration;

use anyhow::Context;

use super::probe::{self, ProbeResult};
use super::session_rows::Probes;
use crate::protocol::Privilege;
use crate::route::ProbeLink;
use crate::socket_loc::Integrity;
use crate::{afunix, shim};

/// Run the probes through this account's agent and read what they found.
///
/// An agent at High integrity (an administrator's elevated one) is probed twice, and keyed on the
/// level of this process, which is the level of the folder the agent serves: first with the unelevated
/// privilege, which makes a junction a token below High made, and then as the account, which follows
/// it. RedirectionGuard refuses only a link a non-administrator made, so a junction the elevated probe
/// made itself would be followed always and prove nothing. Any other agent is probed once, and its
/// probe makes and follows a junction of its own. The junction of the first is removed here whatever
/// became of the second.
///
/// Each probe is bounded by `timeout` ([`super::bounded`]).
pub fn run(exe: &Path, timeout: Option<Duration>) -> anyhow::Result<Probes> {
    match crate::account::integrity().context("read this process's integrity level")? {
        Integrity::Medium => {
            let (default, binary_ok) = drive_bounded(exe, Privilege::Account, ProbeLink::Own, timeout)?;
            Ok(Probes {
                default,
                binary_ok,
                unelevated: None,
                leftover: None,
            })
        }
        Integrity::High => {
            let (unelevated, _) = drive_bounded(exe, Privilege::Unelevated, ProbeLink::Make, timeout)?;
            let dir = unelevated.junction.clone().with_context(|| {
                format!(
                    "the probe that asked for an unelevated session made no junction (its link outcome: {:?})",
                    unelevated.symlink
                )
            })?;
            let followed = match dir.to_str() {
                Some(dir) => drive_bounded(exe, Privilege::Account, ProbeLink::Follow(dir.to_owned()), timeout),
                None => Err(anyhow::anyhow!("the junction's directory {dir:?} is not Unicode text")),
            };
            let leftover = probe::link::remove(&dir)
                .err()
                .map(|e| format!("{}: {e}", dir.display()));
            let (default, binary_ok) = followed?;
            Ok(Probes {
                default,
                binary_ok,
                unelevated: Some(unelevated),
                leftover,
            })
        }
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
/// On expiry the error flows into the same `parity probe (via agent)` row that an unreachable
/// agent produces, so `verify` still prints every local check and exits non-zero — instead of
/// hanging with nothing on stdout, which is what it did before.
fn drive_bounded(
    exe: &Path,
    privilege: Privilege,
    link: ProbeLink,
    timeout: Option<Duration>,
) -> anyhow::Result<(ProbeResult, bool)> {
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
fn drive(exe: &Path, privilege: Privilege, link: &ProbeLink) -> anyhow::Result<(ProbeResult, bool)> {
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
    let parsed = probe::parse_probe_line(&String::from_utf8_lossy(&out))?;
    Ok((parsed, binary_ok))
}
