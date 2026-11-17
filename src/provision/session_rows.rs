//! provision::session_rows — the rows of the `verify` report about what a session through the agent
//! is: elevated or not, whether an unelevated one can be had, and whether a link a session below High
//! made is followed.
//!
//! The facts are the PROBE lines of the probes the agent started, which read their own tokens; nothing
//! is judged from `verify`'s own.

use crate::account::{INTEGRITY_HIGH, INTEGRITY_MEDIUM};
use crate::socket_loc::Elevation;

use super::probe::{ProbeResult, SymlinkState, is_genuine_session};
use super::report::Check;

const APPLY_HINT: &str = "usually an installed exe older than this check: re-run `apply`";

/// What `verify`'s probes through the agent found.
pub struct Probes {
    /// The probe that asked for the account's own session: it follows the junction, and its token is the
    /// session's.
    pub default: ProbeResult,
    /// Whether the payload the child sent downstream arrived byte for byte.
    pub binary_ok: bool,
    /// The probe that asked for an unelevated session, run first for an agent at High integrity, whose
    /// junction the default probe follows; `None` for any other agent.
    pub unelevated: Option<ProbeResult>,
    /// The junction `verify` could not remove, with the cause.
    pub leftover: Option<String>,
}

/// Every row the probes give, in the order `verify` shows them. `active_console` is the id of the
/// physical console's session, which the session row names.
pub fn parity_rows(probes: &Probes, active_console: u32) -> Vec<Check> {
    let p = &probes.default;
    // Parity = escaped session 0 (the limited network-logon session). The agent need not be in THE
    // active-console session — a box can have several interactive sessions — and DPAPI and the junction
    // confirm it is a genuine one.
    let mut rows = vec![
        Check::new(
            "interactive session (via agent)",
            is_genuine_session(p.session_id, p.logon_type),
            format!(
                "session_id={} (active console={active_console}, logon type={})",
                p.session_id,
                p.logon_type.map_or("unknown".to_string(), |t| t.to_string())
            ),
        ),
        Check::new("DPAPI (via agent)", p.dpapi_ok, String::new()),
    ];
    rows.extend(session_rows(p, probes.unelevated.as_ref()));
    let mut junction = link_row(p.symlink);
    if let Some(leftover) = &probes.leftover {
        junction.detail = format!("{} (the junction could not be removed: {leftover})", junction.detail);
    }
    rows.push(junction);
    // Byte-transparency on the real path, in BOTH directions: "the relay carries arbitrary bytes
    // unchanged" is what makes scp and sftp work at all, and these rows hold that claim honest end to end.
    // They are separate because a one-directional failure must name its direction: client → child is the
    // `scp`/`sftp put` upload, child → client the download.
    rows.push(Check::new(
        "binary download (via agent)",
        probes.binary_ok,
        if probes.binary_ok {
            String::new()
        } else {
            "the payload the child sent did not survive the relay byte for byte".into()
        },
    ));
    // `detail()` distinguishes "the child reported a mismatch" from "the child never reported at all" (an
    // installed exe older than this check). Both FAIL — default-deny — but they have different remedies,
    // and claiming the payload was mangled when nothing ever looked at it would be a diagnosis the code
    // cannot support.
    rows.push(Check::new(
        "binary upload (via agent)",
        p.upstream.proven(),
        p.upstream.detail(),
    ));
    rows
}

/// The rows for the session the agent gives, from the probe that asked for the account's own session
/// (`default`) and, when one was run, the probe that asked for an unelevated one (`unelevated`).
///
/// A standard account's agent has one row, which passes. An administrator's has two, and the first
/// fails unless the session is `Full`: an administrator's agent is elevated or absent. The second
/// fails unless the session that asked for less is `Filtered` at Medium.
pub fn session_rows(default: &ProbeResult, unelevated: Option<&ProbeResult>) -> Vec<Check> {
    if default.elevation == Some(Elevation::Standard) {
        return vec![Check::new(
            "session privilege",
            true,
            "this account is not an administrator: its session is a standard account's, and \
             `internal-unelevated` changes nothing",
        )];
    }
    vec![elevated_row(default), unelevated_row(unelevated)]
}

fn elevated_row(default: &ProbeResult) -> Check {
    const NAME: &str = "elevated session";
    match (default.elevation, default.integrity) {
        (Some(Elevation::Full), integrity) => Check::new(
            NAME,
            true,
            format!("Administrators enabled, integrity {}", level(integrity)),
        ),
        (Some(_), integrity) => Check::new(
            NAME,
            false,
            format!(
                "the agent's session is not elevated (integrity {}, Administrators not enabled): an \
                 administrator's agent must be elevated",
                level(integrity)
            ),
        ),
        (None, _) => Check::new(
            NAME,
            false,
            format!("the probe did not report its token ({APPLY_HINT})"),
        ),
    }
}

fn unelevated_row(unelevated: Option<&ProbeResult>) -> Check {
    const NAME: &str = "unelevated session on request";
    let Some(asked) = unelevated else {
        return Check::new(NAME, false, "the probe that asks for an unelevated session was not run");
    };
    match (asked.elevation, asked.integrity) {
        (Some(Elevation::Filtered), Some(INTEGRITY_MEDIUM)) => Check::new(
            NAME,
            true,
            format!(
                "`internal-unelevated` gives integrity {} with Administrators deny-only",
                level(Some(INTEGRITY_MEDIUM))
            ),
        ),
        (Some(_), _) | (None, Some(_)) => Check::new(
            NAME,
            false,
            format!(
                "`internal-unelevated` gave {} at integrity {}, not Administrators deny-only at Medium",
                asked.elevation.map_or("an unknown token", elevation_name),
                level(asked.integrity)
            ),
        ),
        (None, None) => Check::new(
            NAME,
            false,
            format!("the probe did not report its token ({APPLY_HINT})"),
        ),
    }
}

/// `junction (via agent)`: a junction that a token below High made is followed by the session. Only a
/// followed one passes; a refusal means RedirectionGuard is on in the agent's session.
pub fn link_row(symlink: SymlinkState) -> Check {
    const NAME: &str = "junction (via agent)";
    match symlink {
        SymlinkState::Ok => Check::new(NAME, true, "followed"),
        SymlinkState::Blocked => Check::new(
            NAME,
            false,
            "a junction made below High was refused as an untrusted mount point: RedirectionGuard is on in the \
             agent's session",
        ),
        SymlinkState::Failed => Check::new(NAME, false, "the probe could not make the junction or read through it"),
    }
}

fn elevation_name(elevation: Elevation) -> &'static str {
    match elevation {
        Elevation::Full => "a full administrator's token",
        Elevation::Filtered => "a token with Administrators deny-only",
        Elevation::Standard => "a standard account's token",
    }
}

/// An integrity level as `verify` shows it: its name and relative id, or that it was not reported.
fn level(rid: Option<u32>) -> String {
    match rid {
        Some(INTEGRITY_HIGH) => format!("High ({INTEGRITY_HIGH:#x})"),
        Some(INTEGRITY_MEDIUM) => format!("Medium ({INTEGRITY_MEDIUM:#x})"),
        Some(other) => format!("{other:#x}"),
        None => "not reported".to_string(),
    }
}

#[cfg(test)]
#[path = "session_rows_tests.rs"]
mod session_rows_tests;
