//! provision::session_rows — the rows of the `verify` report about what a session through the agent
//! is: elevated or not, whether an unelevated one can be had, and whether a link a session below High
//! made is followed.
//!
//! The facts are the PROBE lines of the probes the agent started, which read their own tokens; nothing
//! is judged from `verify`'s own.

use crate::account::{INTEGRITY_HIGH, INTEGRITY_MEDIUM, integrity_class};
use crate::socket_loc::{Elevation, Integrity};

use super::probe::{ProbeResult, SymlinkState, is_genuine_session};
use super::report::Check;

const APPLY_HINT: &str = "usually an installed exe older than this check: re-run `apply`";

/// What `verify`'s probes through the agent found.
#[derive(Debug)]
pub struct Probes {
    /// The probe that asked for the account's own session: it follows the junction, and its token is the
    /// session's.
    pub default: ProbeResult,
    /// Whether the payload the child sent downstream arrived byte for byte.
    pub binary_ok: bool,
    /// The probe that asked for an unelevated session, run first for an agent at High integrity, whose
    /// junction the default probe follows: its result, or the cause it failed with. `None` for any other
    /// agent.
    pub unelevated: Option<Result<ProbeResult, String>>,
    /// What the probes found about the junction, which for an agent at High is settled from both.
    pub junction: Junction,
    /// The junction `verify` could not remove, with the cause.
    pub leftover: Option<String>,
}

/// What `verify` found about a junction that a token below High made.
#[derive(Debug)]
pub struct Junction {
    pub state: SymlinkState,
    /// What the probes said about it, or why none was tested (empty when there is nothing to say).
    pub note: String,
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
    let mut junction = link_row(&probes.junction);
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
/// (`default`) and, when one was run, the answer of the probe that asked for an unelevated one
/// (`unelevated`).
///
/// The level of the default probe decides, as it does which probes are run: an agent at High has two
/// rows, and one below it has one. The first of the two passes when the session is at High with
/// Administrators enabled (an administrator's agent is elevated or absent) or not there (an account
/// Windows does not split). The second passes when the session that asked for less is at Medium with
/// Administrators not enabled: `Filtered` for an administrator, `Standard` for an account that is not one.
/// The one row below High passes for a standard account; an administrator's agent below High is not
/// elevated, and the one row says so.
pub fn session_rows(default: &ProbeResult, unelevated: Option<&Result<ProbeResult, String>>) -> Vec<Check> {
    // A probe that asked for an unelevated session was run because the agent is at High, whatever the
    // default probe says of itself: its answer is judged, never thrown away.
    let at_high = unelevated.is_some() || default.integrity.map(integrity_class) == Some(Integrity::High);
    if at_high {
        vec![elevated_row(default), unelevated_row(unelevated)]
    } else if default.elevation == Some(Elevation::Standard) {
        vec![Check::new(
            "session privilege",
            true,
            "this account is not an administrator: its session is a standard account's, and \
             `internal-unelevated` changes nothing",
        )]
    } else {
        vec![elevated_row(default)]
    }
}

fn elevated_row(default: &ProbeResult) -> Check {
    const NAME: &str = "elevated session";
    let at_high = default.integrity.map(integrity_class) == Some(Integrity::High);
    match (default.elevation, default.integrity) {
        (Some(elevation @ (Elevation::Full | Elevation::Standard)), integrity) if at_high => Check::new(
            NAME,
            true,
            format!(
                "{}, integrity {}",
                if elevation == Elevation::Full {
                    "Administrators enabled"
                } else {
                    "not an administrator (Administrators not enabled)"
                },
                level(integrity)
            ),
        ),
        (Some(elevation), integrity) => Check::new(
            NAME,
            false,
            format!(
                "the agent's session is not elevated (integrity {}, {}): an administrator's agent must be \
                 elevated",
                level(integrity),
                if elevation == Elevation::Full {
                    "Administrators enabled"
                } else {
                    "Administrators not enabled"
                },
            ),
        ),
        (None, _) => Check::new(
            NAME,
            false,
            format!("the probe did not report its token ({APPLY_HINT})"),
        ),
    }
}

fn unelevated_row(unelevated: Option<&Result<ProbeResult, String>>) -> Check {
    const NAME: &str = "unelevated session on request";
    let asked = match unelevated {
        None => return Check::new(NAME, false, "the probe that asks for an unelevated session was not run"),
        Some(Err(cause)) => {
            return Check::new(
                NAME,
                false,
                format!("the probe that asks for an unelevated session failed: {cause}"),
            );
        }
        Some(Ok(asked)) => asked,
    };
    match (asked.elevation, asked.integrity) {
        (Some(elevation @ (Elevation::Filtered | Elevation::Standard)), Some(INTEGRITY_MEDIUM)) => Check::new(
            NAME,
            true,
            format!(
                "`internal-unelevated` gives integrity {} {}",
                level(Some(INTEGRITY_MEDIUM)),
                if elevation == Elevation::Filtered {
                    "with Administrators deny-only"
                } else {
                    "(this account is not an administrator)"
                }
            ),
        ),
        (Some(_), _) | (None, Some(_)) => Check::new(
            NAME,
            false,
            format!(
                "`internal-unelevated` gave {} at integrity {}, not integrity Medium with Administrators not enabled",
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

/// `junction (via agent)`: a junction that a token below High made is followed by the session. A followed
/// one passes; a refusal means RedirectionGuard is on in the agent's session; one that was made and not
/// read fails. One that could not be made was not tested, which fails nothing and says so. What the probes
/// said is on the row.
pub fn link_row(junction: &Junction) -> Check {
    const NAME: &str = "junction (via agent)";
    let note = junction.note.as_str();
    let with_note = |what: &str| {
        if note.is_empty() {
            what.to_string()
        } else {
            format!("{what} ({note})")
        }
    };
    match junction.state {
        SymlinkState::Ok => Check::new(NAME, true, with_note("followed")),
        SymlinkState::Blocked => Check::new(
            NAME,
            false,
            with_note(
                "a junction made below High was refused as an untrusted mount point: RedirectionGuard is on in \
                 the agent's session",
            ),
        ),
        SymlinkState::Failed => Check::new(NAME, false, with_note("the junction was not followed")),
        SymlinkState::Skipped => Check::new(
            NAME,
            true,
            format!(
                "NOT tested: {}",
                if note.is_empty() {
                    "the probe could not make a junction"
                } else {
                    note
                }
            ),
        ),
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
