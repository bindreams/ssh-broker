//! provision::session_rows — the rows of the `verify` report about what a session through the agent
//! is: elevated or not, whether an unelevated one can be had, and whether a link a session below High
//! made is followed.
//!
//! The facts are the PROBE lines of the probes the agent started, which read their own tokens; nothing
//! is judged from `verify`'s own. Every outcome of every probe has a row ([`ProbeOutcome`]), and the rows
//! are a pure function of [`Probes`].

use crate::account::{INTEGRITY_HIGH, INTEGRITY_MEDIUM, integrity_class};
use crate::socket_loc::{Elevation, Integrity};

use super::probe::{ProbeResult, SymlinkState, is_genuine_session};
use super::report::Check;

const APPLY_HINT: &str = "usually an installed exe older than this check: re-run `apply`";

/// A probe that ran and whose PROBE line was read: the line, whether its binary payload survived, and what
/// it said about its junction on stderr ([`super::probe::junction_notes`]).
#[derive(Debug, Clone)]
pub struct Answer {
    pub result: ProbeResult,
    /// Whether the payload the child sent downstream arrived byte for byte.
    pub binary_ok: bool,
    pub said: String,
}

/// What became of one probe `verify` asked the agent for.
#[derive(Debug, Clone)]
pub enum ProbeOutcome {
    /// It ran and its PROBE line was read.
    Answered(Answer),
    /// The relay or the probe failed with an answer `verify` can show (an exit code, no PROBE line): the cause.
    Failed(String),
    /// `--probe-timeout` passed with no answer: the cause.
    TimedOut(String),
    /// `verify` did not start it: why.
    NotRun(String),
}

impl ProbeOutcome {
    /// Why the probe did not answer, or `None` for one that did.
    pub fn cause(&self) -> Option<&str> {
        match self {
            ProbeOutcome::Answered(_) => None,
            ProbeOutcome::Failed(cause) | ProbeOutcome::TimedOut(cause) | ProbeOutcome::NotRun(cause) => Some(cause),
        }
    }
}

/// What `verify`'s probes through the agent found.
#[derive(Debug)]
pub struct Probes {
    /// The probe that asked for an unelevated session, run first for an agent at High integrity: it makes
    /// the junction the default probe follows. `None` for any other agent.
    pub unelevated: Option<ProbeOutcome>,
    /// The probe that asked for the account's own session: its token is the session's.
    pub default: ProbeOutcome,
    /// What the probes found about the junction, which for an agent at High is settled from both.
    pub junction: Junction,
    /// A directory `verify` named for the junction that is, or may come to be, left behind: what to delete.
    pub leftover: Option<String>,
}

/// What `verify` found about a junction that a token below High made.
#[derive(Debug)]
pub enum Junction {
    /// The default probe read through a junction, which for an agent at High one below High made: the
    /// outcome, and what the probes said about it (empty when there is nothing to say).
    Read { state: SymlinkState, note: String },
    /// There was no junction from below High to read, so nothing about it could be tested: why, and what
    /// the probes said.
    Unavailable { cause: String, note: String },
}

/// Every row the probes give, in the order `verify` shows them. `active_console` is the id of the
/// physical console's session, which the session row names.
///
/// A default probe that did not answer is the one row `parity probe (via agent)`, with the cause; the
/// unelevated probe's row, which does not depend on it, and the directory left behind are shown still.
pub fn parity_rows(probes: &Probes, active_console: u32) -> Vec<Check> {
    let mut rows = Vec::new();
    match &probes.default {
        ProbeOutcome::Answered(answer) => {
            let p = &answer.result;
            // Parity = escaped session 0 (the limited network-logon session). The agent need not be in THE
            // active-console session — a box can have several interactive sessions — and DPAPI and the
            // junction confirm it is a genuine one.
            rows.push(Check::new(
                "interactive session (via agent)",
                is_genuine_session(p.session_id, p.logon_type),
                format!(
                    "session_id={} (active console={active_console}, logon type={})",
                    p.session_id,
                    p.logon_type.map_or("unknown".to_string(), |t| t.to_string())
                ),
            ));
            rows.push(Check::new("DPAPI (via agent)", p.dpapi_ok, String::new()));
            rows.extend(session_rows(p, probes.unelevated.as_ref()));
            rows.push(link_row(&probes.junction));
            // Byte-transparency on the real path, in BOTH directions: "the relay carries arbitrary bytes
            // unchanged" is what makes scp and sftp work at all, and these rows hold that claim honest end
            // to end. They are separate because a one-directional failure must name its direction: client →
            // child is the `scp`/`sftp put` upload, child → client the download.
            rows.push(Check::new(
                "binary download (via agent)",
                answer.binary_ok,
                if answer.binary_ok {
                    String::new()
                } else {
                    "the payload the child sent did not survive the relay byte for byte".into()
                },
            ));
            // `detail()` distinguishes "the child reported a mismatch" from "the child never reported at
            // all" (an installed exe older than this check). Both FAIL — default-deny — but they have
            // different remedies, and claiming the payload was mangled when nothing ever looked at it
            // would be a diagnosis the code cannot support.
            rows.push(Check::new(
                "binary upload (via agent)",
                p.upstream.proven(),
                p.upstream.detail(),
            ));
        }
        unanswered => {
            rows.push(Check::new(
                "parity probe (via agent)",
                false,
                format!("unavailable: {}", unanswered.cause().unwrap_or_default()),
            ));
            if let Some(unelevated) = &probes.unelevated {
                rows.push(unelevated_row(Some(unelevated)));
            }
        }
    }
    if let Some(leftover) = &probes.leftover {
        rows.push(Check::new("junction directory", true, leftover.as_str()));
    }
    rows
}

/// The rows for the session the agent gives, from the probe that asked for the account's own session
/// (`default`) and, when one was run, what became of the probe that asked for an unelevated one
/// (`unelevated`).
///
/// The level that decides the rows is worked out once, here: an agent at High has two rows, and one below
/// it has one. The first of the two passes when the session is at High with Administrators enabled (an
/// administrator's agent is elevated or absent) or not there (an account Windows does not split). The
/// second passes when the session that asked for less is at Medium with Administrators not enabled:
/// `Filtered` for an administrator, `Standard` for an account that is not one. The one row below High
/// passes for a standard account; an administrator's agent below High is not elevated, and the one row
/// says so.
pub fn session_rows(default: &ProbeResult, unelevated: Option<&ProbeOutcome>) -> Vec<Check> {
    let token_level = default.integrity.map(integrity_class);
    // A probe that asked for an unelevated session was run because the agent is at High, whatever the
    // default probe says of itself: its outcome is judged, never thrown away.
    let at_high = unelevated.is_some() || token_level == Some(Integrity::High);
    if at_high {
        vec![elevated_row(default, token_level), unelevated_row(unelevated)]
    } else if default.elevation == Some(Elevation::Standard) {
        vec![Check::new(
            "session privilege",
            true,
            "this account is not an administrator: its session is a standard account's, and \
             `internal-unelevated` changes nothing",
        )]
    } else {
        vec![elevated_row(default, token_level)]
    }
}

/// `elevated session`: `token_level` is the class of the default probe's own integrity, which is what the
/// row judges.
fn elevated_row(default: &ProbeResult, token_level: Option<Integrity>) -> Check {
    const NAME: &str = "elevated session";
    match (default.elevation, default.integrity) {
        (None, None) => Check::new(
            NAME,
            false,
            format!("the probe did not report its token or its level ({APPLY_HINT})"),
        ),
        (Some(_), None) => Check::new(
            NAME,
            false,
            format!("the probe did not report its level ({APPLY_HINT})"),
        ),
        (None, Some(_)) => Check::new(
            NAME,
            false,
            format!("the probe did not report its token ({APPLY_HINT})"),
        ),
        (Some(elevation @ (Elevation::Full | Elevation::Standard)), integrity)
            if token_level == Some(Integrity::High) =>
        {
            Check::new(
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
            )
        }
        (Some(elevation), integrity) => Check::new(
            NAME,
            false,
            format!(
                "the agent's session is not elevated (integrity {}, {}){}",
                level(integrity),
                if elevation == Elevation::Full {
                    "Administrators enabled"
                } else {
                    "Administrators not enabled"
                },
                // An account that is not an administrator has no elevated session to be missing.
                if elevation == Elevation::Standard {
                    ""
                } else {
                    ": an administrator's agent must be elevated"
                }
            ),
        ),
    }
}

fn unelevated_row(unelevated: Option<&ProbeOutcome>) -> Check {
    const NAME: &str = "unelevated session on request";
    let asked = match unelevated {
        None => return Check::new(NAME, false, "the probe that asks for an unelevated session was not run"),
        Some(ProbeOutcome::Failed(cause)) => {
            return Check::new(
                NAME,
                false,
                format!("the probe that asks for an unelevated session failed: {cause}"),
            );
        }
        Some(ProbeOutcome::TimedOut(cause)) => {
            return Check::new(
                NAME,
                false,
                format!("the probe that asks for an unelevated session did not answer: {cause}"),
            );
        }
        Some(ProbeOutcome::NotRun(cause)) => {
            return Check::new(
                NAME,
                false,
                format!("the probe that asks for an unelevated session was not run: {cause}"),
            );
        }
        Some(ProbeOutcome::Answered(answer)) => &answer.result,
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
/// read, or that could not be made for a reason of the directory's, fails. One that a volume refused to make
/// was not tested, which fails nothing and says so. So does having no junction from below High to read:
/// that fails, with why. What the probes said is on the row.
pub fn link_row(junction: &Junction) -> Check {
    const NAME: &str = "junction (via agent)";
    let (state, note) = match junction {
        Junction::Read { state, note } => (*state, note.as_str()),
        Junction::Unavailable { cause, note } => {
            return Check::new(
                NAME,
                false,
                with_note(&format!("no junction from below High could be tested: {cause}"), note),
            );
        }
    };
    match state {
        SymlinkState::Ok => Check::new(NAME, true, with_note("followed", note)),
        SymlinkState::Blocked => Check::new(
            NAME,
            false,
            with_note(
                "a junction made below High was refused as an untrusted mount point: RedirectionGuard is on in \
                 the agent's session",
                note,
            ),
        ),
        SymlinkState::Failed => Check::new(NAME, false, with_note("the junction was not followed", note)),
        SymlinkState::NotMade => Check::new(NAME, false, with_note("no junction could be made", note)),
        SymlinkState::Skipped => Check::new(
            NAME,
            true,
            format!(
                "NOT tested: {}",
                if note.is_empty() {
                    "the volume would not make a junction"
                } else {
                    note
                }
            ),
        ),
    }
}

fn with_note(what: &str, note: &str) -> String {
    if note.is_empty() {
        what.to_string()
    } else {
        format!("{what} ({note})")
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
pub(super) fn level(rid: Option<u32>) -> String {
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
