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
/// it said on stderr about its junction and about its own token ([`super::probe::notes`]).
#[derive(Debug, Clone)]
pub struct Answer {
    pub result: ProbeResult,
    /// Whether the payload the child sent downstream arrived byte for byte.
    pub binary_ok: bool,
    pub junction_said: String,
    pub token_said: String,
}

/// What became of one probe `verify` asked the agent for.
#[derive(Debug, Clone)]
pub enum ProbeOutcome {
    /// It ran and its PROBE line was read.
    Answered(Answer),
    /// The relay or the probe failed (an exit code, no PROBE line): the cause, and whether the probe's child
    /// may still be running: not when the relay ended with the child's exit, and not known when it broke
    /// before that.
    Failed { cause: String, may_still_run: bool },
    /// `--probe-timeout` passed with no answer, so the child may still be running: the cause.
    TimedOut(String),
    /// `verify` could not start it (no connection to the agent, the handshake not sent), so there is no
    /// child: why.
    NotRun(String),
}

impl ProbeOutcome {
    /// What the probe said, or why it did not answer.
    pub fn answer(&self) -> Result<&Answer, &str> {
        match self {
            ProbeOutcome::Answered(answer) => Ok(answer),
            ProbeOutcome::Failed { cause, .. } | ProbeOutcome::TimedOut(cause) | ProbeOutcome::NotRun(cause) => {
                Err(cause)
            }
        }
    }

    /// Whether the probe's child may still be running, and so may still do what it was told.
    pub fn may_still_run(&self) -> bool {
        match self {
            ProbeOutcome::Answered(_) | ProbeOutcome::NotRun(_) => false,
            ProbeOutcome::Failed { may_still_run, .. } => *may_still_run,
            ProbeOutcome::TimedOut(_) => true,
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
    /// outcome (`None` for a probe that reported none), and what the probes said about it (empty when there
    /// is nothing to say).
    Read { state: Option<SymlinkState>, note: String },
    /// There was no junction from below High to read, so nothing about it could be tested: why, and what
    /// the probes said.
    Unavailable { cause: String, note: String },
    /// The default probe, which reads the junction, did not answer: its own outcome says why, and this is
    /// what the probes said.
    Unread { note: String },
}

impl Junction {
    /// What `verify` knows of the junction besides the default probe's outcome: why there was no junction
    /// to read, when there was none, and what the probes said.
    fn said(&self) -> String {
        let (cause, note) = match self {
            Junction::Read { note, .. } | Junction::Unread { note } => ("", note),
            Junction::Unavailable { cause, note } => (cause.as_str(), note),
        };
        [cause, note]
            .into_iter()
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join("; ")
    }
}

/// Every row the probes give, in the order `verify` shows them. `active_console` is the id of the
/// physical console's session, which the session row names.
///
/// A default probe that did not answer is the one row `parity probe (via agent)`, with the cause and what
/// the junction found; the unelevated probe's row, which does not depend on it, and the directory left
/// behind are shown still.
pub fn parity_rows(probes: &Probes, active_console: u32) -> Vec<Check> {
    let mut rows = Vec::new();
    match probes.default.answer() {
        Ok(answer) => {
            let p = &answer.result;
            // Parity = escaped session 0. The agent need not be in the active-console session (a box can
            // have several); DPAPI and the junction confirm it is a genuine one.
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
            rows.extend(session_rows(answer, probes.unelevated.as_ref()));
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
            // Both fail (default-deny) but with different remedies: a mismatch vs a probe too old to check
            // at all; do not claim the payload was mangled when nothing looked.
            rows.push(Check::new(
                "binary upload (via agent)",
                p.upstream.proven(),
                p.upstream.detail(),
            ));
        }
        Err(cause) => {
            let said = probes.junction.said();
            let detail = format!("unavailable: {cause}");
            rows.push(Check::new(
                "parity probe (via agent)",
                false,
                if said.is_empty() {
                    detail
                } else {
                    format!("{detail} (junction: {said})")
                },
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
/// it has one. The one row below High passes for a standard account; an administrator's agent below High
/// is not elevated, and the one row says so.
pub fn session_rows(default: &Answer, unelevated: Option<&ProbeOutcome>) -> Vec<Check> {
    let token_level = default.result.integrity.map(integrity_class);
    // A probe that asked for an unelevated session was run because the agent is at High, whatever the
    // default probe says of itself: its outcome is judged, never thrown away.
    let at_high = unelevated.is_some() || token_level == Some(Integrity::High);
    if at_high {
        vec![elevated_row(default, token_level), unelevated_row(unelevated)]
    } else if default.result.elevation == Some(Elevation::Standard) {
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

/// What a row says of a probe that did not report `what` about its token: its own words when it said
/// any, and otherwise the likeliest reason.
fn not_reported(what: &str, token_said: &str) -> String {
    if token_said.is_empty() {
        format!("the probe did not report {what} ({APPLY_HINT})")
    } else {
        format!("the probe did not report {what}: {token_said}")
    }
}

/// `elevated session`: passes when the default probe's session is at High with Administrators enabled (an
/// administrator's agent is elevated or absent) or not there (an account Windows does not split).
/// `token_level` is the class of the default probe's own integrity, which is what the row judges.
fn elevated_row(default: &Answer, token_level: Option<Integrity>) -> Check {
    const NAME: &str = "elevated session";
    let said = default.token_said.as_str();
    let default = &default.result;
    match (default.elevation, default.integrity) {
        (None, None) => Check::new(NAME, false, not_reported("its token or its level", said)),
        (Some(_), None) => Check::new(NAME, false, not_reported("its level", said)),
        (None, Some(_)) => Check::new(NAME, false, not_reported("its token", said)),
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

/// `unelevated session on request`: passes when the session that asked for less is at Medium with
/// Administrators not enabled: `Filtered` for an administrator, `Standard` for an account that is not one.
fn unelevated_row(unelevated: Option<&ProbeOutcome>) -> Check {
    const NAME: &str = "unelevated session on request";
    let (asked, said) = match unelevated {
        None => return Check::new(NAME, false, "the probe that asks for an unelevated session was not run"),
        Some(ProbeOutcome::Failed { cause, .. }) => {
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
        Some(ProbeOutcome::Answered(answer)) => (&answer.result, answer.token_said.as_str()),
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
        (Some(_), Some(_)) => Check::new(
            NAME,
            false,
            format!(
                "`internal-unelevated` gave {} at integrity {}, not integrity Medium with Administrators not enabled",
                asked.elevation.map_or("an unknown token", elevation_name),
                level(asked.integrity)
            ),
        ),
        (Some(_), None) => Check::new(NAME, false, not_reported("its level", said)),
        (None, Some(_)) => Check::new(NAME, false, not_reported("its token", said)),
        (None, None) => Check::new(NAME, false, not_reported("its token or its level", said)),
    }
}

/// `junction (via agent)`: a junction that a token below High made is followed by the session. A followed
/// one passes; a refusal means RedirectionGuard is on in the agent's session; one that was made and not
/// read, one that could not be made, and a probe that reported no outcome fail. A volume that holds no
/// junctions was not tested, which fails nothing and says so. Having no junction from below High to read
/// fails, with why. What the probes said is on the row.
pub fn link_row(junction: &Junction) -> Check {
    const NAME: &str = "junction (via agent)";
    let (state, note) = match junction {
        Junction::Read {
            state: Some(state),
            note,
        } => (*state, note.as_str()),
        Junction::Read { state: None, note } => {
            return Check::new(
                NAME,
                false,
                with_note(&format!("the probe did not report its junction ({APPLY_HINT})"), note),
            );
        }
        Junction::Unavailable { cause, note } => {
            return Check::new(
                NAME,
                false,
                with_note(&format!("no junction from below High could be tested: {cause}"), note),
            );
        }
        Junction::Unread { note } => {
            return Check::new(
                NAME,
                false,
                with_note("the probe that reads the junction gave no answer", note),
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
                    "this volume holds no junctions"
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
