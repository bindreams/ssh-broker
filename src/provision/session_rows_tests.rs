//! Tests for the `verify` rows about what a session through the agent is.
use super::*;
use crate::account::{INTEGRITY_HIGH, INTEGRITY_MEDIUM};
use crate::provision::probe::{SymlinkState, UpstreamState};

fn probe(elevation: Option<Elevation>, integrity: Option<u32>) -> ProbeResult {
    ProbeResult {
        session_id: 1,
        dpapi_ok: true,
        symlink: Some(SymlinkState::Ok),
        upstream: UpstreamState::Ok,
        logon_type: Some(2),
        elevation,
        integrity,
    }
}

/// What a probe said, with nothing on its stderr.
fn answer(result: ProbeResult) -> Answer {
    Answer {
        result,
        binary_ok: true,
        junction_said: String::new(),
        token_said: String::new(),
    }
}

/// An administrator's agent's own probe, and the one that asked to be unelevated.
fn elevated() -> ProbeResult {
    probe(Some(Elevation::Full), Some(INTEGRITY_HIGH))
}

fn unelevated() -> ProbeResult {
    probe(Some(Elevation::Filtered), Some(INTEGRITY_MEDIUM))
}

/// A probe that ran and was read.
fn answered(result: ProbeResult) -> ProbeOutcome {
    ProbeOutcome::Answered(answer(result))
}

fn names(rows: &[Check]) -> Vec<&str> {
    rows.iter().map(|row| row.name).collect()
}

fn passes(rows: &[Check]) -> Vec<bool> {
    rows.iter().map(|row| row.pass).collect()
}

fn details(rows: &[Check]) -> Vec<&str> {
    rows.iter().map(|row| row.detail.as_str()).collect()
}

// the agent is at High ---------------------------------------------------------------------

#[test]
fn an_elevated_agent_that_steps_down_on_request_passes_both_rows() {
    let rows = session_rows(&answer(elevated()), Some(&answered(unelevated())));

    assert_eq!(names(&rows), ["elevated session", "unelevated session on request"]);
    assert_eq!(passes(&rows), [true, true], "{:?}", details(&rows));
    assert!(rows[0].detail.contains("High (0x3000)"), "{}", rows[0].detail);
}

/// A Backup Operator (a split token with no Administrators entry in it) gets the same two rows, which pass.
#[test]
fn a_standard_account_at_high_passes_both_rows_and_its_unelevated_probe_is_judged() {
    let default = probe(Some(Elevation::Standard), Some(INTEGRITY_HIGH));
    let asked = probe(Some(Elevation::Standard), Some(INTEGRITY_MEDIUM));

    let rows = session_rows(&answer(default.clone()), Some(&answered(asked)));

    assert_eq!(names(&rows), ["elevated session", "unelevated session on request"]);
    assert_eq!(passes(&rows), [true, true], "{:?}", details(&rows));
    assert!(rows[0].detail.contains("not an administrator"), "{}", rows[0].detail);

    let at_high = probe(Some(Elevation::Standard), Some(INTEGRITY_HIGH));
    let rows = session_rows(&answer(default), Some(&answered(at_high)));
    assert_eq!(
        passes(&rows),
        [true, false],
        "it was not stepped down: {:?}",
        details(&rows)
    );
}

/// A deny-only token, one below High and one that said nothing fail the `elevated session` row.
#[test]
fn a_default_probe_that_is_not_at_high_fails_the_elevated_row() {
    for default in [
        probe(Some(Elevation::Filtered), Some(INTEGRITY_MEDIUM)),
        probe(Some(Elevation::Filtered), Some(INTEGRITY_HIGH)),
        probe(Some(Elevation::Full), Some(INTEGRITY_MEDIUM)),
        probe(Some(Elevation::Standard), Some(INTEGRITY_MEDIUM)),
        probe(Some(Elevation::Full), None),
        probe(None, None),
        probe(None, Some(INTEGRITY_HIGH)),
    ] {
        let rows = session_rows(&answer(default.clone()), Some(&answered(unelevated())));

        assert_eq!(names(&rows)[0], "elevated session", "{default:?}");
        assert!(!rows[0].pass, "{default:?}: {}", rows[0].detail);
    }
}

/// A probe that said nothing about its token or its level is named for that, with the remedy, and not
/// blamed on the session.
#[test]
fn a_probe_that_did_not_report_its_token_or_level_says_so_and_does_not_blame_the_session() {
    let rows = session_rows(&answer(probe(None, None)), Some(&answered(unelevated())));
    assert!(rows[0].detail.contains("did not report"), "{}", rows[0].detail);
    assert!(rows[0].detail.contains("apply"), "{}", rows[0].detail);

    let rows = session_rows(
        &answer(probe(Some(Elevation::Full), None)),
        Some(&answered(unelevated())),
    );
    assert!(
        rows[0].detail.contains("did not report its level"),
        "{}",
        rows[0].detail
    );
    assert!(!rows[0].detail.contains("not elevated"), "{}", rows[0].detail);

    let rows = session_rows(
        &answer(probe(None, Some(INTEGRITY_HIGH))),
        Some(&answered(unelevated())),
    );
    assert!(
        rows[0].detail.contains("did not report its token"),
        "{}",
        rows[0].detail
    );
}

/// What the probe said about reading its own token is the reason on the row, in place of a guess that its
/// exe is old, for the default probe's row and the unelevated probe's.
#[test]
fn what_the_probe_said_about_its_token_is_on_the_row_instead_of_the_remedy() {
    let said = "reading its integrity level failed: access denied";
    let default = Answer {
        token_said: said.into(),
        ..answer(probe(Some(Elevation::Full), None))
    };

    let rows = session_rows(&default, Some(&answered(unelevated())));

    assert!(!rows[0].pass);
    assert!(rows[0].detail.contains("access denied"), "{}", rows[0].detail);
    assert!(!rows[0].detail.contains("apply"), "{}", rows[0].detail);

    let asked = ProbeOutcome::Answered(Answer {
        token_said: said.into(),
        ..answer(probe(None, None))
    });
    let rows = session_rows(&answer(elevated()), Some(&asked));
    assert!(!rows[1].pass);
    assert!(rows[1].detail.contains("access denied"), "{}", rows[1].detail);
    assert!(!rows[1].detail.contains("apply"), "{}", rows[1].detail);
}

#[test]
fn a_filtered_agent_is_named_as_not_elevated() {
    let rows = session_rows(
        &answer(probe(Some(Elevation::Filtered), Some(INTEGRITY_MEDIUM))),
        Some(&answered(unelevated())),
    );

    assert!(rows[0].detail.contains("not elevated"), "{}", rows[0].detail);
    assert!(rows[0].detail.contains("administrator's agent"), "{}", rows[0].detail);
}

/// An account that is not an administrator is not told that an administrator's agent must be elevated.
#[test]
fn a_standard_account_is_not_told_an_administrators_agent_must_be_elevated() {
    let rows = session_rows(
        &answer(probe(Some(Elevation::Standard), Some(INTEGRITY_MEDIUM))),
        Some(&answered(unelevated())),
    );

    assert!(!rows[0].pass);
    assert!(rows[0].detail.contains("not elevated"), "{}", rows[0].detail);
    assert!(!rows[0].detail.contains("administrator"), "{}", rows[0].detail);
}

/// Only Medium (`0x2000`) with Administrators not enabled passes `unelevated session on request`.
#[test]
fn an_unelevated_probe_at_the_wrong_level_fails_its_row() {
    for asked in [
        probe(Some(Elevation::Full), Some(INTEGRITY_HIGH)),
        probe(Some(Elevation::Filtered), Some(INTEGRITY_HIGH)),
        probe(Some(Elevation::Standard), Some(INTEGRITY_HIGH)),
        probe(Some(Elevation::Filtered), Some(0x1000)),
        probe(Some(Elevation::Standard), Some(0x1000)),
        probe(Some(Elevation::Filtered), None),
        probe(Some(Elevation::Full), Some(INTEGRITY_MEDIUM)),
        probe(None, Some(INTEGRITY_MEDIUM)),
        probe(None, None),
    ] {
        let rows = session_rows(&answer(elevated()), Some(&answered(asked.clone())));

        assert_eq!(names(&rows)[1], "unelevated session on request", "{asked:?}");
        assert!(!rows[1].pass, "{asked:?}: {}", rows[1].detail);
        assert!(rows[0].pass, "the first row is about the default probe alone");
    }
}

#[test]
fn an_unelevated_probe_at_medium_without_administrators_enabled_passes_for_either_kind_of_account() {
    for asked in [
        probe(Some(Elevation::Filtered), Some(INTEGRITY_MEDIUM)),
        probe(Some(Elevation::Standard), Some(INTEGRITY_MEDIUM)),
    ] {
        let rows = session_rows(&answer(elevated()), Some(&answered(asked.clone())));

        assert!(rows[1].pass, "{asked:?}: {}", rows[1].detail);
    }
}

/// A probe that asked for an unelevated session and did not answer is named on its row with the cause,
/// whichever way it did not: it failed, it timed out, it was not run.
#[test]
fn an_unelevated_probe_that_did_not_answer_fails_its_row_with_the_cause() {
    for (outcome, cause, says) in [
        (
            ProbeOutcome::Failed("relay failed (code 254)".into()),
            "relay failed (code 254)",
            "failed",
        ),
        (
            ProbeOutcome::TimedOut("no output within 30s".into()),
            "no output within 30s",
            "did not answer",
        ),
        (
            ProbeOutcome::NotRun("the agent is gone".into()),
            "the agent is gone",
            "not run",
        ),
    ] {
        let rows = session_rows(&answer(elevated()), Some(&outcome));

        assert_eq!(passes(&rows), [true, false], "{outcome:?}");
        assert!(rows[1].detail.contains(cause), "{}", rows[1].detail);
        assert!(rows[1].detail.contains(says), "{}", rows[1].detail);
    }
}

#[test]
fn no_unelevated_probe_fails_its_row_for_an_agent_at_high() {
    let rows = session_rows(&answer(elevated()), None);

    assert_eq!(passes(&rows), [true, false]);
    assert!(rows[1].detail.contains("not run"), "{}", rows[1].detail);
}

// the agent is below High ------------------------------------------------------------------

/// One row, which passes and says the session is a standard account's.
#[test]
fn a_standard_account_below_high_has_one_passing_row() {
    let default = probe(Some(Elevation::Standard), Some(INTEGRITY_MEDIUM));

    let rows = session_rows(&answer(default), None);

    assert_eq!(names(&rows), ["session privilege"]);
    assert!(rows[0].pass, "{}", rows[0].detail);
    assert!(rows[0].detail.contains("standard account"), "{}", rows[0].detail);
}

/// An administrator's agent below High is not elevated: a fault, not a standard account. The one row
/// is the `elevated session` row, which fails.
#[test]
fn an_administrators_agent_below_high_fails_the_elevated_row() {
    for default in [
        probe(Some(Elevation::Filtered), Some(INTEGRITY_MEDIUM)),
        probe(None, Some(INTEGRITY_MEDIUM)),
    ] {
        let rows = session_rows(&answer(default.clone()), None);

        assert_eq!(names(&rows), ["elevated session"], "{default:?}");
        assert!(!rows[0].pass, "{default:?}: {}", rows[0].detail);
    }
}

// the junction -----------------------------------------------------------------------------

fn read(state: SymlinkState, note: &str) -> Junction {
    Junction::Read {
        state: Some(state),
        note: note.to_string(),
    }
}

fn unavailable(cause: &str, note: &str) -> Junction {
    Junction::Unavailable {
        cause: cause.to_string(),
        note: note.to_string(),
    }
}

#[test]
fn the_junction_row_fails_on_a_junction_that_was_made_and_not_followed() {
    let row = |state| link_row(&read(state, ""));

    assert!(row(SymlinkState::Ok).pass);
    assert!(!row(SymlinkState::Blocked).pass);
    assert!(!row(SymlinkState::Failed).pass);
    assert_eq!(row(SymlinkState::Ok).name, "junction (via agent)");
    assert!(
        row(SymlinkState::Blocked).detail.contains("RedirectionGuard"),
        "{}",
        row(SymlinkState::Blocked).detail
    );
}

/// A probe that reported no outcome did not make a junction, and is not read as one that did: the row
/// fails, with the remedy.
#[test]
fn a_probe_that_reported_no_junction_outcome_fails_the_junction_row() {
    let row = link_row(&Junction::Read {
        state: None,
        note: String::new(),
    });

    assert!(!row.pass, "{}", row.detail);
    assert!(row.detail.contains("did not report"), "{}", row.detail);
    assert!(row.detail.contains("apply"), "{}", row.detail);
}

/// A directory that could not be made is a failure, with the cause the probe gave; it is not the volume
/// that cannot hold a junction.
#[test]
fn a_directory_that_could_not_be_made_fails_the_junction_row_with_the_cause() {
    let row = link_row(&read(
        SymlinkState::NotMade,
        "making a junction in D:\\t failed: access denied",
    ));

    assert!(!row.pass, "{}", row.detail);
    assert!(row.detail.contains("access denied"), "{}", row.detail);
    assert!(!row.detail.contains("NOT tested"), "{}", row.detail);
}

/// A volume that holds no junctions was not tested: the row does not fail `verify`, says in so many
/// words that the property was not tested, and gives the probe's reason.
#[test]
fn a_volume_without_junctions_is_not_tested_and_fails_nothing() {
    let row = link_row(&read(SymlinkState::Skipped, "the volume of D:\\t holds no junctions"));

    assert!(row.pass, "{}", row.detail);
    assert!(row.detail.contains("NOT tested"), "{}", row.detail);
    assert!(row.detail.contains("holds no junctions"), "{}", row.detail);
    assert!(link_row(&read(SymlinkState::Skipped, "")).detail.contains("NOT tested"));
}

/// No junction from below High to read is a failure, whatever the reason, and the reason is on the row.
#[test]
fn no_junction_from_below_high_fails_the_row_with_the_cause_and_the_notes() {
    let row = link_row(&unavailable(
        "the probe timed out",
        "making the directory failed: in use",
    ));

    assert!(!row.pass, "{}", row.detail);
    assert!(
        row.detail.contains("no junction from below High could be tested"),
        "{}",
        row.detail
    );
    assert!(row.detail.contains("the probe timed out"), "{}", row.detail);
    assert!(row.detail.contains("in use"), "{}", row.detail);
}

/// The probe's own words are on every row that does not pass, and on a passing one that has something to
/// say (a directory it could not remove).
#[test]
fn the_probes_words_reach_the_junction_row() {
    let said = "reading through the junction in D:\\t failed: access denied";

    assert!(
        link_row(&read(SymlinkState::Failed, said))
            .detail
            .contains("access denied")
    );
    assert!(
        link_row(&read(SymlinkState::Blocked, said))
            .detail
            .contains("access denied")
    );
    let passing = link_row(&read(SymlinkState::Ok, "removing D:\\t failed: in use"));
    assert!(passing.pass);
    assert!(passing.detail.contains("in use"), "{}", passing.detail);
    assert_eq!(link_row(&read(SymlinkState::Ok, "")).detail, "followed");
}

// the whole report of the probes -----------------------------------------------------------

fn probes(default: ProbeOutcome, unelevated: Option<ProbeOutcome>) -> Probes {
    Probes {
        unelevated,
        default,
        junction: read(SymlinkState::Ok, ""),
        leftover: None,
    }
}

fn rows_of(probes: &Probes) -> Vec<Check> {
    parity_rows(probes, 1)
}

const ALL_ROWS: [&str; 7] = [
    "interactive session (via agent)",
    "DPAPI (via agent)",
    "elevated session",
    "unelevated session on request",
    "junction (via agent)",
    "binary download (via agent)",
    "binary upload (via agent)",
];

/// An administrator's whole report: the session, DPAPI, the two session rows, the junction and the two
/// byte-transparency rows, all passing for a healthy elevated agent.
#[test]
fn a_healthy_administrators_agent_passes_every_row() {
    let rows = rows_of(&probes(answered(elevated()), Some(answered(unelevated()))));

    assert_eq!(names(&rows), ALL_ROWS);
    assert!(rows.iter().all(|row| row.pass), "{:?}", details(&rows));
}

#[test]
fn a_standard_accounts_report_has_one_session_row() {
    let rows = rows_of(&probes(
        answered(probe(Some(Elevation::Standard), Some(INTEGRITY_MEDIUM))),
        None,
    ));

    assert_eq!(
        names(&rows),
        [
            "interactive session (via agent)",
            "DPAPI (via agent)",
            "session privilege",
            "junction (via agent)",
            "binary download (via agent)",
            "binary upload (via agent)",
        ]
    );
    assert!(rows.iter().all(|row| row.pass), "{:?}", details(&rows));
}

/// One outcome of each kind, the one that answered being `answer`.
fn outcomes(answer: ProbeResult) -> [(&'static str, ProbeOutcome); 4] {
    [
        ("answered", answered(answer)),
        ("failed", ProbeOutcome::Failed("relay failed".into())),
        ("timed out", ProbeOutcome::TimedOut("no output".into())),
        ("not run", ProbeOutcome::NotRun("no agent".into())),
    ]
}

/// Every outcome of the default probe against every outcome of the unelevated one has its rows.
#[test]
fn every_pair_of_outcomes_has_its_rows() {
    for (default_name, default) in outcomes(elevated()) {
        for (unelevated_name, unelevated) in outcomes(unelevated()) {
            let unelevated_passes = matches!(unelevated, ProbeOutcome::Answered(_));
            let rows = rows_of(&probes(default.clone(), Some(unelevated)));
            let case = format!(
                "default {default_name}, unelevated {unelevated_name}: {:?}",
                details(&rows)
            );

            if default_name == "answered" {
                assert_eq!(names(&rows), ALL_ROWS, "{case}");
                let failing: Vec<&str> = rows.iter().filter(|row| !row.pass).map(|row| row.name).collect();
                let expected: &[&str] = if unelevated_passes {
                    &[]
                } else {
                    &["unelevated session on request"]
                };
                assert_eq!(failing, expected, "{case}");
            } else {
                assert_eq!(
                    names(&rows),
                    ["parity probe (via agent)", "unelevated session on request"],
                    "{case}"
                );
                assert_eq!(passes(&rows), [false, unelevated_passes], "{case}");
                let cause = match default_name {
                    "failed" => "relay failed",
                    "timed out" => "no output",
                    _ => "no agent",
                };
                assert!(rows[0].detail.starts_with("unavailable"), "{case}");
                assert!(rows[0].detail.contains(cause), "{case}");
            }
        }
    }
}

/// Below High there is no unelevated probe: a default probe that did not answer is the one row.
#[test]
fn a_default_probe_that_did_not_answer_below_high_is_the_one_row() {
    let rows = rows_of(&probes(ProbeOutcome::TimedOut("no output within 30s".into()), None));

    assert_eq!(names(&rows), ["parity probe (via agent)"]);
    assert!(!rows[0].pass);
    assert!(rows[0].detail.contains("no output within 30s"), "{}", rows[0].detail);
}

/// A default probe that did not answer still shows what the junction found: its own cause when it is
/// another, and what the probes said, on the one row; a cause the row has already is not said twice.
#[test]
fn a_default_probe_that_did_not_answer_shows_the_junctions_cause_and_note() {
    let mut p = probes(
        ProbeOutcome::Failed("relay failed".into()),
        Some(answered(unelevated())),
    );
    p.junction = unavailable("making a junction failed", "removing D:\\t failed: in use");

    let rows = rows_of(&p);

    assert_eq!(names(&rows)[0], "parity probe (via agent)");
    for said in ["relay failed", "making a junction failed", "in use"] {
        assert!(rows[0].detail.contains(said), "{said}: {}", rows[0].detail);
    }

    p.junction = unavailable("relay failed", "");
    let rows = rows_of(&p);
    assert_eq!(rows[0].detail.matches("relay failed").count(), 1, "{}", rows[0].detail);
    assert!(!rows[0].detail.contains("junction"), "{}", rows[0].detail);
}

/// The junction row is `Probes::junction`, which `run` settles from both probes: a refusal fails it,
/// whatever the unelevated probe saw of its own.
#[test]
fn the_junction_row_is_the_junction_found() {
    let mut p = probes(answered(elevated()), Some(answered(unelevated())));
    p.junction = read(SymlinkState::Blocked, "");

    let rows = rows_of(&p);

    let row = rows.iter().find(|row| row.name == "junction (via agent)").unwrap();
    assert!(!row.pass);
}

/// A directory left behind is named on a row of its own, whether or not the default probe answered.
#[test]
fn a_junction_left_behind_is_named_on_its_own_row() {
    let leftover = r"C:\Temp\sb-junction-1 could not be removed: access denied";

    for default in [answered(elevated()), ProbeOutcome::Failed("relay failed".into())] {
        let mut p = probes(default, Some(answered(unelevated())));
        p.leftover = Some(leftover.to_string());

        let rows = rows_of(&p);

        let row = rows.last().unwrap();
        assert_eq!(row.name, "junction directory");
        assert!(row.pass, "{}", row.detail);
        assert!(row.detail.contains(r"C:\Temp\sb-junction-1"), "{}", row.detail);
        assert!(row.detail.contains("access denied"), "{}", row.detail);
    }
    let junction = rows_of(&probes(answered(elevated()), Some(answered(unelevated()))));
    assert!(!names(&junction).contains(&"junction directory"));
}

#[test]
fn the_byte_rows_fail_as_they_did_before() {
    let mut result = elevated();
    result.upstream = UpstreamState::Fail;
    let default = ProbeOutcome::Answered(Answer {
        binary_ok: false,
        ..answer(result)
    });
    let p = probes(default, Some(answered(unelevated())));

    let rows = rows_of(&p);

    let failing: Vec<&str> = rows.iter().filter(|row| !row.pass).map(|row| row.name).collect();
    assert_eq!(failing, ["binary download (via agent)", "binary upload (via agent)"]);
}

#[test]
fn a_session_zero_network_logon_fails_the_session_row_and_names_the_console() {
    let mut result = elevated();
    result.session_id = 0;
    result.logon_type = Some(3);
    let p = probes(answered(result), Some(answered(unelevated())));

    let rows = parity_rows(&p, 7);

    assert!(!rows[0].pass);
    assert!(rows[0].detail.contains("active console=7"), "{}", rows[0].detail);
}
