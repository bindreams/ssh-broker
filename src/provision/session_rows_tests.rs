//! Tests for the `doctor` rows about what a session through the agent is.
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

/// What the probe that asks for `always` finds at an administrator's agent.
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

/// A probe whose relay failed.
fn failed(cause: &str) -> ProbeOutcome {
    ProbeOutcome::Failed {
        cause: cause.into(),
        may_still_run: true,
    }
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
fn the_default_probe_row_says_session_and_passes_for_medium_with_administrators_not_enabled() {
    let rows = session_rows(&answer(unelevated()), Some(&answered(elevated())));

    assert_eq!(names(&rows), ["session", "elevated session on request"]);
    assert_eq!(passes(&rows), [true, true], "{:?}", details(&rows));
    assert_eq!(
        rows[0].detail,
        "a login at the default level (`prompt`) gets integrity Medium (0x2000) with Administrators deny-only"
    );
    let standard = session_rows(
        &answer(probe(Some(Elevation::Standard), Some(INTEGRITY_MEDIUM))),
        Some(&answered(elevated())),
    );
    assert!(standard[0].pass, "{}", standard[0].detail);
    assert!(
        standard[0].detail.contains("this account is not an administrator"),
        "{}",
        standard[0].detail
    );
}

/// Only Medium (`0x2000`) with Administrators not enabled passes `session`; the others say what the login got.
#[test]
fn the_default_probe_row_fails_naming_what_it_saw_otherwise() {
    for (got, says) in [
        (
            probe(Some(Elevation::Full), Some(INTEGRITY_HIGH)),
            "gave a full administrator's token at integrity High (0x3000)",
        ),
        (
            probe(Some(Elevation::Filtered), Some(INTEGRITY_HIGH)),
            "gave a token with Administrators deny-only at integrity High (0x3000)",
        ),
        (
            probe(Some(Elevation::Standard), Some(INTEGRITY_HIGH)),
            "gave a standard account's token at integrity High (0x3000)",
        ),
        (
            probe(Some(Elevation::Filtered), Some(0x1000)),
            "gave a token with Administrators deny-only at integrity 0x1000",
        ),
        (
            probe(Some(Elevation::Full), Some(INTEGRITY_MEDIUM)),
            "gave a full administrator's token at integrity Medium (0x2000)",
        ),
        (probe(Some(Elevation::Filtered), None), "did not report its level"),
        (probe(None, Some(INTEGRITY_MEDIUM)), "did not report its token"),
        (probe(None, None), "did not report its token or its level"),
    ] {
        let rows = session_rows(&answer(got.clone()), Some(&answered(elevated())));

        assert_eq!(names(&rows)[0], "session", "{got:?}");
        assert!(!rows[0].pass, "{got:?}: {}", rows[0].detail);
        assert!(rows[0].detail.contains(says), "{got:?}: {}", rows[0].detail);
        assert!(rows[1].pass, "the second row is about the other probe alone");
    }
}

/// What the probe said about reading its own token is the reason on the row, in place of a guess that its
/// exe is old, for either probe's row.
#[test]
fn what_the_probe_said_about_its_token_is_on_the_row_instead_of_the_remedy() {
    let said = "reading its integrity level failed: access denied";
    for (asked, missing) in [
        (probe(Some(Elevation::Filtered), None), "its level"),
        (probe(None, Some(INTEGRITY_MEDIUM)), "its token"),
    ] {
        let session = Answer {
            token_said: said.into(),
            ..answer(asked.clone())
        };

        let rows = session_rows(&session, Some(&answered(elevated())));

        assert!(!rows[0].pass, "{asked:?}");
        assert!(rows[0].detail.contains(said), "{asked:?}: {}", rows[0].detail);
        assert!(rows[0].detail.contains(missing), "{asked:?}: {}", rows[0].detail);
        assert!(
            !rows[0].detail.contains("re-run `install`"),
            "{asked:?}: {}",
            rows[0].detail
        );
    }

    let asked = ProbeOutcome::Answered(Answer {
        token_said: said.into(),
        ..answer(probe(Some(Elevation::Full), None))
    });
    let rows = session_rows(&answer(unelevated()), Some(&asked));
    assert!(!rows[1].pass);
    assert!(rows[1].detail.contains("access denied"), "{}", rows[1].detail);
    assert!(!rows[1].detail.contains("re-run `install`"), "{}", rows[1].detail);
}

/// A probe that said nothing about its token or its level is named for that, with the remedy, and not
/// blamed on the session.
#[test]
fn a_probe_that_did_not_report_its_token_or_level_says_so_and_does_not_blame_the_session() {
    let rows = session_rows(&answer(unelevated()), Some(&answered(probe(None, None))));
    assert!(rows[1].detail.contains("did not report"), "{}", rows[1].detail);
    assert!(rows[1].detail.contains("re-run `install`"), "{}", rows[1].detail);

    let rows = session_rows(
        &answer(unelevated()),
        Some(&answered(probe(Some(Elevation::Full), None))),
    );
    assert!(
        rows[1].detail.contains("did not report its level"),
        "{}",
        rows[1].detail
    );
    assert!(!rows[1].detail.contains("not elevated"), "{}", rows[1].detail);

    let rows = session_rows(
        &answer(unelevated()),
        Some(&answered(probe(None, Some(INTEGRITY_HIGH)))),
    );
    assert!(
        rows[1].detail.contains("did not report its token"),
        "{}",
        rows[1].detail
    );
}

#[test]
fn the_always_probe_row_is_elevated_session_on_request_and_passes_for_high_with_administrators_enabled() {
    let rows = session_rows(&answer(unelevated()), Some(&answered(elevated())));

    assert_eq!(rows[1].name, "elevated session on request");
    assert!(rows[1].pass, "{}", rows[1].detail);
    assert!(rows[1].detail.contains("Administrators enabled"), "{}", rows[1].detail);
    assert!(rows[1].detail.contains("High (0x3000)"), "{}", rows[1].detail);
}

/// A Backup Operator (a split token with no Administrators entry in it) gets the same two rows, which pass.
#[test]
fn a_standard_account_at_high_passes_both_rows_and_both_probes_are_judged() {
    let session = probe(Some(Elevation::Standard), Some(INTEGRITY_MEDIUM));
    let always = probe(Some(Elevation::Standard), Some(INTEGRITY_HIGH));

    let rows = session_rows(&answer(session.clone()), Some(&answered(always.clone())));

    assert_eq!(names(&rows), ["session", "elevated session on request"]);
    assert_eq!(passes(&rows), [true, true], "{:?}", details(&rows));
    assert!(rows[1].detail.contains("not an administrator"), "{}", rows[1].detail);

    // Neither was stepped as asked: the login at the default level was not stepped down, and the one that
    // asks for `always` was.
    let rows = session_rows(&answer(always), Some(&answered(session)));
    assert_eq!(passes(&rows), [false, false], "swapped: {:?}", details(&rows));
}

/// A deny-only token, one below High and one that said nothing fail `elevated session on request`.
#[test]
fn an_always_probe_that_is_not_at_high_fails_its_row() {
    for always in [
        probe(Some(Elevation::Filtered), Some(INTEGRITY_MEDIUM)),
        probe(Some(Elevation::Filtered), Some(INTEGRITY_HIGH)),
        probe(Some(Elevation::Full), Some(INTEGRITY_MEDIUM)),
        probe(Some(Elevation::Standard), Some(INTEGRITY_MEDIUM)),
        probe(Some(Elevation::Full), None),
        probe(None, None),
        probe(None, Some(INTEGRITY_HIGH)),
    ] {
        let rows = session_rows(&answer(unelevated()), Some(&answered(always.clone())));

        assert_eq!(names(&rows)[1], "elevated session on request", "{always:?}");
        assert!(!rows[1].pass, "{always:?}: {}", rows[1].detail);
        assert!(rows[0].pass, "the first row is about the default probe alone");
    }
}

#[test]
fn a_filtered_always_probe_is_named_as_not_elevated() {
    let rows = session_rows(
        &answer(unelevated()),
        Some(&answered(probe(Some(Elevation::Filtered), Some(INTEGRITY_MEDIUM)))),
    );

    assert!(rows[1].detail.contains("not elevated"), "{}", rows[1].detail);
    assert!(rows[1].detail.contains("administrator's agent"), "{}", rows[1].detail);
}

/// An account that is not an administrator is not told that an administrator's agent must be elevated.
#[test]
fn a_standard_account_is_not_told_an_administrators_agent_must_be_elevated() {
    let rows = session_rows(
        &answer(unelevated()),
        Some(&answered(probe(Some(Elevation::Standard), Some(INTEGRITY_MEDIUM)))),
    );

    assert!(!rows[1].pass);
    assert!(rows[1].detail.contains("not elevated"), "{}", rows[1].detail);
    assert!(!rows[1].detail.contains("administrator"), "{}", rows[1].detail);
}

/// A probe that asked for `always` and did not answer is named on its row with the cause, whichever way it did
/// not: it failed, it timed out, it was not run.
#[test]
fn an_always_probe_that_did_not_answer_fails_its_row_with_the_cause() {
    for (outcome, cause, says) in [
        (failed("relay failed (code 254)"), "relay failed (code 254)", "failed"),
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
        let rows = session_rows(&answer(unelevated()), Some(&outcome));

        assert_eq!(passes(&rows), [true, false], "{outcome:?}");
        assert!(rows[1].detail.contains(cause), "{}", rows[1].detail);
        assert!(rows[1].detail.contains(says), "{}", rows[1].detail);
        assert!(rows[1].detail.contains("`always`"), "{}", rows[1].detail);
    }
}

/// A token at High from a probe below High (which an agent below High never gives) is described as seen by the one
/// failing `session` row, whatever its elevation. No login asked for `always`, so there is no row about it, and
/// the token is no standard account's session, so there is no `session privilege`.
#[test]
fn a_token_at_high_with_no_always_probe_gives_the_one_failing_session_row() {
    for elevation in [Elevation::Standard, Elevation::Full, Elevation::Filtered] {
        let rows = session_rows(&answer(probe(Some(elevation), Some(INTEGRITY_HIGH))), None);

        assert_eq!(names(&rows), ["session"], "{elevation:?}");
        assert_eq!(passes(&rows), [false], "{elevation:?}: {:?}", details(&rows));
        assert!(
            rows[0].detail.contains("integrity High"),
            "{elevation:?}: {}",
            rows[0].detail
        );
    }
}

/// A token whose level was not reported, with no `always` probe, is the same one failing `session` row: the row
/// says the probe did not report it, a Standard token included.
#[test]
fn a_token_with_no_level_reported_and_no_always_probe_gives_the_one_failing_session_row() {
    for elevation in [Elevation::Standard, Elevation::Filtered, Elevation::Full] {
        let rows = session_rows(&answer(probe(Some(elevation), None)), None);

        assert_eq!(names(&rows), ["session"], "{elevation:?}");
        assert_eq!(passes(&rows), [false], "{elevation:?}: {:?}", details(&rows));
        assert!(
            rows[0].detail.contains("did not report its level"),
            "{elevation:?}: {}",
            rows[0].detail
        );
    }
    let rows = session_rows(&answer(probe(None, None)), None);
    assert_eq!(names(&rows), ["session"]);
    assert_eq!(passes(&rows), [false], "{:?}", details(&rows));
}

/// `session privilege` is for a Standard token at exactly Medium. At any other level (Untrusted, Low, Medium Plus)
/// the token is described as seen by the one failing `session` row.
#[test]
fn a_standard_token_at_a_level_other_than_medium_and_no_always_probe_gives_the_one_failing_session_row() {
    for (rid, says) in [
        (0x0, "gave a standard account's token at integrity 0x0"),
        (0x1000, "gave a standard account's token at integrity 0x1000"),
        (0x2100, "gave a standard account's token at integrity 0x2100"),
    ] {
        let rows = session_rows(&answer(probe(Some(Elevation::Standard), Some(rid))), None);

        assert_eq!(names(&rows), ["session"], "{rid:#x}");
        assert_eq!(passes(&rows), [false], "{rid:#x}: {:?}", details(&rows));
        assert!(rows[0].detail.contains(says), "{rid:#x}: {}", rows[0].detail);
    }
}

// the agent is below High ------------------------------------------------------------------

/// One row, which passes and says the session is a standard account's.
#[test]
fn a_standard_account_below_high_has_one_passing_row() {
    let session = probe(Some(Elevation::Standard), Some(INTEGRITY_MEDIUM));

    let rows = session_rows(&answer(session), None);

    assert_eq!(names(&rows), ["session privilege"]);
    assert!(rows[0].pass, "{}", rows[0].detail);
    assert!(rows[0].detail.contains("standard account"), "{}", rows[0].detail);
}

/// An administrator's agent below High gives its own token to a login at the default level, which is
/// unelevated, and cannot give an elevated one: a fault, not a standard account. `elevated session on request`
/// fails, naming it, and no probe asked for `always` (which a session below High refuses).
#[test]
fn an_administrators_agent_below_high_passes_session_and_fails_the_elevated_row() {
    let rows = session_rows(&answer(unelevated()), None);

    assert_eq!(names(&rows), ["session", "elevated session on request"]);
    assert_eq!(passes(&rows), [true, false], "{:?}", details(&rows));
    assert!(rows[1].detail.contains("not elevated"), "{}", rows[1].detail);
    assert!(rows[1].detail.contains("administrator's agent"), "{}", rows[1].detail);

    let rows = session_rows(&answer(probe(None, Some(INTEGRITY_MEDIUM))), None);
    assert_eq!(names(&rows), ["session", "elevated session on request"]);
    assert_eq!(passes(&rows), [false, false], "{:?}", details(&rows));
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
    assert!(row.detail.contains("re-run `install`"), "{}", row.detail);
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

/// A volume that holds no junctions was not tested: the row does not fail `doctor`, says in so many
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

/// What the probes found: the one that asked for the default level (`session`), and, for an agent at High, the one
/// that asked for `always` (`elevated`).
fn probes(session: ProbeOutcome, elevated: Option<ProbeOutcome>) -> Probes {
    Probes {
        session,
        elevated,
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
    "session",
    "elevated session on request",
    "junction (via agent)",
    "binary download (via agent)",
    "binary upload (via agent)",
];

/// An administrator's whole report: the session, DPAPI, the two session rows, the junction and the two
/// byte-transparency rows, all passing for a healthy elevated agent.
#[test]
fn a_healthy_administrators_agent_passes_every_row() {
    let rows = rows_of(&probes(answered(unelevated()), Some(answered(elevated()))));

    assert_eq!(names(&rows), ALL_ROWS);
    assert!(rows.iter().all(|row| row.pass), "{:?}", details(&rows));
}

/// What a login gets is what a login at the default level gets: the session id, DPAPI and the bytes of its
/// relay are read from that probe, whatever the probe that asked for `always` found.
#[test]
fn the_rows_about_the_session_a_login_gets_come_from_the_probe_that_asks_for_the_default_level() {
    let mut got = unelevated();
    got.session_id = 7;
    got.dpapi_ok = false;
    got.upstream = UpstreamState::Fail;
    let session = ProbeOutcome::Answered(Answer {
        binary_ok: false,
        ..answer(got)
    });
    let mut always = elevated();
    always.session_id = 9;

    let rows = parity_rows(&probes(session, Some(answered(always))), 1);

    assert_eq!(names(&rows), ALL_ROWS);
    assert!(rows[0].detail.contains("session_id=7"), "{}", rows[0].detail);
    let failing: Vec<&str> = rows.iter().filter(|row| !row.pass).map(|row| row.name).collect();
    assert_eq!(
        failing,
        [
            "DPAPI (via agent)",
            "binary download (via agent)",
            "binary upload (via agent)"
        ]
    );
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
        ("failed", failed("relay failed")),
        ("timed out", ProbeOutcome::TimedOut("no output".into())),
        ("not run", ProbeOutcome::NotRun("no agent".into())),
    ]
}

/// Every outcome of the probe that asks for the default level against every outcome of the one that asks for
/// `always` has its rows.
#[test]
fn every_pair_of_outcomes_has_its_rows() {
    for (session_name, session) in outcomes(unelevated()) {
        for (always_name, always) in outcomes(elevated()) {
            let always_passes = matches!(always, ProbeOutcome::Answered(_));
            let rows = rows_of(&probes(session.clone(), Some(always)));
            let case = format!("session {session_name}, always {always_name}: {:?}", details(&rows));

            if session_name == "answered" {
                assert_eq!(names(&rows), ALL_ROWS, "{case}");
                let failing: Vec<&str> = rows.iter().filter(|row| !row.pass).map(|row| row.name).collect();
                let expected: &[&str] = if always_passes {
                    &[]
                } else {
                    &["elevated session on request"]
                };
                assert_eq!(failing, expected, "{case}");
            } else {
                assert_eq!(
                    names(&rows),
                    ["parity probe (via agent)", "elevated session on request"],
                    "{case}"
                );
                assert_eq!(passes(&rows), [false, always_passes], "{case}");
                let cause = match session_name {
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

/// Below High there is no probe that asks for `always`: a session probe that did not answer is the one row.
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
    let mut p = probes(failed("relay failed"), Some(answered(elevated())));
    p.junction = unavailable("making a junction failed", "removing D:\\t failed: in use");

    let rows = rows_of(&p);

    assert_eq!(names(&rows)[0], "parity probe (via agent)");
    for said in ["relay failed", "making a junction failed", "in use"] {
        assert!(rows[0].detail.contains(said), "{said}: {}", rows[0].detail);
    }

    p.junction = Junction::Unread { note: String::new() };
    let rows = rows_of(&p);
    assert_eq!(rows[0].detail.matches("relay failed").count(), 1, "{}", rows[0].detail);
    assert!(!rows[0].detail.contains("junction"), "{}", rows[0].detail);

    p.junction = Junction::Unread {
        note: "reading through the junction was slow".into(),
    };
    let rows = rows_of(&p);
    assert!(rows[0].detail.contains("was slow"), "{}", rows[0].detail);
}

/// A junction whose default probe gave no answer fails its row, if it is ever asked for one.
#[test]
fn an_unread_junction_fails_its_row() {
    let row = link_row(&Junction::Unread { note: "in use".into() });

    assert!(!row.pass, "{}", row.detail);
    assert!(
        row.detail.contains("no answer") && row.detail.contains("in use"),
        "{}",
        row.detail
    );
}

/// The junction row is `Probes::junction`, which `run` settles from both probes: a refusal fails it,
/// whatever the session probe saw of its own.
#[test]
fn the_junction_row_is_the_junction_found() {
    let mut p = probes(answered(unelevated()), Some(answered(elevated())));
    p.junction = read(SymlinkState::Blocked, "");

    let rows = rows_of(&p);

    let row = rows.iter().find(|row| row.name == "junction (via agent)").unwrap();
    assert!(!row.pass);
}

/// A directory left behind is named on a row of its own, whether or not the default probe answered.
#[test]
fn a_junction_left_behind_is_named_on_its_own_row() {
    let leftover = r"C:\Temp\sb-junction-1 could not be removed: access denied";

    for session in [answered(unelevated()), failed("relay failed")] {
        let mut p = probes(session, Some(answered(elevated())));
        p.leftover = Some(leftover.to_string());

        let rows = rows_of(&p);

        let row = rows.last().unwrap();
        assert_eq!(row.name, "junction directory");
        assert!(row.pass, "{}", row.detail);
        assert!(row.detail.contains(r"C:\Temp\sb-junction-1"), "{}", row.detail);
        assert!(row.detail.contains("access denied"), "{}", row.detail);
    }
    let junction = rows_of(&probes(answered(unelevated()), Some(answered(elevated()))));
    assert!(!names(&junction).contains(&"junction directory"));
}

#[test]
fn the_byte_rows_fail_as_they_did_before() {
    let mut result = unelevated();
    result.upstream = UpstreamState::Fail;
    let session = ProbeOutcome::Answered(Answer {
        binary_ok: false,
        ..answer(result)
    });
    let p = probes(session, Some(answered(elevated())));

    let rows = rows_of(&p);

    let failing: Vec<&str> = rows.iter().filter(|row| !row.pass).map(|row| row.name).collect();
    assert_eq!(failing, ["binary download (via agent)", "binary upload (via agent)"]);
}

#[test]
fn a_session_zero_network_logon_fails_the_session_row_and_names_the_console() {
    let mut result = unelevated();
    result.session_id = 0;
    result.logon_type = Some(3);
    let p = probes(answered(result), Some(answered(elevated())));

    let rows = parity_rows(&p, 7);

    assert!(!rows[0].pass);
    assert!(rows[0].detail.contains("active console=7"), "{}", rows[0].detail);
}
