//! Tests for the `verify` rows about what a session through the agent is.
use super::*;
use crate::account::{INTEGRITY_HIGH, INTEGRITY_MEDIUM};
use crate::provision::probe::{SymlinkState, UpstreamState};

fn probe(elevation: Option<Elevation>, integrity: Option<u32>) -> ProbeResult {
    ProbeResult {
        session_id: 1,
        dpapi_ok: true,
        symlink: SymlinkState::Ok,
        upstream: UpstreamState::Ok,
        logon_type: Some(2),
        elevation,
        integrity,
    }
}

/// An administrator's agent's own probe, and the one that asked to be unelevated.
fn elevated() -> ProbeResult {
    probe(Some(Elevation::Full), Some(INTEGRITY_HIGH))
}

fn unelevated() -> ProbeResult {
    probe(Some(Elevation::Filtered), Some(INTEGRITY_MEDIUM))
}

/// The unelevated probe's answer as `Probes` carries it: its result, or the cause it failed with.
fn answered(result: ProbeResult) -> Result<ProbeResult, String> {
    Ok(result)
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
    let rows = session_rows(&elevated(), Some(&answered(unelevated())));

    assert_eq!(names(&rows), ["elevated session", "unelevated session on request"]);
    assert_eq!(passes(&rows), [true, true], "{:?}", details(&rows));
    assert!(rows[0].detail.contains("High (0x3000)"), "{}", rows[0].detail);
}

/// An account at High that is not an administrator (a Backup Operator: Windows does not split its
/// token) gets the same two probes and the same two rows, which pass: its session is at High, and
/// `internal-unelevated` gives Medium, with no Administrators entry to be deny-only.
#[test]
fn a_standard_account_at_high_passes_both_rows_and_its_unelevated_probe_is_judged() {
    let default = probe(Some(Elevation::Standard), Some(INTEGRITY_HIGH));
    let asked = probe(Some(Elevation::Standard), Some(INTEGRITY_MEDIUM));

    let rows = session_rows(&default, Some(&answered(asked)));

    assert_eq!(names(&rows), ["elevated session", "unelevated session on request"]);
    assert_eq!(passes(&rows), [true, true], "{:?}", details(&rows));
    assert!(rows[0].detail.contains("not an administrator"), "{}", rows[0].detail);

    let at_high = probe(Some(Elevation::Standard), Some(INTEGRITY_HIGH));
    let rows = session_rows(&default, Some(&answered(at_high)));
    assert_eq!(
        passes(&rows),
        [true, false],
        "it was not stepped down: {:?}",
        details(&rows)
    );
}

/// The `elevated session` row passes only for a token at High with Administrators enabled or absent: an
/// administrator's agent is elevated or absent, so a deny-only token, one below High and one that said
/// nothing are faults, whatever else the probe proved.
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
        let rows = session_rows(&default, Some(&answered(unelevated())));

        assert_eq!(names(&rows)[0], "elevated session", "{default:?}");
        assert!(!rows[0].pass, "{default:?}: {}", rows[0].detail);
    }
}

#[test]
fn a_probe_that_did_not_report_its_token_says_so_and_does_not_blame_the_session() {
    let rows = session_rows(&probe(None, None), Some(&answered(unelevated())));

    assert!(rows[0].detail.contains("did not report"), "{}", rows[0].detail);
    assert!(rows[0].detail.contains("apply"), "{}", rows[0].detail);
}

#[test]
fn a_filtered_agent_is_named_as_not_elevated() {
    let rows = session_rows(
        &probe(Some(Elevation::Filtered), Some(INTEGRITY_MEDIUM)),
        Some(&answered(unelevated())),
    );

    assert!(rows[0].detail.contains("not elevated"), "{}", rows[0].detail);
}

/// The `unelevated session on request` row passes only for a token at Medium (`0x2000`) with
/// Administrators not enabled: `Filtered` for an administrator, `Standard` for an account that is not
/// one. A session that is still elevated, one below Medium, one that reported nothing, and an
/// administrator's token that is not filtered fail.
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
        let rows = session_rows(&elevated(), Some(&answered(asked.clone())));

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
        let rows = session_rows(&elevated(), Some(&answered(asked.clone())));

        assert!(rows[1].pass, "{asked:?}: {}", rows[1].detail);
    }
}

/// A probe that asked for an unelevated session and failed is named with its cause on its row: the row
/// is about that session, and the cause is why it cannot say.
#[test]
fn an_unelevated_probe_that_failed_fails_its_row_with_the_cause() {
    let rows = session_rows(&elevated(), Some(&Err("probe relay failed (code 254)".to_string())));

    assert_eq!(passes(&rows), [true, false]);
    assert!(
        rows[1].detail.contains("probe relay failed (code 254)"),
        "{}",
        rows[1].detail
    );
}

#[test]
fn no_unelevated_probe_fails_its_row_for_an_agent_at_high() {
    let rows = session_rows(&elevated(), None);

    assert_eq!(passes(&rows), [true, false]);
    assert!(rows[1].detail.contains("not run"), "{}", rows[1].detail);
}

// the agent is below High ------------------------------------------------------------------

/// One row, which passes and says the session is a standard account's.
#[test]
fn a_standard_account_below_high_has_one_passing_row() {
    let default = probe(Some(Elevation::Standard), Some(INTEGRITY_MEDIUM));

    let rows = session_rows(&default, None);

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
        let rows = session_rows(&default, None);

        assert_eq!(names(&rows), ["elevated session"], "{default:?}");
        assert!(!rows[0].pass, "{default:?}: {}", rows[0].detail);
    }
}

// the junction -----------------------------------------------------------------------------

fn junction(state: SymlinkState, note: &str) -> Junction {
    Junction {
        state,
        note: note.to_string(),
    }
}

#[test]
fn the_junction_row_fails_on_a_junction_that_was_made_and_not_followed() {
    let row = |state| link_row(&junction(state, ""));

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

/// A junction that could not be made was not tested: the row does not fail `verify`, says in so many
/// words that the property was not tested, and gives the probe's reason.
#[test]
fn a_junction_that_could_not_be_made_is_not_tested_and_fails_nothing() {
    let row = link_row(&junction(
        SymlinkState::Skipped,
        "making a junction in D:\\t failed: not supported",
    ));

    assert!(row.pass, "{}", row.detail);
    assert!(row.detail.contains("NOT tested"), "{}", row.detail);
    assert!(row.detail.contains("not supported"), "{}", row.detail);
    assert!(
        link_row(&junction(SymlinkState::Skipped, ""))
            .detail
            .contains("NOT tested")
    );
}

/// The probe's own words are on every row that does not pass, and on a passing one that has something to
/// say (a directory it could not remove).
#[test]
fn the_probes_words_reach_the_junction_row() {
    let said = "reading through the junction in D:\\t failed: access denied";

    assert!(
        link_row(&junction(SymlinkState::Failed, said))
            .detail
            .contains("access denied")
    );
    assert!(
        link_row(&junction(SymlinkState::Blocked, said))
            .detail
            .contains("access denied")
    );
    let passing = link_row(&junction(SymlinkState::Ok, "removing D:\\t failed: in use"));
    assert!(passing.pass);
    assert!(passing.detail.contains("in use"), "{}", passing.detail);
    assert_eq!(link_row(&junction(SymlinkState::Ok, "")).detail, "followed");
}

// the whole report of the probes -----------------------------------------------------------

fn probes(default: ProbeResult, unelevated: Option<Result<ProbeResult, String>>) -> Probes {
    Probes {
        default,
        binary_ok: true,
        unelevated,
        junction: junction(SymlinkState::Ok, ""),
        leftover: None,
    }
}

fn rows_of(probes: &Probes) -> Vec<Check> {
    parity_rows(probes, 1)
}

/// An administrator's whole report: the session, DPAPI, the two session rows, the junction and the two
/// byte-transparency rows, all passing for a healthy elevated agent.
#[test]
fn a_healthy_administrators_agent_passes_every_row() {
    let rows = rows_of(&probes(elevated(), Some(answered(unelevated()))));

    assert_eq!(
        names(&rows),
        [
            "interactive session (via agent)",
            "DPAPI (via agent)",
            "elevated session",
            "unelevated session on request",
            "junction (via agent)",
            "binary download (via agent)",
            "binary upload (via agent)",
        ]
    );
    assert!(rows.iter().all(|row| row.pass), "{:?}", details(&rows));
}

#[test]
fn a_standard_accounts_report_has_one_session_row() {
    let rows = rows_of(&probes(probe(Some(Elevation::Standard), Some(INTEGRITY_MEDIUM)), None));

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

/// A failed unelevated probe takes only its own rows with it: every other row still comes from the
/// default probe, which ran.
#[test]
fn a_failed_unelevated_probe_leaves_the_other_rows_to_the_default_probe() {
    let mut p = probes(elevated(), Some(Err("connect to agent: refused".to_string())));
    p.junction = junction(
        SymlinkState::Failed,
        "no junction from an unelevated session could be tested: connect to agent: refused",
    );

    let rows = rows_of(&p);

    assert_eq!(rows.len(), 7, "{:?}", names(&rows));
    let failing: Vec<&str> = rows.iter().filter(|row| !row.pass).map(|row| row.name).collect();
    assert_eq!(failing, ["unelevated session on request", "junction (via agent)"]);
    let junction = rows.iter().find(|row| row.name == "junction (via agent)").unwrap();
    assert!(junction.detail.contains("could be tested"), "{}", junction.detail);
}

/// The junction row is `Probes::junction`, which `run` settles from both probes: a refusal fails it,
/// whatever the unelevated probe saw of its own.
#[test]
fn the_junction_row_is_the_junction_found() {
    let mut p = probes(elevated(), Some(answered(unelevated())));
    p.junction = junction(SymlinkState::Blocked, "");

    let rows = rows_of(&p);

    let row = rows.iter().find(|row| row.name == "junction (via agent)").unwrap();
    assert!(!row.pass);
}

/// A junction `verify` could not remove is said on the row, so the person can remove it; the row still
/// says what the probe proved.
#[test]
fn a_junction_left_behind_is_named_on_its_row() {
    let mut p = probes(elevated(), Some(answered(unelevated())));
    p.leftover = Some(r"C:\Temp\sb-junction-1: access denied".to_string());

    let rows = rows_of(&p);

    let junction = rows.iter().find(|row| row.name == "junction (via agent)").unwrap();
    assert!(junction.pass, "{}", junction.detail);
    assert!(
        junction.detail.contains(r"C:\Temp\sb-junction-1"),
        "{}",
        junction.detail
    );
    assert!(junction.detail.contains("could not be removed"), "{}", junction.detail);
}

#[test]
fn the_byte_rows_fail_as_they_did_before() {
    let mut p = probes(elevated(), Some(answered(unelevated())));
    p.binary_ok = false;
    p.default.upstream = UpstreamState::Fail;

    let rows = rows_of(&p);

    let failing: Vec<&str> = rows.iter().filter(|row| !row.pass).map(|row| row.name).collect();
    assert_eq!(failing, ["binary download (via agent)", "binary upload (via agent)"]);
}

#[test]
fn a_session_zero_network_logon_fails_the_session_row_and_names_the_console() {
    let mut p = probes(elevated(), Some(answered(unelevated())));
    p.default.session_id = 0;
    p.default.logon_type = Some(3);

    let rows = parity_rows(&p, 7);

    assert!(!rows[0].pass);
    assert!(rows[0].detail.contains("active console=7"), "{}", rows[0].detail);
}
