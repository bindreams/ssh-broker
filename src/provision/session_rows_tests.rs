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
        junction: None,
    }
}

/// An administrator's agent's own probe, and the one that asked to be unelevated.
fn elevated() -> ProbeResult {
    probe(Some(Elevation::Full), Some(INTEGRITY_HIGH))
}

fn unelevated() -> ProbeResult {
    probe(Some(Elevation::Filtered), Some(INTEGRITY_MEDIUM))
}

fn names(rows: &[Check]) -> Vec<&str> {
    rows.iter().map(|row| row.name).collect()
}

fn passes(rows: &[Check]) -> Vec<bool> {
    rows.iter().map(|row| row.pass).collect()
}

// an administrator's agent -----------------------------------------------------------------

#[test]
fn an_elevated_agent_that_steps_down_on_request_passes_both_rows() {
    let rows = session_rows(&elevated(), Some(&unelevated()));

    assert_eq!(names(&rows), ["elevated session", "unelevated session on request"]);
    assert_eq!(passes(&rows), [true, true], "{:?}", details(&rows));
}

fn details(rows: &[Check]) -> Vec<&str> {
    rows.iter().map(|row| row.detail.as_str()).collect()
}

/// The `elevated session` row fails unless the default probe is `Full`: an administrator's agent is
/// elevated or absent, so any other token is a fault, whatever else the probe proved.
#[test]
fn a_default_probe_that_is_not_full_fails_the_elevated_row() {
    for default in [
        probe(Some(Elevation::Filtered), Some(INTEGRITY_MEDIUM)),
        probe(Some(Elevation::Filtered), Some(INTEGRITY_HIGH)),
        probe(None, None),
        probe(None, Some(INTEGRITY_HIGH)),
    ] {
        let rows = session_rows(&default, Some(&unelevated()));

        assert_eq!(names(&rows)[0], "elevated session", "{default:?}");
        assert!(!rows[0].pass, "{default:?}: {}", rows[0].detail);
    }
}

#[test]
fn a_probe_that_did_not_report_its_token_says_so_and_does_not_blame_the_session() {
    let rows = session_rows(&probe(None, None), Some(&unelevated()));

    assert!(rows[0].detail.contains("did not report"), "{}", rows[0].detail);
    assert!(rows[0].detail.contains("apply"), "{}", rows[0].detail);
}

#[test]
fn a_filtered_agent_is_named_as_not_elevated() {
    let rows = session_rows(
        &probe(Some(Elevation::Filtered), Some(INTEGRITY_MEDIUM)),
        Some(&unelevated()),
    );

    assert!(rows[0].detail.contains("not elevated"), "{}", rows[0].detail);
}

/// The `unelevated session on request` row fails unless the probe that asked is `Filtered` at Medium
/// (`0x2000`): a session that is still elevated, one that is below Medium, one that is not an
/// administrator's token at all, and one that reported nothing.
#[test]
fn an_unelevated_probe_that_is_not_filtered_at_medium_fails_its_row() {
    for asked in [
        probe(Some(Elevation::Full), Some(INTEGRITY_HIGH)),
        probe(Some(Elevation::Filtered), Some(INTEGRITY_HIGH)),
        probe(Some(Elevation::Filtered), Some(0x1000)),
        probe(Some(Elevation::Filtered), None),
        probe(Some(Elevation::Standard), Some(INTEGRITY_MEDIUM)),
        probe(None, Some(INTEGRITY_MEDIUM)),
        probe(None, None),
    ] {
        let rows = session_rows(&elevated(), Some(&asked));

        assert_eq!(names(&rows)[1], "unelevated session on request", "{asked:?}");
        assert!(!rows[1].pass, "{asked:?}: {}", rows[1].detail);
        assert!(rows[0].pass, "the first row is about the default probe alone");
    }
}

#[test]
fn no_unelevated_probe_fails_its_row_for_an_administrator() {
    let rows = session_rows(&elevated(), None);

    assert_eq!(passes(&rows), [true, false]);
    assert!(rows[1].detail.contains("not run"), "{}", rows[1].detail);
}

// a standard account's agent ---------------------------------------------------------------

/// One row, which passes and says the session is a standard account's. The unelevated probe, when one
/// was run to make the junction (an account at High that Windows does not split), is not judged.
#[test]
fn a_standard_accounts_agent_has_one_passing_row() {
    for medium_or_high in [INTEGRITY_MEDIUM, INTEGRITY_HIGH] {
        let default = probe(Some(Elevation::Standard), Some(medium_or_high));
        for unelevated in [None, Some(unelevated()), Some(probe(None, None))] {
            let rows = session_rows(&default, unelevated.as_ref());

            assert_eq!(names(&rows), ["session privilege"], "{unelevated:?}");
            assert!(rows[0].pass, "{}", rows[0].detail);
            assert!(rows[0].detail.contains("standard account"), "{}", rows[0].detail);
        }
    }
}

// the junction -----------------------------------------------------------------------------

#[test]
fn the_junction_row_fails_on_everything_but_a_followed_junction() {
    let row = |symlink| link_row(symlink);

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

// the whole report of the probes -----------------------------------------------------------

fn probes(default: ProbeResult, unelevated: Option<ProbeResult>) -> Probes {
    Probes {
        default,
        binary_ok: true,
        unelevated,
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
    let rows = rows_of(&probes(elevated(), Some(unelevated())));

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

/// The junction row is the default probe's, which is the one that followed the junction a lower token
/// made: a refusal there fails it, whatever the unelevated probe saw of its own.
#[test]
fn the_junction_row_is_the_default_probes() {
    let mut default = elevated();
    default.symlink = SymlinkState::Blocked;
    let mut asked = unelevated();
    asked.symlink = SymlinkState::Ok;

    let rows = rows_of(&probes(default, Some(asked)));

    let junction = rows.iter().find(|row| row.name == "junction (via agent)").unwrap();
    assert!(!junction.pass);
}

/// A junction `verify` could not remove is said on the row, so the person can remove it; the row still
/// says what the probe proved.
#[test]
fn a_junction_left_behind_is_named_on_its_row() {
    let mut p = probes(elevated(), Some(unelevated()));
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
    let mut p = probes(elevated(), Some(unelevated()));
    p.binary_ok = false;
    p.default.upstream = UpstreamState::Fail;

    let rows = rows_of(&p);

    let failing: Vec<&str> = rows.iter().filter(|row| !row.pass).map(|row| row.name).collect();
    assert_eq!(failing, ["binary download (via agent)", "binary upload (via agent)"]);
}

#[test]
fn a_session_zero_network_logon_fails_the_session_row_and_names_the_console() {
    let mut p = probes(elevated(), Some(unelevated()));
    p.default.session_id = 0;
    p.default.logon_type = Some(3);

    let rows = parity_rows(&p, 7);

    assert!(!rows[0].pass);
    assert!(rows[0].detail.contains("active console=7"), "{}", rows[0].detail);
}
