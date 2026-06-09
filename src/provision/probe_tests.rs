//! Host tests for the pure probe-line format/parse.
use super::{ProbeResult, SymlinkState, format_probe_line, parse_probe_line};

#[test]
fn probe_line_round_trips() {
    let line = format_probe_line(1, true, SymlinkState::Blocked);
    assert_eq!(line, "PROBE session_id=1 dpapi=ok symlink=blocked");
    assert_eq!(
        parse_probe_line(&line).unwrap(),
        ProbeResult { session_id: 1, dpapi_ok: true, symlink: SymlinkState::Blocked }
    );
}

#[test]
fn symlink_states_round_trip() {
    for st in [SymlinkState::Ok, SymlinkState::Blocked, SymlinkState::Skipped] {
        let line = format_probe_line(2, false, st);
        assert_eq!(parse_probe_line(&line).unwrap().symlink, st);
    }
    // Only a confirmed block is a parity failure.
    assert!(SymlinkState::Blocked.is_failure());
    assert!(!SymlinkState::Ok.is_failure());
    assert!(!SymlinkState::Skipped.is_failure());
}

#[test]
fn parse_is_default_deny_on_gating_keys() {
    // Missing dpapi → fail; missing session_id → 0; missing symlink → Skipped (informational).
    let r = parse_probe_line("PROBE session_id=2").unwrap();
    assert_eq!(r, ProbeResult { session_id: 2, dpapi_ok: false, symlink: SymlinkState::Skipped });
}

#[test]
fn parse_tolerates_surrounding_noise() {
    let out = "starting...\nPROBE session_id=7 dpapi=ok symlink=ok\nbye\n";
    assert_eq!(
        parse_probe_line(out).unwrap(),
        ProbeResult { session_id: 7, dpapi_ok: true, symlink: SymlinkState::Ok }
    );
}

#[test]
fn parse_errors_when_no_probe_line() {
    assert!(parse_probe_line("nothing here\njust noise").is_err());
}
