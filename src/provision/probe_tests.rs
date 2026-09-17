//! Host tests for the pure probe-line format/parse.
use super::{
    ProbeResult, SymlinkState, binary_probe_ok, binary_probe_payload, emit_binary_probe, format_probe_line,
    parse_probe_line,
};

#[test]
fn probe_line_round_trips() {
    let line = format_probe_line(1, true, SymlinkState::Blocked, true);
    assert_eq!(line, "PROBE session_id=1 dpapi=ok symlink=blocked upstream=ok");
    assert_eq!(
        parse_probe_line(&line).unwrap(),
        ProbeResult {
            session_id: 1,
            dpapi_ok: true,
            symlink: SymlinkState::Blocked,
            upstream_ok: true,
        }
    );
}

/// `upstream` is default-deny, like `dpapi`: a probe child too old to report it must read as
/// "not proven" rather than proven. It gates a claim the README makes about the client → child
/// direction, so a default of `true` would silently restore the unverified assertion it replaces.
#[test]
fn a_missing_upstream_token_reads_as_not_proven() {
    let old = "PROBE session_id=1 dpapi=ok symlink=skip";
    assert!(!parse_probe_line(old).unwrap().upstream_ok);
    let failed = format_probe_line(1, true, SymlinkState::Ok, false);
    assert!(failed.contains("upstream=fail"));
    assert!(!parse_probe_line(&failed).unwrap().upstream_ok);
}

#[test]
fn symlink_states_round_trip() {
    for st in [SymlinkState::Ok, SymlinkState::Blocked, SymlinkState::Skipped] {
        let line = format_probe_line(2, false, st, true);
        assert_eq!(parse_probe_line(&line).unwrap().symlink, st);
    }
    // Only a confirmed block is a parity failure.
    assert!(SymlinkState::Blocked.is_failure());
    assert!(!SymlinkState::Ok.is_failure());
    assert!(!SymlinkState::Skipped.is_failure());
}

/// The payload must survive an exact round trip, and the check must be sensitive to a SINGLE
/// flipped byte. A check that only noticed gross damage would pass on a relay that mangles the
/// occasional byte — which is precisely the failure it exists to catch.
#[test]
fn binary_probe_round_trips_and_detects_a_single_flipped_byte() {
    let mut buf = Vec::new();
    emit_binary_probe(&mut buf).unwrap();
    assert!(binary_probe_ok(&buf));

    // Surrounding output is expected — the PROBE line follows, and a shell may add its own.
    let mut noisy = b"leading junk\n".to_vec();
    noisy.extend_from_slice(&buf);
    noisy.extend_from_slice(b"PROBE session_id=1 dpapi=ok symlink=skip\n");
    assert!(binary_probe_ok(&noisy), "must tolerate surrounding output");

    let payload_start = b"BINPROBE<".len();
    for i in [payload_start, payload_start + 128, payload_start + 255] {
        let mut broken = buf.clone();
        broken[i] ^= 0x01;
        assert!(!binary_probe_ok(&broken), "a flipped byte at {i} must fail the check");
    }

    // Default-deny: absent or truncated is a FAILURE, never a silent pass.
    assert!(!binary_probe_ok(b"no markers here"));
    assert!(!binary_probe_ok(&buf[..buf.len() - 4]));
}

/// The brackets must not occur inside the data they delimit, or extraction would truncate and the
/// comparison would fail for the wrong reason. This holds because the payload is the 256 values in
/// ascending order, so every window of it is a consecutive ascending run — but it is asserted
/// rather than trusted, since a future change to the payload could quietly break it.
#[test]
fn binary_probe_markers_cannot_collide_with_the_payload() {
    let payload = binary_probe_payload();
    for marker in [b"BINPROBE<".as_slice(), b">BINPROBE".as_slice()] {
        assert!(
            !payload.windows(marker.len()).any(|w| w == marker),
            "marker {:?} must not appear inside the payload",
            String::from_utf8_lossy(marker)
        );
    }
}

#[test]
fn parse_is_default_deny_on_gating_keys() {
    // Missing dpapi and upstream → fail; missing session_id → 0; missing symlink → Skipped
    // (informational). Only symlink may default to a non-failing value.
    let r = parse_probe_line("PROBE session_id=2").unwrap();
    assert_eq!(
        r,
        ProbeResult {
            session_id: 2,
            dpapi_ok: false,
            symlink: SymlinkState::Skipped,
            upstream_ok: false,
        }
    );
}

#[test]
fn parse_tolerates_surrounding_noise() {
    let out = "starting...\nPROBE session_id=7 dpapi=ok symlink=ok upstream=ok\nbye\n";
    assert_eq!(
        parse_probe_line(out).unwrap(),
        ProbeResult {
            session_id: 7,
            dpapi_ok: true,
            symlink: SymlinkState::Ok,
            upstream_ok: true,
        }
    );
}

#[test]
fn parse_errors_when_no_probe_line() {
    assert!(parse_probe_line("nothing here\njust noise").is_err());
}
