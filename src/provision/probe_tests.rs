//! Host tests for the pure probe-line format/parse.
use super::{
    ProbeResult, SymlinkState, UpstreamState, binary_probe_ok, binary_probe_payload, emit_binary_probe,
    format_probe_line, parse_probe_line, upstream_payload_ok,
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
            upstream: UpstreamState::Ok,
        }
    );
}

/// `upstream` is default-deny, like `dpapi`: a probe child too old to report it must read as "not
/// proven" rather than proven, or a silent default of "ok" would restore exactly the unverified
/// assertion this check exists to replace.
///
/// It must ALSO distinguish the two ways of not being proven, which is why this is an enum rather
/// than a bool. A missing token means the installed child predates the check — reachable on a
/// perfectly healthy box, since `apply` tolerates not replacing the exe while a running agent
/// holds it open — whereas `upstream=fail` means the child looked and the bytes were wrong. Both
/// fail the gate; only the second may tell the operator the payload was mangled.
#[test]
fn a_missing_upstream_token_is_absent_not_a_reported_failure() {
    let old = parse_probe_line("PROBE session_id=1 dpapi=ok symlink=skip")
        .unwrap()
        .upstream;
    assert_eq!(old, UpstreamState::Absent);
    assert!(!old.proven(), "absent must never pass the gate");
    assert!(old.detail().contains("predates"), "{}", old.detail());

    let failed = format_probe_line(1, true, SymlinkState::Ok, false);
    assert!(failed.contains("upstream=fail"));
    let got = parse_probe_line(&failed).unwrap().upstream;
    assert_eq!(got, UpstreamState::Fail);
    assert!(!got.proven());
    assert!(
        got.detail().contains("did not reach the child intact"),
        "{}",
        got.detail()
    );
}

/// The upstream comparison IS the client → child measurement. Its production caller
/// (`provision::imp::verify_probe`) is `#[cfg(windows)]` with no test module, so had this stayed
/// inline there, mutating it to a bare `true` would make `verify` print a PASS for that row
/// unconditionally while the whole suite stayed green — the exact unverified assertion the row
/// replaced. These cases are what make that mutation fail.
#[test]
fn upstream_payload_is_default_deny_on_everything_but_an_exact_match() {
    let payload = binary_probe_payload();
    assert!(
        upstream_payload_ok(&mut payload.as_slice()).unwrap(),
        "the exact payload must pass"
    );

    let mut flipped = payload.clone();
    flipped[128] ^= 0x01;
    assert!(
        !upstream_payload_ok(&mut flipped.as_slice()).unwrap(),
        "a single flipped byte must fail"
    );
    assert!(
        !upstream_payload_ok(&mut &payload[..payload.len() - 1]).unwrap(),
        "a truncated payload must fail"
    );
    assert!(
        !upstream_payload_ok(&mut &payload[..0]).unwrap(),
        "an empty read must fail, not pass vacuously"
    );

    let mut extra = payload.clone();
    extra.push(0);
    assert!(
        !upstream_payload_ok(&mut extra.as_slice()).unwrap(),
        "trailing junk must fail"
    );
}

/// An I/O error must PROPAGATE, never read as "arrived intact". The caller default-denies and
/// prints the cause, so a transport fault is never reported as a byte-transparency fault — the
/// two have different remedies and conflating them sends the operator after the wrong thing.
#[test]
fn upstream_payload_propagates_a_read_error() {
    struct Failing;
    impl std::io::Read for Failing {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "upstream went away",
            ))
        }
    }
    let err = upstream_payload_ok(&mut Failing).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
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
            upstream: UpstreamState::Absent,
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
            upstream: UpstreamState::Ok,
        }
    );
}

#[test]
fn parse_errors_when_no_probe_line() {
    assert!(parse_probe_line("nothing here\njust noise").is_err());
}
