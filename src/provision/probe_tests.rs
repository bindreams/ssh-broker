//! Host tests for the pure probe-line format/parse.
use super::{
    JUNCTION_NOTE_CHARS, JUNCTION_NOTE_LINES, JUNCTION_SAID, ProbeResult, SymlinkState, UpstreamState, binary_probe_ok,
    binary_probe_payload, emit_binary_probe, format_probe_line, is_genuine_session, junction_notes, parse_probe_line,
    upstream_payload_ok,
};
use crate::socket_loc::Elevation;

/// A result with every optional field absent: what a probe child too old to report them gives.
fn bare(session_id: u32, symlink: SymlinkState, upstream: UpstreamState) -> ProbeResult {
    ProbeResult {
        session_id,
        dpapi_ok: true,
        symlink,
        upstream,
        logon_type: None,
        elevation: None,
        integrity: None,
    }
}

#[test]
fn probe_line_round_trips() {
    let result = bare(1, SymlinkState::Blocked, UpstreamState::Ok);
    let line = format_probe_line(&result);
    assert_eq!(line, "PROBE session_id=1 dpapi=ok symlink=blocked upstream=ok");
    assert_eq!(parse_probe_line(&line).unwrap(), result);
}

/// The probe's own token, as the parent reads it: how much of an administrator's power it has and the
/// relative id of its integrity label, in hex as the label SID's sub-authority is written.
#[test]
fn probe_line_carries_the_elevation_and_the_integrity_level() {
    for (elevation, word) in [
        (Elevation::Full, "full"),
        (Elevation::Filtered, "filtered"),
        (Elevation::Standard, "standard"),
    ] {
        for rid in [0x2000, 0x3000] {
            let result = ProbeResult {
                elevation: Some(elevation),
                integrity: Some(rid),
                ..bare(1, SymlinkState::Ok, UpstreamState::Ok)
            };
            let line = format_probe_line(&result);
            assert!(
                line.ends_with(&format!(" elevation={word} integrity={rid:#x}")),
                "{line}"
            );
            assert_eq!(parse_probe_line(&line).unwrap(), result);
        }
    }
}

/// A probe that cannot read its own token, or an exe older than the field, says nothing. That must
/// read as "not proven", never as an elevation: the `elevated session` row is what rests on it.
#[test]
fn a_missing_or_unknown_elevation_or_integrity_is_not_proven() {
    let old = parse_probe_line("PROBE session_id=1 dpapi=ok symlink=ok upstream=ok").unwrap();
    assert_eq!((old.elevation, old.integrity), (None, None));
    let garbled =
        parse_probe_line("PROBE session_id=1 dpapi=ok symlink=ok upstream=ok elevation=root integrity=high").unwrap();
    assert_eq!((garbled.elevation, garbled.integrity), (None, None));
}

/// No probe reports a path: `verify` names the junction's directory itself, and a path a process below
/// High wrote is never one `verify` acts on. The line has no `junction=` field, and a key it does not
/// know (an exe from before this change wrote one) is ignored like any other, not read as a directory.
#[test]
fn the_probe_line_names_no_directory() {
    let line = format_probe_line(&bare(1, SymlinkState::Ok, UpstreamState::Ok));
    assert!(!line.contains("junction"), "{line}");

    let old =
        parse_probe_line(r"PROBE session_id=1 dpapi=ok symlink=ok upstream=ok junction=C:\Users\me\Temp\x").unwrap();
    assert_eq!(old, bare(1, SymlinkState::Ok, UpstreamState::Ok));
}

/// What `verify` shows of a probe's stderr on the junction row: only the junction's own lines, a few of
/// them, so another message of the probe (a failed upstream read) is not put on that row.
#[test]
fn only_the_junction_lines_of_the_probes_stderr_are_kept_and_they_are_bounded() {
    let said = |line: &str| format!("{JUNCTION_SAID}{line}\n");
    let stderr = format!(
        "ssh-broker: reading the upstream probe payload failed: broken pipe\n{}{}",
        said("making a junction in C:\\Temp failed: access denied"),
        said("removing C:\\Temp\\x failed: in use"),
    );
    assert_eq!(
        junction_notes(&stderr),
        "making a junction in C:\\Temp failed: access denied; removing C:\\Temp\\x failed: in use"
    );
    assert_eq!(junction_notes(""), "");
    assert_eq!(junction_notes("ssh-broker: something else\n"), "");

    let many: String = (0..9).map(|i| said(&format!("line {i}"))).collect();
    assert_eq!(junction_notes(&many).split("; ").count(), JUNCTION_NOTE_LINES);
    let long = said(&"x".repeat(1000));
    assert!(junction_notes(&long).chars().count() <= JUNCTION_NOTE_CHARS);
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
    // Gate the PROPERTY, not the phrasing: the detail must name the thing actually observed (no
    // `upstream=` token) and must NOT report the payload as corrupted, because in this state
    // nothing ever looked at the payload — it may well have arrived perfectly.
    assert!(
        old.detail().contains("upstream="),
        "absent must name the missing token rather than guess a cause: {}",
        old.detail()
    );
    assert!(
        !old.detail().contains("did not reach the child intact"),
        "absent must NOT be reported as a mangled payload — nothing examined it: {}",
        old.detail()
    );

    let failed = format_probe_line(&bare(1, SymlinkState::Ok, UpstreamState::Fail));
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
    for st in [
        SymlinkState::Ok,
        SymlinkState::Blocked,
        SymlinkState::Failed,
        SymlinkState::NotMade,
        SymlinkState::Skipped,
    ] {
        let line = format_probe_line(&bare(2, st, UpstreamState::Ok));
        assert_eq!(parse_probe_line(&line).unwrap().symlink, st);
    }
    // A junction that was refused, one that was made and not read, and a directory that could not be made
    // fail. A volume that refused the junction was not tested, which fails nothing.
    assert!(SymlinkState::Blocked.is_failure());
    assert!(SymlinkState::Failed.is_failure());
    assert!(SymlinkState::NotMade.is_failure());
    assert!(!SymlinkState::Skipped.is_failure());
    assert!(!SymlinkState::Ok.is_failure());
}

/// The one rule for whether a probe made a junction: it did when it went on to read through it, and
/// not when it stopped at the directory or at the volume.
#[test]
fn only_a_probe_that_read_through_its_junction_made_one() {
    assert!(SymlinkState::Ok.was_made());
    assert!(SymlinkState::Blocked.was_made());
    assert!(SymlinkState::Failed.was_made());
    assert!(!SymlinkState::NotMade.was_made());
    assert!(!SymlinkState::Skipped.was_made());
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
    // Missing dpapi, symlink and upstream → fail; missing session_id → 0. Nothing defaults to a pass.
    let r = parse_probe_line("PROBE session_id=2").unwrap();
    assert_eq!(
        r,
        ProbeResult {
            dpapi_ok: false,
            ..bare(2, SymlinkState::Failed, UpstreamState::Absent)
        }
    );
    assert!(
        r.symlink.is_failure(),
        "a probe that reported no link outcome did not prove one"
    );
}

#[test]
fn parse_tolerates_surrounding_noise() {
    let out = "starting...\nPROBE session_id=7 dpapi=ok symlink=ok upstream=ok\nbye\n";
    assert_eq!(
        parse_probe_line(out).unwrap(),
        bare(7, SymlinkState::Ok, UpstreamState::Ok)
    );
}

#[test]
fn parse_errors_when_no_probe_line() {
    assert!(parse_probe_line("nothing here\njust noise").is_err());
}

#[test]
fn probe_line_round_trips_with_logon_type() {
    let line = format_probe_line(&ProbeResult {
        logon_type: Some(4),
        ..bare(0, SymlinkState::Ok, UpstreamState::Ok)
    });
    assert_eq!(line, "PROBE session_id=0 dpapi=ok symlink=ok upstream=ok logon=4");
    assert_eq!(parse_probe_line(&line).unwrap().logon_type, Some(4));
}

/// A probe child older than this field, or one that could not read its logon session, says nothing:
/// that must read as "not proven", never as a logon type.
#[test]
fn probe_line_without_logon_parses_to_none() {
    let line = "PROBE session_id=1 dpapi=ok symlink=ok upstream=ok";
    assert_eq!(parse_probe_line(line).unwrap().logon_type, None);
    let garbled = "PROBE session_id=1 dpapi=ok symlink=ok upstream=ok logon=x";
    assert_eq!(parse_probe_line(garbled).unwrap().logon_type, None);
}

#[test]
fn session_one_is_genuine() {
    assert!(is_genuine_session(1, None));
    assert!(is_genuine_session(2, Some(3)));
}

#[test]
fn session_zero_batch_is_genuine() {
    assert!(is_genuine_session(0, Some(4)));
}

#[test]
fn session_zero_interactive_is_genuine() {
    assert!(is_genuine_session(0, Some(2)));
}

#[test]
fn session_zero_network_is_not() {
    assert!(!is_genuine_session(0, Some(3)));
}

#[test]
fn session_zero_unreadable_is_not() {
    assert!(!is_genuine_session(0, None));
    assert!(!is_genuine_session(0, Some(0)));
}

/// The logon type is read from LSA by the logon id of this process's own token, which needs no
/// privilege. Whatever the host, the type is one `SECURITY_LOGON_TYPE` names: Interactive (2) to
/// CachedUnlock (13).
#[cfg(windows)]
#[test]
fn this_process_has_a_logon_type() {
    let logon_type = super::current_logon_type().expect("LSA gave no logon session data for this token");
    assert!(
        (2..=13).contains(&logon_type),
        "{logon_type} is not a SECURITY_LOGON_TYPE"
    );
}
