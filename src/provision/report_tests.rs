//! Host tests for the pure report logic.
use std::path::Path;

use super::{Check, doctor_exit_code, format_report};

const EXE: &str = r"C:\temp\ssh-broker.exe";

#[test]
fn exit_code_zero_only_when_all_pass_and_nonempty() {
    let all_ok = vec![Check::new("a", true, ""), Check::new("b", true, "")];
    assert_eq!(doctor_exit_code(&all_ok), 0);

    let one_fail = vec![Check::new("a", true, ""), Check::new("b", false, "nope")];
    assert_eq!(doctor_exit_code(&one_fail), 1);

    // Empty is fail-closed — an empty report must never look like success.
    assert_eq!(doctor_exit_code(&[]), 1);
}

#[test]
fn report_marks_pass_and_fail() {
    let rows = vec![
        Check::new("DefaultShell", true, "ok"),
        Check::new("DPAPI", false, "absent"),
    ];
    let out = format_report("0.2.0", Some(Path::new(EXE)), &rows);
    assert!(out.contains("[PASS] DefaultShell"));
    assert!(out.contains("[FAIL] DPAPI"));
    assert!(out.contains("absent"));
}

#[test]
fn the_report_begins_with_the_version_and_this_exes_path() {
    for (second, mark) in [(true, "[PASS] b"), (false, "[FAIL] b")] {
        let rows = vec![Check::new("a", true, "ok"), Check::new("b", second, "ok")];
        let out = format_report("0.2.0", Some(Path::new(EXE)), &rows);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 3, "the heading and one line per row: {out}");
        assert_eq!(lines[0], r"ssh-broker v0.2.0 (C:\temp\ssh-broker.exe)", "{out}");
        assert!(lines[1].starts_with("[PASS] a"), "{out}");
        assert!(lines[2].starts_with(mark), "{out}");
    }
}

#[test]
fn a_path_that_cannot_be_read_leaves_the_heading_with_the_version_alone() {
    let out = format_report("0.2.0", None, &[Check::new("a", true, "ok")]);
    assert_eq!(out.lines().next(), Some("ssh-broker v0.2.0"), "{out}");
}
