//! Host tests for the pure report logic.
use super::{Check, format_report, verify_exit_code};

#[test]
fn exit_code_zero_only_when_all_pass_and_nonempty() {
    let all_ok = vec![Check::new("a", true, ""), Check::new("b", true, "")];
    assert_eq!(verify_exit_code(&all_ok), 0);

    let one_fail = vec![Check::new("a", true, ""), Check::new("b", false, "nope")];
    assert_eq!(verify_exit_code(&one_fail), 1);

    // Empty is fail-closed — an empty report must never look like success.
    assert_eq!(verify_exit_code(&[]), 1);
}

#[test]
fn report_marks_pass_and_fail() {
    let rows = vec![Check::new("DefaultShell", true, "ok"), Check::new("DPAPI", false, "absent")];
    let out = format_report(&rows);
    assert!(out.contains("[PASS] DefaultShell"));
    assert!(out.contains("[FAIL] DPAPI"));
    assert!(out.contains("absent"));
}
