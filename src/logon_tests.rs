//! Unit tests for `logon` (pure parts; no logon happens here).
use super::*;

const SID: &str = "S-1-5-21-1-2-3-1001";

#[test]
fn command_line_quotes_a_spaced_exe_path() {
    let line = command_line(Path::new(r"C:\Program Files\ssh-broker\ssh-broker.exe"), SID);
    assert_eq!(
        line,
        format!(r#""C:\Program Files\ssh-broker\ssh-broker.exe" agent --background --expect-user {SID}"#)
    );
}

/// The password reaches the logon call as its own argument and nowhere else: the command line holds
/// the exe, the verb and one flag, and takes no secret.
#[test]
fn command_line_has_no_password() {
    let line = command_line(Path::new(r"C:\ProgramData\ssh-broker\ssh-broker.exe"), SID);
    assert_eq!(
        line,
        format!(r#""C:\ProgramData\ssh-broker\ssh-broker.exe" agent --background --expect-user {SID}"#)
    );
    assert!(!line.to_lowercase().contains("pass"), "{line}");
}

#[test]
fn win32_206_has_the_fixed_sentence() {
    let failure = LogonFailure::from_win32(206);
    assert_eq!(failure.code, 206);
    assert_eq!(failure.reason, "the password is too long for Windows.");
}

#[test]
fn another_code_gets_windows_text_without_trailing_whitespace() {
    let failure = LogonFailure::from_win32(1326);
    assert_eq!(failure.code, 1326);
    assert!(!failure.reason.is_empty());
    assert_eq!(failure.reason, failure.reason.trim());
    assert_ne!(failure.reason, "the password is too long for Windows.");
}

#[test]
fn a_code_windows_has_no_text_for_still_gets_a_reason() {
    let failure = LogonFailure::from_win32(0x7fff_0000);
    assert!(!failure.reason.is_empty());
}
