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

const BREAKAWAY_OK: u32 = 0x0800;
const SILENT_BREAKAWAY_OK: u32 = 0x1000;
const KILL_ON_JOB_CLOSE: u32 = 0x2000;

#[test]
fn a_caller_outside_any_job_asks_for_no_breakaway() {
    assert_eq!(creation_flags(&CallerJob::NotInJob), CREATE_NO_WINDOW);
}

/// The flag is refused (`ERROR_ACCESS_DENIED`) in a job that does not allow it, which would fail the
/// whole logon, so it is passed only where the job says it may be.
#[test]
fn a_job_that_allows_breakaway_gets_the_flag() {
    let job = CallerJob::Limits(KILL_ON_JOB_CLOSE | BREAKAWAY_OK);
    assert_eq!(creation_flags(&job), CREATE_NO_WINDOW | CREATE_BREAKAWAY_FROM_JOB);
}

#[test]
fn a_job_that_forbids_breakaway_gets_no_flag() {
    assert_eq!(creation_flags(&CallerJob::Limits(KILL_ON_JOB_CLOSE)), CREATE_NO_WINDOW);
    // Silent breakaway frees the caller's own children, but the flag needs `BREAKAWAY_OK`.
    assert_eq!(
        creation_flags(&CallerJob::Limits(SILENT_BREAKAWAY_OK)),
        CREATE_NO_WINDOW
    );
}

/// A job that cannot be read is not evidence that breakaway is allowed.
#[test]
fn a_job_that_cannot_be_read_gets_no_flag() {
    assert_eq!(creation_flags(&CallerJob::Unreadable), CREATE_NO_WINDOW);
}
