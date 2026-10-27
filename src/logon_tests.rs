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

fn refused(code: u32) -> Result<u32, LogonFailure> {
    Err(LogonFailure::from_win32(code))
}

const ACCESS_DENIED: u32 = 5;
const LOGON_FAILURE: u32 = 1326;
const ASKED: PROCESS_CREATION_FLAGS = PROCESS_CREATION_FLAGS(CREATE_NO_WINDOW.0 | CREATE_BREAKAWAY_FROM_JOB.0);

/// An outer job in a chain can refuse what the innermost allows; the refusal is `ERROR_ACCESS_DENIED`.
/// The call is then made once more as a caller that asks for no breakaway, and that answer is final.
#[test]
fn a_refused_breakaway_is_followed_by_one_call_without_it() {
    let mut calls = Vec::new();
    let result = with_breakaway_fallback(ASKED, |flags| {
        calls.push(flags);
        if flags == ASKED { refused(ACCESS_DENIED) } else { Ok(7) }
    });
    assert_eq!(result.unwrap(), (7, false), "the call that answered did not keep the breakaway");
    assert_eq!(calls, [ASKED, CREATE_NO_WINDOW]);
}

#[test]
fn the_answer_of_the_second_call_is_final() {
    let mut calls = 0;
    let result = with_breakaway_fallback(ASKED, |_| {
        calls += 1;
        refused(ACCESS_DENIED)
    });
    assert_eq!(result.unwrap_err().code, ACCESS_DENIED);
    assert_eq!(calls, 2);
}

/// A wrong password is not a refused breakaway: the password is tried once.
#[test]
fn any_other_failure_is_not_followed_by_a_second_call() {
    let mut calls = 0;
    let result = with_breakaway_fallback(ASKED, |_| {
        calls += 1;
        refused(LOGON_FAILURE)
    });
    assert_eq!(result.unwrap_err().code, LOGON_FAILURE);
    assert_eq!(calls, 1);
}

#[test]
fn a_call_that_did_not_ask_for_breakaway_is_made_once() {
    let mut calls = 0;
    let result = with_breakaway_fallback(CREATE_NO_WINDOW, |_| {
        calls += 1;
        refused(ACCESS_DENIED)
    });
    assert_eq!(result.unwrap_err().code, ACCESS_DENIED);
    assert_eq!(calls, 1);
}

#[test]
fn a_call_that_succeeds_is_made_once() {
    let mut calls = 0;
    let result = with_breakaway_fallback(ASKED, |_| {
        calls += 1;
        Ok(1)
    });
    assert_eq!(result.unwrap(), (1, true), "the breakaway that was asked for was kept");
    assert_eq!(calls, 1);
}

#[test]
fn a_call_that_asked_for_no_breakaway_did_not_keep_one() {
    let result = with_breakaway_fallback(CREATE_NO_WINDOW, |_| Ok(1));
    assert_eq!(result.unwrap(), (1, false));
}

// survival -----

#[test]
fn a_session_outlives_its_connection_outside_any_job_or_with_breakaway_kept() {
    assert_eq!(survival_of(&CallerJob::NotInJob, false), Survival::OutlivesConnection);
    let allowing = CallerJob::Limits(KILL_ON_JOB_CLOSE | BREAKAWAY_OK);
    assert_eq!(survival_of(&allowing, true), Survival::OutlivesConnection);
}

#[test]
fn a_session_ends_with_its_connection_when_it_stayed_in_the_callers_job() {
    let allowing = CallerJob::Limits(KILL_ON_JOB_CLOSE | BREAKAWAY_OK);
    // The flag was asked for and an outer job refused it: the fallback call kept the child in the job.
    assert_eq!(survival_of(&allowing, false), Survival::EndsWithConnection);
    assert_eq!(
        survival_of(&CallerJob::Limits(KILL_ON_JOB_CLOSE), false),
        Survival::EndsWithConnection
    );
    // A job that cannot be read cannot be asked for breakaway.
    assert_eq!(survival_of(&CallerJob::Unreadable, false), Survival::EndsWithConnection);
}
