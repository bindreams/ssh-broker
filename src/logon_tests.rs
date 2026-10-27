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
    assert_eq!(
        result.unwrap(),
        (7, false),
        "the call that answered did not keep the breakaway"
    );
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

/// A job that has `KILL_ON_JOB_CLOSE` and nothing else: what sshd keeps a session in.
fn killing() -> CallerJob {
    CallerJob::Limits(KILL_ON_JOB_CLOSE)
}

/// The claim comes from a probe the shim starts itself and examines before the logon, not from the
/// flags of the call (CI round 8) and not from the logon child's own membership (CI round 9: a child
/// that broke away is still in a job of the Secondary Logon service's, and survives all the same).
/// A caller in no job has nothing to survive.
#[test]
fn a_caller_in_no_job_outlives_the_connection() {
    assert_eq!(
        survival_of(&CallerJob::NotInJob, Probe::CallerInNoJob, true),
        Survival::OutlivesConnection
    );
}

/// Every job of the chain let the probe go: the logon child gets out too.
#[test]
fn a_probe_that_got_out_of_every_job_outlives_the_connection() {
    assert_eq!(
        survival_of(&killing(), Probe::Started(ChildJob::NotInJob), true),
        Survival::OutlivesConnection
    );
}

/// An outer job kept the probe although the innermost let it go (CI round 8, m3n2). The flags of an
/// outer job cannot be read, and a job ends what is in it only if it kills on close (CI round 11: the
/// runner's job has no limits), so this is not claimed either way.
#[test]
fn a_probe_that_an_outer_job_kept_may_end_with_the_connection() {
    assert_eq!(
        survival_of(&killing(), Probe::Started(ChildJob::InJob), true),
        Survival::MayEndWithConnection
    );
}

/// The innermost job forbids breakaway (the probe's `ERROR_ACCESS_DENIED`) and kills on close: the child
/// is in it and goes when it closes.
#[test]
fn a_probe_that_a_killing_innermost_job_refused_ends_with_the_connection() {
    assert_eq!(
        survival_of(&killing(), Probe::Refused, true),
        Survival::EndsWithConnection
    );
    assert_eq!(
        survival_of(
            &CallerJob::Limits(KILL_ON_JOB_CLOSE | SILENT_BREAKAWAY_OK),
            Probe::Refused,
            true
        ),
        Survival::EndsWithConnection
    );
}

/// A job that does not kill on close ends nothing by closing: the child may still be ended by whoever
/// owns the job, which cannot be known.
#[test]
fn a_probe_that_an_innermost_job_without_kill_on_close_refused_may_end() {
    assert_eq!(
        survival_of(&CallerJob::Limits(0), Probe::Refused, true),
        Survival::MayEndWithConnection
    );
    assert_eq!(
        survival_of(&CallerJob::Limits(SILENT_BREAKAWAY_OK), Probe::Refused, true),
        Survival::MayEndWithConnection
    );
}

/// A membership, a job or a probe that Windows would not give is evidence of nothing: neither that the
/// child gets out nor that it goes.
#[test]
fn a_probe_that_gave_no_answer_is_claimed_neither_way() {
    assert_eq!(
        survival_of(&killing(), Probe::Started(ChildJob::Unreadable), true),
        Survival::MayEndWithConnection
    );
    assert_eq!(
        survival_of(&killing(), Probe::Failed, true),
        Survival::MayEndWithConnection
    );
    assert_eq!(
        survival_of(&CallerJob::Unreadable, Probe::Failed, true),
        Survival::MayEndWithConnection
    );
}

/// The probe always asks for breakaway, so what it found describes the logon child only if the logon
/// call asked too and kept it. When the call fell back to no breakaway (an outer job refused it), the
/// child is in the caller's job whatever the probe got out of, and the claim is the one for staying in
/// the innermost job.
#[test]
fn a_logon_that_fell_back_to_no_breakaway_stays_in_the_callers_job_whatever_the_probe_found() {
    for probe in [
        Probe::Started(ChildJob::NotInJob),
        Probe::Started(ChildJob::InJob),
        Probe::Started(ChildJob::Unreadable),
        Probe::Refused,
        Probe::Failed,
    ] {
        assert_eq!(
            survival_of(&killing(), probe, false),
            Survival::EndsWithConnection,
            "{probe:?} in a killing job"
        );
        assert_eq!(
            survival_of(&CallerJob::Limits(0), probe, false),
            Survival::MayEndWithConnection,
            "{probe:?} in a job that does not kill"
        );
        assert_eq!(
            survival_of(&CallerJob::Unreadable, probe, false),
            Survival::MayEndWithConnection,
            "{probe:?} in a job nobody could read"
        );
    }
}

/// A caller in no job has nothing to fall back into.
#[test]
fn a_caller_in_no_job_outlives_the_connection_without_breakaway_too() {
    assert_eq!(
        survival_of(&CallerJob::NotInJob, Probe::CallerInNoJob, false),
        Survival::OutlivesConnection
    );
}

/// The probe is a process that is started and ended: only a caller that is in a job needs one.
#[test]
fn a_caller_in_no_job_is_not_probed() {
    let probe = probe_for(&CallerJob::NotInJob, || panic!("a process was started"));
    assert_eq!(probe, Probe::CallerInNoJob);
}

/// A job that cannot be read is not evidence that there is none, and the probe is not started on
/// the strength of a job nobody could read.
#[test]
fn a_caller_whose_job_cannot_be_read_is_not_probed_and_not_claimed_to_outlive() {
    let probe = probe_for(&CallerJob::Unreadable, || panic!("a process was started"));
    assert_eq!(probe, Probe::Failed);
}

/// Whatever the flags of the job say: the probe asks Windows, which knows the whole chain.
#[test]
fn a_caller_in_a_job_is_probed_whether_or_not_its_job_allows_breakaway() {
    for flags in [0x0800, 0x2000, 0x2800] {
        let probe = probe_for(&CallerJob::Limits(flags), || Probe::Refused);
        assert_eq!(probe, Probe::Refused, "limit flags {flags:#x}");
    }
}

/// The reading of a process's own membership agrees with the caller-job reading of the same process.
#[test]
fn the_membership_of_this_process_agrees_with_its_job_reading() {
    // SAFETY: the pseudo-handle of the current process needs no closing.
    let own = ChildJob::of_process(unsafe { GetCurrentProcess() });
    match CallerJob::of_this_process() {
        CallerJob::NotInJob => assert_eq!(own, ChildJob::NotInJob),
        CallerJob::Limits(_) => assert_eq!(own, ChildJob::InJob),
        CallerJob::Unreadable => {}
    }
}
