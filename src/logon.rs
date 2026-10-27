//! logon: ask Windows to sign the user on and start their background agent.
//!
//! The call is `CreateProcessWithLogonW(LOGON_WITH_PROFILE)`, which hands the password to the
//! Secondary Logon service and starts `ssh-broker agent --background` as the user in a new logon
//! session with a loaded profile, DPAPI and junction traversal (spike M1, M2). The password is only
//! the call's argument, in a NUL-terminated copy that `Password::with_nul` wipes when the call
//! returns; it is on no command line, in no environment and in no error text.
//!
//! The service puts the child in the caller's job (CI, M3: the child of a caller in a kill-on-close job
//! ended with the job, exit code 0). Whether it gets out is found by a probe the shim starts and reads
//! before the call ([`probe`]), not inferred from the flags the call is made with and not read from
//! the child. `CREATE_BREAKAWAY_FROM_JOB` is passed when the caller's job allows breakaway
//! (`JOB_OBJECT_LIMIT_BREAKAWAY_OK`) and not otherwise: in a job that does not allow it the
//! call fails with `ERROR_ACCESS_DENIED`, which would cost the user their login.
//!
//! A caller can sit in a chain of nested jobs, and the query without a handle reads one job of it, so
//! "the job allows it" is not the whole answer: an outer job can refuse what the one read allows.
//! [`with_breakaway_fallback`] makes that refusal, and only that, cost the child its survival instead
//! of the user their login.

mod probe;

use std::path::Path;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::JobObjects::{
    IsProcessInJob, JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation, QueryInformationJobObject,
};
use windows::Win32::System::Threading::{
    CREATE_BREAKAWAY_FROM_JOB, CREATE_NO_WINDOW, CreateProcessWithLogonW, GetCurrentProcess, LOGON_WITH_PROFILE,
    PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTUPINFOW,
};
use windows::core::{BOOL, HRESULT, PCWSTR, PWSTR};

use crate::account::LocalAccount;
use crate::autologin::BatchRight;
use crate::password_entry::Password;
use crate::winutil::OwnedHandle;
pub use probe::Probe;
use probe::{probe_for, start_probe};

/// `ERROR_FILENAME_EXCED_RANGE`: Windows' answer to a password over its length limit.
const ERROR_FILENAME_EXCED_RANGE: u32 = 206;
/// `ERROR_LOGON_TYPE_NOT_GRANTED`: the account does not hold the right for this logon type.
const ERROR_LOGON_TYPE_NOT_GRANTED: u32 = 1385;
/// `ERROR_ACCESS_DENIED`: what a refused `CREATE_BREAKAWAY_FROM_JOB` is answered with.
const ERROR_ACCESS_DENIED: u32 = 5;
const PASSWORD_TOO_LONG: &str = "the password is too long for Windows.";

/// The background agent the logon started. Dropping it closes the handle; the agent keeps running.
pub struct StartedAgent {
    pub process: OwnedHandle,
    pub survival: Survival,
}

/// Whether the session the logon started outlives the connection that asked for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Survival {
    /// The agent is outside every job the caller is in, so nothing the connection owns closes on it.
    OutlivesConnection,
    /// The agent stays in a job that is known to kill what is in it when it closes.
    EndsWithConnection,
    /// The agent stays in a job that is not known to kill it: an outer job whose flags cannot be read,
    /// or the innermost one without `KILL_ON_JOB_CLOSE`. Whether it ends is up to whoever owns the job.
    MayEndWithConnection,
}

/// The jobs a process is in, as Windows reports them for that process itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildJob {
    NotInJob,
    /// In at least one job.
    InJob,
    /// Windows would not say.
    Unreadable,
}

impl ChildJob {
    /// Whether `process` (a handle with `PROCESS_QUERY_LIMITED_INFORMATION`) is in any job.
    pub fn of_process(process: HANDLE) -> ChildJob {
        let mut in_job = BOOL(0);
        // SAFETY: a valid handle and out-pointer; no job handle means any job.
        match unsafe { IsProcessInJob(process, None, &mut in_job) } {
            Err(_) => ChildJob::Unreadable,
            Ok(()) if in_job.as_bool() => ChildJob::InJob,
            Ok(()) => ChildJob::NotInJob,
        }
    }
}

/// What the session gets from the probe (see [`probe`]) for a caller in `job`. The caller's job flags
/// do not say where the child lands: a job that allows breakaway can sit inside one that keeps the
/// child (CI round 8), and Windows answers the flagged call without refusing it. The logon child does
/// not say either: it is in a job of the Secondary Logon service's even when it outlives its caller's
/// (CI round 9).
///
/// `kept_breakaway` is whether the logon call itself asked for breakaway and was not refused. The
/// probe always asks, so what it found describes the child only if the call did too; if not, the
/// child is in the caller's job whatever the probe got out of, and only the innermost job's flags
/// are known.
///
/// A job ends what is in it only if it kills on close, or its owner ends it (CI round 11: the job of a
/// GitHub runner step has no limits). The flags of the innermost job are readable and the probe is
/// all that is known of the outer ones, so:
/// - the caller is in no job, or the call kept breakaway and nothing kept the probe: it outlives;
/// - the child stays in the innermost job (the call did not keep breakaway, or the probe was
///   refused) and that job kills on close: it ends;
/// - anything else (an outer job kept the probe, the innermost does not kill, no answer): it may end.
pub fn survival_of(job: &CallerJob, probe: Probe, kept_breakaway: bool) -> Survival {
    let stays_in_innermost = || match job {
        CallerJob::Limits(flags) if flags & JOB_KILL_ON_CLOSE != 0 => Survival::EndsWithConnection,
        _ => Survival::MayEndWithConnection,
    };
    match probe {
        Probe::CallerInNoJob => Survival::OutlivesConnection,
        _ if !kept_breakaway => stays_in_innermost(),
        Probe::Started(ChildJob::NotInJob) => Survival::OutlivesConnection,
        Probe::Refused => stays_in_innermost(),
        Probe::Started(ChildJob::InJob | ChildJob::Unreadable) | Probe::Failed => Survival::MayEndWithConnection,
    }
}

/// Why Windows refused: its error code and its own sentence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogonFailure {
    pub code: u32,
    pub reason: String,
}

impl LogonFailure {
    /// The failure for Win32 error `code`. Windows' text is shown as is, except code 206, whose
    /// text ("The filename or extension is too long.") says nothing a user can act on.
    pub fn from_win32(code: u32) -> LogonFailure {
        if code == ERROR_FILENAME_EXCED_RANGE {
            return LogonFailure {
                code,
                reason: PASSWORD_TOO_LONG.into(),
            };
        }
        let text = windows::core::Error::from(HRESULT::from_win32(code)).message();
        let text = text.trim();
        let reason = if text.is_empty() {
            format!("Windows error {code}")
        } else {
            text.to_owned()
        };
        LogonFailure { code, reason }
    }

    fn from_error(error: &windows::core::Error) -> LogonFailure {
        let hresult = error.code().0 as u32;
        // `HRESULT_FROM_WIN32` puts the code under facility 7.
        let code = if hresult >> 16 == 0x8007 {
            hresult & 0xFFFF
        } else {
            hresult
        };
        LogonFailure::from_win32(code)
    }
}

impl std::fmt::Display for LogonFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}

/// The command line of the background agent: the exe quoted (it may hold spaces), the verb, and the
/// flag. The agent exits unless its token's SID equals `expect_user`.
pub fn command_line(exe: &Path, expect_user: &str) -> String {
    format!("\"{}\" agent --background --expect-user {expect_user}", exe.display())
}

/// `JOB_OBJECT_LIMIT_BREAKAWAY_OK`: a process in the job may start a child outside it.
const JOB_BREAKAWAY_OK: u32 = 0x0000_0800;
/// `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`: closing the job ends every process in it.
const JOB_KILL_ON_CLOSE: u32 = 0x0000_2000;

/// The job the calling process is in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallerJob {
    NotInJob,
    /// The `LimitFlags` of the job.
    Limits(u32),
    /// Windows would not say.
    Unreadable,
}

impl CallerJob {
    /// The job of this process.
    pub fn of_this_process() -> CallerJob {
        let mut in_job = BOOL(0);
        // SAFETY: a valid handle and out-pointer; no job handle means any job.
        if unsafe { IsProcessInJob(GetCurrentProcess(), None, &mut in_job) }.is_err() {
            return CallerJob::Unreadable;
        }
        if !in_job.as_bool() {
            return CallerJob::NotInJob;
        }
        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        // SAFETY: a buffer of the size passed; no job handle queries the calling process's own job.
        let queried = unsafe {
            QueryInformationJobObject(
                None,
                JobObjectExtendedLimitInformation,
                (&raw mut info).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                None,
            )
        };
        match queried {
            Ok(()) => CallerJob::Limits(info.BasicLimitInformation.LimitFlags.0),
            Err(_) => CallerJob::Unreadable,
        }
    }
}

/// The creation flags of the logon call for a caller in `job`.
pub fn creation_flags(job: &CallerJob) -> PROCESS_CREATION_FLAGS {
    match job {
        CallerJob::Limits(flags) if flags & JOB_BREAKAWAY_OK != 0 => CREATE_NO_WINDOW | CREATE_BREAKAWAY_FROM_JOB,
        _ => CREATE_NO_WINDOW,
    }
}

/// Make `call` with `flags`. If it asked for breakaway and was refused with `ERROR_ACCESS_DENIED`, make
/// it once more without; that answer is final. Along with the answer comes whether the call that gave
/// it asked for breakaway.
///
/// Why this is right. The refusal comes at the child's creation, after Windows has checked the
/// password: a wrong password is answered `ERROR_LOGON_FAILURE` (1326), not access denied, so a
/// password that failed is not tried twice (`tests/session_on_demand_windows.rs` pins it). A refusal of
/// another cause (an account that may not run the program) is answered the same way by the second
/// call, whose answer is the one the user sees. The second call is what every logon was before the flag
/// existed: the child lives in the caller's job, as long as the job does. It is one fallback on one
/// refusal, not a retry: nothing repeats.
fn with_breakaway_fallback<T>(
    flags: PROCESS_CREATION_FLAGS,
    mut call: impl FnMut(PROCESS_CREATION_FLAGS) -> Result<T, LogonFailure>,
) -> Result<(T, bool), LogonFailure> {
    let asked = flags.0 & CREATE_BREAKAWAY_FROM_JOB.0 != 0;
    match call(flags) {
        Err(failure) if failure.code == ERROR_ACCESS_DENIED && asked => {
            tracing::info!("a job around this process refuses breakaway; starting the session inside it");
            call(PROCESS_CREATION_FLAGS(flags.0 & !CREATE_BREAKAWAY_FROM_JOB.0)).map(|answer| (answer, false))
        }
        other => other.map(|answer| (answer, asked)),
    }
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Sign `account` on with `password` and start `exe agent --background` as that account. Returns
/// once the call has. The caller learns that the agent serves from the files it writes (see
/// `socket_watch`), and that it ended from the process handle in [`StartedAgent`].
pub fn start_background_agent(
    account: &LocalAccount,
    password: &Password,
    exe: &Path,
) -> Result<StartedAgent, LogonFailure> {
    let mut command = wide(&command_line(exe, &account.sid));
    let exe_w = wide(&exe.to_string_lossy());
    // The caller's directory may be one the account cannot enter; the install directory is
    // readable by every user.
    let directory = exe.parent().map(|dir| wide(&dir.to_string_lossy()));
    let startup = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut info = PROCESS_INFORMATION::default();
    let user = wide(&account.name);
    let job = CallerJob::of_this_process();
    let flags = creation_flags(&job);
    // Before the logon, so that what it finds is what the call is about to meet.
    let probe = probe_for(&job, start_probe);
    tracing::info!(
        "logon call: caller's job {job:?}, creation flags {:#x}, survival probe {probe:?}",
        flags.0
    );
    let result = password.with_nul(|password| {
        with_breakaway_fallback(flags, |flags| {
            // SAFETY: every pointer is to a local that outlives the call; `password` is the wiped copy.
            unsafe {
                CreateProcessWithLogonW(
                    PCWSTR(user.as_ptr()),
                    PCWSTR(wide(".").as_ptr()),
                    PCWSTR(password.as_ptr()),
                    LOGON_WITH_PROFILE,
                    PCWSTR(exe_w.as_ptr()),
                    Some(PWSTR(command.as_mut_ptr())),
                    flags,
                    None,
                    directory.as_ref().map_or(PCWSTR::null(), |dir| PCWSTR(dir.as_ptr())),
                    &startup,
                    &mut info,
                )
            }
            .map_err(|e| LogonFailure::from_error(&e))
        })
    });
    match result {
        Ok(((), kept_breakaway)) => {
            drop(OwnedHandle(info.hThread));
            let survival = survival_of(&job, probe, kept_breakaway);
            // The child's own membership is logged for comparison with the probe's.
            let child_job = ChildJob::of_process(info.hProcess);
            tracing::info!(
                "logon started the agent: breakaway kept by the call: {kept_breakaway}, the agent is {child_job:?}, the probe found {probe:?}, so {survival:?}"
            );
            Ok(StartedAgent {
                process: OwnedHandle(info.hProcess),
                survival,
            })
        }
        Err(failure) => Err(failure),
    }
}

/// Whether `account` may log on as a batch job, which a boot task needs. A network-less logon of the
/// batch type, closed at once: with the password in hand, Windows says `ERROR_LOGON_TYPE_NOT_GRANTED`
/// (1385) when the right is missing (spike M5(d)).
pub fn check_batch_logon(account: &LocalAccount, password: &Password) -> BatchRight {
    use windows::Win32::Security::{LOGON32_LOGON_BATCH, LOGON32_PROVIDER_DEFAULT, LogonUserW};
    let user = wide(&account.name);
    let mut token = HANDLE::default();
    let logged_on = password.with_nul(|password| {
        // SAFETY: NUL-terminated inputs and a valid out-pointer; `password` is the wiped copy.
        unsafe {
            LogonUserW(
                PCWSTR(user.as_ptr()),
                PCWSTR(wide(".").as_ptr()),
                PCWSTR(password.as_ptr()),
                LOGON32_LOGON_BATCH,
                LOGON32_PROVIDER_DEFAULT,
                &mut token,
            )
        }
    });
    match logged_on {
        Ok(()) => {
            drop(OwnedHandle(token));
            BatchRight::Granted
        }
        Err(e) => {
            let failure = LogonFailure::from_error(&e);
            if failure.code == ERROR_LOGON_TYPE_NOT_GRANTED {
                BatchRight::Missing
            } else {
                BatchRight::Refused(failure.reason)
            }
        }
    }
}

#[cfg(test)]
#[path = "logon_tests.rs"]
mod logon_tests;
