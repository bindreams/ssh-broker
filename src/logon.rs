//! logon: ask Windows to sign the user on and start their background agent.
//!
//! The call is `CreateProcessWithLogonW(LOGON_WITH_PROFILE)`, which hands the password to the
//! Secondary Logon service and starts `ssh-broker agent --background` as the user in a new logon
//! session with a loaded profile, DPAPI and junction traversal (spike M1, M2). The password is only
//! the call's argument, in a NUL-terminated copy that `Password::with_nul` wipes when the call
//! returns; it is on no command line, in no environment and in no error text.
//!
//! No `CREATE_BREAKAWAY_FROM_JOB`: sshd's job does not allow breakaway, and the child is started by
//! the service, not by the caller. Whether the child outlives the caller's job is the CI test
//! `logon_child_survives_the_callers_job_closing`.

use std::path::Path;

use windows::Win32::System::Threading::{
    CREATE_NO_WINDOW, CreateProcessWithLogonW, LOGON_WITH_PROFILE, PROCESS_INFORMATION, STARTUPINFOW,
};
use windows::core::{HRESULT, PCWSTR, PWSTR};

use crate::account::LocalAccount;
use crate::autologin::BatchRight;
use crate::password_entry::Password;
use crate::winutil::OwnedHandle;

/// `ERROR_FILENAME_EXCED_RANGE`: Windows' answer to a password over its length limit.
const ERROR_FILENAME_EXCED_RANGE: u32 = 206;
/// `ERROR_LOGON_TYPE_NOT_GRANTED`: the account does not hold the right for this logon type.
const ERROR_LOGON_TYPE_NOT_GRANTED: u32 = 1385;
const PASSWORD_TOO_LONG: &str = "the password is too long for Windows.";

/// The background agent the logon started. Dropping it closes the handle; the agent keeps running.
pub struct StartedAgent {
    pub process: OwnedHandle,
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
/// two flags. The agent exits unless its token's SID equals `expect_user`.
pub fn command_line(exe: &Path, ready_name: &str, expect_user: &str) -> String {
    format!(
        "\"{}\" agent --background --ready-event {ready_name} --expect-user {expect_user}",
        exe.display()
    )
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Sign `account` on with `password` and start `exe agent --background` as that account. Returns
/// once the call has; the agent signals `ready_name` when its socket folder exists.
pub fn start_background_agent(
    account: &LocalAccount,
    password: &Password,
    exe: &Path,
    ready_name: &str,
) -> Result<StartedAgent, LogonFailure> {
    let mut command = wide(&command_line(exe, ready_name, &account.sid));
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
    let result = password.with_nul(|password| {
        // SAFETY: every pointer is to a local that outlives the call; `password` is the wiped copy.
        unsafe {
            CreateProcessWithLogonW(
                PCWSTR(user.as_ptr()),
                PCWSTR(wide(".").as_ptr()),
                PCWSTR(password.as_ptr()),
                LOGON_WITH_PROFILE,
                PCWSTR(exe_w.as_ptr()),
                Some(PWSTR(command.as_mut_ptr())),
                CREATE_NO_WINDOW,
                None,
                directory.as_ref().map_or(PCWSTR::null(), |dir| PCWSTR(dir.as_ptr())),
                &startup,
                &mut info,
            )
        }
    });
    match result {
        Ok(()) => {
            drop(OwnedHandle(info.hThread));
            Ok(StartedAgent {
                process: OwnedHandle(info.hProcess),
            })
        }
        Err(e) => Err(LogonFailure::from_error(&e)),
    }
}

/// Whether `account` may log on as a batch job, which a boot task needs. A network-less logon of the
/// batch type, closed at once: with the password in hand, Windows says `ERROR_LOGON_TYPE_NOT_GRANTED`
/// (1385) when the right is missing (spike M5(d)).
pub fn check_batch_logon(account: &LocalAccount, password: &Password) -> BatchRight {
    use windows::Win32::Foundation::HANDLE;
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
