//! Ending an account's background session the way the product does, and waiting for Windows to destroy
//! its logon session. **CI only.**
//!
//! CI rounds 16 and 17: the hive of a profile stayed loaded after a test ended the account's session by
//! killing its processes, when a service had made the logon (Task Scheduler's stored-password task, sshd).
//! A session ended by the product's own `logout` and its logoff (Security 4634) leaves the profile
//! unloaded. So a test ends the session with `logout`, run inside the agent as the account, and waits for
//! the logoff; killing the account's processes (`Account::drop`) is the fallback, and every use of it is
//! recorded.
//!
//! The including crate declares `account_fixture`, `agent_conn`, `bounded_wait` and `logon_session`.
#![allow(dead_code)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ssh_broker::acl::Sid;
use ssh_broker::provision::procwait;
use ssh_broker::socket_loc;
use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
use windows::Win32::System::Threading::WaitForSingleObject;

use crate::account_fixture::{Account, hive};
use crate::agent_conn::AgentConn;
use crate::bounded_wait::CHILD_EXIT_BOUND;
use crate::logon_session::{self, LogoffWatch};

/// How long Windows may take to write the logoff event after the last process of a session has ended: an
/// external event that may never come. Expiry fails the wait and says what was measured.
pub const LOGOFF_EVENT_BOUND: Duration = Duration::from_secs(180);

/// Ask the background agent of `account` (the one running `exe`) to end with `exe logout`, run inside the
/// agent as the account, wait for every process of its logon session to exit, then for the session's
/// logoff. `Ok(true)` when a session was ended; `Ok(false)` when the account has no agent running `exe`.
/// A failure names the step. It does not kill anything: the caller decides what the fallback is.
pub fn log_out(exe: &Path, account: &Account) -> Result<bool, String> {
    match account.try_profile() {
        Some(profile) => attempt("end the session", || try_end(exe, &account.name, &account.sid, profile))?,
        None => Ok(false),
    }
}

/// Ends the background session of an account when dropped, passing or failing. Declare it after the
/// account, so that it drops first. If the logout fails the account's processes are killed by the
/// account's own drop instead, and the failure is recorded.
pub struct LogOutOnDrop {
    exe: PathBuf,
    name: String,
    sid: Sid,
    profile: Option<PathBuf>,
}

impl LogOutOnDrop {
    pub fn new(exe: &Path, account: &Account) -> LogOutOnDrop {
        LogOutOnDrop {
            exe: exe.to_owned(),
            name: account.name.clone(),
            sid: Sid::lookup(&account.name).expect("look up the account's SID"),
            profile: account.try_profile().map(Path::to_owned),
        }
    }
}

impl Drop for LogOutOnDrop {
    fn drop(&mut self) {
        let Some(profile) = &self.profile else { return };
        // A panic here, while a failed test unwinds, would abort the test process.
        let ended = attempt("end the session", || try_end(&self.exe, &self.name, &self.sid, profile)).and_then(|r| r);
        if let Err(why) = ended {
            hive::record(&format!(
                "the logout of {} failed ({why}); its processes are ended by killing them instead",
                self.name
            ));
        }
    }
}

fn try_end(exe: &Path, name: &str, sid: &Sid, profile: &Path) -> Result<bool, String> {
    let agents = procwait::user_agents(exe, sid).map_err(|e| format!("look for the agents of {name}: {e:#}"))?;
    if agents.is_empty() {
        return Ok(false);
    }
    logon_session::assert_logoff_auditing();
    let ids: BTreeSet<u64> = agents
        .iter()
        .map(|agent| logon_session::logon_id(agent.handle()))
        .collect();
    // Subscribed before the logout runs, so the event cannot be missed.
    let watches: Vec<(u64, LogoffWatch)> = ids.iter().map(|id| (*id, LogoffWatch::new(*id))).collect();
    let own = std::process::id();
    let held: Vec<_> = ids
        .iter()
        .flat_map(|id| logon_session::processes_of(*id))
        .filter(|(pid, _)| *pid != own)
        .collect();

    let location = socket_loc::for_profile(profile).map_err(|e| e.to_string())?;
    let finished = attempt("ask the agent to log out", || {
        let mut asker = AgentConn::connect(&location);
        asker.start_exec(&format!("\"{}\" logout", exe.display()));
        asker.end_stdin();
        asker.read_to_end()
    })?;
    if finished.exit != Some(0) {
        return Err(format!(
            "logout exited with {:?}; stderr: {}",
            finished.exit, finished.stderr
        ));
    }
    for (pid, process) in &held {
        wait_exited(process.0, *pid, name)?;
    }
    // A handle on a process keeps its token, and so the logon session, alive.
    drop(held);
    drop(agents);
    for (id, watch) in &watches {
        if !watch.wait(LOGOFF_EVENT_BOUND) {
            return Err(format!(
                "logon session {id:#x} of {name} still present: no 4634 within {LOGOFF_EVENT_BOUND:?} although every \
                 process of it has ended"
            ));
        }
    }
    Ok(true)
}

/// Wait for `process` to exit, up to [`CHILD_EXIT_BOUND`]: an exit that may never come.
fn wait_exited(process: HANDLE, pid: u32, name: &str) -> Result<(), String> {
    let millis = u32::try_from(CHILD_EXIT_BOUND.as_millis()).expect("a bound shorter than INFINITE");
    // SAFETY: a live process handle with SYNCHRONIZE access, held by the caller.
    let rc = unsafe { WaitForSingleObject(process, millis) }; // sleep-ok: failure bound on a process's exit, an external event; expiry is reported and is not read as state
    if rc == WAIT_OBJECT_0 {
        Ok(())
    } else {
        Err(format!(
            "process {pid} of {name} was still running {CHILD_EXIT_BOUND:?} after logout ({rc:?})"
        ))
    }
}

/// Run `step`, turning a panic into an error that names `what`.
fn attempt<T>(what: &str, step: impl FnOnce() -> T) -> Result<T, String> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(step)).map_err(|payload| {
        let text = payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|text| (*text).to_owned()))
            .unwrap_or_else(|| "a panic with no text".to_owned());
        format!("{what}: {text}")
    })
}
