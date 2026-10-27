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

use crate::account_fixture::{Account, hive, profile};
use crate::agent_conn::AgentConn;
use crate::bounded_wait::CHILD_EXIT_BOUND;
use crate::logon_session::{self, LogoffWatch};

/// How long Windows may take to write the logoff event after the last process of a session has ended: an
/// external event that may never come. Expiry fails the wait and says what was measured.
pub const LOGOFF_EVENT_BOUND: Duration = Duration::from_secs(180);

/// Ask the background agent of `account` (the one running `exe`) to end with `exe logout`, run inside the
/// agent as the account, wait for every process of its logon session to exit, then for the session's
/// logoff and for the account's hive to unload. `Ok(true)` when a session was ended; `Ok(false)` when the
/// account has no agent running `exe`. A failure names the step. It does not kill anything: the caller
/// decides what the fallback is. One line about the attempt goes to the measurement file, pass or fail.
pub fn log_out(exe: &Path, account: &Account) -> Result<bool, String> {
    match account.try_profile() {
        Some(profile) => end("log_out", exe, &account.name, &account.sid, &account.sid_text, profile),
        None => {
            hive::record(&format!(
                "session end [log_out] {} ({}): the account has no profile, so no agent to end",
                account.name, account.sid_text
            ));
            Ok(false)
        }
    }
}

/// Ends the background session of an account when dropped, passing or failing. Declare it after the
/// account, so that it drops first. If the logout fails the account's processes are killed by the
/// account's own drop instead, and the failure is recorded.
pub struct LogOutOnDrop {
    exe: PathBuf,
    name: String,
    sid: Sid,
    sid_text: String,
    profile: Option<PathBuf>,
}

impl LogOutOnDrop {
    pub fn new(exe: &Path, account: &Account) -> LogOutOnDrop {
        LogOutOnDrop {
            exe: exe.to_owned(),
            name: account.name.clone(),
            sid: Sid::lookup(&account.name).expect("look up the account's SID"),
            sid_text: account.sid_text.clone(),
            profile: account.try_profile().map(Path::to_owned),
        }
    }
}

impl Drop for LogOutOnDrop {
    fn drop(&mut self) {
        let Some(profile) = &self.profile else {
            hive::record(&format!(
                "session end [drop] {} ({}): the account has no profile, so no agent to end",
                self.name, self.sid_text
            ));
            return;
        };
        if let Err(why) = end("drop", &self.exe, &self.name, &self.sid, &self.sid_text, profile) {
            hive::record(&format!(
                "the logout of {} failed ({why}); its processes are ended by killing them instead",
                self.name
            ));
        }
    }
}

/// [`try_end`], then the wait for the hive to unload, with one line in the measurement file saying what each
/// step found. A panic of a step (this runs in a drop, while a failed test may unwind) is an error.
fn end(who: &str, exe: &Path, name: &str, sid: &Sid, sid_text: &str, profile: &Path) -> Result<bool, String> {
    let mut steps = Vec::new();
    let ended = attempt("end the session", || try_end(exe, name, sid, profile, &mut steps)).and_then(|r| r);
    // Always looked at, so that the line says where the hive is whatever the steps before did.
    let unloaded = profile::wait_unloaded(sid_text);
    let outcome = match (&ended, &unloaded) {
        (Ok(true), Err(why)) => Err(format!("the hive of {name} did not unload after the logoff: {why}")),
        (Ok(ended), _) => Ok(*ended),
        (Err(why), _) => Err(why.clone()),
    };
    let hive_text = match &unloaded {
        Ok(unload) => unload.to_string(),
        Err(why) => why.clone(),
    };
    hive::record(&format!(
        "session end [{who}] {name} ({sid_text}): {}; hive: {hive_text}; result: {}",
        steps.join("; "),
        match &outcome {
            Ok(true) => "a session was ended".to_owned(),
            Ok(false) => "no agent to end".to_owned(),
            Err(why) => format!("failed: {why}"),
        }
    ));
    outcome
}

/// The steps of ending the session; each fact is pushed to `steps` as soon as it is known, so a step that
/// fails leaves the ones before it.
fn try_end(exe: &Path, name: &str, sid: &Sid, profile: &Path, steps: &mut Vec<String>) -> Result<bool, String> {
    let agents = procwait::user_agents(exe, sid).map_err(|e| format!("look for the agents of {name}: {e:#}"))?;
    steps.push(format!(
        "agents running {}: {} (pids {:?})",
        exe.display(),
        agents.len(),
        agents.iter().map(|agent| agent.pid).collect::<Vec<_>>()
    ));
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
    steps.push(format!(
        "logon sessions {:?}, {} other process(es) in them",
        ids.iter().map(|id| format!("{id:#x}")).collect::<Vec<_>>(),
        held.len()
    ));

    let location = socket_loc::for_profile(profile).map_err(|e| e.to_string())?;
    let finished = attempt("ask the agent to log out", || {
        let mut asker = AgentConn::connect(&location);
        asker.start_exec(&format!("\"{}\" logout", exe.display()));
        asker.end_stdin();
        asker.read_to_end()
    })?;
    steps.push(format!("logout exit {:?}", finished.exit));
    if finished.exit != Some(0) {
        return Err(format!(
            "logout exited with {:?}; stderr: {}",
            finished.exit, finished.stderr
        ));
    }
    for (pid, process) in &held {
        wait_exited(process.0, *pid, name)?;
    }
    steps.push("every process of the sessions exited".to_owned());
    // A handle on a process keeps its token, and so the logon session, alive.
    drop(held);
    drop(agents);
    let mut missing = Vec::new();
    for (id, watch) in &watches {
        let seen = watch.wait(LOGOFF_EVENT_BOUND);
        steps.push(format!("4634 for {id:#x}: {}", if seen { "seen" } else { "not seen" }));
        if !seen {
            missing.push(format!("{id:#x}"));
        }
    }
    if missing.is_empty() {
        Ok(true)
    } else {
        Err(format!(
            "logon session(s) {} of {name} still present: no 4634 within {LOGOFF_EVENT_BOUND:?} although every \
             process of them has ended",
            missing.join(", ")
        ))
    }
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
