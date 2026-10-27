//! Ending the background session of an account that a service logged on, the way the product does.
//! **CI only.**
//!
//! A test ends such a session with `logout`, run inside the agent as the account, and checks what
//! ssh-broker controls: its agents ended, every process of their logon sessions exited, and `logout`
//! exited 0. It does not ask Windows to unload the account's hive or to delete its profile: Windows keeps
//! the hive of a Task Scheduler or sshd logon loaded (CI rounds 19 and 20), as it does for a user who
//! logged in at the console (owner, 2026-10-27). Killing the account's processes (`Account::drop`) is the
//! fallback, and every use of it is recorded.
//!
//! The logoff of a session (Security 4634) is waited for. It comes for a secondary-logon session and for
//! most Task Scheduler Batch sessions; where Windows keeps a Batch session with no process left it is not a
//! failure here, and `tests/auto_login_windows.rs` measures that such sessions do not pile up.
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

use crate::account_fixture::{Account, ServiceLogon, hive, profile};
use crate::agent_conn::AgentConn;
use crate::bounded_wait::CHILD_EXIT_BOUND;
use crate::logon_session::{self, LogoffWatch};

/// How long Windows may take to write the logoff event after the last process of a session has ended: an
/// external event that may never come. Expiry fails the wait and says what was measured.
pub const LOGOFF_EVENT_BOUND: Duration = Duration::from_secs(180);

/// What ending a session found.
#[derive(Debug)]
pub struct Ended {
    /// The logon sessions of the agents whose logoff (4634) was seen. Windows has destroyed these, whatever
    /// LSA still lists for a moment.
    pub logged_off: BTreeSet<u64>,
}

/// Ask the background agent of `account` (the one running `exe`) to end with `exe logout`, run inside the
/// agent as the account, wait for every process of its logon session to exit and for the session's logoff.
/// `how` is how the test started the session; the account is declared as logged on that way. `Ok(Some)` when
/// a session was ended; `Ok(None)` when the account has no agent running `exe`. A failure names the step. It
/// does not kill anything: the caller decides what the fallback is. One line about the attempt goes to the
/// measurement file, pass or fail.
pub fn log_out(exe: &Path, account: &Account, how: ServiceLogon) -> Result<Option<Ended>, String> {
    account.started_by(how);
    match account.try_profile() {
        Some(profile) => end(
            "log_out",
            exe,
            &account.name,
            &account.sid,
            &account.sid_text,
            profile,
            how,
        ),
        None => {
            hive::record(&format!(
                "session end [log_out] {} ({}): the account has no profile, so no agent to end",
                account.name, account.sid_text
            ));
            Ok(None)
        }
    }
}

/// Ends the background session of an account when dropped, passing or failing. Declare it after the
/// account, so that it drops first. If the logout fails the account's processes are killed by the
/// account's own drop instead, and the failure is recorded. Creating it declares how the test starts the
/// account's session (`how`, see [`Account::started_by`]).
pub struct LogOutOnDrop {
    exe: PathBuf,
    how: ServiceLogon,
    name: String,
    sid: Sid,
    sid_text: String,
    profile: Option<PathBuf>,
}

impl LogOutOnDrop {
    pub fn new(exe: &Path, account: &Account, how: ServiceLogon) -> LogOutOnDrop {
        account.started_by(how);
        LogOutOnDrop {
            exe: exe.to_owned(),
            how,
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
        if let Err(why) = end(
            "drop",
            &self.exe,
            &self.name,
            &self.sid,
            &self.sid_text,
            profile,
            self.how,
        ) {
            hive::record(&format!(
                "the logout of {} failed ({why}); its processes are ended by killing them instead",
                self.name
            ));
        }
    }
}

/// [`try_end`], with one line in the measurement file saying what each step found and where the hive is. A
/// panic of a step (this runs in a drop, while a failed test may unwind) is an error.
fn end(
    who: &str,
    exe: &Path,
    name: &str,
    sid: &Sid,
    sid_text: &str,
    profile: &Path,
    how: ServiceLogon,
) -> Result<Option<Ended>, String> {
    let mut steps = Vec::new();
    let outcome = attempt("end the session", || try_end(exe, name, sid, profile, how, &mut steps)).and_then(|r| r);
    hive::record(&format!(
        "session end [{who}] {name} ({sid_text}), logged on by {how}: {}; hive now (not required to unload after a \
         {how} logon): {}; result: {}",
        steps.join("; "),
        profile::hive_state(sid_text),
        match &outcome {
            Ok(Some(_)) => "a session was ended".to_owned(),
            Ok(None) => "no agent to end".to_owned(),
            Err(why) => format!("failed: {why}"),
        }
    ));
    outcome
}

/// The steps of ending the session; each fact is pushed to `steps` as soon as it is known, so a step that
/// fails leaves the ones before it.
fn try_end(
    exe: &Path,
    name: &str,
    sid: &Sid,
    profile: &Path,
    how: ServiceLogon,
    steps: &mut Vec<String>,
) -> Result<Option<Ended>, String> {
    let agents = procwait::user_agents(exe, sid).map_err(|e| format!("look for the agents of {name}: {e:#}"))?;
    steps.push(format!(
        "agents running {}: {} (pids {:?})",
        exe.display(),
        agents.len(),
        agents.iter().map(|agent| agent.pid).collect::<Vec<_>>()
    ));
    if agents.is_empty() {
        return Ok(None);
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
    let left = procwait::user_agents(exe, sid).map_err(|e| format!("look again for the agents of {name}: {e:#}"))?;
    if !left.is_empty() {
        return Err(format!(
            "{} agent(s) of {name} running {} after logout (pids {:?})",
            left.len(),
            exe.display(),
            left.iter().map(|agent| agent.pid).collect::<Vec<_>>()
        ));
    }
    steps.push("no agent left".to_owned());
    let mut logged_off = BTreeSet::new();
    let mut missing = Vec::new();
    for (id, watch) in &watches {
        let seen = watch.wait(LOGOFF_EVENT_BOUND);
        steps.push(format!("4634 for {id:#x}: {}", if seen { "seen" } else { "not seen" }));
        if seen {
            logged_off.insert(*id);
        } else {
            missing.push(format!("{id:#x}"));
        }
    }
    if missing.is_empty() {
        return Ok(Some(Ended { logged_off }));
    }
    match how {
        // Windows keeps some Batch sessions of Task Scheduler with no process left (CI round 20). Whether
        // they pile up is measured by `tests/auto_login_windows.rs`; here it is recorded.
        ServiceLogon::TaskScheduler => {
            steps.push(format!(
                "logon session(s) {} stay with no process left, which Windows does at times for a Batch logon",
                missing.join(", ")
            ));
            Ok(Some(Ended { logged_off }))
        }
        ServiceLogon::Sshd => Err(format!(
            "logon session(s) {} of {name} still present: no 4634 within {LOGOFF_EVENT_BOUND:?} although every \
             process of them has ended",
            missing.join(", ")
        )),
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
