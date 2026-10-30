//! The shape of `apply`: install, then bring agents back. Held apart from the Windows calls so
//! the failure paths can be tested with stand-ins.

use super::procwait::{StillRunning, Survivor};

/// Run `install`, then `start` the agents.
///
/// `install` receives the function that stops every agent and must call it at most once, before
/// it replaces the exe. If `install` fails after that call (or inside it, since a stop that
/// failed part-way has still stopped some agents), `start` still runs, best-effort, so a failed
/// `apply` does not leave every logged-on user without an agent. `restart_is_safe` says whether
/// the registered agent task can start one: an older single-user task cannot.
///
/// `resume_agent_task` enables the agent task and runs on every call, whatever came before: a stop
/// disables the task, and an earlier `apply` that was killed before it got here may have left it
/// so. `repair_sessions` does the same for the auto-login tasks and starts the ones with no
/// session (see [`repair_sessions`]); it too runs on every call, including a failed install and an
/// install that stopped nothing, and does not depend on the agent task or on `restart_is_safe`. If
/// the agent task cannot be enabled, no agent is started (a disabled task starts nothing); a
/// failure of `repair_sessions` does not hold the start back. Either failure is the result unless
/// `install` had already failed, in which case that error is returned as it was and the other is
/// printed.
///
/// If the stop left agents running (see [`StillRunning`], found under any context `install`
/// added), `start` is told which: an agent started in the session of a survivor would find that
/// session's slot taken and exit, leaving the session with none once the survivor dies.
pub fn run<T>(
    stop: impl FnOnce() -> anyhow::Result<()>,
    install: impl FnOnce(&mut dyn FnMut() -> anyhow::Result<()>) -> anyhow::Result<T>,
    restart_is_safe: impl FnOnce() -> bool,
    resume_agent_task: impl FnOnce() -> anyhow::Result<()>,
    repair_sessions: impl FnOnce() -> anyhow::Result<()>,
    start: impl FnOnce(&[Survivor]),
) -> anyhow::Result<T> {
    let mut stop = Some(stop);
    let mut attempted = false;
    let result = install(&mut || {
        attempted = true;
        stop.take().expect("the stop is called at most once")()
    });
    let agent_task = resume_agent_task();
    let sessions = repair_sessions();
    // A disabled agent task starts no agent, so its failure holds the start back. The auto-login
    // tasks are other tasks: their failure is reported but does not.
    let (agents_can_start, failure) = match (agent_task, sessions) {
        (Ok(()), Ok(())) => (true, None),
        (Ok(()), Err(e)) => (true, Some(e)),
        (Err(e), Ok(())) => (false, Some(e)),
        (Err(e), Err(sessions)) => {
            eprintln!("apply: {sessions:#}");
            (false, Some(e))
        }
    };
    if agents_can_start && (result.is_ok() || (attempted && restart_is_safe())) {
        let survivors = match &result {
            Err(e) => e.downcast_ref::<StillRunning>().map(|s| s.survivors.as_slice()),
            Ok(_) => None,
        };
        start(survivors.unwrap_or_default());
    }
    match (result, failure) {
        (result, None) => result,
        (Ok(_), Some(e)) => Err(e),
        (Err(install_error), Some(e)) => {
            eprintln!("apply: {e:#}");
            Err(install_error)
        }
    }
}

/// A per-user auto-login task, as `apply` finds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTask {
    pub name: String,
    pub enabled: bool,
}

/// The part of the stop that concerns background sessions: every auto-login task is disabled, then
/// each one's instances are stopped (waiting for their processes), then every background agent
/// still running is ended and waited for, whether or not a task started it (the prompt path starts
/// one without a task).
///
/// All the tasks are disabled before any is stopped, so that none restarts its session (a task
/// restarts itself when its process fails) while another is being stopped. They stay disabled for
/// the caller to copy the exe; [`repair_sessions`] enables them again, and a run that is killed
/// before that leaves them for the next `apply` to repair. The agents are looked for again after
/// each round until none is left: a condition re-checked, not an attempt count; a process that
/// outlives the bound fails the stop through `wait`, naming its pid.
///
/// Only a background agent is ended here. A shim is left alone and, if it holds the exe, the copy
/// reports it as it does today; a desktop agent that is not an instance of the logon task keeps its
/// behaviour too.
pub fn stop_sessions<P>(
    tasks: impl FnOnce() -> anyhow::Result<Vec<SessionTask>>,
    mut disable: impl FnMut(&str) -> anyhow::Result<()>,
    mut stop_task: impl FnMut(&str) -> anyhow::Result<()>,
    mut agents: impl FnMut() -> anyhow::Result<Vec<P>>,
    mut end: impl FnMut(&P) -> anyhow::Result<()>,
    mut wait: impl FnMut(Vec<P>) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let tasks = tasks()?;
    for task in &tasks {
        disable(&task.name)?;
    }
    for task in &tasks {
        stop_task(&task.name)?;
    }
    loop {
        let found = agents()?;
        if found.is_empty() {
            return Ok(());
        }
        for agent in &found {
            end(agent)?;
        }
        wait(found)?;
    }
}

/// Bring the auto-login tasks to a working state, whatever an earlier `apply` left: every task that
/// is disabled is enabled, and every task that is enabled and has no running instance is started,
/// so the users who had auto-login have their session again. A session that is running is not
/// touched.
///
/// Every task is tried. A task that cannot be enabled is not started, and the first such failure
/// is the result, naming the task (the rest are printed). A failure to ask whether a task runs, or
/// to start it, is printed and is not the result: like the start of the desktop agents, the install
/// is complete without it.
pub fn repair_sessions(
    tasks: impl FnOnce() -> anyhow::Result<Vec<SessionTask>>,
    mut enable: impl FnMut(&str) -> anyhow::Result<()>,
    mut running: impl FnMut(&str) -> anyhow::Result<bool>,
    mut run: impl FnMut(&str) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let mut first = None;
    for SessionTask { name, enabled } in tasks()? {
        if !enabled && let Err(e) = enable(&name) {
            let e = e.context(format!(
                "could not enable the {name} task again; no session starts at boot until it is"
            ));
            if first.is_none() {
                first = Some(e);
            } else {
                eprintln!("apply: {e:#}");
            }
            continue;
        }
        match running(&name) {
            Ok(true) => {}
            Ok(false) => {
                if let Err(e) = run(&name) {
                    eprintln!("apply: could not start the {name} task: {e:#}");
                }
            }
            Err(e) => {
                eprintln!("apply: could not tell whether the {name} task is running, so it was not started: {e:#}")
            }
        }
    }
    first.map_or(Ok(()), Err)
}

/// Which of the sessions with a user get an agent started, and which are left alone.
#[derive(Debug, PartialEq, Eq)]
pub struct StartPlan {
    pub start: Vec<u32>,
    /// A session left alone, with the survivors that hold it.
    pub held: Vec<(u32, Vec<u32>)>,
}

/// Split `sessions` by whether a survivor of the stop holds the session's slot. A survivor whose
/// session is unknown may hold any, so it holds every one.
pub fn plan_start(sessions: &[u32], survivors: &[Survivor]) -> StartPlan {
    let mut plan = StartPlan {
        start: Vec::new(),
        held: Vec::new(),
    };
    for &id in sessions {
        let holders: Vec<u32> = survivors
            .iter()
            .filter(|s| s.session.is_none_or(|session| session == id))
            .map(|s| s.pid)
            .collect();
        if holders.is_empty() {
            plan.start.push(id);
        } else {
            plan.held.push((id, holders));
        }
    }
    plan
}

#[cfg(test)]
#[path = "flow_tests.rs"]
mod flow_tests;
