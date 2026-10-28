//! The shape of `apply`: install, then bring agents back. Held apart from the Windows calls so
//! the failure paths can be tested with stand-ins.

use std::cell::RefCell;

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
/// so. `start_sessions` starts the auto-login tasks again; their stop does not disable them (their
/// only trigger is boot, so nothing starts one meanwhile), so there is nothing to enable. It does
/// not depend on the agent task or on `restart_is_safe`: it runs on every path, including a failed
/// install. If the agent task cannot be enabled, no agent is started (the task cannot start one),
/// and the failure is the result unless `install` had already failed, in which case that error is
/// returned as it was.
///
/// If the stop left agents running (see [`StillRunning`], found under any context `install`
/// added), `start` is told which: an agent started in the session of a survivor would find that
/// session's slot taken and exit, leaving the session with none once the survivor dies.
pub fn run<T>(
    stop: impl FnOnce() -> anyhow::Result<()>,
    install: impl FnOnce(&mut dyn FnMut() -> anyhow::Result<()>) -> anyhow::Result<T>,
    restart_is_safe: impl FnOnce() -> bool,
    resume_agent_task: impl FnOnce() -> anyhow::Result<()>,
    start_sessions: impl FnOnce(),
    start: impl FnOnce(&[Survivor]),
) -> anyhow::Result<T> {
    let mut stop = Some(stop);
    let mut attempted = false;
    let result = install(&mut || {
        attempted = true;
        stop.take().expect("the stop is called at most once")()
    });
    let agent_task = resume_agent_task();
    start_sessions();
    if let Err(e) = agent_task {
        return match result {
            Ok(_) => Err(e),
            Err(install_error) => {
                eprintln!("apply: {e:#}");
                Err(install_error)
            }
        };
    }
    if result.is_ok() || (attempted && restart_is_safe()) {
        let survivors = match &result {
            Err(e) => e.downcast_ref::<StillRunning>().map(|s| s.survivors.as_slice()),
            Ok(_) => None,
        };
        start(survivors.unwrap_or_default());
    }
    result
}

/// A per-user auto-login task, as `apply` finds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTask {
    pub name: String,
    pub enabled: bool,
}

/// The part of the stop that concerns background sessions: every auto-login task's instances are
/// stopped (waiting for their processes), then every background agent still running is ended and
/// waited for, whether or not a task started it (the prompt path starts one without a task). No
/// task is disabled: a killed `apply` leaves each exactly as it was.
///
/// `enabled` collects the names of the tasks that are **enabled**, before any is stopped, so that a
/// stop that fails part-way still gets them started again ([`start_sessions`]). A task that was off
/// stays off and is not started. The agents are looked for again after each round until none is
/// left: a condition re-checked, not an attempt count; a process that outlives the bound fails the
/// stop through `wait`, naming its pid.
///
/// Only a background agent is ended here. A shim is left alone and, if it holds the exe, the copy
/// reports it as it does today; a desktop agent that is not an instance of the logon task keeps its
/// behaviour too.
pub fn stop_sessions<P>(
    tasks: impl FnOnce() -> anyhow::Result<Vec<SessionTask>>,
    enabled: &RefCell<Vec<String>>,
    mut stop_task: impl FnMut(&str) -> anyhow::Result<()>,
    mut agents: impl FnMut() -> anyhow::Result<Vec<P>>,
    mut end: impl FnMut(&P) -> anyhow::Result<()>,
    mut wait: impl FnMut(Vec<P>) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let tasks = tasks()?;
    enabled
        .borrow_mut()
        .extend(tasks.iter().filter(|task| task.enabled).map(|task| task.name.clone()));
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

/// Start the tasks [`stop_sessions`] noted as enabled, so the users who had auto-login have their
/// session again. Best-effort, like the start of the desktop agents: the install is complete
/// without it.
pub fn start_sessions(enabled: &RefCell<Vec<String>>, mut run: impl FnMut(&str) -> anyhow::Result<()>) {
    for name in enabled.borrow().iter() {
        if let Err(e) = run(name) {
            eprintln!("apply: could not start the {name} task: {e:#}");
        }
    }
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
