//! The shape of `install`: set up, then bring agents back. Held apart from the Windows calls so
//! the failure paths can be tested with stand-ins.

use anyhow::Context;

use super::procwait::{self, StillRunning, Survivor};
use super::schtasks::{INSTALL_SSHD_TASK, WaitOutcome, end_and_remove_install_sshd_task};
use super::sshd_config::CHECK_SSHD;

/// The wait, at the start of `install` and right after its lock, for the sshd step of an earlier `install`.
///
/// The lock makes one `install` run at a time for its whole run, and an earlier `install` that was ended after its
/// hand-over has the sshd step as the rest of that run: its task's instance outlives its process, running the
/// installed exe, and ending it between its stop of sshd and its start would leave sshd stopped. So it is waited
/// for, with no bound once it has launched, before this run stops, replaces or reads anything it works on.
/// `wait` is given the function that says the wait has begun, and calls it when it finds an earlier step; it
/// returns when the instances have ended. An instance the Task Scheduler never launched stops `install`, as a
/// task that never clears does in `stop_instances`: nothing goes on beside an instance that may still start.
pub fn wait_for_earlier_sshd_step(
    say: &mut dyn FnMut(&str),
    wait: impl FnOnce(&mut dyn FnMut()) -> anyhow::Result<WaitOutcome>,
) -> anyhow::Result<()> {
    let outcome = wait(&mut || {
        say(&format!(
            "install: an earlier install's sshd step is still running (the task {INSTALL_SSHD_TASK}); waiting for it to \
             finish"
        ))
    })
    .context("wait for an earlier install's sshd step")?;
    match outcome {
        WaitOutcome::Ended => Ok(()),
        WaitOutcome::NeverLaunched { count } => anyhow::bail!(
            "the Task Scheduler lists {count} instance(s) of the task {INSTALL_SSHD_TASK} that it has not started \
             after {} s, so install went no further. End and remove the task {}; if the step has started meanwhile, \
             ending it can leave sshd stopped. {CHECK_SSHD} Then run install again",
            procwait::EXIT_BOUND.as_secs(),
            end_and_remove_install_sshd_task()
        ),
    }
}

/// Run `set_up`, then `start` the agents.
///
/// `set_up` receives the function that stops every agent and must call it at most once, before
/// it replaces the exe. If `set_up` fails after that call (or inside it, since a stop that
/// failed part-way has still stopped some agents), `start` still runs, best-effort, so a failed
/// `install` does not leave every logged-on user without an agent.
///
/// `resume_agent_task` enables the agent task and runs on every call, whatever came before: a stop
/// disables the task, and an earlier `install` that was killed before it got here may have left it
/// so. `repair_sessions` does the same for the auto-login tasks and starts the ones with no
/// session (see [`repair_sessions`]); it too runs on every call, including a failed `set_up` and a
/// `set_up` that stopped nothing, and does not depend on the agent task. If
/// the agent task cannot be enabled, no agent is started (a disabled task starts nothing); a
/// failure of `repair_sessions` does not hold the start back. Either failure is the result unless
/// `set_up` had already failed, in which case that error is returned as it was and the other is
/// printed.
///
/// If the stop left agents running (see [`StillRunning`], found under any context `set_up`
/// added), `start` is told which: an agent started in the session of a survivor would find that
/// session's slot taken and exit, leaving the session with none once the survivor dies.
pub fn run<T>(
    stop: impl FnOnce() -> anyhow::Result<()>,
    set_up: impl FnOnce(&mut dyn FnMut() -> anyhow::Result<()>) -> anyhow::Result<T>,
    resume_agent_task: impl FnOnce() -> anyhow::Result<()>,
    repair_sessions: impl FnOnce() -> anyhow::Result<()>,
    start: impl FnOnce(&[Survivor]),
) -> anyhow::Result<T> {
    let mut stop = Some(stop);
    let mut attempted = false;
    let result = set_up(&mut || {
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
            eprintln!("install: {sessions:#}");
            (false, Some(e))
        }
    };
    if agents_can_start && (result.is_ok() || attempted) {
        let survivors = match &result {
            Err(e) => e.downcast_ref::<StillRunning>().map(|s| s.survivors.as_slice()),
            Ok(_) => None,
        };
        start(survivors.unwrap_or_default());
    }
    match (result, failure) {
        (result, None) => result,
        (Ok(_), Some(e)) => Err(e),
        (Err(set_up_error), Some(e)) => {
            eprintln!("install: {e:#}");
            Err(set_up_error)
        }
    }
}

/// A per-user auto-login task, as `install` finds it.
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
/// before that leaves them for the next `install` to repair. The agents are looked for again after
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

/// Bring the auto-login tasks to a working state, whatever an earlier `install` left: every task that
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
                eprintln!("install: {e:#}");
            }
            continue;
        }
        match running(&name) {
            Ok(true) => {}
            Ok(false) => {
                if let Err(e) = run(&name) {
                    eprintln!("install: could not start the {name} task: {e:#}");
                }
            }
            Err(e) => {
                eprintln!("install: could not tell whether the {name} task is running, so it was not started: {e:#}")
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
