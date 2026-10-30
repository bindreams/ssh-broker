use super::*;
use anyhow::Context;
use std::cell::RefCell;

/// Run the flow with an `install` that stops (or not) and then fails (or not); return the
/// events in order and the result.
fn flow(
    stops: bool,
    stop_result: fn() -> anyhow::Result<()>,
    install_ok: bool,
    safe: bool,
) -> (Vec<&'static str>, anyhow::Result<()>) {
    flow_resuming(stops, stop_result, install_ok, safe, || Ok(()), || Ok(()))
}

/// [`flow`] with the outcome of enabling the agent task again and of repairing the auto-login
/// tasks chosen too.
fn flow_resuming(
    stops: bool,
    stop_result: fn() -> anyhow::Result<()>,
    install_ok: bool,
    safe: bool,
    resume_result: fn() -> anyhow::Result<()>,
    repair_result: fn() -> anyhow::Result<()>,
) -> (Vec<&'static str>, anyhow::Result<()>) {
    let events = RefCell::new(Vec::new());
    let result = run(
        || {
            events.borrow_mut().push("stop");
            stop_result()
        },
        |stop| {
            if stops {
                stop()?;
            }
            events.borrow_mut().push("install");
            anyhow::ensure!(install_ok, "register failed");
            Ok(())
        },
        || {
            events.borrow_mut().push("safe?");
            safe
        },
        || {
            events.borrow_mut().push("resume");
            resume_result()
        },
        || {
            events.borrow_mut().push("repair sessions");
            repair_result()
        },
        |left| {
            events.borrow_mut().push("start");
            assert!(left.is_empty(), "no agent survived");
        },
    );
    (events.into_inner(), result)
}

#[test]
fn agents_start_after_a_successful_install() {
    let (events, result) = flow(true, || Ok(()), true, true);
    result.unwrap();
    assert_eq!(events, ["stop", "install", "resume", "repair sessions", "start"]);
}

#[test]
fn agents_that_were_stopped_start_again_when_a_later_step_fails() {
    let (events, result) = flow(true, || Ok(()), false, true);
    assert_eq!(format!("{:#}", result.unwrap_err()), "register failed");
    assert_eq!(
        events,
        ["stop", "install", "resume", "repair sessions", "safe?", "start"]
    );
}

#[test]
fn agents_survive_a_failed_stop_in_the_sessions_the_start_is_told_to_leave_alone() {
    use crate::provision::procwait::{StillRunning, Survivor};
    let left = vec![Survivor {
        pid: 5,
        session: Some(2),
        unconfirmed: None,
    }];
    let told = RefCell::new(Vec::new());
    let result = run(
        || Err(StillRunning::new(left.clone(), std::time::Duration::from_secs(60)).into()),
        |stop| {
            stop().context("stop the running agents")?;
            Ok(())
        },
        || true,
        || Ok(()),
        || Ok(()),
        |survivors| told.borrow_mut().extend_from_slice(survivors),
    );
    let text = format!("{:#}", result.unwrap_err());
    assert!(text.contains("process 5 did not exit"), "{text}");
    assert!(text.contains("run apply again"), "{text}");
    assert_eq!(
        told.into_inner(),
        left,
        "the start hears who is still running, through the context"
    );
}

#[test]
fn agents_start_again_when_the_stop_failed_part_way() {
    let (events, result) = flow(true, || anyhow::bail!("access denied"), true, true);
    assert_eq!(format!("{:#}", result.unwrap_err()), "access denied");
    assert_eq!(events, ["stop", "resume", "repair sessions", "safe?", "start"]);
}

#[test]
fn no_agent_starts_when_none_was_stopped() {
    let (events, result) = flow(false, || Ok(()), false, true);
    assert!(result.is_err());
    assert_eq!(events, ["install", "resume", "repair sessions"]);
}

#[test]
fn the_task_is_enabled_again_even_when_no_agent_was_stopped() {
    // The exe may be unchanged and nothing stopped, and the task still disabled by an earlier
    // `apply` that was killed between its disable and its enable.
    let (events, result) = flow(false, || Ok(()), true, true);
    result.unwrap();
    assert_eq!(events, ["install", "resume", "repair sessions", "start"]);
}

#[test]
fn an_apply_that_could_not_enable_the_task_fails_and_starts_no_agent() {
    // A disabled task starts no agent at any logon, so the install did not take.
    let (events, result) = flow_resuming(
        true,
        || Ok(()),
        true,
        true,
        || anyhow::bail!("access denied"),
        || Ok(()),
    );
    assert!(format!("{:#}", result.unwrap_err()).contains("access denied"));
    assert_eq!(
        events,
        ["stop", "install", "resume", "repair sessions"],
        "the sessions are independent of the agent task"
    );
}

#[test]
fn a_failed_install_is_reported_as_it_was_when_the_task_could_not_be_enabled_either() {
    let (events, result) = flow_resuming(
        true,
        || Ok(()),
        false,
        true,
        || anyhow::bail!("access denied"),
        || Ok(()),
    );
    assert_eq!(format!("{:#}", result.unwrap_err()), "register failed");
    assert_eq!(
        events,
        ["stop", "install", "resume", "repair sessions"],
        "no agent start: the task cannot start one"
    );
}

#[test]
fn an_apply_that_could_not_enable_a_session_task_fails_but_still_starts_the_agents() {
    // A disabled auto-login task starts no session at boot, so the install did not take; the desktop
    // agent is a different task and its start does not wait on that.
    let (events, result) = flow_resuming(true, || Ok(()), true, true, || Ok(()), || anyhow::bail!("task denied"));
    assert!(format!("{:#}", result.unwrap_err()).contains("task denied"));
    assert_eq!(events, ["stop", "install", "resume", "repair sessions", "start"]);
}

#[test]
fn a_failed_install_is_reported_as_it_was_when_a_session_task_could_not_be_enabled_either() {
    let (events, result) = flow_resuming(true, || Ok(()), false, true, || Ok(()), || anyhow::bail!("task denied"));
    assert_eq!(format!("{:#}", result.unwrap_err()), "register failed");
    assert_eq!(
        events,
        ["stop", "install", "resume", "repair sessions", "safe?", "start"],
        "the agents that were stopped start again, as after any failed install"
    );
}

#[test]
fn the_agent_task_failure_is_the_result_when_a_session_task_could_not_be_enabled_either() {
    let (events, result) = flow_resuming(
        true,
        || Ok(()),
        true,
        true,
        || anyhow::bail!("agent denied"),
        || anyhow::bail!("task denied"),
    );
    assert!(format!("{:#}", result.unwrap_err()).contains("agent denied"));
    assert_eq!(events, ["stop", "install", "resume", "repair sessions"]);
}

#[test]
fn no_agent_starts_when_the_registered_task_cannot_start_one() {
    let (events, result) = flow(true, || Ok(()), false, false);
    assert!(result.is_err());
    assert_eq!(events, ["stop", "install", "resume", "repair sessions", "safe?"]);
}

#[test]
fn the_task_is_enabled_again_even_when_no_agent_can_be_restarted() {
    // The stop left the logon task disabled. Leaving it so after a failed apply would mean no
    // agent at the next logon, whatever the registered form.
    let (events, _) = flow(true, || Ok(()), false, false);
    assert!(events.contains(&"resume"), "{events:?}");
}

#[test]
fn a_session_whose_old_agent_survived_gets_no_new_one() {
    use crate::provision::procwait::Survivor;
    let survivors = [
        Survivor {
            pid: 5,
            session: Some(2),
            unconfirmed: None,
        },
        Survivor {
            pid: 6,
            session: Some(2),
            unconfirmed: None,
        },
    ];
    let plan = plan_start(&[1, 2, 3], &survivors);
    assert_eq!(plan.start, [1, 3]);
    assert_eq!(plan.held, [(2, vec![5, 6])]);
}

#[test]
fn a_survivor_in_an_unknown_session_holds_every_session() {
    use crate::provision::procwait::Survivor;
    let plan = plan_start(
        &[1, 2],
        &[Survivor {
            pid: 9,
            session: None,
            unconfirmed: None,
        }],
    );
    assert!(plan.start.is_empty());
    assert_eq!(plan.held, [(1, vec![9]), (2, vec![9])]);
}

#[test]
fn every_session_starts_when_nothing_survived() {
    let plan = plan_start(&[1, 2], &[]);
    assert_eq!(plan.start, [1, 2]);
    assert!(plan.held.is_empty());
}

// session tasks and background agents -----

use crate::provision::procwait::{StillRunning, Survivor};
use std::time::Duration;

fn task(name: &str, enabled: bool) -> SessionTask {
    SessionTask {
        name: name.into(),
        enabled,
    }
}

/// `stop_sessions` over a fake machine: the tasks listed, the agents running (a pid each), and a
/// record of every call. The wait fails with a survivor when `survivor` names one.
struct World {
    tasks: Vec<SessionTask>,
    agents: RefCell<Vec<u32>>,
    survivor: Option<u32>,
    /// The name of a task whose disabling fails.
    undisablable: Option<&'static str>,
    events: RefCell<Vec<String>>,
}

impl World {
    fn new(tasks: Vec<SessionTask>, agents: Vec<u32>) -> World {
        World {
            tasks,
            agents: RefCell::new(agents),
            survivor: None,
            undisablable: None,
            events: RefCell::default(),
        }
    }

    fn stop(&self) -> anyhow::Result<()> {
        stop_sessions(
            || Ok(self.tasks.iter().map(|t| task(&t.name, t.enabled)).collect()),
            |name| {
                self.events.borrow_mut().push(format!("disable {name}"));
                anyhow::ensure!(self.undisablable != Some(name), "cannot disable {name}");
                Ok(())
            },
            |name| {
                self.events.borrow_mut().push(format!("stop task {name}"));
                Ok(())
            },
            || Ok(self.agents.borrow().clone()),
            |pid| {
                self.events.borrow_mut().push(format!("end {pid}"));
                Ok(())
            },
            |pids| {
                self.events.borrow_mut().push(format!("wait {pids:?}"));
                self.agents.borrow_mut().retain(|pid| !pids.contains(pid));
                match self.survivor {
                    Some(pid) => Err(StillRunning::new(
                        vec![Survivor {
                            pid,
                            session: Some(0),
                            unconfirmed: None,
                        }],
                        Duration::from_secs(60),
                    )
                    .into()),
                    None => Ok(()),
                }
            },
        )
    }
}

#[test]
fn a_background_agent_that_is_not_a_task_instance_is_ended() {
    let world = World::new(vec![], vec![4242]);
    world.stop().unwrap();
    assert_eq!(*world.events.borrow(), ["end 4242", "wait [4242]"]);
}

#[test]
fn every_session_task_is_disabled_before_any_is_stopped_and_before_an_agent_is_ended() {
    // A task that is still enabled when another is stopped can start its session again (its
    // restart-on-failure does), so all are disabled first, the ones that are off already too.
    let world = World::new(vec![task("a", true), task("b", false), task("c", true)], vec![7]);
    world.stop().unwrap();
    assert_eq!(
        *world.events.borrow(),
        [
            "disable a",
            "disable b",
            "disable c",
            "stop task a",
            "stop task b",
            "stop task c",
            "end 7",
            "wait [7]"
        ]
    );
}

#[test]
fn nothing_is_stopped_when_a_task_cannot_be_disabled() {
    let mut world = World::new(vec![task("a", true), task("b", true)], vec![7]);
    world.undisablable = Some("b");
    let text = format!("{:#}", world.stop().unwrap_err());
    assert!(text.contains("cannot disable b"), "{text}");
    assert_eq!(*world.events.borrow(), ["disable a", "disable b"]);
}

#[test]
fn the_agents_are_looked_for_again_until_none_is_left() {
    // An agent started by a task between the look and the end shows up on the next look.
    let looks = RefCell::new(vec![vec![1], vec![2], vec![]].into_iter());
    let ended = RefCell::new(Vec::new());
    stop_sessions(
        || Ok(vec![]),
        |_| Ok(()),
        |_| Ok(()),
        || Ok(looks.borrow_mut().next().unwrap()),
        |pid| {
            ended.borrow_mut().push(*pid);
            Ok(())
        },
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(ended.into_inner(), [1, 2]);
}

#[test]
fn background_agent_survivor_blocks_the_copy_with_its_pid() {
    let mut world = World::new(vec![], vec![4242]);
    world.survivor = Some(4242);
    let text = format!("{:#}", world.stop().unwrap_err());
    assert!(text.contains("process 4242"), "{text}");
    assert!(text.contains("run apply again"), "{text}");
}

// repairing the session tasks -----

/// The auto-login tasks as the machine has them, each with its name, whether it is enabled and
/// whether an instance is running.
struct Machine {
    tasks: Vec<(&'static str, bool, bool)>,
    /// The name of a task whose enabling fails, and of one whose start fails.
    unenablable: Option<&'static str>,
    unstartable: Option<&'static str>,
    events: RefCell<Vec<String>>,
}

impl Machine {
    fn new(tasks: Vec<(&'static str, bool, bool)>) -> Machine {
        Machine {
            tasks,
            unenablable: None,
            unstartable: None,
            events: RefCell::default(),
        }
    }

    fn repair(&self) -> anyhow::Result<()> {
        repair_sessions(
            || {
                Ok(self
                    .tasks
                    .iter()
                    .map(|&(name, enabled, _)| task(name, enabled))
                    .collect())
            },
            |name| {
                self.events.borrow_mut().push(format!("enable {name}"));
                anyhow::ensure!(self.unenablable != Some(name), "access denied");
                Ok(())
            },
            |name| {
                self.events.borrow_mut().push(format!("running? {name}"));
                Ok(self.tasks.iter().any(|&(n, _, running)| n == name && running))
            },
            |name| {
                self.events.borrow_mut().push(format!("run {name}"));
                anyhow::ensure!(self.unstartable != Some(name), "no such task");
                Ok(())
            },
        )
    }
}

#[test]
fn a_disabled_session_task_is_enabled_and_then_started() {
    // The state a killed `apply` leaves, or a task disabled by hand.
    let machine = Machine::new(vec![("a", false, false)]);
    machine.repair().unwrap();
    assert_eq!(*machine.events.borrow(), ["enable a", "running? a", "run a"]);
}

#[test]
fn an_enabled_session_task_with_no_instance_is_started() {
    let machine = Machine::new(vec![("a", true, false)]);
    machine.repair().unwrap();
    assert_eq!(*machine.events.borrow(), ["running? a", "run a"]);
}

#[test]
fn an_enabled_session_task_with_a_running_instance_is_left_as_it_is() {
    // Repairing is not restarting: a session that is up is not touched.
    let machine = Machine::new(vec![("a", true, true), ("b", true, false)]);
    machine.repair().unwrap();
    assert_eq!(*machine.events.borrow(), ["running? a", "running? b", "run b"]);
}

#[test]
fn a_task_that_cannot_be_enabled_is_not_started_and_the_others_are_repaired() {
    let mut machine = Machine::new(vec![("a", false, false), ("b", false, false)]);
    machine.unenablable = Some("a");
    let text = format!("{:#}", machine.repair().unwrap_err());
    assert!(text.contains("could not enable the a task again"), "{text}");
    assert!(text.contains("access denied"), "{text}");
    assert_eq!(
        *machine.events.borrow(),
        ["enable a", "enable b", "running? b", "run b"]
    );
}

#[test]
fn a_task_that_cannot_be_started_does_not_fail_the_repair_or_hold_back_the_others() {
    let mut machine = Machine::new(vec![("a", true, false), ("b", true, false)]);
    machine.unstartable = Some("a");
    machine.repair().unwrap();
    assert_eq!(*machine.events.borrow(), ["running? a", "run a", "running? b", "run b"]);
}

#[test]
fn a_listing_of_the_tasks_that_fails_is_the_result() {
    let result = repair_sessions(
        || anyhow::bail!("service unreachable"),
        |_| Ok(()),
        |_| Ok(false),
        |_| Ok(()),
    );
    assert!(format!("{:#}", result.unwrap_err()).contains("service unreachable"));
}

#[test]
fn session_tasks_are_repaired_after_a_failed_install_whatever_the_agent_task_is() {
    // The agent task's form decides whether the desktop agents restart; the session tasks do not
    // depend on it, so a failed query of it (`restart_is_safe` false) must not leave them stopped
    // or disabled.
    let world = World::new(vec![task("a", true), task("b", false)], vec![]);
    let machine = Machine::new(vec![("a", false, false), ("b", false, false)]);
    let agents_started = RefCell::new(false);
    let result: anyhow::Result<()> = run(
        || world.stop(),
        |stop| {
            stop()?;
            anyhow::bail!("register failed")
        },
        || false,
        || Ok(()),
        || machine.repair(),
        |_| *agents_started.borrow_mut() = true,
    );
    assert_eq!(format!("{:#}", result.unwrap_err()), "register failed");
    assert_eq!(
        *machine.events.borrow(),
        ["enable a", "running? a", "run a", "enable b", "running? b", "run b"],
        "both are enabled and started again, including the one that was off"
    );
    assert!(
        !agents_started.into_inner(),
        "the desktop agents are not, by their own rule"
    );
}
