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
    flow_resuming(stops, stop_result, install_ok, safe, || Ok(()))
}

/// [`flow`] with the outcome of enabling the task again chosen too.
fn flow_resuming(
    stops: bool,
    stop_result: fn() -> anyhow::Result<()>,
    install_ok: bool,
    safe: bool,
    resume_result: fn() -> anyhow::Result<()>,
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
            events.borrow_mut().push("resume sessions");
            Ok(())
        },
        || events.borrow_mut().push("start sessions"),
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
    assert_eq!(events, ["stop", "install", "resume", "resume sessions", "start sessions", "start"]);
}

#[test]
fn agents_that_were_stopped_start_again_when_a_later_step_fails() {
    let (events, result) = flow(true, || Ok(()), false, true);
    assert_eq!(format!("{:#}", result.unwrap_err()), "register failed");
    assert_eq!(events, ["stop", "install", "resume", "resume sessions", "start sessions", "safe?", "start"]);
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
        || {},
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
    assert_eq!(events, ["stop", "resume", "resume sessions", "start sessions", "safe?", "start"]);
}

#[test]
fn no_agent_starts_when_none_was_stopped() {
    let (events, result) = flow(false, || Ok(()), false, true);
    assert!(result.is_err());
    assert_eq!(events, ["install", "resume", "resume sessions", "start sessions"]);
}

#[test]
fn the_task_is_enabled_again_even_when_no_agent_was_stopped() {
    // The exe may be unchanged and nothing stopped, and the task still disabled by an earlier
    // `apply` that was killed between its disable and its enable.
    let (events, result) = flow(false, || Ok(()), true, true);
    result.unwrap();
    assert_eq!(events, ["install", "resume", "resume sessions", "start sessions", "start"]);
}

#[test]
fn an_apply_that_could_not_enable_the_task_fails_and_starts_no_agent() {
    // A disabled task starts no agent at any logon, so the install did not take.
    let (events, result) = flow_resuming(true, || Ok(()), true, true, || anyhow::bail!("access denied"));
    assert!(format!("{:#}", result.unwrap_err()).contains("access denied"));
    assert_eq!(
        events,
        ["stop", "install", "resume", "resume sessions", "start sessions"],
        "the sessions are independent of the agent task"
    );
}

#[test]
fn a_failed_install_is_reported_as_it_was_when_the_task_could_not_be_enabled_either() {
    let (events, result) = flow_resuming(true, || Ok(()), false, true, || anyhow::bail!("access denied"));
    assert_eq!(format!("{:#}", result.unwrap_err()), "register failed");
    assert_eq!(
        events,
        ["stop", "install", "resume", "resume sessions", "start sessions"],
        "no agent start: the task cannot start one"
    );
}

#[test]
fn no_agent_starts_when_the_registered_task_cannot_start_one() {
    let (events, result) = flow(true, || Ok(()), false, false);
    assert!(result.is_err());
    assert_eq!(
        events,
        ["stop", "install", "resume", "resume sessions", "start sessions", "safe?"]
    );
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
    events: RefCell<Vec<String>>,
    recorded: RefCell<Vec<String>>,
}

impl World {
    fn new(tasks: Vec<SessionTask>, agents: Vec<u32>) -> World {
        World {
            tasks,
            agents: RefCell::new(agents),
            survivor: None,
            events: RefCell::default(),
            recorded: RefCell::default(),
        }
    }

    fn stop(&self) -> anyhow::Result<()> {
        stop_sessions(
            || Ok(self.tasks.iter().map(|t| task(&t.name, t.enabled)).collect()),
            &self.recorded,
            |names| {
                self.events.borrow_mut().push(format!("record {names:?}"));
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
    assert_eq!(*world.events.borrow(), ["record []", "end 4242", "wait [4242]"]);
}

#[test]
fn every_session_task_is_stopped_and_only_the_enabled_ones_are_recorded() {
    let world = World::new(vec![task("a", true), task("b", false), task("c", true)], vec![]);
    world.stop().unwrap();
    assert_eq!(
        *world.events.borrow(),
        [r#"record ["a", "c"]"#, "stop task a", "stop task b", "stop task c"]
    );
    assert_eq!(*world.recorded.borrow(), ["a", "c"], "a task that was off stays off");
}

#[test]
fn a_task_is_recorded_before_its_stop_so_a_failed_stop_still_gets_it_back() {
    let world = World::new(vec![task("a", true)], vec![]);
    let result = stop_sessions(
        || Ok(world.tasks.iter().map(|t| task(&t.name, t.enabled)).collect()),
        &world.recorded,
        |_| Ok(()),
        |_| anyhow::bail!("access denied"),
        || Ok(vec![]),
        |_| Ok(()),
        |_: Vec<u32>| Ok(()),
    );
    assert!(result.is_err());
    assert_eq!(*world.recorded.borrow(), ["a"]);
}

#[test]
fn the_agents_are_looked_for_again_until_none_is_left() {
    // An agent started by a task between the look and the end shows up on the next look.
    let looks = RefCell::new(vec![vec![1], vec![2], vec![]].into_iter());
    let ended = RefCell::new(Vec::new());
    stop_sessions(
        || Ok(vec![]),
        &RefCell::default(),
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

#[test]
fn session_tasks_are_reenabled_and_started_after_a_failed_install_whatever_the_agent_task_is() {
    // The agent task's form decides whether the desktop agents restart; the session tasks do not
    // depend on it, so a failed query of it (`restart_is_safe` false) must not leave them stopped.
    let world = World::new(vec![task("a", true), task("b", false)], vec![]);
    let enabled = RefCell::new(Vec::new());
    let ran = RefCell::new(Vec::new());
    let agents_started = RefCell::new(false);
    let result: anyhow::Result<()> = run(
        || world.stop(),
        |stop| {
            stop()?;
            anyhow::bail!("register failed")
        },
        || false,
        || Ok(()),
        || {
            resume_sessions(&world.recorded, |name| {
                enabled.borrow_mut().push(name.to_string());
                Ok(())
            })
        },
        || {
            start_sessions(&world.recorded, |name| {
                ran.borrow_mut().push(name.to_string());
                Ok(())
            })
        },
        |_| *agents_started.borrow_mut() = true,
    );
    assert_eq!(format!("{:#}", result.unwrap_err()), "register failed");
    assert_eq!(
        enabled.into_inner(),
        ["a"],
        "the task that was on is on again, the other stays off"
    );
    assert_eq!(ran.into_inner(), ["a"], "and is started again");
    assert!(!agents_started.into_inner(), "the desktop agents are not, by their own rule");
}

#[test]
fn the_tasks_to_enable_again_are_recorded_before_any_is_disabled() {
    let world = World::new(vec![task("a", true), task("b", false), task("c", true)], vec![]);
    world.stop().unwrap();
    assert_eq!(
        *world.events.borrow(),
        [
            r#"record ["a", "c"]"#,
            "stop task a",
            "stop task b",
            "stop task c"
        ]
    );
}

#[test]
fn a_task_that_cannot_be_recorded_is_not_disabled() {
    let world = World::new(vec![task("a", true)], vec![]);
    let result = stop_sessions(
        || Ok(world.tasks.iter().map(|t| task(&t.name, t.enabled)).collect()),
        &world.recorded,
        |_| anyhow::bail!("disk full"),
        |name| {
            world.events.borrow_mut().push(format!("stop task {name}"));
            Ok(())
        },
        || Ok(Vec::<u32>::new()),
        |_| Ok(()),
        |_| Ok(()),
    );
    assert!(format!("{:#}", result.unwrap_err()).contains("disk full"));
    assert!(world.events.borrow().is_empty(), "nothing was disabled without a record");
}

#[test]
fn an_apply_killed_between_two_disables_leaves_the_next_one_able_to_enable_both() {
    use crate::provision::pending_sessions;
    use crate::test_support::TempProfile;
    let dir = TempProfile::new("flow-crash");
    let pending = dir.0.join("pending.txt");
    let prefix = crate::provision::session_task::TASK_PREFIX;
    let (a, b) = (format!("{prefix}a"), format!("{prefix}b"));

    // First apply: both tasks are on; "a" is disabled, then the process dies before "b".
    let first = RefCell::new(Vec::new());
    let died = stop_sessions(
        || Ok(vec![task(&a, true), task(&b, true)]),
        &first,
        |names| pending_sessions::store(&pending, names),
        |name| {
            if name == b {
                anyhow::bail!("killed here")
            }
            Ok(())
        },
        || Ok(Vec::<u32>::new()),
        |_| Ok(()),
        |_| Ok(()),
    );
    assert!(died.is_err());
    // Nothing runs after the kill: no resume, no cleanup.

    // Next apply: "a" is found disabled, "b" enabled. The record brings "a" back.
    let second = RefCell::new(pending_sessions::load(&pending).unwrap());
    stop_sessions(
        || Ok(vec![task(&a, false), task(&b, true)]),
        &second,
        |names| pending_sessions::store(&pending, names),
        |_| Ok(()),
        || Ok(Vec::<u32>::new()),
        |_| Ok(()),
        |_| Ok(()),
    )
    .unwrap();
    let enabled = RefCell::new(Vec::new());
    resume_sessions(&second, |name| {
        enabled.borrow_mut().push(name.to_string());
        Ok(())
    })
    .unwrap();
    assert_eq!(enabled.into_inner(), [a, b], "the task that was on stays recorded until enabled");
}

#[test]
fn a_task_owed_from_an_earlier_apply_is_not_recorded_twice() {
    let owed = RefCell::new(vec!["a".to_string()]);
    stop_sessions(
        || Ok(vec![task("a", true), task("b", true)]),
        &owed,
        |_| Ok(()),
        |_| Ok(()),
        || Ok(Vec::<u32>::new()),
        |_| Ok(()),
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(*owed.borrow(), ["a", "b"]);
}

#[test]
fn a_session_task_that_cannot_be_enabled_again_is_an_error_and_the_rest_still_are() {
    let recorded = RefCell::new(vec!["a".to_string(), "b".to_string()]);
    let tried = RefCell::new(Vec::new());
    let result = resume_sessions(&recorded, |name| {
        tried.borrow_mut().push(name.to_string());
        if name == "a" {
            anyhow::bail!("access denied")
        }
        Ok(())
    });
    assert_eq!(tried.into_inner(), ["a", "b"]);
    let text = format!("{:#}", result.unwrap_err());
    assert!(text.contains("access denied") && text.contains("a"), "{text}");
}
