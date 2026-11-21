use super::*;
use crate::provision::sshd_task::{LineKind, REPORT_END, hand_over, render};
use crate::test_support::{FakeSshdTask, Said, recording, silent};
use anyhow::Context;
use std::cell::RefCell;
use std::path::Path;
use std::rc::Rc;

/// Run the flow with a `set_up` that stops (or not) and then fails (or not); return the
/// events in order and the result.
fn flow(
    stops: bool,
    stop_result: fn() -> anyhow::Result<()>,
    set_up_ok: bool,
) -> (Vec<&'static str>, anyhow::Result<()>) {
    flow_resuming(stops, stop_result, set_up_ok, || Ok(()), || Ok(()))
}

/// [`flow`] with the outcome of enabling the agent task again and of repairing the auto-login
/// tasks chosen too.
fn flow_resuming(
    stops: bool,
    stop_result: fn() -> anyhow::Result<()>,
    set_up_ok: bool,
    resume_result: fn() -> anyhow::Result<()>,
    repair_result: fn() -> anyhow::Result<()>,
) -> (Vec<&'static str>, anyhow::Result<()>) {
    let events = RefCell::new(Vec::new());
    let result = run(
        &mut silent,
        || {
            events.borrow_mut().push("stop");
            stop_result()
        },
        |stop, _| {
            if stops {
                stop()?;
            }
            events.borrow_mut().push("set up");
            anyhow::ensure!(set_up_ok, "register failed");
            Ok(())
        },
        || {
            events.borrow_mut().push("resume");
            resume_result()
        },
        |_| {
            events.borrow_mut().push("repair sessions");
            repair_result()
        },
        |left, _| {
            events.borrow_mut().push("start");
            assert!(left.is_empty(), "no agent survived");
        },
    );
    (events.into_inner(), result)
}

#[test]
fn agents_start_after_a_successful_install() {
    let (events, result) = flow(true, || Ok(()), true);
    result.unwrap();
    assert_eq!(events, ["stop", "set up", "resume", "repair sessions", "start"]);
}

#[test]
fn agents_that_were_stopped_start_again_when_a_later_step_fails() {
    let (events, result) = flow(true, || Ok(()), false);
    assert_eq!(format!("{:#}", result.unwrap_err()), "register failed");
    assert_eq!(events, ["stop", "set up", "resume", "repair sessions", "start"]);
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
        &mut silent,
        || Err(StillRunning::new(left.clone(), std::time::Duration::from_secs(60)).into()),
        |stop, _| {
            stop().context("stop the running agents")?;
            Ok(())
        },
        || Ok(()),
        |_| Ok(()),
        |survivors, _| told.borrow_mut().extend_from_slice(survivors),
    );
    let text = format!("{:#}", result.unwrap_err());
    assert!(text.contains("process 5 did not exit"), "{text}");
    assert!(text.contains("run install again"), "{text}");
    assert_eq!(
        told.into_inner(),
        left,
        "the start hears who is still running, through the context"
    );
}

/// [`wait_for_earlier_sshd_step`] over a script: whether the wait finds an earlier step (and so calls
/// `waiting`) and how it ends. The events are in the order the calls were made.
fn wait_for_earlier(found: bool, waited: anyhow::Result<WaitOutcome>) -> (Vec<String>, anyhow::Result<()>) {
    let events = RefCell::new(Vec::new());
    let log = |event: &str| events.borrow_mut().push(event.to_owned());
    let result = wait_for_earlier_sshd_step(&mut |stream, line| log(&format!("say {stream:?}: {line}")), |waiting| {
        log("look for the sshd step");
        if found {
            waiting();
        }
        log("wait for the sshd step");
        waited
    });
    (events.into_inner(), result)
}

#[test]
fn an_earlier_sshd_step_is_said_once_and_waited_for() {
    let (events, result) = wait_for_earlier(true, Ok(WaitOutcome::Ended));
    result.unwrap();
    assert_eq!(
        events,
        [
            "look for the sshd step",
            "say Out: Waiting for an earlier sshd step to finish...",
            "wait for the sshd step",
        ]
    );
}

#[test]
fn nothing_is_said_when_no_earlier_sshd_step_runs() {
    let (events, result) = wait_for_earlier(false, Ok(WaitOutcome::Ended));
    result.unwrap();
    assert_eq!(events, ["look for the sshd step", "wait for the sshd step"]);
}

#[test]
fn an_earlier_sshd_step_never_launched_stops_install() {
    let (_, result) = wait_for_earlier(true, Ok(WaitOutcome::NeverLaunched { count: 2 }));
    let text = format!("{:#}", result.unwrap_err());
    assert_eq!(
        text,
        format!(
            "the Task Scheduler lists 2 instance(s) of the task ssh-broker-install-sshd that it has not started \
             after {} s, so install went no further. End and remove the task (`schtasks /End /TN \
             ssh-broker-install-sshd`, then `schtasks /Delete /TN ssh-broker-install-sshd /F`, elevated); if the step \
             has started meanwhile, ending it can leave sshd stopped. Check sshd at this PC: `sc query sshd`; \
             start it with `net start sshd` if it is stopped. Then run install again",
            procwait::EXIT_BOUND.as_secs()
        )
    );
}

#[test]
fn a_failed_wait_for_an_earlier_sshd_step_stops_install() {
    let (_, result) = wait_for_earlier(true, Err(anyhow::anyhow!("the Task Scheduler did not answer")));
    assert_eq!(
        format!("{:#}", result.unwrap_err()),
        "wait for an earlier install's sshd step: the Task Scheduler did not answer"
    );
}

#[test]
fn agents_start_again_when_the_stop_failed_part_way() {
    let (events, result) = flow(true, || anyhow::bail!("access denied"), true);
    assert_eq!(format!("{:#}", result.unwrap_err()), "access denied");
    assert_eq!(events, ["stop", "resume", "repair sessions", "start"]);
}

#[test]
fn no_agent_starts_when_none_was_stopped() {
    let (events, result) = flow(false, || Ok(()), false);
    assert!(result.is_err());
    assert_eq!(events, ["set up", "resume", "repair sessions"]);
}

#[test]
fn the_task_is_enabled_again_even_when_no_agent_was_stopped() {
    // The exe may be unchanged and nothing stopped, and the task still disabled by an earlier
    // `install` that was killed between its disable and its enable.
    let (events, result) = flow(false, || Ok(()), true);
    result.unwrap();
    assert_eq!(events, ["set up", "resume", "repair sessions", "start"]);
}

#[test]
fn an_install_that_could_not_enable_the_task_fails_and_starts_no_agent() {
    // A disabled task starts no agent at any logon, so the install did not take.
    let (events, result) = flow_resuming(true, || Ok(()), true, || anyhow::bail!("access denied"), || Ok(()));
    assert!(format!("{:#}", result.unwrap_err()).contains("access denied"));
    assert_eq!(
        events,
        ["stop", "set up", "resume", "repair sessions"],
        "the sessions are independent of the agent task"
    );
}

#[test]
fn a_failed_install_is_reported_as_it_was_when_the_task_could_not_be_enabled_either() {
    let (events, result) = flow_resuming(true, || Ok(()), false, || anyhow::bail!("access denied"), || Ok(()));
    assert_eq!(format!("{:#}", result.unwrap_err()), "register failed");
    assert_eq!(
        events,
        ["stop", "set up", "resume", "repair sessions"],
        "no agent start: the task cannot start one"
    );
}

#[test]
fn an_install_that_could_not_enable_a_session_task_fails_but_still_starts_the_agents() {
    // A disabled auto-login task starts no session at boot, so the install did not take; the desktop
    // agent is a different task and its start does not wait on that.
    let (events, result) = flow_resuming(true, || Ok(()), true, || Ok(()), || anyhow::bail!("task denied"));
    assert!(format!("{:#}", result.unwrap_err()).contains("task denied"));
    assert_eq!(events, ["stop", "set up", "resume", "repair sessions", "start"]);
}

#[test]
fn a_failed_install_is_reported_as_it_was_when_a_session_task_could_not_be_enabled_either() {
    let (events, result) = flow_resuming(true, || Ok(()), false, || Ok(()), || anyhow::bail!("task denied"));
    assert_eq!(format!("{:#}", result.unwrap_err()), "register failed");
    assert_eq!(
        events,
        ["stop", "set up", "resume", "repair sessions", "start"],
        "the agents that were stopped start again, as after any failed install"
    );
}

#[test]
fn the_agent_task_failure_is_the_result_when_a_session_task_could_not_be_enabled_either() {
    let (events, result) = flow_resuming(
        true,
        || Ok(()),
        true,
        || anyhow::bail!("agent denied"),
        || anyhow::bail!("task denied"),
    );
    assert!(format!("{:#}", result.unwrap_err()).contains("agent denied"));
    assert_eq!(events, ["stop", "set up", "resume", "repair sessions"]);
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
    assert!(text.contains("run install again"), "{text}");
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
        self.repair_saying(&mut silent)
    }

    fn repair_saying(&self, say: &mut Say<'_>) -> anyhow::Result<()> {
        repair_sessions(
            say,
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
    // The state a killed `install` leaves, or a task disabled by hand.
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
        &mut silent,
        || anyhow::bail!("service unreachable"),
        |_| Ok(()),
        |_| Ok(false),
        |_| Ok(()),
    );
    assert!(format!("{:#}", result.unwrap_err()).contains("service unreachable"));
}

// what `install` says =====

use crate::provision::path_env::Stored;
use crate::provision::sessions::Targets;

const DIR: &str = r"C:\ProgramData\ssh-broker";
const INSTALLING: &str = "Installing ssh-broker v0.2.0 for every user of this PC...";
const INSTALLED: &str = "ssh-broker v0.2.0 has been installed!";
const STARTING: &str = "Starting an agent in each logged-on session...";

fn out(text: &str) -> (Stream, String) {
    (Stream::Out, text.to_owned())
}

fn err(text: &str) -> (Stream, String) {
    (Stream::Err, text.to_owned())
}

/// A system `PATH` without the install directory, and one with it.
fn path_without() -> path_env::Reading {
    Ok(Some(Stored::Sz(r"C:\Windows;C:\Windows\System32".into())))
}

fn path_with() -> path_env::Reading {
    Ok(Some(Stored::Sz(format!(r"C:\Windows;{DIR}"))))
}

fn plain_length(text: &str) -> Result<usize, String> {
    Ok(text.encode_utf16().count())
}

/// `add_install_dir_to_path` over `current`, whose write gives `written`; returns what was said and the values
/// written, and whether the other programs were told.
fn put_on_the_path(current: path_env::Reading, written: anyhow::Result<()>) -> (Said, Vec<(String, bool)>, bool) {
    let said = RefCell::new(Vec::new());
    let writes = RefCell::new(Vec::new());
    let mut told = false;
    add_install_dir_to_path(
        &mut recording(&said),
        DIR,
        &current,
        plain_length,
        |value, expand| {
            assert!(
                !said.borrow().is_empty(),
                "the line comes before the write, which can take seconds"
            );
            writes.borrow_mut().push((value.to_owned(), expand));
            written
        },
        || {
            assert!(!writes.borrow().is_empty(), "the programs are told after the write");
            told = true;
        },
    );
    (said.into_inner(), writes.into_inner(), told)
}

#[test]
fn the_last_thing_install_says_is_the_installed_line_on_stdout() {
    let said = RefCell::new(Vec::new());
    install_run(
        &mut recording(&said),
        "0.2.0",
        |say| {
            say(Stream::Out, "A step...");
            say(Stream::Err, "a warning");
            Ok(())
        },
        |(), say| say(Stream::Out, "a line of the sshd step"),
    )
    .unwrap();
    assert_eq!(
        said.into_inner(),
        [
            out(INSTALLING),
            out("A step..."),
            err("a warning"),
            out("a line of the sshd step"),
            out(INSTALLED),
        ]
    );
}

#[test]
fn an_install_that_fails_says_no_installed_line_and_runs_no_sshd_step() {
    let said = RefCell::new(Vec::new());
    let result = install_run(
        &mut recording(&said),
        "0.2.0",
        |say| -> anyhow::Result<()> {
            say(Stream::Out, "A step...");
            anyhow::bail!("copy failed")
        },
        |(), _| panic!("the sshd step comes only after the install worked"),
    );
    assert_eq!(format!("{:#}", result.unwrap_err()), "copy failed");
    assert_eq!(said.into_inner(), [out(INSTALLING), out("A step...")]);
}

/// The sshd step runs while the install's own state (the lock) is still held, and nothing is dropped before the
/// installed line.
#[test]
fn what_the_install_holds_is_held_through_the_sshd_step() {
    struct Held<'a>(&'a RefCell<Vec<&'static str>>);
    impl Drop for Held<'_> {
        fn drop(&mut self) {
            self.0.borrow_mut().push("released");
        }
    }
    let events = RefCell::new(Vec::new());
    install_run(
        &mut |_, text| {
            if text == INSTALLED {
                events.borrow_mut().push("installed line")
            }
        },
        "0.2.0",
        |_| Ok(Held(&events)),
        |_, _| events.borrow_mut().push("sshd step"),
    )
    .unwrap();
    assert_eq!(events.into_inner(), ["sshd step", "installed line", "released"]);
}

#[test]
fn the_wait_for_another_install_is_a_step_line_on_stdout_said_when_the_lock_is_held() {
    let said = RefCell::new(Vec::new());
    let held = wait_for_lock(&mut recording(&said), |waiting| {
        waiting();
        Ok("the lock")
    })
    .unwrap();
    assert_eq!(held, "the lock");
    assert_eq!(
        said.into_inner(),
        [out("Waiting for another install or auto-login command to finish...")]
    );

    let said = RefCell::new(Vec::new());
    wait_for_lock(&mut recording(&said), |_| Ok(())).unwrap();
    assert_eq!(said.into_inner(), [], "a free lock says nothing");
}

/// `start_agents` over a machine: the sessions listed, the survivors of the stop, and the sessions whose start fails.
fn started(targets: anyhow::Result<Targets>, survivors: &[Survivor], unstartable: &[u32]) -> (Said, Vec<u32>) {
    let said = RefCell::new(Vec::new());
    let mut starts = Vec::new();
    start_agents(
        &mut recording(&said),
        || targets,
        |id| {
            assert_eq!(
                said.borrow().iter().filter(|line| **line == out(STARTING)).count(),
                1,
                "the line is said once, before the first agent is started"
            );
            anyhow::ensure!(!unstartable.contains(&id), "no such task");
            starts.push(id);
            Ok(())
        },
        survivors,
    );
    (said.into_inner(), starts)
}

fn survivor(pid: u32, session: u32) -> Survivor {
    Survivor {
        pid,
        session: Some(session),
        unconfirmed: None,
    }
}

#[test]
fn the_start_of_the_agents_is_a_step_line_and_nothing_else_when_it_works() {
    let targets = Targets {
        ids: vec![1, 2],
        unknown: vec![],
    };
    let (said, starts) = started(Ok(targets), &[], &[]);
    assert_eq!(said, [out(STARTING)]);
    assert_eq!(starts, [1, 2]);
}

#[test]
fn every_line_that_was_on_stderr_is_still_said_there() {
    // `start_agents`
    let targets = || Targets {
        ids: vec![1, 2, 4],
        unknown: vec![(3, "access denied".into())],
    };
    let (said, starts) = started(Ok(targets()), &[survivor(5, 2), survivor(6, 2)], &[4]);
    assert_eq!(
        said,
        [
            err("could not tell whether session 3 has a user, so no agent was started there: access denied"),
            err(
                "no agent was started in session 2: its old agent (process 5, 6) was stopped but has not been seen to \
                 exit; run install again once it has exited"
            ),
            out(STARTING),
            err("could not start the agent in session 4: no such task"),
        ]
    );
    assert_eq!(starts, [1]);
    let (said, _) = started(Err(anyhow::anyhow!("the service is down")), &[], &[]);
    assert_eq!(
        said,
        [err("the logged-on sessions could not be listed: the service is down")]
    );

    // `add_install_dir_to_path`
    let (said, writes, _) = put_on_the_path(Ok(None), Ok(()));
    assert_eq!(
        said,
        [err(&format!(
            "{DIR} was not added to the system PATH: the system PATH has no Path value"
        ))]
    );
    assert_eq!(writes, []);
    let (said, _, told) = put_on_the_path(path_without(), Err(anyhow::anyhow!("access denied")));
    assert_eq!(
        said,
        [
            out(&format!("Adding {DIR} to the system PATH...")),
            err(&format!("{DIR} was not added to the system PATH: access denied")),
        ]
    );
    assert!(
        !told,
        "a failed write is not followed by the notice to the running programs"
    );
}

/// `run` says what failed when two things fail and only one can be the result.
#[test]
fn the_failure_that_is_not_the_result_is_said_on_stderr() {
    let said = RefCell::new(Vec::new());
    let result = run(
        &mut recording(&said),
        || Ok(()),
        |_, _| Ok(()),
        || anyhow::bail!("agent denied"),
        |_| anyhow::bail!("task denied"),
        |_, _| panic!("a disabled agent task starts no agent"),
    );
    assert_eq!(format!("{:#}", result.unwrap_err()), "agent denied");
    assert_eq!(said.into_inner(), [err("task denied")]);

    let said = RefCell::new(Vec::new());
    let result = run::<()>(
        &mut recording(&said),
        || Ok(()),
        |_, _| anyhow::bail!("register failed"),
        || Ok(()),
        |_| anyhow::bail!("task denied"),
        |_, _| panic!("nothing was stopped"),
    );
    assert_eq!(format!("{:#}", result.unwrap_err()), "register failed");
    assert_eq!(said.into_inner(), [err("task denied")]);
}

#[test]
fn the_repair_says_what_it_could_not_enable_after_the_first_and_what_it_could_not_start_or_ask() {
    let said = RefCell::new(Vec::new());
    // `a` and `b` cannot be enabled: `a`'s failure is the result and `b`'s is said. `c` cannot be asked whether it
    // runs, `d` cannot be started.
    let result = repair_sessions(
        &mut recording(&said),
        || {
            Ok(vec![
                task("a", false),
                task("b", false),
                task("c", true),
                task("d", true),
            ])
        },
        |_| anyhow::bail!("access denied"),
        |name| match name {
            "c" => anyhow::bail!("the Task Scheduler did not answer"),
            _ => Ok(false),
        },
        |_| anyhow::bail!("no such task"),
    );
    assert!(format!("{:#}", result.unwrap_err()).contains("could not enable the a task again"));
    assert_eq!(
        said.into_inner(),
        [
            err("could not enable the b task again; no session starts at boot until it is: access denied"),
            err(
                "could not tell whether the c task is running, so it was not started: the Task Scheduler did not answer"
            ),
            err("could not start the d task: no such task"),
        ]
    );
}

#[test]
fn a_step_that_does_not_happen_says_nothing() {
    // A PATH that is right already: nothing is written, nothing broadcast, nothing said.
    let (said, writes, told) = put_on_the_path(path_with(), Ok(()));
    assert_eq!((said, writes, told), (vec![], vec![], false));
    // An agent task and a stop that were not needed: `run` says nothing of its own.
    let said = RefCell::new(Vec::new());
    run(
        &mut recording(&said),
        || Ok(()),
        |_, _| Ok(()),
        || Ok(()),
        |_| Ok(()),
        |_, _| {},
    )
    .unwrap();
    assert_eq!(said.into_inner(), []);
    // No start, so no step line.
    let (said, starts) = started(Ok(Targets::default()), &[], &[]);
    assert_eq!((said, starts), (vec![], vec![]));
    let targets = Targets {
        ids: vec![2],
        unknown: vec![(3, "access denied".into())],
    };
    let (said, starts) = started(Ok(targets), &[survivor(5, 2)], &[]);
    assert_eq!(starts, Vec::<u32>::new());
    assert!(!said.contains(&out(STARTING)), "{said:?}");
    assert_eq!(said.len(), 2, "{said:?}");
    // Nor when the sessions could not be listed: that is said, and nothing starts.
    let (said, starts) = started(Err(anyhow::anyhow!("the service is down")), &[], &[]);
    assert_eq!(starts, Vec::<u32>::new());
    assert!(!said.contains(&out(STARTING)), "{said:?}");
    assert_eq!(said.len(), 1, "{said:?}");
}

#[test]
fn the_path_is_announced_before_it_is_written_and_the_programs_told_after() {
    let (said, writes, told) = put_on_the_path(path_without(), Ok(()));
    assert_eq!(said, [out(&format!("Adding {DIR} to the system PATH..."))]);
    assert_eq!(writes, [(format!(r"C:\Windows;C:\Windows\System32;{DIR}"), false)]);
    assert!(told, "the running programs hear of the change");
}

const EXE: &str = r"C:\ProgramData\ssh-broker\ssh-broker.exe";
const REPORT: &str = r"C:\ProgramData\ssh-broker\install-sshd.log";
const NOTE_OF_THE_STEP: &str = "sshd is not running; it reads the change when it starts";
const WARNING_OF_THE_STEP: &str = "add `AcceptEnv SSH_BROKER_ELEVATION` above the first `Match` in sshd_config";

/// The lines of a first install on a machine with trouble at every step that goes on: the waits, the PATH, the
/// agents and the sessions, and an sshd step that is the real hand-over over a stand-in task whose report holds a
/// note and a warning.
fn what_a_troubled_install_says() -> Said {
    let said = RefCell::new(Vec::new());
    install_run(
        &mut recording(&said),
        "0.2.0",
        |say| {
            wait_for_lock(say, |waiting| {
                waiting();
                Ok(())
            })?;
            wait_for_earlier_sshd_step(say, |waiting| {
                waiting();
                Ok(WaitOutcome::Ended)
            })?;
            run(
                say,
                || Ok(()),
                |stop, say| {
                    stop()?;
                    add_install_dir_to_path(say, DIR, &Ok(None), plain_length, |_, _| Ok(()), || {});
                    add_install_dir_to_path(say, DIR, &path_without(), plain_length, |_, _| Ok(()), || {});
                    Ok(())
                },
                || Ok(()),
                |say| {
                    let mut machine = Machine::new(vec![("a", true, false), ("b", true, true)]);
                    machine.unstartable = Some("a");
                    machine.repair_saying(say)
                },
                |survivors, say| {
                    start_agents(
                        say,
                        || {
                            Ok(Targets {
                                ids: vec![1, 2],
                                unknown: vec![(3, "access denied".into())],
                            })
                        },
                        |id| {
                            anyhow::ensure!(id != 2, "no such task");
                            Ok(())
                        },
                        survivors,
                    )
                },
            )
        },
        |_, say| {
            let log = Rc::new(RefCell::new(Vec::new()));
            let mut task = FakeSshdTask::new(&log);
            task.report = Ok(format!(
                "{}\r\n{}\r\n{REPORT_END}\r\n",
                render(LineKind::Note, NOTE_OF_THE_STEP),
                render(LineKind::Warning, WARNING_OF_THE_STEP)
            ));
            hand_over(&mut task, Path::new(REPORT), Path::new(EXE), say);
        },
    )
    .unwrap();
    said.into_inner()
}

/// stdout carries the step lines and the last line, and every step line says that it is going on, the sshd
/// step's included.
#[test]
fn every_stdout_line_but_the_last_ends_in_three_dots() {
    let said = what_a_troubled_install_says();
    let stdout: Vec<&str> = said
        .iter()
        .filter(|(stream, _)| *stream == Stream::Out)
        .map(|(_, text)| text.as_str())
        .collect();
    assert_eq!(stdout.last(), Some(&INSTALLED));
    assert!(stdout.len() >= 6, "{stdout:#?}");
    for line in &stdout[..stdout.len() - 1] {
        assert!(line.ends_with("..."), "{line}");
    }
    assert_eq!(
        stdout.iter().filter(|line| **line == INSTALLED).count(),
        1,
        "nothing else is said as the last line"
    );
}

/// The sshd step of a troubled install says its step line on stdout, after the lines of the steps before it, and
/// the warning of its report on stderr; its note stays in the report.
#[test]
fn the_sshd_step_says_its_step_line_and_its_warning_and_not_its_note() {
    let said = what_a_troubled_install_says();
    let step_line = out(&crate::provision::sshd_task::step_line(Path::new(EXE)));
    let at = said.iter().position(|line| *line == step_line).expect("the step line");
    assert_eq!(said[at + 1], err(WARNING_OF_THE_STEP));
    assert_eq!(said.last(), Some(&out(INSTALLED)));
    assert_eq!(
        said.len(),
        at + 3,
        "the step line, the warning and the last line close the install"
    );
    assert!(
        said.iter().all(|(_, line)| !line.contains(NOTE_OF_THE_STEP)),
        "{said:#?}"
    );
}

/// No line `install` says, the sshd step's included, begins with `install`.
#[test]
fn no_line_begins_with_the_verb() {
    let said = what_a_troubled_install_says();
    assert!(said.iter().any(|(stream, _)| *stream == Stream::Err), "{said:#?}");
    for (_, line) in &said {
        let first = line.split(|c: char| !c.is_alphanumeric()).next().unwrap_or_default();
        assert!(!first.eq_ignore_ascii_case("install"), "{line}");
    }
}
