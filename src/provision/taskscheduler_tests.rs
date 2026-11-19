//! Tests for the Task Scheduler wrapper. The ones marked Elevated register a throwaway task and
//! run in CI only; they refuse to start anywhere else. Starting a task in a second user's
//! session cannot be tested in CI at all: the acceptance procedure covers it.
use super::*;
use crate::provision::procwait::wait_all_exited;
use crate::test_support::ThrowawayTask;
use std::cell::RefCell;
use std::path::PathBuf;
use std::time::Duration;
use windows::Win32::System::TaskScheduler::{
    TASK_STATE_DISABLED, TASK_STATE_QUEUED, TASK_STATE_READY, TASK_STATE_RUNNING,
};

/// A task with no trigger that runs a process forever as SYSTEM, so it can be started on demand
/// and has a running instance to stop. SYSTEM so that it needs no logged-on user and shows no
/// window.
const FOREVER_TASK_XML: &str = r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Principals><Principal id="System"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
  </Settings>
  <Actions Context="System"><Exec><Command>C:\Windows\System32\PING.EXE</Command><Arguments>-t 127.0.0.1</Arguments></Exec></Actions>
</Task>
"#;

/// What [`FOREVER_TASK_XML`] runs.
fn forever_image() -> PathBuf {
    PathBuf::from(r"C:\Windows\System32\PING.EXE")
}

fn state_of(name: &str) -> i32 {
    let _com = Com::init().unwrap();
    let service = connect().unwrap();
    let task = registered_task(&service, name)
        .unwrap()
        .expect("the task is registered");
    unsafe { task.State() }.unwrap().0
}

/// Start `name` and return once its instance is visible as a process of `image`.
fn start_and_find(name: &str, image: &Path) -> Vec<Process> {
    let _com = Com::init().unwrap();
    let service = connect().unwrap();
    let task = registered_task(&service, name).unwrap().unwrap();
    unsafe { task.Run(&windows::Win32::System::Variant::VARIANT::default()) }.unwrap();
    // The instance appears when the service has launched it; there is no event to wait on, so
    // this re-reads the real condition until it holds.
    loop {
        let found = running_instances(&task, image).unwrap().processes;
        if !found.is_empty() {
            return found;
        }
        std::thread::yield_now();
    }
}

// Stopping, without a real task -----

#[test]
fn stop_instances_succeeds_for_a_task_that_does_not_exist() {
    // Nothing is registered under this name, here or in CI: the no-task case is not an error.
    let name = format!("ssh-broker-test-absent-{}", std::process::id());
    stop_instances(&name, Path::new(r"C:\x\ssh-broker.exe")).unwrap();
}

#[test]
fn a_task_that_does_not_exist_has_no_running_instance() {
    let name = format!("ssh-broker-test-absent-{}", std::process::id());
    assert!(!has_running_instance(&name).unwrap());
}

#[test]
fn enabling_a_task_that_does_not_exist_is_not_an_error() {
    // A failed `apply` enables the task again whether or not it got as far as registering it.
    let name = format!("ssh-broker-test-absent-{}", std::process::id());
    set_enabled(&name, true).unwrap();
}

#[test]
fn task_xml_is_none_for_a_task_that_does_not_exist() {
    let name = format!("ssh-broker-test-absent-{}", std::process::id());
    assert_eq!(task_xml(&name).unwrap(), None);
}

#[test]
fn run_in_session_rejects_session_zero_before_it_calls_the_service() {
    // Session 0 is the services session, and `RunEx` into it would start a task where nobody is
    // logged on. The wrapper refuses without touching the Task Scheduler (the task does not
    // exist, so a call through would fail differently).
    let err = run_in_session("ssh-broker-test-never-registered", 0).unwrap_err();
    assert!(format!("{err:#}").contains("session 0"), "{err:#}");
}

#[test]
fn stop_that_returned_s_false_is_an_error_naming_the_task() {
    // S_FALSE is a success code the windows crate maps to Ok; it means the caller may not stop
    // the instances, so nothing was stopped.
    let err = stop_outcome("the-task", S_FALSE).unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("the-task"), "{text}");
    assert!(text.contains("cannot stop"), "{text}");
}

#[test]
fn stop_that_found_nothing_running_is_not_an_error() {
    stop_outcome("t", S_OK).unwrap();
    stop_outcome("t", SCHED_E_TASK_NOT_RUNNING).unwrap();
}

#[test]
fn stop_that_failed_is_an_error_naming_the_task() {
    let err = stop_outcome("the-task", HRESULT(0x8007_0005_u32 as i32)).unwrap_err();
    assert!(format!("{err:#}").contains("the-task"), "{err:#}");
}

/// What a listing of the task's instances shows: for each instance, the pid its process has (0 if
/// the engine has not launched it yet).
type Listing = Vec<u32>;

/// Long enough that no test of the order of the steps reaches it.
const NO_BOUND: Duration = Duration::from_secs(3600);

/// The steps of a stop over a script of listings (the last one repeats), recording the order they
/// run in.
fn run_stop_and_wait(
    listings: Vec<Listing>,
    disable: bool,
    stop: bool,
    wait: bool,
    events: &RefCell<Vec<String>>,
) -> anyhow::Result<()> {
    run_stop_and_wait_within(NO_BOUND, listings, disable, stop, wait, events)
}

fn run_stop_and_wait_within(
    bound: Duration,
    listings: Vec<Listing>,
    disable: bool,
    stop: bool,
    wait: bool,
    events: &RefCell<Vec<String>>,
) -> anyhow::Result<()> {
    let log = |e: &str| events.borrow_mut().push(e.to_string());
    let outcome = |ok: bool| if ok { Ok(()) } else { anyhow::bail!("failed") };
    let mut listings = listings.into_iter().peekable();
    stop_and_wait(
        "the-task",
        bound,
        || {
            log("disable");
            outcome(disable)
        },
        || {
            let pids = if listings.len() > 1 {
                listings.next().unwrap()
            } else {
                listings.peek().cloned().unwrap_or_default()
            };
            log(&format!("list {pids:?}"));
            Ok(Instances {
                count: pids.len(),
                pids: pids.clone(),
                processes: pids.into_iter().filter(|pid| *pid != 0).collect(),
            })
        },
        || {
            log("stop");
            outcome(stop)
        },
        |pids| {
            log(&format!("wait {pids:?}"));
            outcome(wait)
        },
    )
}

#[test]
fn the_task_is_disabled_then_listed_then_stopped_then_waited_for_then_listed_again() {
    // Disabled first, so a logon cannot start an agent from the old exe in between; listed before
    // the stop, because the instances are gone from the task afterwards; waited for before the
    // next look, so the caller proceeds only once every process has exited and none is left.
    let events = RefCell::new(Vec::new());
    run_stop_and_wait(vec![vec![11, 22], vec![]], true, true, true, &events).unwrap();
    assert_eq!(
        events.into_inner(),
        ["disable", "list [11, 22]", "stop", "wait [11, 22]", "list []"]
    );
}

#[test]
fn a_task_with_no_instance_is_not_stopped() {
    let events = RefCell::new(Vec::new());
    run_stop_and_wait(vec![vec![]], true, true, true, &events).unwrap();
    assert_eq!(events.into_inner(), ["disable", "list []"]);
}

#[test]
fn an_instance_the_engine_had_not_launched_is_stopped_and_looked_for_again() {
    // Its pid is 0, so there is no process to wait for yet; the engine can still launch it after
    // the stop, so the stop is repeated until the task has no instance.
    let events = RefCell::new(Vec::new());
    run_stop_and_wait(vec![vec![0], vec![33], vec![]], true, true, true, &events).unwrap();
    assert_eq!(
        events.into_inner(),
        [
            "disable",
            "list [0]",
            "stop",
            "wait []",
            "list [33]",
            "stop",
            "wait [33]",
            "list []"
        ]
    );
}

#[test]
fn the_stop_repeats_for_as_long_as_an_instance_appears_with_no_count_of_passes() {
    let events = RefCell::new(Vec::new());
    let mut listings: Vec<Listing> = (0..1000).map(|_| vec![0]).collect();
    listings.push(vec![]);
    run_stop_and_wait(listings, true, true, true, &events).unwrap();
    assert_eq!(events.borrow().iter().filter(|e| *e == "stop").count(), 1000);
}

#[test]
fn an_instance_that_stop_never_clears_fails_the_stop_naming_the_task_and_the_instance() {
    // The service keeps listing an instance that `Stop` does not remove (a stale entry). That is
    // an external condition that might never clear, so past the bound it is an error and the
    // caller's failure path puts the task back. With a zero bound the first stop has been made
    // and the next look ends it.
    let events = RefCell::new(Vec::new());
    let err = run_stop_and_wait_within(Duration::ZERO, vec![vec![0, 44]], true, true, true, &events).unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("the-task"), "{text}");
    assert!(text.contains("44"), "names the instance with a process: {text}");
    assert!(text.contains("not launched"), "names the instance with none: {text}");
    assert_eq!(
        events.into_inner(),
        ["disable", "list [0, 44]", "stop", "wait [44]", "list [0, 44]"],
        "stopped once before giving up, and did not stop again"
    );
}

#[test]
fn nothing_is_stopped_when_the_task_cannot_be_disabled() {
    let events = RefCell::new(Vec::new());
    assert!(run_stop_and_wait(vec![vec![11]], false, true, true, &events).is_err());
    assert_eq!(events.into_inner(), ["disable"]);
}

#[test]
fn a_failed_stop_is_not_followed_by_a_wait() {
    let events = RefCell::new(Vec::new());
    assert!(run_stop_and_wait(vec![vec![11]], true, false, true, &events).is_err());
    assert_eq!(events.into_inner(), ["disable", "list [11]", "stop"]);
}

#[test]
fn a_process_that_does_not_exit_fails_the_stop_without_another_pass() {
    let events = RefCell::new(Vec::new());
    assert!(run_stop_and_wait(vec![vec![11], vec![]], true, true, false, &events).is_err());
    assert_eq!(events.into_inner(), ["disable", "list [11]", "stop", "wait [11]"]);
}

// Waiting for the instances of a task (host) -----

/// The wait over a script of listings (the last one repeats), recording the order of its calls.
fn run_wait_until_ended(
    bound: Duration,
    listings: Vec<Listing>,
    wait: bool,
    events: &RefCell<Vec<String>>,
) -> anyhow::Result<WaitOutcome> {
    let log = |e: &str| events.borrow_mut().push(e.to_string());
    let mut listings = listings.into_iter().peekable();
    wait_until_ended(
        bound,
        || {
            let pids = if listings.len() > 1 {
                listings.next().unwrap()
            } else {
                listings.peek().cloned().unwrap_or_default()
            };
            log(&format!("list {pids:?}"));
            Ok(Instances {
                count: pids.len(),
                pids: pids.clone(),
                processes: pids.into_iter().filter(|pid| *pid != 0).collect(),
            })
        },
        |pids| {
            log(&format!("wait {pids:?}"));
            if wait { Ok(()) } else { anyhow::bail!("failed") }
        },
    )
}

#[test]
fn the_instances_are_listed_waited_for_and_listed_again_until_there_are_none() {
    let events = RefCell::new(Vec::new());
    let outcome = run_wait_until_ended(NO_BOUND, vec![vec![11, 22], vec![]], true, &events).unwrap();
    assert_eq!(outcome, WaitOutcome::Ended);
    assert_eq!(events.into_inner(), ["list [11, 22]", "wait [11, 22]", "list []"]);
}

#[test]
fn a_task_with_no_instance_has_ended_and_nothing_is_waited_for() {
    let events = RefCell::new(Vec::new());
    assert_eq!(
        run_wait_until_ended(Duration::ZERO, vec![vec![]], true, &events).unwrap(),
        WaitOutcome::Ended
    );
    assert_eq!(events.into_inner(), ["list []"]);
}

#[test]
fn an_instance_the_engine_has_not_launched_yet_is_looked_at_again_with_no_count_of_passes() {
    let events = RefCell::new(Vec::new());
    let mut listings: Vec<Listing> = (0..1000).map(|_| vec![0]).collect();
    listings.push(vec![33]);
    listings.push(vec![]);
    let outcome = run_wait_until_ended(NO_BOUND, listings, true, &events).unwrap();
    assert_eq!(outcome, WaitOutcome::Ended);
    let events = events.into_inner();
    assert_eq!(events.iter().filter(|e| *e == "list [0]").count(), 1000);
    assert_eq!(&events[1000..], ["list [33]", "wait [33]", "list []"]);
}

#[test]
fn an_instance_that_is_never_launched_is_not_an_end_and_is_reported_with_how_many_past_the_bound() {
    // With a zero bound the first look that finds only unlaunched instances is past it. The expiry is the
    // failure bound of an external event that may never come, and says nothing of what the instance does.
    let events = RefCell::new(Vec::new());
    let outcome = run_wait_until_ended(Duration::ZERO, vec![vec![0, 0]], true, &events).unwrap();
    assert_eq!(outcome, WaitOutcome::NeverLaunched { count: 2 });
    assert_eq!(events.into_inner(), ["list [0, 0]"]);
}

#[test]
fn a_launched_instance_is_waited_for_with_no_bound_however_long_the_bound_is_past() {
    // The bound is for an instance that is never launched, not for one that runs: a launched one is
    // waited for until it exits, and a zero bound does not cut that wait.
    let events = RefCell::new(Vec::new());
    let outcome = run_wait_until_ended(Duration::ZERO, vec![vec![0, 44], vec![]], true, &events).unwrap();
    assert_eq!(outcome, WaitOutcome::Ended);
    assert_eq!(events.into_inner(), ["list [0, 44]", "wait [44]", "list []"]);
}

/// The process of an instance, as the tests hold one: its pid; `open` finds one for the pids in `alive`.
fn instances_listed(listed: Vec<u32>, alive: &[u32]) -> Instances<u32> {
    instances_of(listed, |pid| Ok(alive.contains(&pid).then_some(pid))).unwrap()
}

#[test]
fn an_instance_whose_process_has_exited_is_not_an_instance_and_one_not_launched_yet_is() {
    let instances = instances_listed(vec![0, 7, 8], &[8]);
    assert_eq!(instances.count, 2);
    assert_eq!(instances.pids, [0, 8]);
    assert_eq!(instances.processes, [8]);
}

/// A slow engine lists an instance after its process has exited. It has ended: it is not an instance that was
/// never launched, which would leave the report unread and the task registered.
#[test]
fn a_listed_instance_whose_process_has_exited_ends_the_wait_and_is_not_never_launched() {
    let outcome = wait_until_ended(
        Duration::ZERO,
        || Ok(instances_listed(vec![7], &[])),
        |_: Vec<u32>| anyhow::bail!("nothing is waited for"),
    )
    .unwrap();
    assert_eq!(outcome, WaitOutcome::Ended);
}

#[test]
fn a_failure_to_identify_the_process_of_an_instance_is_an_error_and_never_an_end() {
    let result = instances_of(vec![7], |_| -> anyhow::Result<Option<u32>> {
        anyhow::bail!("cannot tell")
    });
    assert!(result.is_err());
}

#[test]
fn a_wait_that_fails_is_an_error_and_is_not_looked_past() {
    let events = RefCell::new(Vec::new());
    assert!(run_wait_until_ended(NO_BOUND, vec![vec![11], vec![]], false, &events).is_err());
    assert_eq!(events.into_inner(), ["list [11]", "wait [11]"]);
}

// Stopping a real task (Elevated, CI only) -----

/// Elevated (CI only).
#[test]
fn stop_instances_succeeds_for_a_task_that_is_not_running() {
    let task = ThrowawayTask::new("stop-idle");
    task.register(FOREVER_TASK_XML);
    assert_eq!(state_of(&task.0), TASK_STATE_READY.0, "control: nothing is running");

    stop_instances(&task.0, &forever_image()).unwrap();
}

/// Elevated (CI only).
#[test]
fn stop_instances_returns_after_the_instance_process_has_exited_and_leaves_the_task_disabled() {
    let task = ThrowawayTask::new("stop-running");
    task.register(FOREVER_TASK_XML);
    let image = forever_image();
    let processes = start_and_find(&task.0, &image);
    let started = state_of(&task.0);
    assert!(
        started == TASK_STATE_RUNNING.0 || started == TASK_STATE_QUEUED.0,
        "control: the task was started (state {started})"
    );

    stop_instances(&task.0, &image).unwrap();

    // The wait inside `stop_instances` is the property: a zero bound only reads the state.
    wait_all_exited(&processes, Duration::ZERO).expect("the process had exited when stop_instances returned");
    assert_eq!(
        state_of(&task.0),
        TASK_STATE_DISABLED.0,
        "left disabled so a logon cannot start an agent before the caller resumes it"
    );

    // `verify` reads this off the queried XML, so the service has to write it there.
    let disabled_xml = task_xml(&task.0).unwrap().unwrap();
    assert!(
        crate::provision::schtasks::xml_is_disabled(&disabled_xml),
        "{disabled_xml}"
    );

    set_enabled(&task.0, true).unwrap();
    assert_eq!(state_of(&task.0), TASK_STATE_READY.0, "resumed");
    let enabled_xml = task_xml(&task.0).unwrap().unwrap();
    assert!(
        !crate::provision::schtasks::xml_is_disabled(&enabled_xml),
        "{enabled_xml}"
    );
}

/// Elevated (CI only). A task registered as a service account (SYSTEM) with no trigger and started on demand:
/// the wait returns once its instance has no process left, so what the process writes last is there, and the
/// task has no instance afterwards.
#[test]
fn a_system_task_is_registered_run_and_waited_for_until_its_process_has_exited() {
    let task = ThrowawayTask::new("system-wait");
    let cmd = PathBuf::from(r"C:\Windows\System32\cmd.exe");
    let marker = std::env::temp_dir().join(format!("sb-system-wait-{}.txt", std::process::id()));
    let _ = std::fs::remove_file(&marker);
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Principals><Principal id="System"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>Queue</MultipleInstancesPolicy><ExecutionTimeLimit>PT0S</ExecutionTimeLimit></Settings>
  <Actions Context="System"><Exec><Command>{}</Command><Arguments>{}</Arguments></Exec></Actions>
</Task>
"#,
        cmd.display(),
        crate::provision::schtasks::xml_escape(&format!("/c echo done> \"{}\"", marker.display()))
    );
    register_system_task(&task.0, &xml, "D:P(A;;FA;;;SY)(A;;FA;;;BA)").unwrap();
    run_task(&task.0).unwrap();

    let outcome = wait_for_instances(&task.0, &cmd).unwrap();
    let written = std::fs::read_to_string(&marker);
    let _ = std::fs::remove_file(&marker);
    assert_eq!(outcome, WaitOutcome::Ended);
    assert_eq!(
        written.expect("the task's process wrote before the wait ended").trim(),
        "done"
    );
    assert!(!has_running_instance(&task.0).unwrap(), "no instance is left");
}

/// Elevated (CI only).
#[test]
fn a_task_has_a_running_instance_from_its_start_until_it_is_stopped() {
    let task = ThrowawayTask::new("has-instance");
    task.register(FOREVER_TASK_XML);
    assert!(!has_running_instance(&task.0).unwrap(), "control: nothing is running");

    assert!(
        !has_unended_instance(&task.0, &forever_image()).unwrap(),
        "control: nothing is running"
    );

    let image = forever_image();
    let processes = start_and_find(&task.0, &image);
    assert!(has_running_instance(&task.0).unwrap());
    assert!(
        has_unended_instance(&task.0, &image).unwrap(),
        "an instance whose process runs is unended"
    );

    stop_instances(&task.0, &image).unwrap();
    wait_all_exited(&processes, Duration::ZERO).expect("the process had exited when stop_instances returned");
    assert!(!has_running_instance(&task.0).unwrap());
    assert!(!has_unended_instance(&task.0, &image).unwrap());
}

/// Elevated (CI only).
#[test]
fn task_xml_returns_the_registered_definition() {
    let task = ThrowawayTask::new("xml");
    task.register(FOREVER_TASK_XML);
    let xml = task_xml(&task.0).unwrap().expect("the task is registered");
    assert!(xml.contains("PING.EXE"), "{xml}");
}

/// Elevated (CI only).
#[test]
fn task_xml_of_the_agent_task_is_recognised_as_the_group_form() {
    let task = ThrowawayTask::new("xml-group");
    task.register(&crate::provision::schtasks::agent_task_xml(
        r"C:\Windows\System32\cmd.exe",
    ));
    let xml = task_xml(&task.0).unwrap().unwrap();
    assert!(crate::provision::schtasks::xml_is_group_logon_task(&xml), "{xml}");
}
