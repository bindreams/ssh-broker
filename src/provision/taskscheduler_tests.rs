//! Tests for the Task Scheduler wrapper. The ones marked Elevated register a throwaway task and
//! run in CI only; they refuse to start anywhere else. Starting a task in a second user's
//! session cannot be tested in CI at all: the acceptance procedure covers it.
use super::*;
use crate::test_support::ThrowawayTask;
use windows::Win32::System::TaskScheduler::{TASK_STATE_QUEUED, TASK_STATE_READY, TASK_STATE_RUNNING};

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

fn state_of(name: &str) -> i32 {
    let _com = Com::init().unwrap();
    let service = connect().unwrap();
    let task = registered_task(&service, name)
        .unwrap()
        .expect("the task is registered");
    unsafe { task.State() }.unwrap().0
}

#[test]
fn stop_instances_succeeds_for_a_task_that_does_not_exist() {
    // Nothing is registered under this name, here or in CI: the no-task case is not an error.
    let name = format!("ssh-broker-test-absent-{}", std::process::id());
    stop_instances(&name).unwrap();
}

#[test]
fn run_in_session_rejects_session_zero_before_it_calls_the_service() {
    // Session 0 is the services session, and `RunEx` into it would start a task where nobody is
    // logged on. The wrapper refuses without touching the Task Scheduler (the task does not
    // exist, so a call through would fail differently).
    let err = run_in_session("ssh-broker-test-never-registered", 0).unwrap_err();
    assert!(format!("{err:#}").contains("session 0"), "{err:#}");
}

/// Elevated (CI only).
#[test]
fn stop_instances_succeeds_for_a_task_that_is_not_running() {
    let task = ThrowawayTask::new("stop-idle");
    task.register(FOREVER_TASK_XML);
    assert_eq!(state_of(&task.0), TASK_STATE_READY.0, "control: nothing is running");

    stop_instances(&task.0).unwrap();
}

/// Elevated (CI only).
#[test]
fn stop_instances_ends_a_running_instance() {
    let task = ThrowawayTask::new("stop-running");
    task.register(FOREVER_TASK_XML);
    {
        let _com = Com::init().unwrap();
        let service = connect().unwrap();
        let registered = registered_task(&service, &task.0).unwrap().unwrap();
        unsafe { registered.Run(&windows::Win32::System::Variant::VARIANT::default()) }.unwrap();
    }
    let started = state_of(&task.0);
    assert!(
        started == TASK_STATE_RUNNING.0 || started == TASK_STATE_QUEUED.0,
        "control: the task was started (state {started})"
    );

    stop_instances(&task.0).unwrap();
    assert_eq!(state_of(&task.0), TASK_STATE_READY.0, "the instance was stopped");
}
