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
    assert_eq!(events, ["stop", "install", "resume", "start"]);
}

#[test]
fn agents_that_were_stopped_start_again_when_a_later_step_fails() {
    let (events, result) = flow(true, || Ok(()), false, true);
    assert_eq!(format!("{:#}", result.unwrap_err()), "register failed");
    assert_eq!(events, ["stop", "install", "resume", "safe?", "start"]);
}

#[test]
fn agents_survive_a_failed_stop_in_the_sessions_the_start_is_told_to_leave_alone() {
    use crate::provision::procwait::{StillRunning, Survivor};
    let left = vec![Survivor {
        pid: 5,
        session: Some(2),
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
    assert_eq!(events, ["stop", "resume", "safe?", "start"]);
}

#[test]
fn nothing_starts_when_no_agent_was_stopped() {
    let (events, result) = flow(false, || Ok(()), false, true);
    assert!(result.is_err());
    assert_eq!(events, ["install", "resume"]);
}

#[test]
fn the_task_is_enabled_again_even_when_no_agent_was_stopped() {
    // The exe may be unchanged and nothing stopped, and the task still disabled by an earlier
    // `apply` that was killed between its disable and its enable.
    let (events, result) = flow(false, || Ok(()), true, true);
    result.unwrap();
    assert_eq!(events, ["install", "resume", "start"]);
}

#[test]
fn an_apply_that_could_not_enable_the_task_fails_and_starts_nothing() {
    // A disabled task starts no agent at any logon, so the install did not take.
    let (events, result) = flow_resuming(true, || Ok(()), true, true, || anyhow::bail!("access denied"));
    assert!(format!("{:#}", result.unwrap_err()).contains("access denied"));
    assert_eq!(events, ["stop", "install", "resume"]);
}

#[test]
fn a_failed_install_is_reported_as_it_was_when_the_task_could_not_be_enabled_either() {
    let (events, result) = flow_resuming(true, || Ok(()), false, true, || anyhow::bail!("access denied"));
    assert_eq!(format!("{:#}", result.unwrap_err()), "register failed");
    assert_eq!(
        events,
        ["stop", "install", "resume"],
        "no start: the task cannot start one"
    );
}

#[test]
fn nothing_starts_when_the_registered_task_cannot_start_an_agent() {
    let (events, result) = flow(true, || Ok(()), false, false);
    assert!(result.is_err());
    assert_eq!(events, ["stop", "install", "resume", "safe?"]);
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
        },
        Survivor {
            pid: 6,
            session: Some(2),
        },
    ];
    let plan = plan_start(&[1, 2, 3], &survivors);
    assert_eq!(plan.start, [1, 3]);
    assert_eq!(plan.held, [(2, vec![5, 6])]);
}

#[test]
fn a_survivor_in_an_unknown_session_holds_every_session() {
    use crate::provision::procwait::Survivor;
    let plan = plan_start(&[1, 2], &[Survivor { pid: 9, session: None }]);
    assert!(plan.start.is_empty());
    assert_eq!(plan.held, [(1, vec![9]), (2, vec![9])]);
}

#[test]
fn every_session_starts_when_nothing_survived() {
    let plan = plan_start(&[1, 2], &[]);
    assert_eq!(plan.start, [1, 2]);
    assert!(plan.held.is_empty());
}
