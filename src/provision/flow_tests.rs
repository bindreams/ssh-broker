use super::*;
use std::cell::RefCell;

/// Run the flow with an `install` that stops (or not) and then fails (or not); return the
/// events in order and the result.
fn flow(
    stops: bool,
    stop_result: fn() -> anyhow::Result<()>,
    install_ok: bool,
    safe: bool,
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
        || events.borrow_mut().push("resume"),
        || events.borrow_mut().push("start"),
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
fn agents_start_again_when_the_stop_failed_part_way() {
    let (events, result) = flow(true, || anyhow::bail!("access denied"), true, true);
    assert_eq!(format!("{:#}", result.unwrap_err()), "access denied");
    assert_eq!(events, ["stop", "resume", "safe?", "start"]);
}

#[test]
fn nothing_starts_when_no_agent_was_stopped() {
    let (events, result) = flow(false, || Ok(()), false, true);
    assert!(result.is_err());
    assert_eq!(events, ["install"]);
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
