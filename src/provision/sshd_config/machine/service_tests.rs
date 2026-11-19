//! Host tests for what is pure in the service module: how a state the service manager reports is read. The
//! waits and the controls need a real service, and `tests/sshd_config_windows.rs` measures them in CI.
use super::*;

#[test]
fn running_paused_and_stopped_are_settled() {
    assert_eq!(classify(SERVICE_RUNNING.0), Reading::Settled(ServiceState::Running));
    assert_eq!(classify(SERVICE_PAUSED.0), Reading::Settled(ServiceState::Paused));
    assert_eq!(classify(SERVICE_STOPPED.0), Reading::Settled(ServiceState::Stopped));
}

#[test]
fn every_pending_state_is_waited_for_and_never_returned() {
    for pending in [
        SERVICE_START_PENDING,
        SERVICE_STOP_PENDING,
        SERVICE_CONTINUE_PENDING,
        SERVICE_PAUSE_PENDING,
    ] {
        assert_eq!(classify(pending.0), Reading::Pending, "state {}", pending.0);
    }
}

#[test]
fn a_state_that_is_none_of_the_seven_is_not_guessed_at() {
    assert_eq!(classify(0), Reading::Unknown(0));
    assert_eq!(classify(8), Reading::Unknown(8));
}

fn a_notification() -> *mut Notification {
    Box::into_raw(Box::new(Notification {
        buffer: SERVICE_NOTIFY_2W::default(),
        fired: AtomicBool::new(false),
    }))
}

#[test]
fn a_notification_is_freed_after_its_handle_was_closed() {
    assert_eq!(release(a_notification(), Ok(())), ReleaseOutcome::Freed);
}

/// A late callback may still write into a notification whose registration was not ended: it is never freed.
#[test]
fn a_notification_whose_handle_could_not_be_closed_is_left_alone() {
    let notification = a_notification();
    let failed = windows::core::Error::from(windows::Win32::Foundation::E_FAIL);
    assert_eq!(release(notification, Err(failed)), ReleaseOutcome::Leaked);
    // SAFETY: `release` left it allocated; this test frees what it made.
    drop(unsafe { Box::from_raw(notification) });
}

#[test]
fn the_notification_mask_is_the_settled_states_and_no_pending_one() {
    assert_eq!(
        SETTLED_MASK,
        SERVICE_NOTIFY_RUNNING | SERVICE_NOTIFY_PAUSED | SERVICE_NOTIFY_STOPPED
    );
}
