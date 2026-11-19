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

/// 1053: the service's control handler did not answer the STOP in time.
const REQUEST_TIMEOUT: u32 = 1053;

#[test]
fn a_stop_answered_with_1053_that_leaves_sshd_running_waits_for_the_old_process() {
    assert_eq!(REQUEST_TIMEOUT, ERROR_SERVICE_REQUEST_TIMEOUT.0);
    assert!(waits_for_the_old_process(Some(REQUEST_TIMEOUT), ServiceState::Running));
}

#[test]
fn no_other_answer_to_a_stop_that_leaves_sshd_running_waits_for_the_old_process() {
    // 1051: a control the service cannot take (a dependent service runs); 1061: it is not accepting controls; 5:
    // access denied. An accepted STOP is `None`.
    for reply in [Some(1051), Some(1061), Some(5), Some(1056), None] {
        assert!(
            !waits_for_the_old_process(reply, ServiceState::Running),
            "a STOP answered with {reply:?} is not waited on"
        );
    }
}

#[test]
fn a_1053_that_leaves_sshd_paused_or_stopped_is_not_waited_on() {
    for state in [ServiceState::Paused, ServiceState::Stopped] {
        assert!(!waits_for_the_old_process(Some(REQUEST_TIMEOUT), state), "{state}");
    }
}

// the wait for a started process -----

/// The looks at a process's sockets are of this machine's real table, and the processes are this test's own.
#[test]
fn a_process_that_listens_is_serving_and_the_reply_is_kept() {
    let _listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    let own = Process::open(std::process::id()).unwrap().expect("this process runs");
    let refused = StartReply::Refused("An instance of the service is already running. (1056)".to_owned());
    assert_eq!(
        listening_or_exit(&own, StartReply::Accepted),
        StartOutcome::Serving(StartReply::Accepted)
    );
    assert_eq!(listening_or_exit(&own, refused.clone()), StartOutcome::Serving(refused));
}

#[test]
fn a_process_that_exits_without_listening_is_exited_with_its_code_and_the_reply_is_kept() {
    use std::os::windows::process::CommandExt;
    let cmd =
        std::path::PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot is set")).join(r"System32\cmd.exe");
    let mut child = std::process::Command::new(cmd)
        .args(["/d", "/c", "exit 5"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .creation_flags(0x0800_0000)
        .spawn()
        .unwrap();
    let process = Process::open(child.id())
        .unwrap()
        .expect("the child's handle keeps it openable");
    assert_eq!(
        listening_or_exit(&process, StartReply::Accepted),
        StartOutcome::Exited {
            reply: StartReply::Accepted,
            code: 5
        }
    );
    child.wait().unwrap();
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
