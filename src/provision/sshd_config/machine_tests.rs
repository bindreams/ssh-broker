//! Host tests for the pure parts of `machine`; the machine itself is measured by `tests/sshd_config_windows.rs`,
//! which CI runs.
use super::*;

#[test]
fn the_service_manager_s_states_are_running_stopped_or_changing_by_name() {
    let named = |code: u32| state_of(SERVICE_STATUS_CURRENT_STATE(code));
    assert_eq!(named(1), ServiceState::Stopped);
    assert_eq!(named(4), ServiceState::Running);
    assert_eq!(named(2), ServiceState::Changing("starting".into()));
    assert_eq!(named(3), ServiceState::Changing("stopping".into()));
    assert_eq!(named(5), ServiceState::Changing("continuing".into()));
    assert_eq!(named(6), ServiceState::Changing("pausing".into()));
    assert_eq!(named(7), ServiceState::Changing("paused".into()));
    assert_eq!(named(99), ServiceState::Changing("in state 99".into()));
}
