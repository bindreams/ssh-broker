//! Tests for choosing the sessions `apply` starts an agent in.
use super::*;

fn session(id: u32, state: SessionState, has_user: bool) -> SessionInfo {
    SessionInfo { id, state, has_user }
}

#[test]
fn target_sessions_skips_session_zero_and_sessions_without_a_user() {
    let all = [
        session(0, SessionState::Active, true),
        session(1, SessionState::Active, true),
        session(2, SessionState::Active, false), // the logon screen of a session nobody uses
        session(65536, SessionState::Other, false),
    ];
    assert_eq!(target_sessions(&all), [1]);
}

#[test]
fn target_sessions_includes_active_and_disconnected_users() {
    // A disconnected RDP session is still logged on, and its user's SSH logins need an agent.
    let all = [
        session(1, SessionState::Active, true),
        session(3, SessionState::Disconnected, true),
        session(4, SessionState::Other, true), // connecting, listening, shadowing, ...
    ];
    assert_eq!(target_sessions(&all), [1, 3]);
}

#[test]
fn target_sessions_is_empty_when_nobody_is_logged_on() {
    assert_eq!(target_sessions(&[]), Vec::<u32>::new());
    assert_eq!(
        target_sessions(&[
            session(0, SessionState::Active, false),
            session(1, SessionState::Active, false)
        ]),
        Vec::<u32>::new()
    );
}

#[test]
fn interactive_sessions_reads_this_host_and_never_names_session_zero() {
    // Read-only: enumerates sessions and asks each for its user name.
    let ids = interactive_sessions().unwrap();
    assert!(!ids.contains(&0), "{ids:?}");
}
