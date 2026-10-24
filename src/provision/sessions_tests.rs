//! Tests for choosing the sessions `apply` starts an agent in.
use super::*;

fn session(id: u32, state: SessionState, has_user: bool) -> SessionInfo {
    SessionInfo {
        id,
        state,
        has_user: Ok(has_user),
    }
}

fn unreadable(id: u32, state: SessionState) -> SessionInfo {
    SessionInfo {
        id,
        state,
        has_user: Err("access denied".to_string()),
    }
}

#[test]
fn target_sessions_skips_session_zero_and_sessions_without_a_user() {
    let all = [
        session(0, SessionState::Active, true),
        session(1, SessionState::Active, true),
        session(2, SessionState::Active, false), // the logon screen of a session nobody uses
        session(65536, SessionState::Other, false),
    ];
    assert_eq!(target_sessions(&all).ids, [1]);
}

#[test]
fn target_sessions_includes_active_and_disconnected_users() {
    // A disconnected RDP session is still logged on, and its user's SSH logins need an agent.
    let all = [
        session(1, SessionState::Active, true),
        session(3, SessionState::Disconnected, true),
        session(4, SessionState::Other, true), // connecting, listening, shadowing, ...
    ];
    assert_eq!(target_sessions(&all).ids, [1, 3]);
}

#[test]
fn target_sessions_is_empty_when_nobody_is_logged_on() {
    assert_eq!(target_sessions(&[]), Targets::default());
    assert_eq!(
        target_sessions(&[
            session(0, SessionState::Active, false),
            session(1, SessionState::Active, false)
        ]),
        Targets::default()
    );
}

#[test]
fn interactive_sessions_reads_this_host_and_never_names_session_zero() {
    // Read-only: enumerates sessions and asks each for its user name.
    let targets = interactive_sessions().unwrap();
    assert!(!targets.ids.contains(&0), "{targets:?}");
    assert!(targets.unknown.iter().all(|(id, _)| *id != 0), "{targets:?}");
}

#[test]
fn a_session_whose_user_query_failed_is_reported_and_counted_not_dropped() {
    let all = [
        session(1, SessionState::Active, true),
        unreadable(3, SessionState::Disconnected),
    ];
    let targets = target_sessions(&all);
    assert_eq!(targets.ids, [1]);
    assert_eq!(targets.unknown, [(3, "access denied".to_string())]);
    assert_eq!(targets.total(), 2, "the failed session counts in the total");
}

#[test]
fn a_failed_query_for_a_session_that_would_be_skipped_anyway_is_not_reported() {
    // Session 0 is never a target, and a session that is neither active nor disconnected has
    // nobody to serve: neither's unreadable name is a missed agent.
    let all = [unreadable(0, SessionState::Active), unreadable(2, SessionState::Other)];
    assert_eq!(target_sessions(&all), Targets::default());
}

#[test]
fn a_null_session_list_is_an_empty_list() {
    // SAFETY: a null list with a zero count is the empty case `entries` documents.
    assert!(unsafe { entries(std::ptr::null(), 0) }.is_empty());
}

#[test]
fn a_session_list_is_read_up_to_its_count() {
    let raw = [
        WTS_SESSION_INFOW {
            SessionId: 4,
            ..Default::default()
        },
        WTS_SESSION_INFOW {
            SessionId: 9,
            ..Default::default()
        },
    ];
    // SAFETY: `raw` holds two initialised entries and outlives the borrow.
    let read = unsafe { entries(raw.as_ptr(), 2) };
    assert_eq!(read.iter().map(|s| s.SessionId).collect::<Vec<_>>(), [4, 9]);
}
