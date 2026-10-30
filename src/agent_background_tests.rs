//! Unit tests for `agent_background` (no account, no logon, no window).
use super::*;
use crate::test_support::TempProfile;

const ME: &str = "S-1-5-21-1-2-3-1001";
const OTHER: &str = "S-1-5-21-1-2-3-1002";

fn background(expect_user: Option<&str>) -> BackgroundArgs {
    BackgroundArgs {
        expect_user: expect_user.map(str::to_string),
    }
}

#[test]
fn the_exit_codes_are_the_record() {
    assert_eq!(Refusal::WrongUser.code(), 64);
    assert_eq!(Refusal::SessionRefused.code(), 65);
    assert_eq!(Refusal::NoSocketLocation.code(), 66);
    assert_eq!(Refusal::SocketFolderRefused.code(), 67);
}

#[test]
fn a_desktop_agent_is_refused_in_session_zero_and_allowed_elsewhere() {
    assert_eq!(check_start(None, 0, ME), Err(Refusal::SessionRefused));
    assert_eq!(check_start(None, 1, ME), Ok(()));
}

#[test]
fn a_background_agent_is_allowed_in_any_session_including_zero() {
    let args = background(Some(ME));
    assert_eq!(check_start(Some(&args), 0, ME), Ok(()));
    assert_eq!(check_start(Some(&args), 2, ME), Ok(()));
}

#[test]
fn a_background_agent_whose_token_is_not_the_expected_user_is_refused() {
    let args = background(Some(OTHER));
    assert_eq!(check_start(Some(&args), 2, ME), Err(Refusal::WrongUser));
    assert_eq!(check_start(Some(&args), 0, ME), Err(Refusal::WrongUser));
}

#[test]
fn the_user_check_runs_before_the_session_check() {
    // A desktop agent has no expected user; a background agent is never refused for its session.
    let args = background(Some(OTHER));
    assert_eq!(check_start(Some(&args), 0, ME), Err(Refusal::WrongUser));
}

#[test]
fn a_hand_started_background_agent_without_an_expected_user_serves_its_own_account() {
    assert_eq!(check_start(Some(&background(None)), 2, ME), Ok(()));
}

#[test]
fn the_expected_user_is_compared_exactly() {
    let args = background(Some("s-1-5-21-1-2-3-1001"));
    assert_eq!(check_start(Some(&args), 2, ME), Err(Refusal::WrongUser));
}

#[test]
fn mark_listening_writes_the_marker_in_the_socket_folder() {
    let profile = TempProfile::new("mark");
    let loc = profile.location();
    std::fs::create_dir_all(&loc.dir).unwrap();
    mark_listening(&loc).unwrap();
    assert!(loc.serving_marker_path().is_file());
    // Every call is a write, so a watch on the folder wakes each time.
    mark_listening(&loc).unwrap();
}

#[test]
fn mark_listening_fails_when_the_folder_is_missing() {
    let profile = TempProfile::new("mark-missing");
    let loc = profile.location();
    assert!(mark_listening(&loc).is_err());
}
