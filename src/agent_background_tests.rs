//! Unit tests for `agent_background` (no account, no logon, no window).
use super::*;
use crate::account::Elevation;
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
    assert_eq!(Refusal::Filtered.code(), 68);
    assert_eq!(Refusal::ElevationUnreadable.code(), 69);
}

#[test]
fn an_agent_is_allowed_with_a_full_or_a_standard_token() {
    for elevation in [Elevation::Full, Elevation::Standard] {
        assert_eq!(check_start(None, 1, ME, elevation), Ok(()));
        assert_eq!(check_start(Some(&background(Some(ME))), 2, ME, elevation), Ok(()));
    }
}

#[test]
fn an_agent_with_a_filtered_token_is_refused_in_desktop_mode() {
    assert_eq!(check_start(None, 1, ME, Elevation::Filtered), Err(Refusal::Filtered));
}

#[test]
fn an_agent_with_a_filtered_token_is_refused_in_background_mode() {
    for args in [background(Some(ME)), background(None)] {
        assert_eq!(
            check_start(Some(&args), 2, ME, Elevation::Filtered),
            Err(Refusal::Filtered)
        );
    }
}

#[test]
fn the_filtered_check_runs_before_every_other_check() {
    // Not session 0 (65), not another account's agent (64): a filtered agent never starts.
    assert_eq!(check_start(None, 0, ME, Elevation::Filtered), Err(Refusal::Filtered));
    assert_eq!(
        check_start(Some(&background(Some(OTHER))), 0, ME, Elevation::Filtered),
        Err(Refusal::Filtered)
    );
}

#[test]
fn a_desktop_agent_is_refused_in_session_zero_and_allowed_elsewhere() {
    assert_eq!(
        check_start(None, 0, ME, Elevation::Standard),
        Err(Refusal::SessionRefused)
    );
    assert_eq!(check_start(None, 1, ME, Elevation::Standard), Ok(()));
}

#[test]
fn a_background_agent_is_allowed_in_any_session_including_zero() {
    let args = background(Some(ME));
    assert_eq!(check_start(Some(&args), 0, ME, Elevation::Standard), Ok(()));
    assert_eq!(check_start(Some(&args), 2, ME, Elevation::Standard), Ok(()));
}

#[test]
fn a_background_agent_whose_token_is_not_the_expected_user_is_refused() {
    let args = background(Some(OTHER));
    assert_eq!(
        check_start(Some(&args), 2, ME, Elevation::Standard),
        Err(Refusal::WrongUser)
    );
    assert_eq!(
        check_start(Some(&args), 0, ME, Elevation::Standard),
        Err(Refusal::WrongUser)
    );
}

#[test]
fn the_user_check_runs_before_the_session_check() {
    // A desktop agent has no expected user; a background agent is never refused for its session.
    let args = background(Some(OTHER));
    assert_eq!(
        check_start(Some(&args), 0, ME, Elevation::Standard),
        Err(Refusal::WrongUser)
    );
}

#[test]
fn a_hand_started_background_agent_without_an_expected_user_serves_its_own_account() {
    assert_eq!(check_start(Some(&background(None)), 2, ME, Elevation::Standard), Ok(()));
}

#[test]
fn the_expected_user_is_compared_exactly() {
    let args = background(Some("s-1-5-21-1-2-3-1001"));
    assert_eq!(
        check_start(Some(&args), 2, ME, Elevation::Standard),
        Err(Refusal::WrongUser)
    );
}

#[test]
fn mark_listening_writes_the_marker_in_the_socket_folder() {
    let profile = TempProfile::new("mark");
    let loc = profile.location();
    std::fs::create_dir_all(loc.dir()).unwrap();
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
