//! Tests for the per-user rows of the `verify` report.
use super::*;
use crate::acl::{self, Sid};
use crate::socket_loc::{SocketLocationError, for_profile};
use crate::test_support::TempProfile;
use crate::userdir::ensure_socket_dir;

fn me() -> Sid {
    Sid::current_user().unwrap()
}

fn too_long_location() -> anyhow::Result<SocketLocation> {
    let profile = std::path::PathBuf::from(format!(r"C:\Users\{}", "x".repeat(120)));
    Ok(for_profile(&profile)?)
}

// socket location ---------------------------------------------------------------------------

#[test]
fn socket_location_row_fails_with_the_reason_for_a_too_long_profile() {
    let location = too_long_location();
    assert!(
        matches!(
            location.as_ref().unwrap_err().downcast_ref::<SocketLocationError>(),
            Some(SocketLocationError::TooLong { .. })
        ),
        "control: the profile really is too long"
    );

    let row = socket_location_row(&location);

    assert!(!row.pass);
    assert!(row.detail.contains("the AF_UNIX limit is 107"), "{}", row.detail);
}

#[test]
fn socket_location_row_shows_the_path_it_resolved() {
    let profile = TempProfile::new("row-loc");
    let row = socket_location_row(&Ok(profile.location()));
    assert!(row.pass);
    assert_eq!(row.detail, profile.location().path.display().to_string());
}

// socket dir ACL ----------------------------------------------------------------------------

#[test]
fn socket_dir_row_passes_for_this_users_hardened_dir_and_names_the_account() {
    let profile = TempProfile::new("row-dir-ok");
    ensure_socket_dir(&profile.location(), &me()).unwrap();

    let row = socket_dir_row(&Ok(profile.location()), &me());

    assert!(row.pass, "{}", row.detail);
    assert!(
        row.detail.contains(&me().describe()),
        "the grantee is shown: {}",
        row.detail
    );
}

#[test]
fn socket_dir_row_fails_for_a_widened_dir() {
    let profile = TempProfile::new("row-dir-wide");
    let loc = profile.location();
    ensure_socket_dir(&loc, &me()).unwrap();
    let status = std::process::Command::new("icacls")
        .arg(&loc.dir)
        .args(["/grant", "*S-1-1-0:(OI)(CI)F"])
        .status()
        .unwrap();
    assert!(status.success());

    let row = socket_dir_row(&Ok(loc), &me());

    assert!(!row.pass);
    assert!(row.detail.contains("does not grant exactly"), "{}", row.detail);
}

#[test]
fn socket_dir_row_fails_when_the_dir_is_absent() {
    let profile = TempProfile::new("row-dir-absent");

    let row = socket_dir_row(&Ok(profile.location()), &me());

    assert!(!row.pass);
    assert!(row.detail.contains("no agent has made it yet"), "{}", row.detail);
}

#[test]
fn socket_dir_row_fails_when_there_is_no_location() {
    let row = socket_dir_row(&too_long_location(), &me());
    assert!(!row.pass);
    assert!(row.detail.contains("no socket location"), "{}", row.detail);
}

// log folder --------------------------------------------------------------------------------

#[test]
fn log_folder_row_passes_for_this_users_hardened_logs_folder() {
    let profile = TempProfile::new("row-log-ok");
    ensure_socket_dir(&profile.location(), &me()).unwrap();

    let row = log_folder_row(&Ok(profile.location()), &me());

    assert!(row.pass, "{}", row.detail);
}

#[test]
fn log_folder_row_names_the_folder_when_there_is_none() {
    // Neither the agent nor the shim has made it yet, or the shim could not: either way nothing
    // is being logged, and the row says where the log would go.
    let profile = TempProfile::new("row-log-absent");
    let loc = profile.location();

    let row = log_folder_row(&Ok(loc.clone()), &me());

    assert!(!row.pass);
    assert!(
        row.detail.contains(&loc.logs_dir().display().to_string()),
        "{}",
        row.detail
    );
    assert!(row.detail.contains("does not exist"), "{}", row.detail);
}

#[test]
fn log_folder_row_fails_for_a_widened_logs_folder() {
    let profile = TempProfile::new("row-log-wide");
    let loc = profile.location();
    ensure_socket_dir(&loc, &me()).unwrap();
    let status = std::process::Command::new("icacls")
        .arg(loc.logs_dir())
        .args(["/grant", "*S-1-1-0:(OI)(CI)F"])
        .status()
        .unwrap();
    assert!(status.success());

    let row = log_folder_row(&Ok(loc), &me());

    assert!(!row.pass);
    assert!(row.detail.contains("does not grant exactly"), "{}", row.detail);
}

#[test]
fn log_folder_row_fails_when_there_is_no_location() {
    let row = log_folder_row(&too_long_location(), &me());
    assert!(!row.pass);
    assert!(row.detail.contains("no socket location"), "{}", row.detail);
}

// socket file ACL ---------------------------------------------------------------------------

#[test]
fn socket_file_row_passes_for_a_socket_bound_by_this_user() {
    let profile = TempProfile::new("row-file-ok");
    let loc = profile.location();
    ensure_socket_dir(&loc, &me()).unwrap();
    let _listener = crate::afunix::Listener::bind(&loc.path).unwrap();

    let row = socket_file_row(&Ok(loc), &me());

    assert!(row.pass, "{}", row.detail);
}

#[test]
fn socket_file_row_fails_when_no_agent_has_bound() {
    let profile = TempProfile::new("row-file-absent");
    let loc = profile.location();
    ensure_socket_dir(&loc, &me()).unwrap();

    let row = socket_file_row(&Ok(loc), &me());

    assert!(!row.pass);
    assert!(row.detail.contains("no socket"), "{}", row.detail);
}

#[test]
fn socket_file_row_fails_for_a_file_that_grants_someone_else() {
    let profile = TempProfile::new("row-file-wide");
    let loc = profile.location();
    ensure_socket_dir(&loc, &me()).unwrap();
    std::fs::write(&loc.path, "").unwrap();
    let status = std::process::Command::new("icacls")
        .arg(&loc.path)
        .args(["/grant", "*S-1-1-0:(R)"])
        .status()
        .unwrap();
    assert!(status.success());
    assert!(!acl::verify_file_acl(&loc.path, &me()).unwrap(), "control");

    let row = socket_file_row(&Ok(loc), &me());

    assert!(!row.pass);
}

// reachable and the others -------------------------------------------------------------------

#[test]
fn socket_reachable_row_follows_the_connection() {
    let profile = TempProfile::new("row-reach");
    let loc = profile.location();
    ensure_socket_dir(&loc, &me()).unwrap();
    assert!(!socket_reachable_row(&Ok(loc.clone())).pass, "nothing listens yet");

    let _listener = crate::afunix::Listener::bind(&loc.path).unwrap();
    assert!(socket_reachable_row(&Ok(loc)).pass);
}

#[test]
fn socket_reachable_row_tells_the_user_how_to_see_why_the_agent_is_not_there() {
    // An agent the logon task starts has its stderr discarded, and a start-up error before its log
    // opens goes nowhere else. Run by hand in a desktop session, it prints the error.
    let profile = TempProfile::new("row-reach-hint");
    let row = socket_reachable_row(&Ok(profile.location()));

    assert!(!row.pass);
    assert!(row.detail.contains("ssh-broker agent"), "{}", row.detail);
    assert!(row.detail.contains("desktop session"), "{}", row.detail);
}

#[test]
fn socket_reachable_row_fails_without_a_location() {
    assert!(!socket_reachable_row(&too_long_location()).pass);
}

#[test]
fn other_users_row_always_passes_and_says_each_user_runs_their_own_agent() {
    let row = other_users_row();
    assert!(row.pass);
    assert!(row.detail.contains("run verify as that user"), "{}", row.detail);
}
