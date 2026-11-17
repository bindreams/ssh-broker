//! Host tests for the per-profile socket location rule.
use super::*;
use std::path::PathBuf;

/// A Windows-style profile path, so the tests read the same on every host.
fn profile(name: &str) -> PathBuf {
    PathBuf::from(format!(r"C:\Users\{name}"))
}

/// A profile padded so the socket path is exactly `bytes` long.
fn profile_for_socket_path_of(bytes: usize, integrity: Integrity) -> PathBuf {
    let fixed = for_profile(&profile("x"), integrity).unwrap().path.as_os_str().len();
    profile(&"x".repeat(1 + bytes - fixed))
}

#[test]
fn for_profile_puts_the_socket_in_appdata_local_ssh_broker() {
    let profile = profile("a");
    let loc = for_profile(&profile, Integrity::Medium).unwrap();
    assert_eq!(loc.dir, profile.join("AppData").join("Local").join("ssh-broker"));
    assert_eq!(loc.path, loc.dir.join("agent.sock"));
}

#[test]
fn the_folder_is_the_profile_walked_through_the_named_folders_and_the_private_one() {
    let loc = for_profile(&profile("a"), Integrity::Medium).unwrap();
    let mut walked = loc.profile_dir().to_path_buf();
    for name in FOLDERS_IN_PROFILE.iter().chain(&[SOCKET_DIR_NAME]) {
        walked.push(name);
    }
    assert_eq!(loc.dir(), walked);
}

#[test]
fn lock_and_logs_live_inside_the_socket_dir() {
    let loc = for_profile(&profile("a"), Integrity::Medium).unwrap();
    assert_eq!(loc.lock_path(), loc.dir.join("agent.lock"));
    assert_eq!(loc.logs_dir(), loc.dir.join("logs"));
}

#[test]
fn the_session_slots_share_one_lock_file_inside_the_socket_dir() {
    let loc = for_profile(&profile("a"), Integrity::Medium).unwrap();
    assert_eq!(loc.sessions_lock_path(), loc.dir.join("sessions.lock"));
    assert_ne!(loc.sessions_lock_path(), loc.lock_path(), "not the user lock");
}

#[test]
fn the_serving_marker_lives_inside_the_socket_dir() {
    let loc = for_profile(&profile("a"), Integrity::Medium).unwrap();
    assert_eq!(loc.serving_marker_path(), loc.dir.join("serving"));
}

#[test]
fn for_profile_accepts_exactly_107_bytes_and_rejects_108() {
    let ok = for_profile(
        &profile_for_socket_path_of(MAX_SOCKET_PATH_BYTES, Integrity::Medium),
        Integrity::Medium,
    )
    .unwrap();
    assert_eq!(ok.path.as_os_str().len(), MAX_SOCKET_PATH_BYTES);

    let too_long = profile_for_socket_path_of(MAX_SOCKET_PATH_BYTES + 1, Integrity::Medium);
    match for_profile(&too_long, Integrity::Medium).unwrap_err() {
        SocketLocationError::TooLong { path, bytes, max } => {
            assert_eq!(bytes, MAX_SOCKET_PATH_BYTES + 1);
            assert_eq!(max, MAX_SOCKET_PATH_BYTES);
            assert_eq!(path.as_os_str().len(), bytes);
        }
    }
}

#[test]
fn for_profile_counts_utf8_bytes_not_characters() {
    // Each U+3042 is one character and three bytes. 30 of them stay under 107 characters and go
    // over 107 bytes; the same number of ASCII characters fits.
    let wide_profile = profile(&"\u{3042}".repeat(30));
    let wide = for_profile(&wide_profile, Integrity::Medium);
    let ascii = for_profile(&profile(&"a".repeat(30)), Integrity::Medium);
    assert!(ascii.is_ok(), "30 ASCII characters fit");
    let chars = wide_profile.to_string_lossy().chars().count();
    assert!(
        chars < MAX_SOCKET_PATH_BYTES,
        "the profile is under the limit in characters"
    );
    assert!(
        matches!(wide, Err(SocketLocationError::TooLong { .. })),
        "but over it in bytes"
    );
}

#[test]
fn for_profile_keeps_spaces_in_the_profile() {
    let spaced = profile("Two Words");
    let loc = for_profile(&spaced, Integrity::Medium).unwrap();
    assert!(loc.path.starts_with(&spaced));
    assert!(loc.path.to_string_lossy().contains("Two Words"));
}

#[test]
fn too_long_message_names_path_bytes_and_limit() {
    let profile = profile_for_socket_path_of(MAX_SOCKET_PATH_BYTES + 3, Integrity::Medium);
    let err = for_profile(&profile, Integrity::Medium).unwrap_err();
    let path = profile
        .join("AppData")
        .join("Local")
        .join("ssh-broker")
        .join("agent.sock");
    assert_eq!(
        err.to_string(),
        format!(
            "the socket path {} is {} bytes; the AF_UNIX limit is 107. ssh-broker keeps the socket \
             inside your profile so that only you can reach it and will not move it; use a shorter profile path",
            path.display(),
            MAX_SOCKET_PATH_BYTES + 3
        )
    );
}

#[test]
fn different_profiles_never_share_a_socket() {
    let a = for_profile(&profile("a"), Integrity::Medium).unwrap();
    let b = for_profile(&profile("b"), Integrity::Medium).unwrap();
    assert_ne!(a.dir, b.dir);
    assert_ne!(a.path, b.path);
}

#[test]
fn the_location_keeps_the_profile_it_was_made_from() {
    let profile = profile("a");
    assert_eq!(
        for_profile(&profile, Integrity::Medium).unwrap().profile_dir(),
        profile.as_path()
    );
}

// The elevated folder -----

#[test]
fn a_high_location_is_in_the_elevated_folder_and_a_medium_one_in_the_plain_folder() {
    let profile = profile("a");
    let local = profile.join("AppData").join("Local");
    let high = for_profile(&profile, Integrity::High).unwrap();
    let medium = for_profile(&profile, Integrity::Medium).unwrap();
    assert_eq!(high.dir(), local.join("ssh-broker-elevated"));
    assert_eq!(medium.dir(), local.join("ssh-broker"));
    assert_eq!(high.integrity(), Integrity::High);
    assert_eq!(medium.integrity(), Integrity::Medium);
    assert_eq!(ELEVATED_SOCKET_DIR_NAME, "ssh-broker-elevated");
}

#[test]
fn everything_the_agent_keeps_follows_the_folder_of_its_integrity() {
    let loc = for_profile(&profile("a"), Integrity::High).unwrap();
    assert_eq!(loc.path(), loc.dir().join("agent.sock"));
    assert_eq!(loc.lock_path(), loc.dir().join("agent.lock"));
    assert_eq!(loc.sessions_lock_path(), loc.dir().join("sessions.lock"));
    assert_eq!(loc.serving_marker_path(), loc.dir().join("serving"));
    assert_eq!(loc.logs_dir(), loc.dir().join("logs"));
}

#[test]
fn the_walk_to_the_elevated_folder_ends_at_it() {
    let loc = for_profile(&profile("a"), Integrity::High).unwrap();
    let mut walked = loc.profile_dir().to_path_buf();
    for name in FOLDERS_IN_PROFILE.iter().chain(&[ELEVATED_SOCKET_DIR_NAME]) {
        walked.push(name);
    }
    assert_eq!(loc.dir(), walked);
}

#[test]
fn the_two_folders_of_one_profile_never_share_a_socket() {
    let high = for_profile(&profile("a"), Integrity::High).unwrap();
    let medium = for_profile(&profile("a"), Integrity::Medium).unwrap();
    assert_ne!(high.dir(), medium.dir());
    assert_ne!(high.path(), medium.path());
}

#[test]
fn the_longest_profile_path_is_71_bytes_for_a_medium_location_and_62_for_a_high_one() {
    let longest = |integrity| {
        let fits = |n: usize| for_profile(&profile(&"x".repeat(n)), integrity).is_ok();
        let n = (1..).take_while(|n| fits(*n)).last().unwrap();
        profile(&"x".repeat(n)).as_os_str().len()
    };
    assert_eq!(longest(Integrity::Medium), 71);
    assert_eq!(longest(Integrity::High), 62);
}

#[test]
fn a_profile_that_fits_the_plain_folder_but_not_the_elevated_one_is_told_the_elevated_socket_is_too_long() {
    let profile = profile_for_socket_path_of(MAX_SOCKET_PATH_BYTES, Integrity::Medium);
    assert!(for_profile(&profile, Integrity::Medium).is_ok());
    match for_profile(&profile, Integrity::High).unwrap_err() {
        SocketLocationError::TooLong { path, bytes, max } => {
            assert_eq!(bytes, MAX_SOCKET_PATH_BYTES + 9);
            assert_eq!(max, MAX_SOCKET_PATH_BYTES);
            assert!(path.ends_with(r"ssh-broker-elevated\agent.sock"), "{}", path.display());
        }
    }
}

#[test]
fn the_socket_file_refusal_names_the_label_only_for_the_elevated_folder() {
    let path = Path::new("agent.sock");
    assert_eq!(
        file_acl_refusal(path, "alice", Integrity::Medium),
        "agent.sock does not grant exactly alice, SYSTEM and Administrators"
    );
    assert_eq!(
        file_acl_refusal(path, "alice", Integrity::High),
        "agent.sock does not grant exactly alice, SYSTEM and Administrators, or lacks the High integrity label"
    );
}
