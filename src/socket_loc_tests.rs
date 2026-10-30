//! Host tests for the per-profile socket location rule.
use super::*;
use std::path::PathBuf;

/// A Windows-style profile path, so the tests read the same on every host.
fn profile(name: &str) -> PathBuf {
    PathBuf::from(format!(r"C:\Users\{name}"))
}

/// A profile padded so the socket path is exactly `bytes` long.
fn profile_for_socket_path_of(bytes: usize) -> PathBuf {
    let fixed = for_profile(&profile("x")).unwrap().path.as_os_str().len();
    profile(&"x".repeat(1 + bytes - fixed))
}

#[test]
fn for_profile_puts_the_socket_in_appdata_local_ssh_broker() {
    let profile = profile("a");
    let loc = for_profile(&profile).unwrap();
    assert_eq!(loc.dir, profile.join("AppData").join("Local").join("ssh-broker"));
    assert_eq!(loc.path, loc.dir.join("agent.sock"));
}

#[test]
fn lock_and_logs_live_inside_the_socket_dir() {
    let loc = for_profile(&profile("a")).unwrap();
    assert_eq!(loc.lock_path(), loc.dir.join("agent.lock"));
    assert_eq!(loc.logs_dir(), loc.dir.join("logs"));
}

#[test]
fn the_session_slots_share_one_lock_file_inside_the_socket_dir() {
    let loc = for_profile(&profile("a")).unwrap();
    assert_eq!(loc.sessions_lock_path(), loc.dir.join("sessions.lock"));
    assert_ne!(loc.sessions_lock_path(), loc.lock_path(), "not the user lock");
}

#[test]
fn the_serving_marker_lives_inside_the_socket_dir() {
    let loc = for_profile(&profile("a")).unwrap();
    assert_eq!(loc.serving_marker_path(), loc.dir.join("serving"));
}

#[test]
fn for_profile_accepts_exactly_107_bytes_and_rejects_108() {
    let ok = for_profile(&profile_for_socket_path_of(MAX_SOCKET_PATH_BYTES)).unwrap();
    assert_eq!(ok.path.as_os_str().len(), MAX_SOCKET_PATH_BYTES);

    let too_long = profile_for_socket_path_of(MAX_SOCKET_PATH_BYTES + 1);
    match for_profile(&too_long).unwrap_err() {
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
    let wide = for_profile(&wide_profile);
    let ascii = for_profile(&profile(&"a".repeat(30)));
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
    let loc = for_profile(&spaced).unwrap();
    assert!(loc.path.starts_with(&spaced));
    assert!(loc.path.to_string_lossy().contains("Two Words"));
}

#[test]
fn too_long_message_names_path_bytes_and_limit() {
    let profile = profile_for_socket_path_of(MAX_SOCKET_PATH_BYTES + 3);
    let err = for_profile(&profile).unwrap_err();
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
    let a = for_profile(&profile("a")).unwrap();
    let b = for_profile(&profile("b")).unwrap();
    assert_ne!(a.dir, b.dir);
    assert_ne!(a.path, b.path);
}
