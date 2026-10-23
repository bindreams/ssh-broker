//! Host tests for the per-profile socket location rule.
use super::*;
use std::path::{Path, PathBuf};

/// A profile path (Windows drive-style, so the tests read the same on every host) padded so the
/// socket path is exactly `bytes` long.
fn profile_for_socket_path_of(bytes: usize) -> PathBuf {
    let fixed = for_profile(Path::new(r"C:\Users\x")).unwrap().path.as_os_str().len();
    let pad = bytes - fixed;
    PathBuf::from(format!(r"C:\Users\x{}", "x".repeat(pad)))
}

#[test]
fn for_profile_puts_the_socket_in_appdata_local_ssh_broker() {
    let profile = Path::new(r"C:\Users\alice");
    let loc = for_profile(profile).unwrap();
    assert_eq!(loc.dir, profile.join("AppData").join("Local").join("ssh-broker"));
    assert_eq!(loc.path, loc.dir.join("agent.sock"));
}

#[test]
fn lock_and_logs_live_inside_the_socket_dir() {
    let loc = for_profile(Path::new(r"C:\Users\alice")).unwrap();
    assert_eq!(loc.lock_path(), loc.dir.join("agent.lock"));
    assert_eq!(loc.logs_dir(), loc.dir.join("logs"));
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
    // Each U+3042 is one character and three bytes. 30 of them with the fixed parts stays under
    // 107 characters and over 107 bytes; the same number of ASCII characters fits.
    let base = r"C:\Users\";
    let wide_name = "\u{3042}".repeat(30);
    let ascii_name = "a".repeat(30);
    let wide = for_profile(Path::new(&format!("{base}{wide_name}")));
    let ascii = for_profile(Path::new(&format!("{base}{ascii_name}")));
    assert!(ascii.is_ok(), "30 ASCII characters fit");
    let chars = format!("{base}{wide_name}").chars().count();
    assert!(chars < MAX_SOCKET_PATH_BYTES, "the profile is under the limit in characters");
    assert!(
        matches!(wide, Err(SocketLocationError::TooLong { .. })),
        "but over it in bytes"
    );
}

#[test]
fn for_profile_keeps_spaces_in_the_profile() {
    let loc = for_profile(Path::new(r"C:\Users\John Smith")).unwrap();
    assert!(loc.path.starts_with(r"C:\Users\John Smith"));
    assert!(loc.path.to_string_lossy().contains("John Smith"));
}

#[test]
fn too_long_message_names_path_bytes_and_limit() {
    let profile = profile_for_socket_path_of(MAX_SOCKET_PATH_BYTES + 3);
    let err = for_profile(&profile).unwrap_err();
    let path = format!("{}", profile.join("AppData").join("Local").join("ssh-broker").join("agent.sock").display());
    assert_eq!(
        err.to_string(),
        format!(
            "the socket path {path} is {} bytes; the AF_UNIX limit is 107. ssh-broker keeps the socket \
             inside your profile so that only you can reach it and will not move it; use a shorter profile path",
            MAX_SOCKET_PATH_BYTES + 3
        )
    );
}

#[test]
fn different_profiles_never_share_a_socket() {
    let a = for_profile(Path::new(r"C:\Users\alice")).unwrap();
    let b = for_profile(Path::new(r"C:\Users\bob")).unwrap();
    assert_ne!(a.dir, b.dir);
    assert_ne!(a.path, b.path);
}
