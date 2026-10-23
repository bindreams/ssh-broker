//! Tests for the current user's profile and socket location.
//!
//! Anything that needs a second account or elevation lives in `userdir_isolation_tests.rs`.
use super::*;
use crate::winutil::OwnedHandle;
use std::path::PathBuf;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::TOKEN_QUERY;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

fn own_token() -> OwnedHandle {
    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.unwrap();
    OwnedHandle(token)
}

#[test]
fn current_profile_matches_userprofile_of_this_process() {
    let profile = profile_dir_of_token(own_token().0).unwrap();
    let env = PathBuf::from(std::env::var_os("USERPROFILE").expect("USERPROFILE is set for a test run"));
    assert_eq!(
        profile.to_string_lossy().to_lowercase(),
        env.to_string_lossy().to_lowercase()
    );
}

#[test]
fn current_socket_location_lies_inside_the_profile() {
    let profile = profile_dir_of_token(own_token().0).unwrap();
    let loc = current_socket_location().unwrap();
    assert!(loc.path.starts_with(&profile));
    assert!(loc.path.ends_with(r"AppData\Local\ssh-broker\agent.sock"));
}

#[test]
fn current_socket_location_fits_sockaddr_un() {
    let loc = current_socket_location().unwrap();
    assert!(crate::afunix::unix_addr(&loc.path).is_ok());
}

#[test]
fn profile_dir_of_token_rejects_an_invalid_handle() {
    let err = profile_dir_of_token(HANDLE::default()).unwrap_err();
    assert!(!format!("{err:#}").is_empty());
}

#[test]
fn for_profile_limit_agrees_with_unix_addr() {
    // Pins `MAX_SOCKET_PATH_BYTES` to what `socket2` accepts on this platform.
    let profile_named = |name: &str| PathBuf::from(format!(r"C:\Users\{name}"));
    let fixed = crate::socket_loc::for_profile(&profile_named("x"))
        .unwrap()
        .path
        .as_os_str()
        .len();
    for bytes in 105..=109 {
        let profile = profile_named(&"x".repeat(1 + bytes - fixed));
        let location = crate::socket_loc::for_profile(&profile);
        let path = profile
            .join("AppData")
            .join("Local")
            .join(crate::socket_loc::SOCKET_DIR_NAME)
            .join(crate::socket_loc::SOCKET_FILE_NAME);
        assert_eq!(
            location.is_ok(),
            crate::afunix::unix_addr(&path).is_ok(),
            "at {bytes} bytes"
        );
    }
}

// Re-run as a child with a decoy environment -----

const CHILD_FLAG: &str = "SSH_BROKER_USERDIR_TEST_CHILD";

/// Not a test of its own: when the parent below re-runs this binary with the flag set, it prints
/// the location the process resolves. Without the flag it passes at once.
#[test]
fn child_prints_its_socket_location() {
    if std::env::var_os(CHILD_FLAG).is_none() {
        return;
    }
    let loc = current_socket_location().unwrap();
    println!("LOCATION={}", loc.path.display());
}

#[test]
fn current_socket_location_ignores_decoy_environment() {
    // The environment is the caller's to set; the token is not. A resolver that read
    // %USERPROFILE% or %LOCALAPPDATA% would follow the decoy into another account's folder.
    let expected = current_socket_location().unwrap().path;
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "userdir::userdir_tests::child_prints_its_socket_location",
            "--nocapture",
        ])
        .env(CHILD_FLAG, "1")
        .env("USERPROFILE", r"C:\decoy\profile")
        .env("LOCALAPPDATA", r"C:\decoy\profile\AppData\Local")
        .env("APPDATA", r"C:\decoy\profile\AppData\Roaming")
        .env("HOMEDRIVE", "C:")
        .env("HOMEPATH", r"\decoy\profile")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "child failed: {stdout} {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let line = stdout
        .lines()
        .find_map(|l| l.strip_prefix("LOCATION="))
        .unwrap_or_else(|| panic!("the child printed no location: {stdout}"));
    assert_eq!(PathBuf::from(line), expected);
}
