//! Tests for the current user's profile and socket location.
//!
//! Anything that needs a second account or elevation lives in `tests/user_isolation_windows.rs`.
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
    assert!(format!("{err:#}").contains("no profile directory"), "{err:#}");
}

/// A required length of 0 is the discriminator (measured: a never-logged-on account gets error
/// 0x8007007a with length 0, an account with a profile the same error with a length), so a caller
/// can tell "no profile yet" from every other failure.
#[test]
fn a_zero_length_probe_is_the_typed_no_profile_error() {
    let err = profile_dir_of_token(HANDLE::default()).unwrap_err();
    assert!(err.downcast_ref::<NoProfile>().is_some(), "{err:#}");
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
const DECOY_PROFILE: &str = r"C:\decoy\profile";

/// Child half of [`current_socket_location_ignores_decoy_environment`], started only by it. Knows
/// it is the child from [`CHILD_FLAG`] and panics without it, so a bare `--ignored` run is not a
/// pass. Prints the location it resolves, after checking that the decoy reached it; the parent
/// fails when the line is missing.
#[test]
#[ignore = "run as a child of current_socket_location_ignores_decoy_environment"]
fn child_prints_its_socket_location() {
    assert!(
        std::env::var_os(CHILD_FLAG).is_some(),
        "this is a child half; its parent starts it with {CHILD_FLAG} set"
    );
    assert_eq!(
        std::env::var("USERPROFILE").as_deref(),
        Ok(DECOY_PROFILE),
        "the decoy environment did not reach the child"
    );
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
            "--ignored",
            "--nocapture",
        ])
        .env(CHILD_FLAG, "1")
        .env("USERPROFILE", DECOY_PROFILE)
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
        .unwrap_or_else(|| panic!("the child printed no location (it did not run?): {stdout}"));
    assert_eq!(PathBuf::from(line), expected);
}

// ensure_socket_dir ---------------------------------------------------------------------

use crate::acl::{self, Sid};
use crate::test_support::{FILE_ALL, TempProfile, aces, dacl_sddl};
use std::path::Path;

fn me() -> Sid {
    Sid::current_user().unwrap()
}

#[test]
fn ensure_socket_dir_creates_a_dir_that_verifies() {
    let profile = TempProfile::new("create");
    let loc = profile.location();
    ensure_socket_dir(&loc, &me()).unwrap();
    assert!(acl::verify_dir_acl(&loc.dir, &me()).unwrap());
}

#[test]
fn ensure_socket_dir_is_idempotent() {
    let profile = TempProfile::new("idem");
    let loc = profile.location();
    ensure_socket_dir(&loc, &me()).unwrap();
    std::fs::write(loc.lock_path(), "").unwrap();
    ensure_socket_dir(&loc, &me()).unwrap();
    assert!(acl::verify_dir_acl(&loc.dir, &me()).unwrap());
    assert!(loc.lock_path().is_file(), "what was inside is left alone");
}

#[test]
fn ensure_socket_dir_repairs_a_dir_widened_with_an_everyone_ace() {
    let profile = TempProfile::new("repair");
    let loc = profile.location();
    ensure_socket_dir(&loc, &me()).unwrap();
    let status = std::process::Command::new("icacls")
        .arg(&loc.dir)
        .args(["/grant", "*S-1-1-0:(OI)(CI)F"])
        .status()
        .unwrap();
    assert!(status.success());
    assert!(!acl::verify_dir_acl(&loc.dir, &me()).unwrap(), "control: widened");

    ensure_socket_dir(&loc, &me()).unwrap();
    assert!(acl::verify_dir_acl(&loc.dir, &me()).unwrap());
}

#[test]
fn ensure_socket_dir_does_not_create_a_missing_profile() {
    let profile = TempProfile::new("missing");
    std::fs::remove_dir_all(profile.0.join("AppData")).unwrap();
    let loc = profile.location();
    assert!(ensure_socket_dir(&loc, &me()).is_err());
    assert!(!profile.0.join("AppData").exists(), "nothing was invented");
}

#[test]
fn ensure_socket_dir_refuses_a_junction_at_the_dir() {
    let profile = TempProfile::new("junction");
    let loc = profile.location();
    let target = profile.0.join("elsewhere");
    std::fs::create_dir(&target).unwrap();
    let before = dacl_sddl(&target);
    let out = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&loc.dir)
        .arg(&target)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "mklink /J: {}",
        String::from_utf8_lossy(&out.stdout)
    );

    let err = format!("{:#}", ensure_socket_dir(&loc, &me()).unwrap_err());
    assert!(err.contains("reparse point"), "{err}");
    assert_eq!(dacl_sddl(&target), before, "the junction target was not touched");

    std::fs::remove_dir(&loc.dir).unwrap();
}

#[test]
fn ensure_socket_dir_refuses_a_file_at_the_dir() {
    let profile = TempProfile::new("file");
    let loc = profile.location();
    std::fs::write(&loc.dir, "x").unwrap();
    let err = format!("{:#}", ensure_socket_dir(&loc, &me()).unwrap_err());
    assert!(err.contains("not a directory"), "{err}");
    assert_eq!(std::fs::read_to_string(&loc.dir).unwrap(), "x");
}

/// The three ACEs a private directory carries, by SDDL alias, as `(type, mask, trustee)`.
fn trustees(path: &Path) -> Vec<(String, u32, String)> {
    let sddl = dacl_sddl(path);
    let mut out: Vec<_> = aces(&sddl)
        .into_iter()
        .map(|(kind, _, mask, who)| (kind.to_owned(), mask, who.to_owned()))
        .collect();
    out.sort();
    out
}

#[test]
fn ensure_socket_dir_acl_is_exactly_user_system_administrators() {
    let profile = TempProfile::new("exact");
    let loc = profile.location();
    ensure_socket_dir(&loc, &me()).unwrap();
    let sddl = dacl_sddl(&loc.dir);
    assert!(sddl.starts_with("D:P"), "protected: {sddl}");
    let list = trustees(&loc.dir);
    assert_eq!(list.len(), 3, "{sddl}");
    assert!(
        list.iter().all(|(kind, mask, _)| kind == "A" && *mask == FILE_ALL),
        "{sddl}"
    );
    for alias in ["SY", "BA"] {
        assert!(list.iter().any(|(_, _, who)| who == alias), "{alias} in {sddl}");
    }
    assert!(!sddl.contains("ID;"), "nothing is inherited: {sddl}");
}

#[test]
fn ensure_socket_dir_creates_a_logs_dir_with_the_same_exact_acl() {
    let profile = TempProfile::new("logs");
    let loc = profile.location();
    ensure_socket_dir(&loc, &me()).unwrap();
    assert!(loc.logs_dir().is_dir());
    assert!(acl::verify_file_acl(&loc.logs_dir(), &me()).unwrap());
    assert_eq!(trustees(&loc.logs_dir()), trustees(&loc.dir));
}

#[test]
fn ensure_socket_dir_gives_what_it_makes_inside_exactly_the_three_aces() {
    let profile = TempProfile::new("born");
    let loc = profile.location();
    ensure_socket_dir(&loc, &me()).unwrap();
    std::fs::write(loc.lock_path(), "").unwrap();
    assert!(acl::verify_file_acl(&loc.lock_path(), &me()).unwrap());
    assert_eq!(trustees(&loc.lock_path()), trustees(&loc.dir));
}
