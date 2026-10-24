//! Tests for the file log sink.
use super::*;
use crate::acl::{self, Sid};
use crate::test_support::TempProfile;
use std::os::windows::process::CommandExt;

/// `CREATE_NO_WINDOW`: a child console process gets no console window.
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// A directory that refuses new files, removed (deny ACE lifted first) when dropped.
struct WriteDeniedDir(std::path::PathBuf);

impl WriteDeniedDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("sb-logdeny-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // DENY beats the runner's admin ALLOW, so this holds for an elevated test process too.
        let status = std::process::Command::new("icacls")
            .arg(&dir)
            .args(["/deny", "*S-1-1-0:(OI)(CI)(WD)"])
            .status()
            .expect("run icacls");
        assert!(status.success(), "icacls /deny should succeed");
        Self(dir)
    }
}

impl Drop for WriteDeniedDir {
    fn drop(&mut self) {
        let _ = std::process::Command::new("icacls")
            .arg(&self.0)
            .args(["/remove:d", "*S-1-1-0"])
            .status();
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A log directory the user cannot write must disable logging, not abort the shim (a panic exits
/// 101 before the fail-open path runs), and the error must name the folder.
#[test]
fn file_logging_is_disabled_not_fatal_when_the_log_directory_is_unwritable() {
    let dir = WriteDeniedDir::new("unwritable");
    let err = open_in(&dir.0, "shim.log").expect_err("an unwritable folder yields no sink");
    assert!(format!("{err:#}").contains(&dir.0.display().to_string()), "{err:#}");
}

#[test]
fn file_logging_is_enabled_for_a_writable_log_directory() {
    let dir = std::env::temp_dir().join(format!("sb-logok-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let sink = open_in(&dir, "shim.log");

    assert!(sink.is_ok(), "a writable log directory must yield a sink");
    drop(sink);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn file_logging_names_the_prefix() {
    let dir = std::env::temp_dir().join(format!("sb-logprefix-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let sink = open_in(&dir, "agent.log");

    assert!(sink.is_ok());
    let names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        names.iter().any(|n| n.starts_with("agent.log")) && !names.iter().any(|n| n.starts_with("shim.log")),
        "the agent and the shim must not share a file: {names:?}"
    );
    drop(sink);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_subscriber_that_is_already_installed_is_reported_not_ignored() {
    // Whoever got there first owns the process's logging; ours would go nowhere, so the caller
    // must be told. Install one here so the outcome does not depend on which test ran first.
    let _ = tracing_subscriber::fmt().with_writer(std::io::sink).try_init();
    let dir = std::env::temp_dir().join(format!("sb-logtwice-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let err = init_in(&dir, "shim.log").expect_err("a second subscriber cannot be installed");

    assert!(format!("{err:#}").contains("already"), "{err:#}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn logging_for_a_user_goes_into_a_folder_that_is_exactly_theirs() {
    let profile = TempProfile::new("log-acl");
    let loc = profile.location();
    let me = Sid::current_user().unwrap();

    let sink = open_for_location(&loc, &me, "shim.log");

    assert!(sink.is_ok());
    assert!(loc.logs_dir().is_dir());
    assert!(acl::verify_file_acl(&loc.logs_dir(), &me).unwrap());
    assert!(
        std::fs::read_dir(loc.logs_dir()).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("shim.log")),
        "the log file is in the user's own folder"
    );
    // The files made there carry exactly the same three grantees, so the shim's log is private
    // to the user instead of being readable by whoever the profile's parent grants.
    let file = std::fs::read_dir(loc.logs_dir())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert!(acl::verify_file_acl(&file, &me).unwrap());
    drop(sink);
}

#[test]
fn logging_is_off_not_fatal_when_there_is_no_profile_and_the_error_says_why() {
    let profile = TempProfile::new("log-noprofile");
    std::fs::remove_dir_all(profile.0.join("AppData")).unwrap();
    let me = Sid::current_user().unwrap();

    let err = open_for_location(&profile.location(), &me, "shim.log").expect_err("no profile, no log");

    assert!(format!("{err:#}").contains("ssh-broker"), "names the folder: {err:#}");
}

#[test]
fn a_private_folder_that_is_not_the_users_is_the_reason_logging_is_off() {
    // A folder that is a link cannot be adopted; the cause reaches the caller instead of None.
    let profile = TempProfile::new("log-link");
    let loc = profile.location();
    let elsewhere = profile.0.join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    let status = std::process::Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(&loc.dir)
        .arg(&elsewhere)
        .creation_flags(CREATE_NO_WINDOW)
        .status()
        .unwrap();
    assert!(status.success(), "control: the junction was made");
    let me = Sid::current_user().unwrap();

    let err = open_for_location(&loc, &me, "shim.log").expect_err("a junction is refused");

    assert!(
        format!("{err:#}").contains("cannot be used as the private folder"),
        "{err:#}"
    );
}
