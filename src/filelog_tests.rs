//! Tests for the file log sink.
use super::*;
use crate::acl::{self, DirHandle, Sid};
use crate::test_support::TempProfile;
use std::os::windows::process::CommandExt;

/// `CREATE_NO_WINDOW`: a child console process gets no console window.
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// `dir` (made if it is missing) as the folder a log is opened in.
fn folder(dir: &std::path::Path) -> DirHandle {
    std::fs::create_dir_all(dir).unwrap();
    acl::open_root(dir).unwrap()
}

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
    let err = open_in(&folder(&dir.0), "shim.log").expect_err("an unwritable folder yields no sink");
    assert!(format!("{err:#}").contains(&dir.0.display().to_string()), "{err:#}");
}

#[test]
fn file_logging_is_enabled_for_a_writable_log_directory() {
    let dir = std::env::temp_dir().join(format!("sb-logok-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let sink = open_in(&folder(&dir), "shim.log");

    assert!(sink.is_ok(), "a writable log directory must yield a sink");
    drop(sink);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn file_logging_names_the_prefix() {
    let dir = std::env::temp_dir().join(format!("sb-logprefix-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let sink = open_in(&folder(&dir), "agent.log");

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

    let err = init_in(&folder(&dir), "shim.log").expect_err("a second subscriber cannot be installed");

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
        .arg(loc.dir())
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

/// The private folder (or its `logs`) of a stand-in profile, made and then given to Everyone too.
fn widened(tag: &str, logs_only: bool) -> (TempProfile, SocketLocation) {
    let profile = TempProfile::new(tag);
    let loc = profile.location();
    crate::userdir::ensure_socket_dir(&loc, &Sid::current_user().unwrap()).unwrap();
    let folder = if logs_only {
        loc.logs_dir()
    } else {
        loc.dir().to_path_buf()
    };
    crate::test_support::widen(&folder);
    (profile, loc)
}

#[test]
fn a_refused_private_folder_is_said_to_be_the_reason_there_is_no_log() {
    let (_profile, loc) = widened("log-wide-dir", false);

    let no_log = open_for_location(&loc, &Sid::current_user().unwrap(), "shim.log").expect_err("a widened folder");

    assert!(no_log.cause.is::<acl::Refused>(), "{no_log}");
    assert!(
        no_log.to_string().contains(&loc.dir().display().to_string()),
        "{no_log}"
    );
}

#[test]
fn a_refused_logs_folder_alone_costs_the_log() {
    let (_profile, loc) = widened("log-wide-logs", true);

    let no_log = open_for_location(&loc, &Sid::current_user().unwrap(), "shim.log").expect_err("a widened logs folder");

    assert!(no_log.cause.is::<acl::Refused>(), "{no_log}");
    assert!(
        no_log.to_string().contains(&loc.logs_dir().display().to_string()),
        "{no_log}"
    );
}

// A link above the log -----------------------------------------------------------------------

use crate::test_support::{junction, tree_state};
use std::io::Write;

/// Reproduces the by-path creation of the log: the folder outside is a correct private folder, so
/// every check passes, and the log is created and written there. Fails until the log is opened
/// under the folder's handle.
#[test]
fn the_log_is_not_created_outside_the_profile_when_a_directory_above_the_folder_is_a_junction() {
    let me = Sid::current_user().unwrap();
    let profile = TempProfile::new("lg");
    let outside = TempProfile::new("lg-out");
    crate::userdir::ensure_socket_dir(&outside.location(), &me).unwrap();
    let before = tree_state(&outside.0);
    let local = profile.0.join(r"AppData\Local");
    std::fs::remove_dir_all(&local).unwrap();
    junction(&local, &outside.0.join(r"AppData\Local"));

    let result = open_for_location(&profile.location(), &me, "shim.log");

    let refused = result.is_err();
    if let Ok((mut writer, guard)) = result {
        writer.write_all(b"a line\n").unwrap();
        drop(guard); // flush
    }
    assert_eq!(
        tree_state(&outside.0),
        before,
        "a log file was made outside the profile"
    );
    assert!(refused, "a junction above the folder must be refused");
}

/// Reproduces the append through a link in the logs folder: the folder is the user's own and right,
/// and the log file's name is a symlink to a file elsewhere. Fails until the log file is opened
/// without following a link.
#[test]
fn the_log_does_not_append_to_a_file_that_a_symlink_in_the_logs_folder_points_to() {
    let me = Sid::current_user().unwrap();
    let profile = TempProfile::new("lg-sym");
    let loc = profile.location();
    // The first open makes the file; its name is today's, so the link can take exactly that name.
    drop(open_for_location(&loc, &me, "shim.log").unwrap());
    let name = std::fs::read_dir(loc.logs_dir())
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.file_name().unwrap().to_string_lossy().starts_with("shim.log"))
        .expect("the first open made the log file");
    let victim = profile.0.join("victim.txt");
    std::fs::write(&victim, "keep").unwrap();
    std::fs::remove_file(&name).unwrap();
    std::os::windows::fs::symlink_file(&victim, &name)
        .unwrap_or_else(|e| panic!("file symlink: {e} (needs Developer Mode or the symlink privilege)"));

    let result = open_for_location(&loc, &me, "shim.log");

    if let Ok((mut writer, guard)) = result {
        writer.write_all(b"a line\n").unwrap();
        drop(guard); // flush
    }
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
}
