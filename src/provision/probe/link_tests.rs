//! Tests for the junction the probe reads through, in a temporary directory of the test's own.
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};

use super::*;
use crate::route::ProbeLink;

/// A directory of this test's own, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let path = std::env::temp_dir().join(format!("sb-link-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Scratch(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

fn is_reparse_point(path: &Path) -> bool {
    std::fs::symlink_metadata(path).unwrap().file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

/// The junction is a real one (a reparse point, not a copy of a directory), and reading through it
/// reaches the file the probe wrote.
#[test]
fn a_junction_made_in_a_directory_is_followed() {
    let scratch = Scratch::new("made");

    let dir = make(&scratch.0).unwrap();

    assert!(
        dir.starts_with(&scratch.0),
        "{dir:?} is made in the directory it was given"
    );
    assert!(is_reparse_point(&dir.join(LINK_NAME)), "the link is a reparse point");
    assert!(
        !is_reparse_point(&dir.join(TARGET_NAME)),
        "control: the target is a plain folder"
    );
    assert_eq!(follow(&dir), SymlinkState::Ok);
}

/// What the probe writes through the junction is what it reads back: a link to some other folder that
/// holds no such file does not read as followed.
#[test]
fn a_junction_to_a_folder_without_the_file_is_not_followed() {
    let scratch = Scratch::new("wrong");
    let dir = make(&scratch.0).unwrap();
    std::fs::remove_file(dir.join(TARGET_NAME).join(FILE_NAME)).unwrap();

    assert_eq!(follow(&dir), SymlinkState::Failed);
}

#[test]
fn a_directory_with_no_junction_is_failed_and_not_blocked() {
    let scratch = Scratch::new("none");

    assert_eq!(follow(&scratch.0), SymlinkState::Failed);
    assert_eq!(follow(&scratch.0.join("absent")), SymlinkState::Failed);
}

/// Only error 448 is RedirectionGuard's refusal; any other failure to read is not reported as one.
#[test]
fn only_an_untrusted_mount_point_error_is_a_block() {
    let untrusted = std::io::Error::from_raw_os_error(448);
    let other = std::io::Error::from_raw_os_error(5);

    assert_eq!(state_of_read(Err(untrusted)), SymlinkState::Blocked);
    assert_eq!(state_of_read(Err(other)), SymlinkState::Failed);
    assert_eq!(state_of_read(Ok(b"parity".to_vec())), SymlinkState::Ok);
    assert_eq!(state_of_read(Ok(b"other".to_vec())), SymlinkState::Failed);
}

/// Making again in the same place replaces what an earlier run of this process left, so a stale
/// directory never makes the new junction fail.
#[test]
fn making_again_replaces_a_stale_directory() {
    let scratch = Scratch::new("again");
    let first = make(&scratch.0).unwrap();

    let second = make(&scratch.0).unwrap();

    assert_eq!(first, second, "one directory per process");
    assert_eq!(follow(&second), SymlinkState::Ok);
}

/// Removal takes the junction, the target and the directory, and never goes through the junction: a
/// folder the link points at from outside survives whole.
#[test]
fn removing_the_directory_does_not_go_through_the_junction() {
    let scratch = Scratch::new("remove");
    let dir = make(&scratch.0).unwrap();
    // Point the link at a folder outside the directory instead of the probe's own target.
    let outside = scratch.0.join("outside");
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(outside.join("keep.txt"), b"keep").unwrap();
    let link = dir.join(LINK_NAME);
    std::fs::remove_dir(&link).unwrap();
    crate::test_support::junction(&link, &outside);
    assert!(is_reparse_point(&link), "control: the link points outside");

    remove(&dir).unwrap();

    assert!(!dir.exists(), "the directory is gone");
    assert_eq!(std::fs::read(outside.join("keep.txt")).unwrap(), b"keep");
}

#[test]
fn removing_a_directory_that_is_gone_is_not_an_error() {
    let scratch = Scratch::new("gone");
    remove(&scratch.0.join("never-made")).unwrap();
}

// what a probe does with its junction ---------------------------------------------------------

/// `Own`: the one probe of a standard account's agent makes a junction, follows it and removes it, and
/// names nothing for `verify` to clean up.
#[test]
fn an_own_junction_is_followed_and_removed_by_the_probe_that_made_it() {
    let scratch = Scratch::new("own");

    let (state, left) = run_in(&ProbeLink::Own, &scratch.0);

    assert_eq!(state, SymlinkState::Ok);
    assert_eq!(left, None);
    assert_eq!(
        std::fs::read_dir(&scratch.0).unwrap().count(),
        0,
        "nothing is left behind"
    );
}

/// `Make`: the unelevated probe of an administrator's agent leaves the junction and names its
/// directory; a second probe follows it by that name and leaves it for `verify` to remove.
#[test]
fn a_made_junction_is_left_for_the_next_probe_to_follow() {
    let scratch = Scratch::new("make");

    let (made, dir) = run_in(&ProbeLink::Make, &scratch.0);
    let dir = dir.expect("the probe names the directory it made");
    let (followed, left) = run_in(&ProbeLink::Follow(dir.to_str().unwrap().to_owned()), &scratch.0);

    assert_eq!(made, SymlinkState::Ok);
    assert_eq!(followed, SymlinkState::Ok);
    assert_eq!(left, None, "following leaves what it follows to `verify`");
    assert!(dir.exists());
    remove(&dir).unwrap();
    assert_eq!(
        follow(&dir),
        SymlinkState::Failed,
        "a directory that was removed is not followed"
    );
}

/// A junction that cannot be made is a failed outcome with no directory, not a panic or a pass.
#[test]
fn a_junction_that_cannot_be_made_is_failed() {
    let scratch = Scratch::new("cannot");
    let not_a_directory = scratch.0.join("file");
    std::fs::write(&not_a_directory, b"x").unwrap();

    assert_eq!(run_in(&ProbeLink::Make, &not_a_directory), (SymlinkState::Failed, None));
    assert_eq!(run_in(&ProbeLink::Own, &not_a_directory), (SymlinkState::Failed, None));
}
