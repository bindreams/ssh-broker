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
    let dir = scratch.0.join("d");

    make(&dir).unwrap();

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
    let dir = scratch.0.join("d");
    make(&dir).unwrap();
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

/// A path that exists is never made over or cleared: the probe fails and leaves what is there alone,
/// whether it is a stale directory of an earlier run or something that was put there.
#[test]
fn making_in_a_path_that_exists_fails_and_leaves_it_alone() {
    let scratch = Scratch::new("exists");
    let dir = scratch.0.join("d");
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(dir.join("keep.txt"), b"keep").unwrap();

    let made = make(&dir);

    assert_eq!(made.unwrap_err().kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(std::fs::read(dir.join("keep.txt")).unwrap(), b"keep");
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1, "nothing was added to it");
    let file = scratch.0.join("f");
    std::fs::write(&file, b"keep").unwrap();
    assert!(make(&file).is_err());
    assert_eq!(std::fs::read(&file).unwrap(), b"keep");
}

/// Each call names a directory of its own, in the parent it was given, and the name is not the process
/// id alone: a later process that has the same id does not meet a stale name.
#[test]
fn each_unique_directory_is_new_and_below_its_parent() {
    let scratch = Scratch::new("unique");

    let first = unique_dir(&scratch.0);
    let second = unique_dir(&scratch.0);

    assert_ne!(first, second);
    assert_eq!(first.parent(), Some(scratch.0.as_path()));
    assert_ne!(
        first.file_name().unwrap().to_str().unwrap(),
        format!("sb-junction-{}", std::process::id()),
        "the process id alone is not a unique name"
    );
}

/// Removal takes the junction, the target and the directory, and never goes through the junction: a
/// folder the link points at from outside survives whole.
#[test]
fn removing_the_directory_does_not_go_through_the_junction() {
    let scratch = Scratch::new("remove");
    let dir = scratch.0.join("d");
    make(&dir).unwrap();
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

/// `Own`: the one probe of an agent below High makes a junction in a directory of its own, follows it and
/// removes it.
#[test]
fn an_own_junction_is_followed_and_removed_by_the_probe_that_made_it() {
    let scratch = Scratch::new("own");

    let state = run_in(&ProbeLink::Own, &scratch.0);

    assert_eq!(state, SymlinkState::Ok);
    assert_eq!(
        std::fs::read_dir(&scratch.0).unwrap().count(),
        0,
        "nothing is left behind"
    );
}

/// `Make`: the unelevated probe of an administrator's agent makes the junction in the directory `verify`
/// named and leaves it; a second probe follows it by that name and leaves it for `verify` to remove.
#[test]
fn a_made_junction_is_left_for_the_next_probe_to_follow() {
    let scratch = Scratch::new("make");
    let dir = scratch.0.join("named");
    let text = dir.to_str().unwrap().to_owned();

    let made = run_in(&ProbeLink::Make(text.clone()), &scratch.0);
    let followed = run_in(&ProbeLink::Follow(text), &scratch.0);

    assert_eq!(made, SymlinkState::Ok);
    assert_eq!(followed, SymlinkState::Ok);
    assert!(dir.exists(), "following leaves what it follows to `verify`");
    remove(&dir).unwrap();
    assert_eq!(
        follow(&dir),
        SymlinkState::Failed,
        "a directory that was removed is not followed"
    );
}

/// A junction that cannot be made was not tested: `Skipped`, which fails nothing, not a panic and not a
/// pass. A path that exists is such a case, and is left as it is.
#[test]
fn a_junction_that_cannot_be_made_is_skipped() {
    let scratch = Scratch::new("cannot");
    let not_a_directory = scratch.0.join("file");
    std::fs::write(&not_a_directory, b"x").unwrap();
    let existing = scratch.0.join("existing");
    std::fs::create_dir(&existing).unwrap();

    assert_eq!(
        run_in(
            &ProbeLink::Make(not_a_directory.join("d").to_str().unwrap().to_owned()),
            &scratch.0
        ),
        SymlinkState::Skipped
    );
    assert_eq!(run_in(&ProbeLink::Own, &not_a_directory), SymlinkState::Skipped);
    assert_eq!(
        run_in(&ProbeLink::Make(existing.to_str().unwrap().to_owned()), &scratch.0),
        SymlinkState::Skipped
    );
    assert_eq!(std::fs::read_dir(&existing).unwrap().count(), 0, "it was not touched");
}
