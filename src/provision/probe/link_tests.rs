//! Tests for the junction the probe reads through, in a temporary directory of the test's own.
use std::os::windows::fs::MetadataExt;
use std::path::Path;

use super::*;
use crate::route::ProbeLink;
use crate::test_support::Scratch;

const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

fn is_reparse_point(path: &Path) -> bool {
    std::fs::symlink_metadata(path).unwrap().file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

/// The junction is a real one (a reparse point, not a copy of a directory), and reading through it
/// reaches the file the probe wrote.
#[test]
fn a_junction_made_in_a_directory_is_followed() {
    let scratch = Scratch::new();
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
    let scratch = Scratch::new();
    let dir = scratch.0.join("d");
    make(&dir).unwrap();
    std::fs::remove_file(dir.join(TARGET_NAME).join(FILE_NAME)).unwrap();

    assert_eq!(follow(&dir), SymlinkState::Failed);
}

#[test]
fn a_directory_with_no_junction_is_failed_and_not_blocked() {
    let scratch = Scratch::new();

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

/// Every read that is not a followed junction or RedirectionGuard's refusal says why on stderr, a read
/// that gave the wrong content too.
#[test]
fn a_read_that_failed_or_gave_other_content_is_said() {
    let dir = Path::new(r"D:\t");
    let said = |read| read_note(dir, &read);

    assert_eq!(said(Ok(b"parity".to_vec())), None);
    assert_eq!(said(Err(io::Error::from_raw_os_error(UNTRUSTED_MOUNT_POINT))), None);
    let denied = said(Err(io::Error::from_raw_os_error(5))).expect("a failed read is said");
    assert!(denied.contains(r"D:\t") && denied.contains("denied"), "{denied}");
    let other = said(Ok(b"other".to_vec())).expect("other content is said");
    assert!(other.contains("parity") && other.contains("differ"), "{other}");
}

/// A path that exists is never made over or cleared: the probe fails and leaves what is there alone,
/// whether it is a stale directory of an earlier run or something that was put there.
#[test]
fn making_in_a_path_that_exists_fails_and_leaves_it_alone() {
    let scratch = Scratch::new();
    let dir = scratch.0.join("d");
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(dir.join("keep.txt"), b"keep").unwrap();

    let made = make(&dir);

    assert!(
        matches!(&made, Err(MakeError::NotMade(e)) if e.kind() == io::ErrorKind::AlreadyExists),
        "{made:?}"
    );
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
    let scratch = Scratch::new();

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
    let scratch = Scratch::new();
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
    let scratch = Scratch::new();
    remove(&scratch.0.join("never-made")).unwrap();
}

// what a probe does with its junction ---------------------------------------------------------

/// `Make`: a probe makes the junction in the directory `verify` named and leaves it; a second probe
/// follows it by that name and leaves it for `verify` to remove.
#[test]
fn a_made_junction_is_left_for_the_next_probe_to_follow() {
    let scratch = Scratch::new();
    let dir = scratch.0.join("named");
    let text = dir.to_str().unwrap().to_owned();

    let made = run(&ProbeLink::Make(text.clone()));
    let followed = run(&ProbeLink::Follow(text));

    assert_eq!(made, Some(SymlinkState::Ok));
    assert_eq!(followed, Some(SymlinkState::Ok));
    assert!(dir.exists(), "following leaves what it follows to `verify`");
    remove(&dir).unwrap();
    assert_eq!(
        follow(&dir),
        SymlinkState::Failed,
        "a directory that was removed is not followed"
    );
}

/// A probe told nothing about a junction makes and reads none, and reports no outcome.
#[test]
fn a_probe_given_no_junction_reports_none() {
    assert_eq!(run(&ProbeLink::NoJunction), None);
}

/// A directory that cannot be made is `NotMade`, which fails: it is not the volume refusing a junction. A
/// path that exists is such a case, and is left as it is.
#[test]
fn a_directory_that_cannot_be_made_is_not_made_and_is_left_alone() {
    let scratch = Scratch::new();
    let not_a_directory = scratch.0.join("file");
    std::fs::write(&not_a_directory, b"x").unwrap();
    let existing = scratch.0.join("existing");
    std::fs::create_dir(&existing).unwrap();

    assert_eq!(
        run(&ProbeLink::Make(not_a_directory.join("d").to_str().unwrap().to_owned())),
        Some(SymlinkState::NotMade)
    );
    assert_eq!(
        run(&ProbeLink::Make(existing.to_str().unwrap().to_owned())),
        Some(SymlinkState::NotMade)
    );
    assert_eq!(std::fs::read_dir(&existing).unwrap().count(), 0, "it was not touched");
    assert_eq!(std::fs::read(&not_a_directory).unwrap(), b"x");
}

// the volume --------------------------------------------------------------------------------

/// Whether a volume holds junctions is read off its flags and nothing else.
#[test]
fn a_volume_holds_junctions_exactly_when_it_says_it_supports_reparse_points() {
    assert!(holds_reparse_points(FILE_SUPPORTS_REPARSE_POINTS));
    assert!(holds_reparse_points(!0));
    assert!(!holds_reparse_points(0));
    assert!(!holds_reparse_points(!FILE_SUPPORTS_REPARSE_POINTS));
}

/// Once the volume has said it holds junctions, a later failure is `NotMade` with its cause and fails the
/// row: here the folder the junction leads to is already in the directory. The half-made directory is
/// removed.
#[test]
fn a_failure_after_the_directory_was_made_is_not_made_and_removes_the_directory() {
    let scratch = Scratch::new();
    let dir = scratch.0.join("d");
    std::fs::create_dir_all(dir.join(TARGET_NAME)).unwrap();

    let made = complete(&dir);

    assert!(
        matches!(&made, Err(MakeError::NotMade(e)) if e.kind() == io::ErrorKind::AlreadyExists),
        "{made:?}"
    );
    assert_eq!(made.unwrap_err().state(), SymlinkState::NotMade);
    assert!(!dir.exists(), "the half-made directory is removed");
}

/// Each way a junction is not made says its cause for the row: a fault names the directory and the error, and a
/// volume without junctions says that it holds none and is not tested.
#[test]
fn where_the_junction_failed_decides_not_tested_or_failed() {
    let dir = Path::new(r"D:\t");
    let fault = MakeError::NotMade(io::Error::from_raw_os_error(5));
    let volume = MakeError::NoJunctions;

    assert_eq!(fault.state(), SymlinkState::NotMade);
    assert_eq!(volume.state(), SymlinkState::Skipped);
    assert!(fault.said(dir).contains(r"D:\t"), "{}", fault.said(dir));
    assert!(fault.said(dir).contains("denied"), "{}", fault.said(dir));
    assert!(volume.said(dir).contains("holds no junctions"), "{}", volume.said(dir));
}

// the target path ----------------------------------------------------------------------------

/// What `buffer` holds as the substitute name and the print name, decoded back out.
fn names_of(buffer: &[u8]) -> (String, String) {
    let u16_at = |at: usize| usize::from(u16::from_le_bytes([buffer[at], buffer[at + 1]]));
    let (sub_at, sub_len, print_at, print_len) = (u16_at(8), u16_at(10), u16_at(12), u16_at(14));
    let path = &buffer[16..];
    let text = |at: usize, len: usize| {
        let wide: Vec<u16> = path[at..at + len]
            .chunks(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        assert_eq!(path[at + len..at + len + 2], [0, 0], "a name ends in a NUL");
        String::from_utf16(&wide).unwrap()
    };
    assert_eq!(
        u16_at(4),
        buffer.len() - 8,
        "the data length is what follows the 8 byte header"
    );
    (text(sub_at, sub_len), text(print_at, print_len))
}

/// The kernel follows `\??\...`: every form of the target gets it, in the one order of prefixes, and the
/// print name is the path as it was given.
#[test]
fn every_form_of_a_target_path_gets_the_name_the_kernel_follows() {
    for (target, substitute) in [
        (r"C:\a\b", r"\??\C:\a\b"),
        (r"\\?\C:\a\b", r"\??\C:\a\b"),
        (r"\\.\C:\a\b", r"\??\C:\a\b"),
        (r"\\?\UNC\srv\share\a", r"\??\UNC\srv\share\a"),
        (r"\\.\UNC\srv\share\a", r"\??\UNC\srv\share\a"),
        (r"\\srv\share\a", r"\??\UNC\srv\share\a"),
    ] {
        let buffer = mount_point_buffer(Path::new(target)).unwrap();

        assert_eq!(
            names_of(&buffer),
            (substitute.to_owned(), target.to_owned()),
            "{target}"
        );
    }
}

#[test]
fn a_target_path_too_long_for_a_reparse_buffer_is_an_error() {
    let long = format!(r"C:\{}", "a".repeat(40_000));

    assert!(mount_point_buffer(Path::new(&long)).is_err());
}
