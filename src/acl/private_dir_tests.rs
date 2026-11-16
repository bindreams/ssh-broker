//! Tests for the private folder reached by handle. A link below the profile directory has to be
//! refused wherever it is, and nothing outside the profile may change.
use super::*;
use crate::acl::{self, Sid};
use crate::test_support::{TempProfile, dacl_sddl, junction, tree_state};
use std::io::Write;

fn me() -> Sid {
    Sid::current_user().unwrap()
}

/// Every folder from the profile directory down to `logs`, as `ensure_socket_dir` walks them.
fn walk(profile: &Path, user: &Sid) -> anyhow::Result<(DirHandle, DirHandle)> {
    let root = open_root(profile)?;
    let app_data = open_dir(&root, "AppData")?;
    let local = open_dir(&app_data, "Local")?;
    let broker = ensure_private_dir(&local, "ssh-broker", user)?;
    let logs = ensure_private_dir(&broker, "logs", user)?;
    Ok((broker, logs))
}

/// The private folder of a stand-in profile, made.
fn made(profile: &TempProfile) -> (DirHandle, DirHandle) {
    walk(&profile.0, &me()).unwrap()
}

fn symlink_dir(link: &Path, target: &Path) {
    std::os::windows::fs::symlink_dir(target, link).unwrap_or_else(|e| {
        panic!(
            "symlink {} -> {}: {e} (needs Developer Mode or the symlink privilege)",
            link.display(),
            target.display()
        )
    });
}

fn icacls(path: &Path, args: &[&str]) {
    let status = std::process::Command::new("icacls")
        .arg(path)
        .args(args)
        .status()
        .unwrap();
    assert!(status.success(), "icacls {args:?}");
}

const LINKS: [&str; 4] = [
    "AppData",
    r"AppData\Local",
    r"AppData\Local\ssh-broker",
    r"AppData\Local\ssh-broker\logs",
];

#[test]
fn a_link_at_any_component_is_refused_with_the_component_named() {
    let me = me();
    for symlinked in [false, true] {
        for link_at in LINKS {
            let profile = TempProfile::new("lk");
            let outside = TempProfile::new("lk-out");
            made(&outside);
            std::fs::write(outside.0.join(r"AppData\Local\ssh-broker\note.txt"), "x").unwrap();
            made(&profile);
            let before = tree_state(&outside.0);
            let link = profile.0.join(link_at);
            std::fs::remove_dir_all(&link).unwrap();
            if symlinked {
                symlink_dir(&link, &outside.0.join(link_at));
            } else {
                junction(&link, &outside.0.join(link_at));
            }

            let what = format!("{} at {link_at}", if symlinked { "symlink" } else { "junction" });
            let err = walk(&profile.0, &me)
                .err()
                .unwrap_or_else(|| panic!("{what} was not refused"));
            let text = format!("{err:#}");

            assert!(text.contains(&link.display().to_string()), "{what}: {text}");
            assert!(text.contains("reparse point"), "{what}: {text}");
            assert_eq!(tree_state(&outside.0), before, "{what}: something outside was changed");
        }
    }
}

#[test]
fn a_missing_folder_is_created_with_exactly_the_private_acl_and_owner_in_the_set() {
    let profile = TempProfile::new("mk");
    let (broker, logs) = made(&profile);
    for dir in [broker.path(), logs.path()] {
        assert!(acl::verify_dir_acl(dir, &me()).unwrap(), "{}", dacl_sddl(dir));
        let sddl = dacl_sddl(dir);
        assert!(sddl.starts_with("D:P"), "protected: {sddl}");
        assert!(!sddl.contains("ID"), "no inherited ACE: {sddl}");
    }
}

#[test]
fn an_exact_folder_is_left_untouched() {
    let profile = TempProfile::new("same");
    let (broker, _) = made(&profile);
    let child = broker.path().join("child.txt");
    std::fs::write(&child, "x").unwrap();
    icacls(&child, &["/grant", "*S-1-1-0:R"]);
    let before = tree_state(&profile.0);

    let local = open_dir(&open_dir(&open_root(&profile.0).unwrap(), "AppData").unwrap(), "Local").unwrap();
    ensure_private_dir(&local, "ssh-broker", &me()).unwrap();

    assert_eq!(tree_state(&profile.0), before);
}

#[test]
fn a_widened_folder_is_refused_and_left_untouched() {
    let profile = TempProfile::new("wide");
    let (broker, _) = made(&profile);
    std::fs::write(broker.path().join("child.txt"), "x").unwrap();
    icacls(broker.path(), &["/grant", "*S-1-1-0:(OI)(CI)F"]);
    assert!(!acl::verify_dir_acl(broker.path(), &me()).unwrap(), "control: widened");
    let before = tree_state(&profile.0);

    let local = open_dir(&open_dir(&open_root(&profile.0).unwrap(), "AppData").unwrap(), "Local").unwrap();
    let err = format!("{:#}", ensure_private_dir(&local, "ssh-broker", &me()).err().unwrap());

    assert!(err.contains(&broker.path().display().to_string()), "{err}");
    assert!(err.contains("remove"), "{err}");
    assert_eq!(
        tree_state(&profile.0),
        before,
        "the folder and what is in it were changed"
    );
}

#[test]
fn a_file_at_the_name_is_refused_and_left_untouched() {
    let profile = TempProfile::new("file");
    let local = profile.0.join(r"AppData\Local");
    std::fs::write(local.join("ssh-broker"), "x").unwrap();
    let root = open_root(&profile.0).unwrap();
    let local = open_dir(&open_dir(&root, "AppData").unwrap(), "Local").unwrap();

    let err = format!("{:#}", ensure_private_dir(&local, "ssh-broker", &me()).err().unwrap());

    assert!(err.contains("not a directory"), "{err}");
    assert_eq!(std::fs::read_to_string(local.path().join("ssh-broker")).unwrap(), "x");
}

#[test]
fn open_dir_does_not_create_what_is_missing() {
    let profile = TempProfile::new("miss");
    let root = open_root(&profile.0).unwrap();
    let err = format!("{:#}", open_dir(&root, "Nothing").err().unwrap());
    assert!(err.contains("Nothing"), "{err}");
    assert!(!profile.0.join("Nothing").exists());
}

#[test]
fn a_name_that_is_not_one_component_is_refused() {
    let profile = TempProfile::new("name");
    let root = open_root(&profile.0).unwrap();
    for name in ["", ".", "..", r"AppData\Local", "AppData/Local", "C:", "a\0b"] {
        assert!(open_dir(&root, name).is_err(), "open_dir {name:?}");
        assert!(
            ensure_private_dir(&root, name, &me()).is_err(),
            "ensure_private_dir {name:?}"
        );
        assert!(open_log_file(&root, name).is_err(), "open_log_file {name:?}");
    }
}

#[test]
fn the_root_may_be_reached_through_a_link_and_the_walk_below_it_works() {
    // The profile directory is the administrator's, opened following links; only what is below it
    // is refused.
    let profile = TempProfile::new("root");
    let via = TempProfile::new("root-via");
    let link = via.0.join("p");
    junction(&link, &profile.0);
    walk(&link, &me()).unwrap();
    assert!(acl::verify_dir_acl(&profile.0.join(r"AppData\Local\ssh-broker"), &me()).unwrap());
}

#[test]
fn a_clone_is_the_same_directory() {
    let profile = TempProfile::new("dup");
    let (_, logs) = made(&profile);
    let clone = logs.try_clone().unwrap();
    assert_eq!(clone.path(), logs.path());
    drop(logs);
    open_log_file(&clone, "x.log").unwrap();
    assert!(clone.path().join("x.log").is_file());
}

#[test]
fn the_log_file_is_made_with_the_inherited_acl_and_appended_to() {
    let profile = TempProfile::new("log");
    let (_, logs) = made(&profile);
    for line in ["one\n", "two\n"] {
        open_log_file(&logs, "shim.log.2026-01-01")
            .unwrap()
            .write_all(line.as_bytes())
            .unwrap();
    }
    let file = logs.path().join("shim.log.2026-01-01");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "one\ntwo\n");
    assert!(acl::verify_file_acl(&file, &me()).unwrap());
}

#[test]
fn a_symlink_named_like_the_log_is_refused_and_its_target_is_untouched() {
    let profile = TempProfile::new("logsym");
    let (_, logs) = made(&profile);
    let victim = profile.0.join("victim.txt");
    std::fs::write(&victim, "keep").unwrap();
    let name = logs.path().join("shim.log.2026-01-02");
    std::os::windows::fs::symlink_file(&victim, &name)
        .unwrap_or_else(|e| panic!("file symlink: {e} (needs Developer Mode or the symlink privilege)"));

    let err = format!("{:#}", open_log_file(&logs, "shim.log.2026-01-02").err().unwrap());

    assert!(err.contains(&name.display().to_string()), "{err}");
    assert!(err.contains("reparse point"), "{err}");
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
}

#[test]
fn a_directory_named_like_the_log_is_refused() {
    let profile = TempProfile::new("logdir");
    let (_, logs) = made(&profile);
    std::fs::create_dir(logs.path().join("shim.log.2026-01-03")).unwrap();
    assert!(open_log_file(&logs, "shim.log.2026-01-03").is_err());
}

// open_existing_file -----

use windows::Win32::Storage::FileSystem::{FILE_READ_DATA, FILE_WRITE_DATA};

const READ_WRITE: FILE_ACCESS_RIGHTS = FILE_ACCESS_RIGHTS(FILE_READ_DATA.0 | FILE_WRITE_DATA.0);

#[test]
fn an_existing_file_is_opened_and_a_missing_one_is_none_and_not_made() {
    let profile = TempProfile::new("exf");
    let (broker, _) = made(&profile);
    let present = broker.path().join("agent.lock");
    std::fs::write(&present, "kept").unwrap();

    let file = open_existing_file(&broker, "agent.lock", READ_WRITE).unwrap();
    assert!(file.is_some(), "an existing file is opened");
    assert_eq!(std::fs::read_to_string(&present).unwrap(), "kept");

    assert!(
        open_existing_file(&broker, "missing.lock", READ_WRITE)
            .unwrap()
            .is_none()
    );
    assert!(!broker.path().join("missing.lock").exists(), "looking never creates");
}

#[test]
fn a_symlink_named_like_an_existing_file_is_refused_and_its_target_is_untouched() {
    let profile = TempProfile::new("exfsym");
    let (broker, _) = made(&profile);
    let victim = profile.0.join("victim.txt");
    std::fs::write(&victim, "keep").unwrap();
    let name = broker.path().join("agent.lock");
    std::os::windows::fs::symlink_file(&victim, &name)
        .unwrap_or_else(|e| panic!("file symlink: {e} (needs Developer Mode or the symlink privilege)"));

    let err = format!(
        "{:#}",
        open_existing_file(&broker, "agent.lock", READ_WRITE).err().unwrap()
    );

    assert!(err.contains(&name.display().to_string()), "{err}");
    assert!(err.contains("reparse point"), "{err}");
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
}

#[test]
fn a_directory_named_like_an_existing_file_is_refused() {
    let profile = TempProfile::new("exfdir");
    let (broker, _) = made(&profile);
    std::fs::create_dir(broker.path().join("agent.lock")).unwrap();
    assert!(open_existing_file(&broker, "agent.lock", READ_WRITE).is_err());
}

#[test]
fn a_missing_name_is_missing_for_a_downcast_and_open_dir_does_not_create_it() {
    let profile = TempProfile::new("missing");
    let root = open_root(&profile.0).unwrap();
    let err = open_dir(&root, "Nothing").err().unwrap();
    assert!(err.downcast_ref::<Missing>().is_some(), "{err:#}");
    let gone = profile.0.join("gone");
    let err = open_root(&gone).err().unwrap();
    assert!(err.downcast_ref::<Missing>().is_some(), "{err:#}");
    assert!(!gone.exists());
}
