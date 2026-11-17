//! What a held walk to the private folder pins, against a process of the same administrator that is
//! not elevated. Windows only; **Elevated (CI only)**.
//!
//! The walk holds `AppData`, `Local`, the private folder and `logs` without `FILE_SHARE_DELETE`. An
//! unelevated process of the same account (the child of this test, started with
//! `winutil::UnelevatedToken`: Medium integrity, Administrators deny-only) has every right on the
//! stand-in profile that the account has, so what keeps it from renaming a folder aside and putting
//! another in its place is the hold and nothing else. Once the hold is dropped it can.
#![cfg(windows)]

use std::path::{Path, PathBuf};

use ssh_broker::account::{Elevation, elevation};
use ssh_broker::acl::Sid;
use ssh_broker::pipes::ExecChild;
use ssh_broker::winutil::UnelevatedToken;
use ssh_broker::{socket_loc, userdir};

#[path = "common/child_entry.rs"]
mod child_entry;

const CHILD: &str = "the_unelevated_child_renames_the_folders_it_is_told_of";

/// A stand-in profile with `AppData\Local` in it, and the directory for one child's input and result,
/// removed on drop.
struct Scene {
    profile: PathBuf,
    child_dir: PathBuf,
}

impl Scene {
    fn new(tag: &str) -> Scene {
        let root = std::env::temp_dir().join(format!("sb-pin-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let profile = root.join("profile");
        std::fs::create_dir_all(profile.join(r"AppData\Local")).unwrap();
        let child_dir = root.join("child");
        std::fs::create_dir_all(&child_dir).unwrap();
        Scene { profile, child_dir }
    }

    fn location(&self) -> socket_loc::SocketLocation {
        socket_loc::for_profile(&self.profile).expect("the stand-in profile path is short enough")
    }

    /// Run the child, which tries to rename each of `folders` to a name beside it, in the order given,
    /// and return what it saw for each, one line per folder: `<folder>=<ok|os error N>`.
    fn rename_as_unelevated(&self, folders: &[PathBuf]) -> Vec<String> {
        assert_eq!(
            elevation().unwrap(),
            Elevation::Full,
            "this test needs an elevated administrator (CI runs it); not running it here"
        );
        let token = UnelevatedToken::of_this_process().expect("make the unelevated token");
        let _ = std::fs::remove_file(child_entry::result_path(&self.child_dir));
        let list: Vec<String> = folders.iter().map(|f| f.display().to_string()).collect();
        child_entry::write_input(&self.child_dir, &list.join("\n"));
        let line = child_entry::command_line(&std::env::current_exe().unwrap(), CHILD, &self.child_dir);
        ExecChild::spawn(&line, None, Some(&token))
            .expect("start the child on pipes")
            .wait()
            .expect("wait for the child");
        child_entry::result(&self.child_dir)
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

impl Drop for Scene {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.profile.parent().unwrap());
    }
}

/// The folders of the walk, innermost first, so that each path is still good when its turn comes.
fn folders_of(location: &socket_loc::SocketLocation) -> Vec<PathBuf> {
    let local = location.dir().parent().unwrap().to_path_buf();
    vec![
        location.logs_dir(),
        location.dir().to_path_buf(),
        local.clone(),
        local.parent().unwrap().to_path_buf(),
    ]
}

fn aside(folder: &Path) -> PathBuf {
    let mut name = folder.file_name().unwrap().to_os_string();
    name.push(".aside");
    folder.with_file_name(name)
}

/// While the walk is held an unelevated process of the same account cannot rename `AppData`, `Local`,
/// the private folder or `logs`; after it is dropped it can.
#[test]
fn an_unelevated_process_of_the_same_account_cannot_rename_a_folder_of_a_held_walk() {
    let scene = Scene::new("held");
    let location = scene.location();
    let folders = folders_of(&location);
    let held = userdir::open_socket_dir(&location, &Sid::current_user().unwrap()).unwrap();

    let while_held = scene.rename_as_unelevated(&folders);

    for (folder, seen) in folders.iter().zip(&while_held) {
        assert!(
            seen.starts_with(&format!("{}=os error ", folder.display())),
            "the unelevated child renamed {} while the walk held it: {seen}",
            folder.display()
        );
        assert!(folder.exists() && !aside(folder).exists(), "{} moved", folder.display());
    }
    assert_eq!(while_held.len(), folders.len(), "{while_held:?}");

    drop(held);
    let after = scene.rename_as_unelevated(&folders);

    for (folder, seen) in folders.iter().zip(&after) {
        assert_eq!(
            seen,
            &format!("{}=ok", folder.display()),
            "the hold was let go and {} still cannot be renamed",
            folder.display()
        );
    }
}

/// The child half. Run by the test above with `--ignored`, never on its own.
#[test]
#[ignore = "the child half of a parent/child pair; its parent starts it with the pair's directory"]
fn the_unelevated_child_renames_the_folders_it_is_told_of() {
    let dir = child_entry::dir();
    let input = child_entry::input(&dir);
    let seen: Vec<String> = input
        .lines()
        .map(|folder| {
            let folder = Path::new(folder);
            match std::fs::rename(folder, aside(folder)) {
                Ok(()) => format!("{}=ok", folder.display()),
                Err(e) => format!("{}=os error {}", folder.display(), e.raw_os_error().unwrap_or(-1)),
            }
        })
        .collect();
    child_entry::write_result(&dir, &seen.join("\n"));
}
