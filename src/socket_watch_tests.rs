//! Tests for `socket_watch` on a temporary folder and a temporary key under `HKEY_CURRENT_USER`. No
//! account, no machine state.
use super::*;
use crate::socket_loc;
use std::cell::Cell;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use windows::Win32::Foundation::WAIT_OBJECT_0;
use windows::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, KEY_WRITE, REG_OPTION_NON_VOLATILE, RegCloseKey, RegCreateKeyExW, RegDeleteTreeW,
};
use windows::Win32::System::Threading::{INFINITE, WaitForSingleObject};
use windows::core::PCWSTR;

fn unique(tag: &str) -> String {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    format!(
        "sb-watch-{tag}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

/// A folder, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> TempDir {
        let dir = std::env::temp_dir().join(unique(tag));
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }

    /// The location of a socket inside a profile at this folder.
    fn location(&self) -> SocketLocation {
        socket_loc::for_profile(&self.0).unwrap()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Block until `handle` is signalled: a wait on the real condition, which the test's own call has
/// just made true, so it returns at once.
fn signalled(handle: HANDLE) {
    // SAFETY: a valid handle owned by the watch under test.
    let woke = unsafe { WaitForSingleObject(handle, INFINITE) }; // sleep-ok: the awaited change has been made by this thread; a wait on the real condition, no cap
    assert_eq!(woke, WAIT_OBJECT_0, "the watch did not signal");
}

fn watch_of(location: &SocketLocation) -> SocketWatch {
    let location = location.clone();
    SocketWatch::new(move || Ok(location.clone()), ProfileList::none()).unwrap()
}

// the deepest folder that exists -----

#[test]
fn the_deepest_existing_folder_is_the_folder_itself_when_it_exists() {
    let dir = TempDir::new("deep-self");
    assert_eq!(deepest_existing(&dir.0).unwrap(), dir.0);
}

#[test]
fn the_deepest_existing_folder_of_a_missing_path_is_its_nearest_existing_parent() {
    let dir = TempDir::new("deep-parent");
    assert_eq!(deepest_existing(&dir.0.join("a").join("b").join("c")).unwrap(), dir.0);
    std::fs::create_dir(dir.0.join("a")).unwrap();
    assert_eq!(deepest_existing(&dir.0.join("a").join("b")).unwrap(), dir.0.join("a"));
}

#[test]
fn a_file_in_the_way_is_not_a_folder_to_watch() {
    let dir = TempDir::new("deep-file");
    std::fs::write(dir.0.join("a"), "").unwrap();
    assert_eq!(deepest_existing(&dir.0.join("a").join("b")).unwrap(), dir.0);
}

// the folder -----

#[test]
fn a_folder_made_after_the_watch_wakes_it_and_rearming_moves_the_watch_into_it() {
    let dir = TempDir::new("folder");
    let location = dir.location();
    std::fs::create_dir_all(location.dir.parent().unwrap()).unwrap();
    let mut watch = watch_of(&location);
    assert_eq!(watch.location(), Some(&location));

    std::fs::create_dir(&location.dir).unwrap();
    signalled(watch.handle());
    watch.rearm().unwrap();

    // Now inside the folder: a file made there wakes it.
    std::fs::write(location.serving_marker_path(), "1").unwrap();
    signalled(watch.handle());
}

#[test]
fn a_whole_chain_of_folders_made_at_once_is_found_by_one_rearm() {
    let dir = TempDir::new("chain");
    let location = dir.location();
    let mut watch = watch_of(&location);

    std::fs::create_dir_all(&location.dir).unwrap();
    signalled(watch.handle());
    watch.rearm().unwrap();

    std::fs::write(location.serving_marker_path(), "1").unwrap();
    signalled(watch.handle());
}

#[test]
fn a_chain_made_one_level_at_a_time_is_followed_down() {
    let dir = TempDir::new("steps");
    let location = dir.location();
    let mut watch = watch_of(&location);
    let mut level = dir.0.clone();
    for part in ["AppData", "Local", socket_loc::SOCKET_DIR_NAME] {
        level.push(part);
        std::fs::create_dir(&level).unwrap();
        signalled(watch.handle());
        watch.rearm().unwrap();
    }
    std::fs::write(location.serving_marker_path(), "1").unwrap();
    signalled(watch.handle());
}

#[test]
fn a_folder_that_already_exists_is_watched_from_the_start() {
    let dir = TempDir::new("exists");
    let location = dir.location();
    std::fs::create_dir_all(&location.dir).unwrap();
    let watch = watch_of(&location);
    std::fs::write(location.serving_marker_path(), "1").unwrap();
    signalled(watch.handle());
}

// the profile -----

/// A key under `HKEY_CURRENT_USER` that stands for `ProfileList`, deleted on drop.
struct TempKey {
    subkey: String,
}

impl TempKey {
    fn new(tag: &str) -> TempKey {
        let key = TempKey {
            subkey: format!(r"Software\{}", unique(tag)),
        };
        key.make("");
        key
    }

    fn make(&self, child: &str) {
        let path = if child.is_empty() {
            self.subkey.clone()
        } else {
            format!(r"{}\{child}", self.subkey)
        };
        let path_w: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
        let mut made = HKEY::default();
        // SAFETY: a NUL-terminated path and a valid out-pointer; the handle is closed at once.
        unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                PCWSTR(path_w.as_ptr()),
                None,
                PCWSTR::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_WRITE,
                None,
                &mut made,
                None,
            )
            .ok()
            .unwrap();
            let _ = RegCloseKey(made);
        }
    }

    fn profiles(&self) -> ProfileList {
        ProfileList::under(HKEY_CURRENT_USER, &self.subkey)
    }
}

impl Drop for TempKey {
    fn drop(&mut self) {
        let path_w: Vec<u16> = self.subkey.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: a NUL-terminated path.
        let _ = unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, PCWSTR(path_w.as_ptr())) };
    }
}

#[test]
fn a_missing_profile_is_waited_for_in_the_profile_list_and_then_in_the_folder() {
    let dir = TempDir::new("profile");
    let location = dir.location();
    let key = TempKey::new("profile");
    let exists = Rc::new(Cell::new(false));
    let mut watch = {
        let (location, exists) = (location.clone(), Rc::clone(&exists));
        SocketWatch::new(
            move || {
                if exists.get() {
                    Ok(location.clone())
                } else {
                    Err(crate::userdir::NoProfile.into())
                }
            },
            key.profiles(),
        )
        .unwrap()
    };
    assert_eq!(watch.location(), None, "no profile, so no location yet");

    // The logon makes the profile's entry; the watch on the list wakes.
    exists.set(true);
    key.make("S-1-5-21-1-2-3-1001");
    signalled(watch.handle());
    std::fs::create_dir_all(location.dir.parent().unwrap()).unwrap();
    watch.rearm().unwrap();
    assert_eq!(watch.location(), Some(&location));

    // The handle is now the folder's.
    std::fs::create_dir(&location.dir).unwrap();
    signalled(watch.handle());
}

#[test]
fn a_locate_failure_that_is_not_a_missing_profile_is_an_error() {
    let key = TempKey::new("other");
    let result = SocketWatch::new(|| anyhow::bail!("the profile path is too long"), key.profiles());
    assert!(result.is_err());
}

#[test]
fn the_profile_list_is_not_touched_while_the_profile_is_known() {
    let dir = TempDir::new("known");
    let location = dir.location();
    std::fs::create_dir_all(&location.dir).unwrap();
    // A key that does not exist: opening it would fail, so a watch on it would be an error.
    let watch = SocketWatch::new(
        {
            let location = location.clone();
            move || Ok(location.clone())
        },
        ProfileList::under(HKEY_CURRENT_USER, &format!(r"Software\{}", unique("absent"))),
    );
    assert!(watch.is_ok());
}
