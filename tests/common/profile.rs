//! Deleting a test account's profile once nothing holds it any more. **CI only.**
//!
//! Included by `account.rs`. A profile is deleted by `DeleteProfileW`, which answers
//! `ERROR_SHARING_VIOLATION` while the account's registry hive is loaded. After a secondary logon the hive
//! is unloaded by the system, after the last process of the account has exited and the last handle on one
//! of its tokens is closed, and that happens a moment after the exit.
//! So [`remove`] retries the delete until it succeeds, woken by a change of the subkeys of `HKEY_USERS` (a
//! hive being unloaded is one), and a profile that stays loaded fails the test.
//!
//! After a Task Scheduler or sshd logon Windows keeps the hive loaded for as long as it was measured (40
//! min; an sshd restart does not release it), as it does for a user who logged in at the console. That
//! is Windows' behaviour and not a defect. [`remove_or_clear`] is for
//! those accounts: it deletes the profile when Windows allows it, and otherwise deletes what can be deleted
//! of the profile folder (the hive's files stay), so that the disk does not fill.
#![allow(dead_code)]

use std::os::windows::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ssh_broker::winutil::OwnedHandle;
use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SHARING_VIOLATION, ERROR_SUCCESS, WAIT_OBJECT_0};
use windows::Win32::System::Registry::{
    HKEY, HKEY_USERS, KEY_NOTIFY, KEY_QUERY_VALUE, REG_NOTIFY_CHANGE_NAME, RegCloseKey, RegNotifyChangeKeyValue,
    RegOpenKeyExW,
};
use windows::Win32::System::Threading::{CreateEventW, ResetEvent, WaitForSingleObject};
use windows::Win32::UI::Shell::DeleteProfileW;
use windows::core::{HRESULT, PCWSTR};

use super::wide;

/// How long a profile may stay loaded after the processes of its account have ended. The system's unload
/// is an external event that can fail to come (something outside the test holds the account's token), and
/// expiry fails the test saying so; it is never read as "the profile is gone".
pub const UNLOAD_BOUND: Duration = Duration::from_secs(120);

/// How often the delete is tried again without a change of `HKEY_USERS` to say so: a hive unloaded without
/// a notification reaching us must not cost the whole bound.
const RECHECK: Duration = Duration::from_secs(1);

/// Delete the profile of the account `sid_text` (SDDL form); an account that has none is not an error.
/// Fails with the reason, and with whether the account's hive is still loaded, if the profile is still held
/// after [`UNLOAD_BOUND`] or the delete fails for another reason.
pub fn remove(sid_text: &str) -> Result<(), String> {
    let watch = HiveWatch::arm()?;
    let started = Instant::now();
    loop {
        match delete(sid_text) {
            Ok(()) => return Ok(()),
            Err(e) if e.code() == HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0) => return Ok(()),
            Err(e) if e.code() == HRESULT::from_win32(ERROR_SHARING_VIOLATION.0) => {
                let left = UNLOAD_BOUND.saturating_sub(started.elapsed());
                if left.is_zero() {
                    return Err(format!(
                        "{e}; still held {UNLOAD_BOUND:?} after the account's processes ended; {}",
                        hive_state(sid_text)
                    ));
                }
                watch.wait(left.min(RECHECK))?;
            }
            Err(e) => return Err(format!("{e}; {}", hive_state(sid_text))),
        }
    }
}

/// What [`remove_or_clear`] did.
pub enum Removal {
    /// The profile is deleted (or there was none).
    Deleted,
    /// The hive is loaded, so Windows refuses to delete the profile; the folder was cleared of what could be
    /// deleted.
    HiveLoaded(Cleared),
}

/// What is left of a profile folder after [`clear_folder`].
pub struct Cleared {
    pub folder: PathBuf,
    /// Files and links deleted.
    pub removed: u64,
    /// What could not be deleted, each with the reason (the loaded hive's files are among them).
    pub kept: Vec<String>,
}

impl std::fmt::Display for Removal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Removal::Deleted => f.write_str("the profile was deleted"),
            Removal::HiveLoaded(cleared) => {
                const SHOWN: usize = 6;
                write!(
                    f,
                    "the hive is still loaded, so the profile stays: {} had {} files deleted, {} entries stayed",
                    cleared.folder.display(),
                    cleared.removed,
                    cleared.kept.len()
                )?;
                if !cleared.kept.is_empty() {
                    let shown: Vec<&str> = cleared.kept.iter().take(SHOWN).map(String::as_str).collect();
                    write!(f, " ({}", shown.join("; "))?;
                    if cleared.kept.len() > SHOWN {
                        write!(f, "; and {} more", cleared.kept.len() - SHOWN)?;
                    }
                    f.write_str(")")?;
                }
                Ok(())
            }
        }
    }
}

/// [`remove`] for an account whose logon Windows may keep the hive of (Task Scheduler's, sshd's): one
/// delete, no wait for the hive. If Windows refuses because the hive is loaded, `folder` (the profile
/// folder, if the account has one) is cleared of what can be deleted. Any other refusal is [`remove`]'s.
pub fn remove_or_clear(sid_text: &str, folder: Option<&Path>) -> Result<Removal, String> {
    match delete(sid_text) {
        Ok(()) => return Ok(Removal::Deleted),
        Err(e) if e.code() == HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0) => return Ok(Removal::Deleted),
        Err(e) if e.code() == HRESULT::from_win32(ERROR_SHARING_VIOLATION.0) => {
            let loaded = hive_loaded(sid_text) == Ok(true) || hive_loaded(&format!("{sid_text}_Classes")) == Ok(true);
            if loaded {
                let folder = folder.ok_or_else(|| {
                    format!(
                        "{e}; the hive is loaded and the account has no profile folder to clear of what can be deleted"
                    )
                })?;
                return Ok(Removal::HiveLoaded(clear_folder(folder)?));
            }
        }
        Err(_) => {}
    }
    remove(sid_text).map(|()| Removal::Deleted)
}

/// Delete every file, link and folder under the profile folder `root` that can be deleted, and not
/// `root` itself. Links are removed, never followed. Refuses a folder whose name does not start with `sb`,
/// as every test account's profile does, so that a wrong path cannot cost anything else.
pub fn clear_folder(root: &Path) -> Result<Cleared, String> {
    let named_for_a_test_account = root
        .file_name()
        .is_some_and(|name| name.to_string_lossy().starts_with("sb"));
    if !named_for_a_test_account {
        return Err(format!(
            "{} is not named like a test account's profile folder (sb...), so it was not cleared",
            root.display()
        ));
    }
    let mut cleared = Cleared {
        folder: root.to_owned(),
        removed: 0,
        kept: Vec::new(),
    };
    clear_inside(root, &mut cleared);
    Ok(cleared)
}

fn clear_inside(dir: &Path, cleared: &mut Cleared) {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            cleared.kept.push(format!("{}: {e}", dir.display()));
            return;
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                cleared.kept.push(format!("{}: {e}", dir.display()));
                continue;
            }
        };
        let path = entry.path();
        let kind = match entry.file_type() {
            Ok(kind) => kind,
            Err(e) => {
                cleared.kept.push(format!("{}: {e}", path.display()));
                continue;
            }
        };
        let outcome = if kind.is_symlink_dir() {
            // A junction or directory symlink: the link goes, what it points at is not touched.
            std::fs::remove_dir(&path)
        } else if kind.is_dir() {
            let before = cleared.kept.len();
            clear_inside(&path, cleared);
            // Something kept inside it has been named already.
            if cleared.kept.len() != before {
                continue;
            }
            std::fs::remove_dir(&path)
        } else {
            remove_file(&path)
        };
        match outcome {
            Ok(()) => cleared.removed += 1,
            Err(e) => cleared.kept.push(format!("{}: {e}", path.display())),
        }
    }
}

fn remove_file(path: &Path) -> std::io::Result<()> {
    std::fs::remove_file(path).or_else(|first| {
        // A read-only file is not deleted until it is made writable.
        let mut permissions = std::fs::metadata(path).map_err(|_| first)?.permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        permissions.set_readonly(false);
        std::fs::set_permissions(path, permissions)?;
        std::fs::remove_file(path)
    })
}

pub(super) fn delete(sid_text: &str) -> windows::core::Result<()> {
    // SAFETY: NUL-terminated input; no computer name.
    unsafe { DeleteProfileW(PCWSTR(wide(sid_text).as_ptr()), PCWSTR::null(), PCWSTR::null()) }
}

/// When `HKEY_USERS\<sid>` was found unloaded.
pub enum Unload {
    /// The first look found it unloaded.
    Already,
    /// It was loaded at the first look and unloaded this long after.
    After(Duration),
}

impl std::fmt::Display for Unload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Unload::Already => f.write_str("already unloaded when first looked at"),
            Unload::After(took) => write!(f, "unloaded {took:?} after it was first looked at"),
        }
    }
}

/// Wait for `HKEY_USERS\<sid>` to unload. Fails, saying what is loaded, if it is still loaded
/// [`UNLOAD_BOUND`] after the first look: an external event that can fail to come.
pub fn wait_unloaded(sid_text: &str) -> Result<Unload, String> {
    let watch = HiveWatch::arm().map_err(|e| format!("not measured: {e}"))?;
    let started = Instant::now();
    let mut first = true;
    loop {
        match hive_loaded(sid_text) {
            Ok(false) => {
                return Ok(if first {
                    Unload::Already
                } else {
                    Unload::After(started.elapsed())
                });
            }
            Ok(true) => first = false,
            Err(e) => return Err(format!("not measured: {e}")),
        }
        let left = UNLOAD_BOUND.saturating_sub(started.elapsed());
        if left.is_zero() {
            return Err(format!(
                "still loaded {UNLOAD_BOUND:?} after it was first looked at; {}",
                hive_state(sid_text)
            ));
        }
        watch
            .wait(left.min(RECHECK))
            .map_err(|e| format!("not measured: {e}"))?;
    }
}

/// Whether `HKEY_USERS\<sid>` (the loaded hive) and its classes hive are present, as text.
pub fn hive_state(sid_text: &str) -> String {
    let state = |subkey: String| match hive_loaded(&subkey) {
        Ok(true) => "loaded".to_string(),
        Ok(false) => "not loaded".to_string(),
        Err(e) => format!("unknown ({e})"),
    };
    format!(
        "HKEY_USERS\\{sid_text} is {}, its _Classes is {}",
        state(sid_text.to_string()),
        state(format!("{sid_text}_Classes"))
    )
}

fn hive_loaded(subkey: &str) -> Result<bool, String> {
    let mut key = HKEY::default();
    // SAFETY: a NUL-terminated name and a valid out-pointer; the key is closed below.
    let opened = unsafe {
        RegOpenKeyExW(
            HKEY_USERS,
            PCWSTR(wide(subkey).as_ptr()),
            None,
            KEY_QUERY_VALUE,
            &mut key,
        )
    };
    if opened == ERROR_SUCCESS {
        // SAFETY: the key just opened.
        let _ = unsafe { RegCloseKey(key) };
        Ok(true)
    } else if opened == ERROR_FILE_NOT_FOUND {
        Ok(false)
    } else {
        Err(format!("RegOpenKeyExW: {opened:?}"))
    }
}

/// A notification on the subkeys of `HKEY_USERS`, signalled through an unnamed event.
struct HiveWatch {
    key: HKEY,
    event: OwnedHandle,
}

impl HiveWatch {
    /// Registered before the first delete, so an unload between that delete and the first wait signals.
    fn arm() -> Result<HiveWatch, String> {
        let mut key = HKEY::default();
        // SAFETY: a valid out-pointer; the key is closed on drop.
        unsafe { RegOpenKeyExW(HKEY_USERS, PCWSTR::null(), None, KEY_NOTIFY, &mut key) }
            .ok()
            .map_err(|e| format!("open HKEY_USERS to watch it: {e}"))?;
        // SAFETY: an unnamed manual-reset event, not signalled.
        let event = match unsafe { CreateEventW(None, true, false, PCWSTR::null()) } {
            Ok(event) => OwnedHandle(event),
            Err(e) => {
                // SAFETY: the key just opened.
                let _ = unsafe { RegCloseKey(key) };
                return Err(format!("CreateEventW: {e}"));
            }
        };
        let watch = HiveWatch { key, event };
        watch.register()?;
        Ok(watch)
    }

    fn register(&self) -> Result<(), String> {
        // SAFETY: valid handles. The event is reset first, so a change after the registration signals it
        // again and is not lost.
        unsafe {
            ResetEvent(self.event.0).map_err(|e| format!("ResetEvent: {e}"))?;
            RegNotifyChangeKeyValue(self.key, false, REG_NOTIFY_CHANGE_NAME, Some(self.event.0), true)
                .ok()
                .map_err(|e| format!("watch HKEY_USERS: {e}"))
        }
    }

    /// Wait for a change of `HKEY_USERS` for at most `bound`, then register again if one came. The caller
    /// tries the delete again either way; the wait only says when.
    fn wait(&self, bound: Duration) -> Result<(), String> {
        let millis = u32::try_from(bound.as_millis()).expect("a bound shorter than INFINITE");
        // SAFETY: a valid event handle.
        let woke = unsafe { WaitForSingleObject(self.event.0, millis) }; // sleep-ok: wakes the retry of a delete whose real condition is re-checked each time; expiry is not read as state
        if woke == WAIT_OBJECT_0 { self.register() } else { Ok(()) }
    }
}

impl Drop for HiveWatch {
    fn drop(&mut self) {
        // SAFETY: the key from `arm`.
        let _ = unsafe { RegCloseKey(self.key) };
    }
}
