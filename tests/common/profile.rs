//! Deleting a test account's profile once nothing holds it any more. **CI only.**
//!
//! Included by `account.rs`. A profile is deleted by `DeleteProfileW`, which answers
//! `ERROR_SHARING_VIOLATION` while the account's registry hive is loaded. The hive is unloaded by the
//! system, after the last process of the account has exited and the last handle on one of its tokens is
//! closed, and that happens a moment after the exit (CI round 14: most profiles stayed). So the delete
//! is retried until it succeeds, woken by a change of the subkeys of `HKEY_USERS` (a hive being unloaded
//! is one), and a profile that stays loaded fails the test.
#![allow(dead_code)]

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

pub(super) fn delete(sid_text: &str) -> windows::core::Result<()> {
    // SAFETY: NUL-terminated input; no computer name.
    unsafe { DeleteProfileW(PCWSTR(wide(sid_text).as_ptr()), PCWSTR::null(), PCWSTR::null()) }
}

/// Wait for `HKEY_USERS\<sid>` to unload, and say when it did or that it had not after [`UNLOAD_BOUND`]. A
/// measurement of the normal end of a session, not a check: nothing is asserted from the answer.
pub fn measure_unload(sid_text: &str) -> String {
    let watch = match HiveWatch::arm() {
        Ok(watch) => watch,
        Err(e) => return format!("not measured: {e}"),
    };
    let started = Instant::now();
    let mut first = true;
    loop {
        match hive_loaded(sid_text) {
            Ok(false) => {
                return if first {
                    "already unloaded when first looked at".to_string()
                } else {
                    format!("unloaded {:?} after it was first looked at", started.elapsed())
                };
            }
            Ok(true) if first => first = false,
            Ok(true) => {}
            Err(e) => return format!("not measured: {e}"),
        }
        let left = UNLOAD_BOUND.saturating_sub(started.elapsed());
        if left.is_zero() {
            return format!(
                "still loaded {UNLOAD_BOUND:?} after it was first looked at; {}",
                hive_state(sid_text)
            );
        }
        if let Err(e) = watch.wait(left.min(RECHECK)) {
            return format!("not measured: {e}");
        }
    }
}

/// Whether `HKEY_USERS\<sid>` (the loaded hive) and its classes hive are present, as text.
fn hive_state(sid_text: &str) -> String {
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
