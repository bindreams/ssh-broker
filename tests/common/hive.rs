//! What the system says about a test account's registry hive, and where measurements are recorded.
//! **CI only.**
//!
//! The hive of a profile (`HKEY_USERS\<sid>` and `_Classes`) can stay loaded 120 s after the account's
//! processes ended, with no process handle on it and no logon session of the account (bar one Batch
//! session). The profile service decides when a hive unloads, from the reference count in
//! `ProfileList\<sid>`; [`profile_list`] prints it. `RegUnLoadKey` by hand is refused (access denied, even
//! with backup/restore privileges), so a test cannot unload it.
//!
//! A teardown hides a passing test's output, so a measurement is also written to a file that CI prints
//! ([`record`]).
#![allow(dead_code)]

use std::io::Write;

use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS, WIN32_ERROR};
use windows::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, REG_DWORD, REG_VALUE_TYPE, RegCloseKey, RegOpenKeyExW, RegQueryValueExW,
};
use windows::core::PCWSTR;

use super::wide;

/// Where [`record`] appends. A fixed path, because the M3 tests run as SYSTEM in a scheduled task and see
/// none of the runner's variables; the CI job prints it after the tests.
pub const MEASUREMENT_FILE: &str = r"C:\ProgramData\sb-profile-measure.log";

const PROFILE_LIST: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";

/// Append `entry` to [`MEASUREMENT_FILE`] in one write, and print it. nextest hides the output of a test that
/// passes, which is why the file exists.
pub fn record(entry: &str) {
    eprintln!("{entry}");
    let text = format!("{entry}\n");
    let written = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(MEASUREMENT_FILE)
        .and_then(|mut file| file.write_all(text.as_bytes()));
    if let Err(e) = written {
        eprintln!("could not write the measurement to {MEASUREMENT_FILE}: {e}");
    }
}

fn describe(result: WIN32_ERROR) -> String {
    if result == ERROR_SUCCESS {
        "ok".to_string()
    } else {
        format!("{} ({:#x})", windows::core::Error::from(result.to_hresult()), result.0)
    }
}

/// `RefCount`, `State`, `Flags` and `ProfileImagePath` of `ProfileList\<sid>`, read only, as text.
pub fn profile_list(sid_text: &str) -> String {
    let path = format!(r"{PROFILE_LIST}\{sid_text}");
    let mut key = HKEY::default();
    // SAFETY: a NUL-terminated name and a valid out-pointer; the key is closed below.
    let opened = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(wide(&path).as_ptr()),
            None,
            KEY_QUERY_VALUE,
            &mut key,
        )
    };
    if opened == ERROR_FILE_NOT_FOUND {
        return "no entry".to_string();
    }
    if opened != ERROR_SUCCESS {
        return format!("could not open it: {}", describe(opened));
    }
    let values: Vec<String> = ["RefCount", "State", "Flags"]
        .iter()
        .map(|name| format!("{name} = {}", dword(key, name)))
        .collect();
    // SAFETY: the key just opened.
    let _ = unsafe { RegCloseKey(key) };
    values.join(", ")
}

fn dword(key: HKEY, name: &str) -> String {
    let mut kind = REG_VALUE_TYPE(0);
    let mut value = 0u32;
    let mut size = std::mem::size_of::<u32>() as u32;
    // SAFETY: valid out-pointers for a 4-byte value.
    let result = unsafe {
        RegQueryValueExW(
            key,
            PCWSTR(wide(name).as_ptr()),
            None,
            Some(&mut kind),
            Some((&mut value as *mut u32).cast()),
            Some(&mut size),
        )
    };
    if result == ERROR_FILE_NOT_FOUND {
        "absent".to_string()
    } else if result != ERROR_SUCCESS {
        format!("unreadable ({})", describe(result))
    } else if kind != REG_DWORD {
        format!("not a DWORD (type {})", kind.0)
    } else {
        format!("{value} ({value:#x})")
    }
}
