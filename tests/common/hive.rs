//! Unloading a test account's registry hive by hand, and what the system says about it. **CI only.**
//!
//! Included by `account.rs`. In CI round 16 the hive of a profile (`HKEY_USERS\<sid>` and `_Classes`) stayed
//! loaded 120 s after the account's processes ended, with no process handle on it and no logon session of the
//! account (bar one Batch session). The profile service decides when a hive unloads, from the reference count
//! in `ProfileList\<sid>`. [`profile_list`] prints that count; [`unload_and_delete`] unloads the two hives
//! itself, as the teardown of a throwaway account in an attended run, and deletes the profile.
//!
//! A teardown that does this hides the "stays loaded" failure, so every use is also written to a file that CI
//! prints ([`record`]): the measurement is the point of the run.
#![allow(dead_code)]

use std::io::Write;

use windows::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_NOT_ALL_ASSIGNED, ERROR_SUCCESS, GetLastError, LUID, WIN32_ERROR,
};
use windows::Win32::Security::{
    AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_BACKUP_NAME, SE_PRIVILEGE_ENABLED,
    SE_RESTORE_NAME, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_QUERY_VALUE, REG_DWORD, REG_VALUE_TYPE, RegCloseKey, RegOpenKeyExW,
    RegQueryValueExW, RegUnLoadKeyW,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::PCWSTR;

use super::{profile, wide};
use ssh_broker::winutil::OwnedHandle;

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

/// What the unload by hand did, and whether the profile is gone after it.
pub struct Forced {
    pub deleted: bool,
    pub text: String,
}

/// Unload `HKEY_USERS\<sid>_Classes` and then `HKEY_USERS\<sid>`, and delete the profile. The test process
/// enables `SeBackupPrivilege` and `SeRestorePrivilege` first (an elevated administrator holds them,
/// disabled). Each step's result is in the text; a step that fails does not stop the next one, so the text
/// shows what each did.
pub fn unload_and_delete(sid_text: &str) -> Forced {
    let mut lines = vec![format!("ProfileList before: {}", profile_list(sid_text))];
    for name in [SE_BACKUP_NAME, SE_RESTORE_NAME] {
        lines.push(match enable(name) {
            Ok(()) => format!("enabled {}", unsafe { name.to_string() }.unwrap_or_default()),
            Err(why) => format!(
                "could not enable {}: {why}",
                unsafe { name.to_string() }.unwrap_or_default()
            ),
        });
    }
    for subkey in [format!("{sid_text}_Classes"), sid_text.to_string()] {
        // SAFETY: a NUL-terminated name; the hive key is HKEY_USERS.
        let result = unsafe { RegUnLoadKeyW(HKEY_USERS, PCWSTR(wide(&subkey).as_ptr())) };
        lines.push(format!("RegUnLoadKey HKEY_USERS\\{subkey}: {}", describe(result)));
    }
    let deleted = match profile::delete(sid_text) {
        Ok(()) => {
            lines.push("DeleteProfileW: deleted".to_string());
            true
        }
        Err(e) if e.code() == windows::core::HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0) => {
            lines.push("DeleteProfileW: no such profile".to_string());
            true
        }
        Err(e) => {
            lines.push(format!("DeleteProfileW: {e}"));
            false
        }
    };
    lines.push(format!("ProfileList after: {}", profile_list(sid_text)));
    Forced {
        deleted,
        text: lines.join("\n  "),
    }
}

fn describe(result: WIN32_ERROR) -> String {
    if result == ERROR_SUCCESS {
        "ok".to_string()
    } else {
        format!("{} ({:#x})", windows::core::Error::from(result.to_hresult()), result.0)
    }
}

/// Enable the privilege `name` on this process's token.
fn enable(name: PCWSTR) -> Result<(), String> {
    let mut token = windows::Win32::Foundation::HANDLE::default();
    // SAFETY: a valid out-pointer; the handle is closed by `OwnedHandle`.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token) }
        .map_err(|e| format!("OpenProcessToken: {e}"))?;
    let token = OwnedHandle(token);
    let mut luid = LUID::default();
    // SAFETY: a valid privilege name and out-pointer.
    unsafe { LookupPrivilegeValueW(PCWSTR::null(), name, &mut luid) }
        .map_err(|e| format!("LookupPrivilegeValueW: {e}"))?;
    let privileges = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };
    // SAFETY: a valid token with TOKEN_ADJUST_PRIVILEGES.
    unsafe { AdjustTokenPrivileges(token.0, false, Some(&privileges), 0, None, None) }
        .map_err(|e| format!("AdjustTokenPrivileges: {e}"))?;
    // AdjustTokenPrivileges succeeds although it assigned nothing when the token does not hold the privilege.
    // SAFETY: reads the calling thread's last error.
    if unsafe { GetLastError() } == ERROR_NOT_ALL_ASSIGNED {
        return Err("the token does not hold it".to_string());
    }
    Ok(())
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
