//! What still holds a test account's profile after its processes have ended. **CI only.**
//!
//! Included by `account.rs`. A hive stays loaded while a logon session of the account lives, and a
//! session lives while some process holds a handle on one of its tokens (or on a process that has one).
//! [`report`] names the logon sessions of the account that still exist.
#![allow(dead_code)]

use std::time::{SystemTime, UNIX_EPOCH};

use windows::Win32::Foundation::{HLOCAL, LUID, LocalFree};
use windows::Win32::Security::Authentication::Identity::{
    LSA_UNICODE_STRING, LsaEnumerateLogonSessions, LsaFreeReturnBuffer, LsaGetLogonSessionData,
    SECURITY_LOGON_SESSION_DATA,
};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::core::PWSTR;

/// The logon sessions that exist for the account `sid_text` (SDDL form), as text for a failure message.
pub fn report(sid_text: &str) -> String {
    format!("logon sessions of the account:\n{}", logon_sessions(sid_text))
}

fn logon_sessions(sid_text: &str) -> String {
    let mut count = 0u32;
    let mut list: *mut LUID = std::ptr::null_mut();
    // SAFETY: valid out-pointers; the list LSA allocates is freed below.
    let status = unsafe { LsaEnumerateLogonSessions(&mut count, &mut list) };
    if status.0 != 0 || list.is_null() {
        return format!("  LsaEnumerateLogonSessions failed: NTSTATUS {:#010x}", status.0);
    }
    // SAFETY: LSA returned `count` consecutive LUIDs, read before they are freed.
    let ids: Vec<LUID> = unsafe { std::slice::from_raw_parts(list, count as usize) }.to_vec();
    // SAFETY: the buffer came from LSA.
    let _ = unsafe { LsaFreeReturnBuffer(list.cast()) };

    let mut lines = Vec::new();
    for id in &ids {
        let mut data: *mut SECURITY_LOGON_SESSION_DATA = std::ptr::null_mut();
        // SAFETY: a LUID from the list and a valid out-pointer; the buffer is freed below.
        let status = unsafe { LsaGetLogonSessionData(id, &mut data) };
        if status.0 != 0 || data.is_null() {
            // A session can end between the listing and the query.
            continue;
        }
        // SAFETY: LSA returned a valid structure; it is read, formatted and freed before the next one.
        let line = unsafe { describe(&*data, sid_text) };
        // SAFETY: the buffer came from LSA.
        let _ = unsafe { LsaFreeReturnBuffer(data.cast()) };
        lines.extend(line);
    }
    if lines.is_empty() {
        "  none".to_string()
    } else {
        lines.join("\n")
    }
}

/// The line for `data` if it belongs to the account `sid_text`.
///
/// # Safety
/// The strings and the SID in `data` must be valid, as LSA returns them.
unsafe fn describe(data: &SECURITY_LOGON_SESSION_DATA, sid_text: &str) -> Option<String> {
    if data.Sid.0.is_null() {
        return None;
    }
    let mut text = PWSTR::null();
    // SAFETY: a valid SID from LSA; the string is freed below.
    unsafe { ConvertSidToStringSidW(data.Sid, &mut text) }.ok()?;
    // SAFETY: the NUL-terminated string just made.
    let owner = unsafe { text.to_string() }.unwrap_or_default();
    // SAFETY: allocated by `ConvertSidToStringSidW`, to be freed with `LocalFree`.
    let _ = unsafe { LocalFree(Some(HLOCAL(text.0.cast()))) };
    if owner != sid_text {
        return None;
    }
    let logon_type = match data.LogonType {
        2 => "Interactive",
        3 => "Network",
        4 => "Batch",
        5 => "Service",
        7 => "Unlock",
        8 => "NetworkCleartext",
        9 => "NewCredentials",
        10 => "RemoteInteractive",
        11 => "CachedInteractive",
        _ => "other",
    };
    // FILETIME (100 ns since 1601) to seconds before now.
    let started = (data.LogonTime / 10_000_000) - 11_644_473_600;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    Some(format!(
        "  logon id {:#x}{:08x}: type {} ({logon_type}), auth package {}, windows session {}, started {} s ago",
        data.LogonId.HighPart,
        data.LogonId.LowPart,
        data.LogonType,
        // SAFETY: valid per this function's contract.
        unsafe { lsa_string(&data.AuthenticationPackage) },
        data.Session,
        now - started
    ))
}

/// # Safety
/// `text` must be valid, as LSA returns it.
unsafe fn lsa_string(text: &LSA_UNICODE_STRING) -> String {
    if text.Buffer.is_null() || text.Length == 0 {
        return String::new();
    }
    // SAFETY: `Length` bytes of UTF-16 at `Buffer`.
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text.Buffer.0, usize::from(text.Length) / 2) })
}
