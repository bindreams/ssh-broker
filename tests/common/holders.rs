//! The logon sessions of a test account, from LSA (read only). **CI only.**
//!
//! Included by `account.rs`. A hive stays loaded while a logon session of the account lives, and a
//! session lives while some process holds a handle on one of its tokens (or on a process that has one).
//! [`sessions_of`] lists the logon sessions of the account that exist; [`report`] prints them for a failure
//! message.
#![allow(dead_code)]

use std::time::{SystemTime, UNIX_EPOCH};

use windows::Win32::Foundation::{HLOCAL, LUID, LocalFree};
use windows::Win32::Security::Authentication::Identity::{
    LSA_UNICODE_STRING, LsaEnumerateLogonSessions, LsaFreeReturnBuffer, LsaGetLogonSessionData,
    SECURITY_LOGON_SESSION_DATA,
};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::core::PWSTR;

/// A logon session LSA lists.
#[derive(Debug, Clone)]
pub struct LogonSession {
    /// The logon id, as `logon_session::logon_id` reads it from a token.
    pub id: u64,
    pub logon_type: u32,
    pub auth_package: String,
    pub windows_session: u32,
    /// Seconds since the Unix epoch.
    pub started: i64,
    /// Seconds since the Unix epoch, when this was read.
    pub read_at: i64,
}

impl std::fmt::Display for LogonSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let logon_type = match self.logon_type {
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
        let time_of_day = self.started.rem_euclid(86_400);
        write!(
            f,
            "logon id {:#x}: type {} ({logon_type}), auth package {}, windows session {}, started {:02}:{:02}:{:02} UTC ({} s before this was read)",
            self.id,
            self.logon_type,
            self.auth_package,
            self.windows_session,
            time_of_day / 3600,
            time_of_day % 3600 / 60,
            time_of_day % 60,
            self.read_at - self.started
        )
    }
}

/// The logon sessions that exist for the account `sid_text` (SDDL form), as text for a failure message.
pub fn report(sid_text: &str) -> String {
    let body = match sessions_of(sid_text) {
        Ok(sessions) if sessions.is_empty() => "  none".to_string(),
        Ok(sessions) => sessions
            .iter()
            .map(|session| format!("  {session}"))
            .collect::<Vec<_>>()
            .join("\n"),
        Err(why) => format!("  {why}"),
    };
    format!("logon sessions of the account:\n{body}")
}

/// The logon sessions LSA lists for the account `sid_text` (SDDL form), in LSA's order.
pub fn sessions_of(sid_text: &str) -> Result<Vec<LogonSession>, String> {
    let mut count = 0u32;
    let mut list: *mut LUID = std::ptr::null_mut();
    // SAFETY: valid out-pointers; the list LSA allocates is freed below.
    let status = unsafe { LsaEnumerateLogonSessions(&mut count, &mut list) };
    if status.0 != 0 || list.is_null() {
        return Err(format!("LsaEnumerateLogonSessions failed: NTSTATUS {:#010x}", status.0));
    }
    // SAFETY: LSA returned `count` consecutive LUIDs, read before they are freed.
    let ids: Vec<LUID> = unsafe { std::slice::from_raw_parts(list, count as usize) }.to_vec();
    // SAFETY: the buffer came from LSA.
    let _ = unsafe { LsaFreeReturnBuffer(list.cast()) };

    let mut sessions = Vec::new();
    for id in &ids {
        let mut data: *mut SECURITY_LOGON_SESSION_DATA = std::ptr::null_mut();
        // SAFETY: a LUID from the list and a valid out-pointer; the buffer is freed below.
        let status = unsafe { LsaGetLogonSessionData(id, &mut data) };
        if status.0 != 0 || data.is_null() {
            // A session can end between the listing and the query.
            continue;
        }
        // SAFETY: LSA returned a valid structure; it is read and freed before the next one.
        let session = unsafe { describe(&*data, sid_text) };
        // SAFETY: the buffer came from LSA.
        let _ = unsafe { LsaFreeReturnBuffer(data.cast()) };
        sessions.extend(session);
    }
    Ok(sessions)
}

/// The session `data` describes, if it belongs to the account `sid_text`.
///
/// # Safety
/// The strings and the SID in `data` must be valid, as LSA returns them.
unsafe fn describe(data: &SECURITY_LOGON_SESSION_DATA, sid_text: &str) -> Option<LogonSession> {
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
    // FILETIME (100 ns since 1601) to seconds since the Unix epoch.
    let started = (data.LogonTime / 10_000_000) - 11_644_473_600;
    let read_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    Some(LogonSession {
        id: (u64::from(data.LogonId.HighPart as u32) << 32) | u64::from(data.LogonId.LowPart),
        logon_type: data.LogonType,
        // SAFETY: valid per this function's contract.
        auth_package: unsafe { lsa_string(&data.AuthenticationPackage) },
        windows_session: data.Session,
        started,
        read_at,
    })
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
