//! Looking at a logon session from outside: which processes hold it, and when Windows destroys it.
//! **CI only.**
#![allow(dead_code)]

use std::time::Duration;

use ssh_broker::winutil::OwnedHandle;
use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
use windows::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_STATISTICS, TokenStatistics};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::EventLog::{EVT_HANDLE, EvtClose, EvtSubscribe, EvtSubscribeToFutureEvents};
use windows::Win32::System::Threading::{
    CreateEventW, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    WaitForSingleObject,
};
use windows::core::PCWSTR;

/// The logon id of `process`' token, as the 64-bit value the event log prints in hex.
pub fn logon_id(process: HANDLE) -> u64 {
    let mut token = HANDLE::default();
    // SAFETY: a valid process handle and out-pointer; the token is closed by `OwnedHandle`.
    unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) }.expect("open the process token");
    let token = OwnedHandle(token);
    let mut stats = TOKEN_STATISTICS::default();
    let mut len = 0u32;
    // SAFETY: `stats` is a `TOKEN_STATISTICS` and the length passed is its size.
    unsafe {
        GetTokenInformation(
            token.0,
            TokenStatistics,
            Some(&mut stats as *mut _ as *mut core::ffi::c_void),
            std::mem::size_of::<TOKEN_STATISTICS>() as u32,
            &mut len,
        )
    }
    .expect("read the token statistics");
    (u64::from(stats.AuthenticationId.HighPart as u32) << 32) | u64::from(stats.AuthenticationId.LowPart)
}

/// A handle on every process whose token belongs to logon session `id`, with its process id. A
/// process that cannot be opened is skipped: it is not one of the account's.
pub fn processes_of(id: u64) -> Vec<(u32, OwnedHandle)> {
    // SAFETY: a snapshot of all processes; the handle is closed by `OwnedHandle`.
    let snapshot = OwnedHandle(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.expect("snapshot"));
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut found = Vec::new();
    // SAFETY: `entry` is a valid out-pointer with `dwSize` set; the snapshot outlives the loop.
    let mut more = unsafe { Process32FirstW(snapshot.0, &mut entry) }.is_ok();
    while more {
        let pid = entry.th32ProcessID;
        // SAFETY: a plain open by id; the handle is closed by `OwnedHandle`.
        if let Ok(handle) = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE, false, pid) }
        {
            let handle = OwnedHandle(handle);
            let mut token = HANDLE::default();
            // SAFETY: as above.
            if unsafe { OpenProcessToken(handle.0, TOKEN_QUERY, &mut token) }.is_ok() {
                drop(OwnedHandle(token));
                if logon_id(handle.0) == id {
                    found.push((pid, handle));
                }
            }
        }
        // SAFETY: as above.
        more = unsafe { Process32NextW(snapshot.0, &mut entry) }.is_ok();
    }
    found
}

/// Fail unless Logoff auditing for success is on: without it the system writes no event 4634 and
/// the watch below could only time out.
pub fn assert_logoff_auditing() {
    let out = std::process::Command::new("auditpol")
        .args(["/get", "/subcategory:Logoff"])
        .output()
        .expect("run auditpol");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("Success"),
        "precondition: Logoff auditing for success must be on (CI runs `auditpol /set /subcategory:\"Logoff\" /success:enable`); auditpol says:\n{text}"
    );
}

/// A subscription to the Security event 4634 (an account was logged off) of one logon session.
pub struct LogoffWatch {
    subscription: EVT_HANDLE,
    signal: OwnedHandle,
}

impl LogoffWatch {
    /// Subscribe to events from now on. Create it before the session can end.
    pub fn new(id: u64) -> LogoffWatch {
        // SAFETY: an unnamed manual-reset event.
        let signal = OwnedHandle(unsafe { CreateEventW(None, true, false, PCWSTR::null()) }.expect("CreateEventW"));
        let query: Vec<u16> = format!(
            "*[System[EventID=4634]] and *[EventData[Data[@Name='TargetLogonId']='{lower}' or Data[@Name='TargetLogonId']='{upper}']]",
            lower = format_args!("{id:#x}"),
            upper = format_args!("0x{id:X}"),
        )
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
        let channel: Vec<u16> = "Security".encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: NUL-terminated inputs; the signal event outlives the subscription (dropped after it).
        let subscription = unsafe {
            EvtSubscribe(
                None,
                Some(signal.0),
                PCWSTR(channel.as_ptr()),
                PCWSTR(query.as_ptr()),
                None,
                None,
                None,
                EvtSubscribeToFutureEvents.0,
            )
        }
        .unwrap_or_else(|e| panic!("subscribe to the Security log (needs an elevated administrator): {e}"));
        LogoffWatch { subscription, signal }
    }

    /// Wait for the logoff event for at most `bound`. An event the OS may never deliver is an
    /// external event, so this is the one bounded wait; the caller treats expiry as a failure that
    /// reports what was measured, never as a pass.
    pub fn wait(&self, bound: Duration) -> bool {
        let millis = u32::try_from(bound.as_millis()).expect("a bound shorter than INFINITE");
        // SAFETY: a valid event handle.
        let rc = unsafe { WaitForSingleObject(self.signal.0, millis) }; // sleep-ok: failure bound on an OS event that may never come; expiry fails the test and is not read as state
        rc == WAIT_OBJECT_0
    }
}

impl Drop for LogoffWatch {
    fn drop(&mut self) {
        // SAFETY: the handle from `new`.
        let _ = unsafe { EvtClose(self.subscription) };
    }
}
