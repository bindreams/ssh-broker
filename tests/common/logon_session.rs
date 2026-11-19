//! Looking at a logon session from outside: which processes hold it, whether LSA still lists it and how
//! long it takes to leave the list ([`wait_until_unlisted`]), and a watch on the Security log for a refused
//! logon (4625). **CI only.**
//!
//! The including crate declares `account_fixture` (the list is read by `account_fixture::holders`) and
//! `process_list`.
#![allow(dead_code)]

use std::time::{Duration, Instant};

use ssh_broker::winutil::OwnedHandle;
use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
use windows::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_STATISTICS, TokenStatistics};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::EventLog::{EVT_HANDLE, EvtClose, EvtNext, EvtSubscribe, EvtSubscribeToFutureEvents};
use windows::Win32::System::Threading::{
    CreateEventW, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    WaitForSingleObject,
};
use windows::core::PCWSTR;

use crate::account_fixture::holders;
use crate::process_list;

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

/// Fail unless `auditpol` reports `setting` ("Success" or "Failure") on for `subcategory`: without
/// the auditing the system writes no event, and the watch below could only time out.
pub fn assert_auditing(subcategory: &str, setting: &str) {
    let out = std::process::Command::new("auditpol")
        .args(["/get", &format!("/subcategory:{subcategory}")])
        .output()
        .expect("run auditpol");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains(setting),
        "precondition: {subcategory} auditing for {} must be on (CI runs `auditpol /set /subcategory:\"{subcategory}\" /{}:enable`); auditpol says:\n{text}",
        setting.to_lowercase(),
        setting.to_lowercase(),
    );
}

/// How long LSA may keep listing a logon session after its last process has ended: an external event
/// that may never come. A Batch logon that the product made (the shim's password prompt) leaves the list after
/// about 90 s and an interactive secondary logon after about 180 s; the bound is twice the longer. It is for the
/// logons the product made: a logon the Task Scheduler made stayed listed past 360 s with no process in it, and
/// is not waited for (see `session_end`). The sessions a `logout` ends share one deadline of this
/// length, counted from when no process is left in them (see [`wait_until_unlisted`]). A test that ends several
/// sessions, one `logout` each, needs a termination in `.config/nextest.toml` beyond the sum of its bounds.
/// Expiry fails the wait and names what still refers to the session.
pub const SESSION_END_BOUND: Duration = Duration::from_secs(360);

/// The pause between two looks at LSA's list in [`wait_until_unlisted`].
const LOOK_EVERY: Duration = Duration::from_secs(1);

/// Whether `LsaEnumerateLogonSessions` still lists the logon session `id`.
pub fn is_listed(id: u64) -> Result<bool, String> {
    Ok(holders::listed()?
        .iter()
        .any(|luid| (u64::from(luid.HighPart as u32) << 32) | u64::from(luid.LowPart) == id))
}

/// Fail unless LSA lists the logon session `id` of the account `sid_text` now. Call it before ending the
/// session: [`wait_until_unlisted`] passes at once for an id that was never listed (read from the wrong
/// token, or a list that omits it), and so would show nothing.
pub fn require_listed(id: u64, sid_text: &str) -> Result<(), String> {
    if is_listed(id)? {
        Ok(())
    } else {
        Err(format!(
            "logon session {id:#x} of its agent is not in LSA's list before the session is ended\n{}",
            holders::report(sid_text)
        ))
    }
}

/// Wait until the logon session `id` is no longer in LSA's list. The caller holds no handle on a process or
/// token of the session: one keeps it listed. It looks once a second. Once `deadline` has passed it fails,
/// naming the processes of the session that still run. `deadline` is [`SESSION_END_BOUND`] after the moment
/// no process is left in any session a `logout` ended, the same for each of them.
pub fn wait_until_unlisted(id: u64, deadline: Instant) -> Result<(), String> {
    while is_listed(id)? {
        if Instant::now() >= deadline {
            let own = std::process::id();
            let running: Vec<u32> = processes_of(id)
                .iter()
                .filter(|(pid, process)| *pid != own && !process_list::has_exited(process.0))
                .map(|(pid, _)| *pid)
                .collect();
            return Err(format!(
                "logon session {id:#x} is still in LSA's list {SESSION_END_BOUND:?} after the last process of \
                 its logout's sessions ended; processes still running in it (pids {running:?})"
            ));
        }
        std::thread::sleep(LOOK_EVERY); // sleep-ok: the pause between two looks at the list; its expiry proves nothing
    }
    Ok(())
}

/// A subscription to Security events that match an XPath query, from now on.
pub struct EventWatch {
    subscription: EVT_HANDLE,
    signal: OwnedHandle,
    /// A matching event arrived before the first `EvtNext` call in [`EventWatch::on`] returned.
    arrived_early: bool,
}

/// The XPath for event `id` whose `Data` field `field` is `value`.
fn query_for(id: u32, field: &str, value: &str) -> String {
    format!("*[System[EventID={id}]] and *[EventData[Data[@Name='{field}']='{value}']]")
}

impl EventWatch {
    pub fn new(query: &str) -> EventWatch {
        EventWatch::on("Security", query)
    }

    /// Subscribe to `channel`. A pull subscription signals its event only after a call of `EvtNext`
    /// has returned `ERROR_NO_MORE_ITEMS`: the service does not signal for a client that has not yet
    /// asked (measured: with no such call a logged event never signalled, on the Application channel
    /// and, in CI, for Security events). So the subscription is primed
    /// with one call here, and an event that arrived before it is remembered.
    pub fn on(channel: &str, query: &str) -> EventWatch {
        // SAFETY: an unnamed manual-reset event.
        let signal = OwnedHandle(unsafe { CreateEventW(None, true, false, PCWSTR::null()) }.expect("CreateEventW"));
        let query: Vec<u16> = query.encode_utf16().chain(std::iter::once(0)).collect();
        let channel: Vec<u16> = channel.encode_utf16().chain(std::iter::once(0)).collect();
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
        let mut event = [0isize; 1];
        let mut returned = 0u32;
        // SAFETY: a valid subscription and buffers of the sizes passed; no wait (timeout 0).
        let primed = unsafe { EvtNext(subscription, &mut event, 0, 0, &mut returned) };
        let arrived_early = primed.is_ok() && returned > 0;
        if arrived_early {
            // SAFETY: the event handle EvtNext just returned.
            let _ = unsafe { EvtClose(EVT_HANDLE(event[0])) };
        } else if let Err(e) = primed {
            // ERROR_NO_MORE_ITEMS (259): nothing yet, and the service now signals when something comes.
            assert_eq!(e.code().0 as u32, 0x8007_0103, "prime the event subscription: {e}");
        }
        EventWatch {
            subscription,
            signal,
            arrived_early,
        }
    }

    /// Wait for a matching event for at most `bound`. An event the OS may never deliver is an
    /// external event, so this is the one bounded wait; the caller treats expiry as a failure that
    /// reports what was measured, never as a pass.
    pub fn wait(&self, bound: Duration) -> bool {
        if self.arrived_early {
            return true;
        }
        let millis = u32::try_from(bound.as_millis()).expect("a bound shorter than INFINITE");
        // SAFETY: a valid event handle.
        let rc = unsafe { WaitForSingleObject(self.signal.0, millis) }; // sleep-ok: failure bound on an OS event that may never come; expiry fails the test and is not read as state
        rc == WAIT_OBJECT_0
    }
}

impl Drop for EventWatch {
    fn drop(&mut self) {
        // SAFETY: the handle from `new`.
        let _ = unsafe { EvtClose(self.subscription) };
    }
}

/// A failed logon (Security 4625) of the account named `user`.
pub fn failed_logon_watch(user: &str) -> EventWatch {
    EventWatch::new(&query_for(4625, "TargetUserName", user))
}
