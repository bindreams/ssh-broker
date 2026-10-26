//! Small Win32 helpers shared by the spike's processes.

use std::ffi::c_void;
use std::path::Path;

use ssh_broker::winutil::OwnedHandle;
use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LUID, LocalFree, WAIT_EVENT, WAIT_OBJECT_0};
use windows::Win32::Security::Authentication::Identity::{
    LsaEnumerateLogonSessions, LsaFreeReturnBuffer, LsaGetLogonSessionData, SECURITY_LOGON_SESSION_DATA,
};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
};
use windows::Win32::Security::Cryptography::{CRYPT_INTEGER_BLOB, CryptProtectData, CryptUnprotectData};
use windows::Win32::Security::{
    CheckTokenMembership, GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_ATTRIBUTES, TOKEN_ELEVATION, TOKEN_ELEVATION_TYPE, TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_STATISTICS,
    TOKEN_USER, TokenElevation, TokenElevationType, TokenIntegrityLevel, TokenSessionId, TokenStatistics, TokenUser,
};
use windows::Win32::Storage::FileSystem::{
    FILE_NOTIFY_CHANGE_FILE_NAME, FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_CHANGE_SIZE, FindCloseChangeNotification,
    FindFirstChangeNotificationW, FindNextChangeNotification,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::JobObjects::JOBOBJECT_EXTENDED_LIMIT_INFORMATION;
use windows::Win32::System::JobObjects::{
    IsProcessInJob, JobObjectExtendedLimitInformation, QueryInformationJobObject,
};
use windows::Win32::System::Registry::{HKEY, HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_READ, RegCloseKey, RegOpenKeyExW};
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::System::SystemServices::PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY;
use windows::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, GetProcessMitigationPolicy, INFINITE, OpenEventW, OpenProcess, OpenProcessToken,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE, ProcessRedirectionTrustPolicy, ResetEvent, SetEvent,
    SetProcessMitigationPolicy, TerminateProcess, WaitForMultipleObjects, WaitForSingleObject,
};
use windows::core::{BOOL, PCWSTR, PWSTR};

use crate::rec::Rec;

pub fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// A Windows error as `0xHRESULT message`.
pub fn describe(e: &windows::core::Error) -> String {
    format!("{:#010x} {}", e.code().0 as u32, e.message().trim())
}

// Waiting --------------------------------------------------------------------------------------

/// Wait with no limit until any of `handles` is signalled; the index of the lowest one signalled.
pub fn wait_any(handles: &[HANDLE]) -> usize {
    // SAFETY: valid handles owned by the caller.
    let rc = unsafe { WaitForMultipleObjects(handles, false, INFINITE) };
    let index = rc.0.wrapping_sub(WAIT_OBJECT_0.0) as usize;
    assert!(
        index < handles.len(),
        "wait failed: {rc:?} {}",
        windows::core::Error::from_thread()
    );
    index
}

/// Wait for an external event that may never come (a service starting a task, sshd ending a session)
/// for at most `seconds`. `false` means only that the event did not arrive in that time; the caller
/// reports it as that and proves nothing else from it.
pub fn wait_bounded(handle: HANDLE, seconds: u32) -> bool {
    // SAFETY: a valid handle owned by the caller.
    let rc = unsafe { WaitForSingleObject(handle, seconds * 1000) }; // sleep-ok: failure bound on an external event; expiry is reported as expiry
    rc == WAIT_OBJECT_0
}

/// Enable a privilege the token holds (for example `SeDebugPrivilege`).
pub fn enable_privilege(name: &str) -> windows::core::Result<()> {
    use windows::Win32::Foundation::{ERROR_NOT_ALL_ASSIGNED, GetLastError};
    use windows::Win32::Security::{
        AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
    };
    let mut token = HANDLE::default();
    // SAFETY: valid out-pointers; the token is closed by `OwnedHandle`.
    unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token)?;
        let token = OwnedHandle(token);
        let mut luid = LUID::default();
        LookupPrivilegeValueW(PCWSTR::null(), PCWSTR(wide(name).as_ptr()), &mut luid)?;
        let privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        AdjustTokenPrivileges(token.0, false, Some(&privileges), 0, None, None)?;
        if GetLastError() == ERROR_NOT_ALL_ASSIGNED {
            return Err(windows::core::Error::from(ERROR_NOT_ALL_ASSIGNED));
        }
    }
    Ok(())
}

pub fn wait_one(handle: HANDLE) {
    // SAFETY: a valid handle owned by the caller.
    let rc: WAIT_EVENT = unsafe { WaitForSingleObject(handle, INFINITE) };
    assert_eq!(rc, WAIT_OBJECT_0, "wait failed: {rc:?}");
}

/// A manual-reset event. Named ones are open to everyone, so any account can set or wait on them.
pub struct Event(OwnedHandle);

impl Event {
    pub fn unnamed() -> Event {
        // SAFETY: no pointers.
        Event(OwnedHandle(
            unsafe { CreateEventW(None, true, false, PCWSTR::null()) }.expect("CreateEventW"),
        ))
    }

    pub fn create(name: &str) -> windows::core::Result<Event> {
        let mut sd = PSECURITY_DESCRIPTOR::default();
        // SAFETY: NUL-terminated input; the descriptor outlives the call and is freed after it.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide("D:(A;;GA;;;WD)").as_ptr()),
                1,
                &mut sd,
                None,
            )?;
            let attributes = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd.0,
                bInheritHandle: BOOL(0),
            };
            let made = CreateEventW(Some(&attributes), true, false, PCWSTR(wide(name).as_ptr()));
            let _ = LocalFree(Some(HLOCAL(sd.0)));
            Ok(Event(OwnedHandle(made?)))
        }
    }

    pub fn open(name: &str) -> windows::core::Result<Event> {
        use windows::Win32::System::Threading::{EVENT_MODIFY_STATE, SYNCHRONIZATION_SYNCHRONIZE};
        // SAFETY: NUL-terminated name.
        let handle = unsafe {
            OpenEventW(
                EVENT_MODIFY_STATE | SYNCHRONIZATION_SYNCHRONIZE,
                false,
                PCWSTR(wide(name).as_ptr()),
            )
        }?;
        Ok(Event(OwnedHandle(handle)))
    }

    pub fn set(&self) {
        // SAFETY: a valid event handle.
        unsafe { SetEvent(self.0.0) }.expect("SetEvent");
    }

    pub fn reset(&self) {
        // SAFETY: a valid event handle.
        unsafe { ResetEvent(self.0.0) }.expect("ResetEvent");
    }

    pub fn handle(&self) -> HANDLE {
        self.0.0
    }
}

// SAFETY: a kernel event handle is usable from any thread.
unsafe impl Sync for Event {}

/// A unique name for an event the orchestrator makes and a stand-in or child opens.
pub fn event_name(what: &str) -> String {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    format!(
        "Global\\sbspike-{}-{}-{what}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    )
}

/// A directory-change notification on `dir`.
pub struct DirWatch(HANDLE);

impl DirWatch {
    pub fn new(dir: &Path, subtree: bool) -> windows::core::Result<DirWatch> {
        // SAFETY: NUL-terminated path.
        let handle = unsafe {
            FindFirstChangeNotificationW(
                PCWSTR(wide(&dir.to_string_lossy()).as_ptr()),
                subtree,
                FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE,
            )
        }?;
        Ok(DirWatch(handle))
    }

    pub fn handle(&self) -> HANDLE {
        self.0
    }

    /// Arm it again after a wake, before looking at the directory.
    pub fn rearm(&self) {
        // SAFETY: a valid notification handle.
        unsafe { FindNextChangeNotification(self.0) }.expect("FindNextChangeNotification");
    }
}

impl Drop for DirWatch {
    fn drop(&mut self) {
        // SAFETY: closed once.
        let _ = unsafe { FindCloseChangeNotification(self.0) };
    }
}

// SAFETY: a notification handle is usable from any thread.
unsafe impl Send for DirWatch {}

// Processes ------------------------------------------------------------------------------------

pub fn session_of(pid: u32) -> String {
    let mut session = 0u32;
    // SAFETY: a valid out-pointer.
    match unsafe { ProcessIdToSessionId(pid, &mut session) } {
        Ok(()) => session.to_string(),
        Err(e) => format!("ERROR {}", describe(&e)),
    }
}

/// Every process: (pid, parent pid, image name).
pub fn processes() -> Vec<(u32, u32, String)> {
    let mut out = Vec::new();
    // SAFETY: the snapshot handle is closed below; the entry is sized as the API requires.
    unsafe {
        let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
            return out;
        };
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut more = Process32FirstW(snapshot, &mut entry).is_ok();
        while more {
            let len = entry
                .szExeFile
                .iter()
                .position(|&u| u == 0)
                .unwrap_or(entry.szExeFile.len());
            out.push((
                entry.th32ProcessID,
                entry.th32ParentProcessID,
                String::from_utf16_lossy(&entry.szExeFile[..len]),
            ));
            more = Process32NextW(snapshot, &mut entry).is_ok();
        }
        let _ = CloseHandle(snapshot);
    }
    out
}

pub fn parent_of(pid: u32) -> String {
    processes()
        .into_iter()
        .find(|(p, _, _)| *p == pid)
        .map_or_else(|| "gone".into(), |(_, parent, _)| format!("{parent}"))
}

/// The image name of process `pid`, if it exists.
pub fn image_of(pid: u32) -> String {
    processes()
        .into_iter()
        .find(|(p, _, _)| *p == pid)
        .map_or_else(|| "gone".into(), |(_, _, name)| name)
}

fn open_process(pid: u32, access: windows::Win32::System::Threading::PROCESS_ACCESS_RIGHTS) -> Option<OwnedHandle> {
    // SAFETY: plain value arguments.
    unsafe { OpenProcess(access, false, pid) }.ok().map(OwnedHandle)
}

/// Open `pid` for waiting and reading its state.
pub fn open_for_wait(pid: u32) -> windows::core::Result<OwnedHandle> {
    use windows::Win32::System::Threading::PROCESS_SYNCHRONIZE;
    // SAFETY: plain value arguments.
    unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE | PROCESS_TERMINATE,
            false,
            pid,
        )
    }
    .map(OwnedHandle)
}

pub fn terminate(handle: HANDLE) {
    // SAFETY: a valid process handle with terminate access.
    let _ = unsafe { TerminateProcess(handle, 1) };
}

/// The exit code of a process that has exited.
pub fn exit_code(handle: HANDLE) -> u32 {
    let mut code = 0u32;
    // SAFETY: a valid handle and out-pointer.
    let _ = unsafe { windows::Win32::System::Threading::GetExitCodeProcess(handle, &mut code) };
    code
}

/// The user SID text and logon-session id of `pid`'s token, if it can be read.
pub fn process_identity(pid: u32) -> Option<(String, LUID)> {
    let process = open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION)?;
    let mut token = HANDLE::default();
    // SAFETY: valid out-pointer; closed by `OwnedHandle`.
    unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &mut token) }.ok()?;
    let token = OwnedHandle(token);
    let user = token_user_sid(token.0)?;
    let luid = token_info::<TOKEN_STATISTICS>(token.0, TokenStatistics)?.AuthenticationId;
    Some((user, luid))
}

/// End every process of the account `sid`, except this one. The accounts are the spike's own.
pub fn kill_account_processes(sid: &str) {
    let me = std::process::id();
    for (pid, _, _) in processes() {
        if pid == me {
            continue;
        }
        if process_identity(pid).is_some_and(|(user, _)| user == sid) {
            if let Some(process) = open_process(pid, PROCESS_TERMINATE) {
                terminate(process.0);
            }
        }
    }
}

// Tokens ---------------------------------------------------------------------------------------

fn token_bytes(token: HANDLE, class: windows::Win32::Security::TOKEN_INFORMATION_CLASS) -> Option<Vec<u8>> {
    let mut len = 0u32;
    // SAFETY: the size probe takes no buffer.
    let _ = unsafe { GetTokenInformation(token, class, None, 0, &mut len) };
    if len == 0 {
        return None;
    }
    let mut buf = vec![0u8; len as usize];
    // SAFETY: `buf` holds `len` bytes.
    unsafe { GetTokenInformation(token, class, Some(buf.as_mut_ptr().cast()), len, &mut len) }.ok()?;
    Some(buf)
}

fn token_info<T: Copy>(token: HANDLE, class: windows::Win32::Security::TOKEN_INFORMATION_CLASS) -> Option<T> {
    let buf = token_bytes(token, class)?;
    if buf.len() < std::mem::size_of::<T>() {
        return None;
    }
    // SAFETY: the buffer holds at least one `T`, written by the system; read unaligned.
    Some(unsafe { std::ptr::read_unaligned(buf.as_ptr().cast::<T>()) })
}

pub fn sid_text(sid: PSID) -> Option<String> {
    let mut text = PWSTR::null();
    // SAFETY: valid SID; the string is freed below.
    unsafe {
        ConvertSidToStringSidW(sid, &mut text).ok()?;
        let out = text.to_string().ok();
        let _ = LocalFree(Some(HLOCAL(text.0.cast())));
        out
    }
}

fn token_user_sid(token: HANDLE) -> Option<String> {
    let buf = token_bytes(token, TokenUser)?;
    // SAFETY: the buffer holds a TOKEN_USER whose SID points into the same buffer.
    let user = unsafe { std::ptr::read_unaligned(buf.as_ptr().cast::<TOKEN_USER>()) };
    sid_text(user.User.Sid)
}

pub fn luid_text(luid: LUID) -> String {
    format!("{:#x}:{:#x}", luid.HighPart, luid.LowPart)
}

/// The facts of this process's own token under `prefix`.
pub fn own_token_facts(rec: &Rec, prefix: &str) -> Option<LUID> {
    let mut token = HANDLE::default();
    // SAFETY: valid out-pointer; closed by `OwnedHandle`.
    if let Err(e) = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } {
        rec.err(&format!("{prefix}.token"), &e);
        return None;
    }
    let token = OwnedHandle(token);
    rec.put(
        &format!("{prefix}.user_sid"),
        token_user_sid(token.0).unwrap_or_default(),
    );
    rec.put(
        &format!("{prefix}.session_id_token"),
        token_info::<u32>(token.0, TokenSessionId).map_or("unreadable".into(), |s| s.to_string()),
    );
    rec.put(
        &format!("{prefix}.elevation_type"),
        token_info::<TOKEN_ELEVATION_TYPE>(token.0, TokenElevationType).map_or("unreadable".into(), |t| {
            format!("{} (1 default, 2 full, 3 limited)", t.0)
        }),
    );
    rec.put(
        &format!("{prefix}.is_elevated"),
        token_info::<TOKEN_ELEVATION>(token.0, TokenElevation)
            .map_or("unreadable".into(), |t| (t.TokenIsElevated != 0).to_string()),
    );
    rec.put(&format!("{prefix}.integrity_rid"), integrity_rid(token.0));
    let mut admin = BOOL(0);
    // SAFETY: the well-known Administrators SID text converts to a SID freed below; the check is of the thread's or
    // process's effective token (None).
    let admin_member = unsafe {
        let mut sid = PSID::default();
        if windows::Win32::Security::Authorization::ConvertStringSidToSidW(
            PCWSTR(wide("S-1-5-32-544").as_ptr()),
            &mut sid,
        )
        .is_ok()
        {
            let ok = CheckTokenMembership(None, sid, &mut admin).is_ok() && admin.as_bool();
            let _ = LocalFree(Some(HLOCAL(sid.0)));
            ok.to_string()
        } else {
            "unknown".into()
        }
    };
    rec.put(&format!("{prefix}.in_enabled_administrators_group"), admin_member);
    let luid = token_info::<TOKEN_STATISTICS>(token.0, TokenStatistics).map(|s| s.AuthenticationId);
    if let Some(luid) = luid {
        rec.put(&format!("{prefix}.logon_luid"), luid_text(luid));
        logon_session_facts(rec, prefix, luid);
    }
    luid
}

fn integrity_rid(token: HANDLE) -> String {
    let Some(buf) = token_bytes(token, TokenIntegrityLevel) else {
        return "unreadable".into();
    };
    // SAFETY: the buffer holds a TOKEN_MANDATORY_LABEL whose SID points into the same buffer.
    unsafe {
        let label = std::ptr::read_unaligned(buf.as_ptr().cast::<TOKEN_MANDATORY_LABEL>());
        let count = *GetSidSubAuthorityCount(label.Label.Sid);
        if count == 0 {
            return "none".into();
        }
        format!("{:#x}", *GetSidSubAuthority(label.Label.Sid, u32::from(count) - 1))
    }
}

fn lsa_string(s: &windows::Win32::Security::Authentication::Identity::LSA_UNICODE_STRING) -> String {
    if s.Buffer.is_null() || s.Length == 0 {
        return String::new();
    }
    // SAFETY: the system returned `Length` bytes at `Buffer`.
    let units = unsafe { std::slice::from_raw_parts(s.Buffer.0, usize::from(s.Length) / 2) };
    String::from_utf16_lossy(units)
}

/// `LsaGetLogonSessionData` for `luid`, recorded under `prefix`.
pub fn logon_session_facts(rec: &Rec, prefix: &str, luid: LUID) {
    let mut data: *mut SECURITY_LOGON_SESSION_DATA = std::ptr::null_mut();
    // SAFETY: valid pointers; the buffer is freed below.
    let status = unsafe { LsaGetLogonSessionData(&luid, &mut data) };
    if status.0 != 0 || data.is_null() {
        rec.put(
            &format!("{prefix}.logon_session_data"),
            format!("ERROR ntstatus {:#010x}", status.0),
        );
        return;
    }
    // SAFETY: the system filled the structure.
    unsafe {
        let d = &*data;
        rec.put(
            &format!("{prefix}.logon_type"),
            format!(
                "{} (2 Interactive, 3 Network, 4 Batch, 5 Service, 7 Unlock, 9 NewCredentials, 10 RemoteInteractive)",
                d.LogonType
            ),
        );
        rec.put(&format!("{prefix}.logon_session_ts_session"), d.Session);
        rec.put(
            &format!("{prefix}.logon_auth_package"),
            lsa_string(&d.AuthenticationPackage),
        );
        rec.put(
            &format!("{prefix}.logon_user"),
            format!("{}\\{}", lsa_string(&d.LogonDomain), lsa_string(&d.UserName)),
        );
        let _ = LsaFreeReturnBuffer(data.cast::<c_void>());
    }
}

/// Every logon session the system lists.
pub fn logon_sessions() -> Vec<LUID> {
    let mut count = 0u32;
    let mut list: *mut LUID = std::ptr::null_mut();
    // SAFETY: valid out-pointers; the list is copied and freed.
    unsafe {
        let status = LsaEnumerateLogonSessions(&mut count, &mut list);
        if status.0 != 0 || list.is_null() {
            panic!("LsaEnumerateLogonSessions failed: ntstatus {:#010x}", status.0);
        }
        let out = std::slice::from_raw_parts(list, count as usize).to_vec();
        let _ = LsaFreeReturnBuffer(list.cast::<c_void>());
        out
    }
}

// Mitigation, job, registry --------------------------------------------------------------------

/// Turn RedirectionGuard on for this process: the stand-in's equivalent of sshd's session.
pub fn redirection_guard_on(rec: &Rec) {
    let mut policy = PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY::default();
    policy.Anonymous.Flags = 1; // EnforceRedirectionTrust
    // SAFETY: the buffer is a policy structure of the stated size.
    match unsafe {
        SetProcessMitigationPolicy(
            ProcessRedirectionTrustPolicy,
            (&policy as *const PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY).cast(),
            std::mem::size_of::<PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY>(),
        )
    } {
        Ok(()) => rec.put("redirection_guard_applied", "true"),
        Err(e) => rec.err("redirection_guard_applied", &e),
    }
}

/// Whether RedirectionGuard is enforced in this process.
pub fn redirection_guard_state(rec: &Rec, prefix: &str) {
    let mut policy = PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY::default();
    // SAFETY: the buffer is a policy structure of the stated size.
    let read = unsafe {
        GetProcessMitigationPolicy(
            GetCurrentProcess(),
            ProcessRedirectionTrustPolicy,
            (&mut policy as *mut PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY).cast(),
            std::mem::size_of::<PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY>(),
        )
    };
    match read {
        // SAFETY: a union of plain integers.
        Ok(()) => rec.put(
            &format!("{prefix}.redirection_guard_enforced"),
            unsafe { policy.Anonymous.Flags } & 1 != 0,
        ),
        Err(e) => rec.err(&format!("{prefix}.redirection_guard_enforced"), &e),
    }
}

/// The job this process is in, if any, and its limit flags.
pub fn own_job_facts(rec: &Rec, prefix: &str) {
    let mut in_job = BOOL(0);
    // SAFETY: valid out-pointer; no job handle asks "any job".
    if let Err(e) = unsafe { IsProcessInJob(GetCurrentProcess(), None, &mut in_job) } {
        rec.err(&format!("{prefix}.in_job"), &e);
        return;
    }
    rec.put(&format!("{prefix}.in_job"), in_job.as_bool());
    if !in_job.as_bool() {
        return;
    }
    let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    // SAFETY: a null job handle means the calling process's job; the buffer is the stated size.
    let queried = unsafe {
        QueryInformationJobObject(
            None,
            JobObjectExtendedLimitInformation,
            (&mut info as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            None,
        )
    };
    match queried {
        Ok(()) => {
            let flags = info.BasicLimitInformation.LimitFlags.0;
            rec.put(
                &format!("{prefix}.job_limit_flags"),
                format!(
                    "{flags:#x} (kill_on_close {}, breakaway_ok {}, silent_breakaway_ok {})",
                    flags & 0x2000 != 0,
                    flags & 0x800 != 0,
                    flags & 0x1000 != 0
                ),
            );
        }
        Err(e) => rec.err(&format!("{prefix}.job_limit_flags"), &e),
    }
}

/// Whether the registry key `subkey` of `root` opens, and the error if not.
pub fn registry_key_exists(root: HKEY, subkey: &str) -> String {
    let mut key = HKEY::default();
    // SAFETY: NUL-terminated name, valid out-pointer.
    let rc = unsafe { RegOpenKeyExW(root, PCWSTR(wide(subkey).as_ptr()), None, KEY_READ, &mut key) };
    if rc.0 == 0 {
        // SAFETY: opened above.
        let _ = unsafe { RegCloseKey(key) };
        "present".into()
    } else {
        format!("absent (win32 {})", rc.0)
    }
}

pub fn profile_list_entry(sid: &str) -> String {
    registry_key_exists(
        HKEY_LOCAL_MACHINE,
        &format!(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}"),
    )
}

pub fn hive_loaded(sid: &str) -> String {
    registry_key_exists(HKEY_USERS, sid)
}

// DPAPI ----------------------------------------------------------------------------------------

/// User-scope DPAPI protect then unprotect, with the error of whichever step fails.
pub fn dpapi_facts(rec: &Rec, prefix: &str) {
    let data = b"session-spike";
    let input = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut protected = CRYPT_INTEGER_BLOB::default();
    // SAFETY: valid blobs; the output is freed below.
    unsafe {
        if let Err(e) = CryptProtectData(&input, None, None, None, None, 0, &mut protected) {
            rec.err(&format!("{prefix}.dpapi_protect"), &e);
            return;
        }
        rec.put(&format!("{prefix}.dpapi_protect"), "ok");
        let mut back = CRYPT_INTEGER_BLOB::default();
        match CryptUnprotectData(&protected, None, None, None, None, 0, &mut back) {
            Ok(()) => {
                let same = std::slice::from_raw_parts(back.pbData, back.cbData as usize) == data;
                rec.put(
                    &format!("{prefix}.dpapi_unprotect"),
                    if same { "ok" } else { "ok but different bytes" },
                );
                let _ = LocalFree(Some(HLOCAL(back.pbData.cast())));
            }
            Err(e) => rec.err(&format!("{prefix}.dpapi_unprotect"), &e),
        }
        let _ = LocalFree(Some(HLOCAL(protected.pbData.cast())));
    }
}

// Profile directory ----------------------------------------------------------------------------

/// What `GetUserProfileDirectoryW` says for this process's token: the raw first-call result, and
/// the directory or the error.
pub fn profile_dir_facts(rec: &Rec, prefix: &str) {
    use windows::Win32::UI::Shell::GetUserProfileDirectoryW;
    let mut token = HANDLE::default();
    // SAFETY: valid out-pointer; closed by `OwnedHandle`.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.is_err() {
        return;
    }
    let token = OwnedHandle(token);
    let mut len = 0u32;
    // SAFETY: the size probe takes no buffer.
    let probe = unsafe { GetUserProfileDirectoryW(token.0, None, &mut len) };
    match probe {
        Ok(()) => rec.put(&format!("{prefix}.profile_dir_probe"), format!("ok len={len}")),
        Err(e) => rec.put(
            &format!("{prefix}.profile_dir_probe"),
            format!("ERROR {} (needed length {len})", describe(&e)),
        ),
    }
    if len == 0 {
        return;
    }
    let mut buf = vec![0u16; len as usize];
    // SAFETY: `buf` holds `len` units.
    match unsafe { GetUserProfileDirectoryW(token.0, Some(PWSTR(buf.as_mut_ptr())), &mut len) } {
        Ok(()) => {
            let end = buf.iter().position(|&u| u == 0).unwrap_or(buf.len());
            rec.put(&format!("{prefix}.profile_dir"), String::from_utf16_lossy(&buf[..end]));
        }
        Err(e) => rec.err(&format!("{prefix}.profile_dir"), &e),
    }
}

// Junctions ------------------------------------------------------------------------------------

/// Make a directory junction `link` to `target` (no privilege needed) with `cmd /c mklink /J`.
pub fn make_junction(link: &Path, target: &Path) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    let out = std::process::Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .creation_flags(0x0800_0000)
        .output()
        .map_err(|e| format!("mklink did not run: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "mklink /J failed: {} {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}

/// Read `probe.txt` through the junction at `link`.
pub fn read_through_junction(rec: &Rec, key: &str, link: &Path) {
    match std::fs::read_to_string(link.join("probe.txt")) {
        Ok(text) => rec.put(key, format!("traversed, read {:?}", text.trim())),
        Err(e) => rec.put(key, format!("BLOCKED or failed: {e} (os error {:?})", e.raw_os_error())),
    }
}
