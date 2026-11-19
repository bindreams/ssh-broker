//! A measurement, not a check: why PSReadLine cannot create its history mutex in a session the password
//! prompt started, and why the next typed line then stops. Windows only; **Elevated (CI only)**. It fails
//! on purpose: its panic text is the record, and nextest prints a failing test's output only.
//!
//! The scenario is the one `prompt_path_windows` runs (a fresh account, the shim on a console of its own,
//! the password at the prompt, the background agent's PowerShell as the shell), repeated until PSReadLine
//! prints its bug report. The test only observes: it lists processes, opens kernel objects and tokens for
//! reading, and types into its own session. Nothing here writes to or signals a process or object it did
//! not create.
#![cfg(windows)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::{SystemTime, UNIX_EPOCH};

use ssh_broker::vtinput::{KeyEvent, encode_key_event};
use ssh_broker::winutil::{OwnedHandle, find_group, process_token, token_information};
use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows::Wdk::Storage::FileSystem::{
    NtOpenDirectoryObject, NtOpenSymbolicLinkObject, NtQueryDirectoryObject, NtQuerySymbolicLinkObject,
};
use windows::Wdk::System::SystemServices::RtlGetVersion;
use windows::Win32::Foundation::{HANDLE, HLOCAL, LUID, LocalFree, NTSTATUS, OBJ_CASE_INSENSITIVE, UNICODE_STRING};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW, GetSecurityInfo, SDDL_REVISION_1,
    SE_KERNEL_OBJECT,
};
use windows::Win32::Security::{
    DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, IsTokenRestricted, LABEL_SECURITY_INFORMATION,
    LUID_AND_ATTRIBUTES, LookupPrivilegeNameW, OBJECT_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, TOKEN_ELEVATION_TYPE, TOKEN_PRIVILEGES, TOKEN_STATISTICS, TokenElevationType,
    TokenIsAppContainer, TokenPrivileges, TokenSessionId, TokenStatistics,
};
use windows::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, VS_FIXEDFILEINFO, VerQueryValueW,
};
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::System::SystemInformation::OSVERSIONINFOW;
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenMutexW, OpenProcess, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION,
    QueryFullProcessImageNameW, SYNCHRONIZATION_ACCESS_RIGHTS,
};
use windows::core::{PCWSTR, PWSTR, w};

#[path = "common/account.rs"]
mod account_fixture;
#[path = "common/bounded_wait.rs"]
mod bounded_wait;
#[path = "common/desktop.rs"]
mod desktop;
#[path = "common/hard_errors.rs"]
mod hard_errors;
#[path = "common/machine.rs"]
mod machine;
#[path = "common/password.rs"]
mod password;
#[path = "common/process_list.rs"]
mod process_list;
#[path = "common/pty_client.rs"]
mod pty_client;
#[path = "common/stand_in.rs"]
mod stand_in;

use account_fixture::Account;
use pty_client::PtyRun;
use stand_in::Kit;

/// How many fresh-account repetitions to run: about 12 minutes at the 15 to 40 s one takes.
const REPETITIONS: usize = 20;

/// What the prompt says first, as in `prompt_path_windows`.
const PROMPT: &str = "Enter your Windows password to start one.";
/// The start of a PowerShell prompt.
const SHELL_PROMPT: &str = "PS C:\\";
/// The first line the prompt tests type at the shell: PSReadLine out, so the host's own reader reads on.
const REMOVE_MODULE: &str =
    "Remove-Module PSReadLine -ErrorAction SilentlyContinue; Write-Output ('psreadline' + '-off')";
/// What PSReadLine prints at its first prompt when it cannot start.
const BUG_REPORT: &str = "Oops, something went wrong";
/// The start of the name of PSReadLine's history mutex.
const MUTEX_PREFIX: &str = "PSReadLineHistoryFile_";

// The record -----

/// Everything observed, as text; the panic that ends the test carries it.
#[derive(Default)]
struct Record {
    text: String,
    /// Descriptors of object directories already printed: each is read once.
    directories: BTreeSet<String>,
    /// Image files whose version is already printed.
    versions: BTreeSet<String>,
    sessions_listed: bool,
}

impl Record {
    fn line(&mut self, text: impl AsRef<str>) {
        self.text.push_str(text.as_ref());
        self.text.push('\n');
    }
}

enum Verdict {
    Worked,
    Failed,
}

/// Elevated (CI only). Fails on purpose; read the panic text.
#[test]
fn psreadline_history_mutex_measurement() {
    let _machine = machine::shared();
    account_fixture::assert_elevated();
    let mut record = Record::default();
    record.line(format!(
        "Windows {}; this test process is pid {} in Windows session {}",
        windows_version(),
        std::process::id(),
        session_text(std::process::id())
    ));
    let (mut ran, mut failed_in) = (0, None);
    for n in 1..=REPETITIONS {
        ran = n;
        match catch_unwind(AssertUnwindSafe(|| repetition(n, &mut record))) {
            Ok(Verdict::Worked) => {}
            Ok(Verdict::Failed) => {
                failed_in = Some(n);
                break;
            }
            Err(panic) => {
                record.line(format!("repetition {n} panicked: {}", panic_text(&panic)));
                break;
            }
        }
    }
    panic!(
        "MEASURED (this test fails on purpose): {ran} of {REPETITIONS} repetitions ran; the line typed after the first answer stalled in {}\n\n{}",
        failed_in.map_or_else(|| "none of them".to_owned(), |n| format!("repetition {n}")),
        record.text
    );
}

/// One fresh account, logged in through the prompt; what is observed on the way.
fn repetition(n: usize, record: &mut Record) -> Verdict {
    let kit = Kit::broker_with_helper("psr");
    let account = Account::create("psr", true);
    let location = account.socket_location();
    record.line(format!(
        "\n######## repetition {n}: account {} ({})",
        account.name, account.sid_text
    ));
    let mut run = start_run(&kit, &account);
    run.read_until(PROMPT);
    run.type_line(&account.password);
    stand_in::wait_for_serving_marker_of_a_task(&location, stand_in::SERVING_BOUND);
    if n == 1 {
        observe(
            record,
            "A: the agent serves; the shell's first prompt is not waited for yet",
            &account,
            None,
        );
    }

    run.read_until(SHELL_PROMPT);
    run.type_line(REMOVE_MODULE);
    if n == 1 {
        observe(record, "C1: right after the first line was typed", &account, None);
    }

    run.read_until("psreadline-off");
    let shown = run.text();
    let failed = shown.contains(BUG_REPORT);
    let name = mutex_name_in(&shown);
    record.line(format!(
        "PSReadLine failed in this repetition: {failed}; the name in the bug report: {name:?}"
    ));
    // The census is the same in every repetition: it is taken in the first only, to keep the record readable.
    if n == 1 {
        observe(record, "B: the first line was answered", &account, name.as_deref());
        record.line(format!(
            "the console showed, up to the first line's answer:\n{}",
            shown.replace('\x1b', "<ESC>")
        ));
    }
    // What the tests that stalled do next: a whole line typed at once, with no pause after the answer. Under this
    // harness PSReadLine fails at every first prompt (`prompt_path_windows::without_psreadline`), so the hunt is
    // for the STALL of this line, not for the bug report.
    let line = "Write-Output ('profile=' + $env:USERPROFILE + '.')";
    let sent = key_bytes(line) + enter_bytes();
    let before = run.bytes().len();
    run.type_line(line);
    match bounded(&mut run, |run| run.read_until("profile=C:")) {
        Ok(()) => {
            record.line(format!(
                "the line typed at once after the first answer WAS answered ({sent} bytes of key events; the \
                 console wrote {} more bytes)",
                run.bytes().len() - before
            ));
            run.type_line("exit");
            run.finish();
            Verdict::Worked
        }
        Err(why) => {
            record.line(format!(
                "THE STALL: the line typed at once after the first answer was NOT answered ({sent} bytes of key \
                 events sent; the console wrote {} more bytes):\n{why}",
                run.bytes().len() - before
            ));
            record.line(format!("the console showed:\n{}", run.text().replace('\x1b', "<ESC>")));
            observe(record, "S: at the stall", &account, name.as_deref());
            typing_probe(record, &mut run);
            record.line(format!(
                "the agent's logs (agent.log, shim.log):\n{}",
                stand_in::read_logs(&location)
            ));
            Verdict::Failed
        }
    }
}

/// The shim of `account` on a console, with the logs printed when a wait fails.
fn start_run(kit: &Kit, account: &Account) -> PtyRun {
    let location = account.try_socket_location();
    PtyRun::start(kit, account, &kit.exe).with_context(move || {
        let logs = location.as_ref().map(stand_in::read_logs).unwrap_or_default();
        format!("logs of the account (shim.log, agent.log):\n{logs}")
    })
}

/// `PSReadLineHistoryFile_<digits>` as the bug report prints it, if it can be read from the console text.
fn mutex_name_in(shown: &str) -> Option<String> {
    let at = shown.find(MUTEX_PREFIX)?;
    let name: String = shown[at..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    (name.len() > MUTEX_PREFIX.len()).then_some(name)
}

// The second question: do the keys get lost, or does the shell stop reading -----

/// The key events `PtyRun::type_text` sends for `text` (a down and an up event per UTF-16 unit), in bytes.
fn key_bytes(text: &str) -> usize {
    text.encode_utf16().map(|unit| event_bytes(unit, 0)).sum()
}

/// The key events `PtyRun::press_enter` sends, in bytes.
fn enter_bytes() -> usize {
    event_bytes(0x0D, 0x0D)
}

fn event_bytes(unicode_char: u16, virtual_key_code: u16) -> usize {
    [true, false]
        .into_iter()
        .map(|key_down| {
            encode_key_event(&KeyEvent {
                virtual_key_code,
                virtual_scan_code: 0,
                unicode_char,
                key_down,
                control_key_state: 0,
                repeat_count: 1,
            })
            .len()
        })
        .sum()
}

/// Run `wait`, one of the fixture's reads, turning its failure (the console silent for the fixture's bound, or
/// closed) into the failure's text.
fn bounded(run: &mut PtyRun, wait: impl FnOnce(&mut PtyRun)) -> Result<(), String> {
    catch_unwind(AssertUnwindSafe(|| wait(run))).map_err(|panic| panic_text(&panic))
}

/// After the first line is answered: type a line the length of the longest one that stopped, in pieces, and
/// record per piece what came back; then type a second short line.
///
/// Each piece but the last ends in a capital that occurs once in the line, and its echo is the count of
/// that capital in the console text rising by one. A piece's echo is not matched as a string: the console
/// breaks a long line at the right edge with cursor movements in the middle of it.
fn typing_probe(record: &mut Record, run: &mut PtyRun) {
    const LINE_LEN: usize = 258;
    const PIECE_LEN: usize = 32;
    const FILLER: &str = "0123456789abcdefghijklmnop";
    let mut chars: Vec<char> = "Write-Output ('mrk' + 'done') #".chars().collect();
    while chars.len() < LINE_LEN {
        chars.push(
            FILLER
                .chars()
                .nth(chars.len() % FILLER.len())
                .expect("a filler character"),
        );
    }
    for k in 0..chars.len().div_ceil(PIECE_LEN) - 1 {
        chars[(k + 1) * PIECE_LEN - 1] = char::from(b'A' + u8::try_from(k).expect("few pieces"));
    }
    record.line(format!(
        "\n-- typing a {LINE_LEN}-character line in pieces of {PIECE_LEN} after the first line was answered"
    ));
    let mut sent = 0;
    let mut stalled = false;
    for (k, piece) in chars.chunks(PIECE_LEN).enumerate() {
        let text: String = piece.iter().collect();
        let last = (k + 1) * PIECE_LEN >= LINE_LEN;
        let needle = (!last).then(|| *piece.last().expect("a piece has characters"));
        let before_count = needle.map_or(0, |c| run.text().matches(c).count());
        let before_bytes = run.bytes().len();
        let bytes = key_bytes(&text);
        run.type_text(&text);
        sent += bytes;
        let outcome = match needle {
            None => "the last piece: no echo is waited for; Enter follows".to_owned(),
            Some(c) => match bounded(run, |run| run.read_until_count(&c.to_string(), before_count + 1)) {
                Ok(()) => format!("its last character {c:?} was echoed"),
                Err(why) => {
                    stalled = true;
                    format!("its last character {c:?} was NOT echoed:\n{why}")
                }
            },
        };
        record.line(format!(
            "piece {k}: {} characters, {bytes} bytes of key events sent ({sent} in all); {outcome}; the console wrote {} more bytes",
            piece.len(),
            run.bytes().len() - before_bytes
        ));
        if stalled {
            break;
        }
    }
    if !stalled {
        run.press_enter();
        sent += enter_bytes();
        let answered = bounded(run, |run| run.read_until("mrkdone"));
        record.line(format!(
            "Enter: {} bytes sent ({sent} in all); the line was answered: {}",
            enter_bytes(),
            answered.map_or_else(|why| format!("NO:\n{why}"), |()| "yes".to_owned())
        ));
    }
    let second = "Write-Output ('probe' + '-two')";
    let before_bytes = run.bytes().len();
    run.type_line(second);
    let answered = bounded(run, |run| run.read_until("probe-two"));
    record.line(format!(
        "the second line ({} characters, {} bytes of key events) was answered: {}; the console wrote {} more bytes",
        second.len(),
        key_bytes(second) + enter_bytes(),
        answered.map_or_else(|why| format!("NO:\n{why}"), |()| "yes".to_owned()),
        run.bytes().len() - before_bytes
    ));
    let shown = run.text();
    let tail: String = shown
        .chars()
        .rev()
        .take(1500)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    record.line(format!(
        "the last 1500 characters the console showed:\n{}",
        tail.replace('\x1b', "<ESC>")
    ));
}

fn panic_text(panic: &Box<dyn std::any::Any + Send>) -> String {
    panic
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| panic.downcast_ref::<&str>().map(|text| (*text).to_owned()))
        .unwrap_or_else(|| "(a panic with no text)".to_owned())
}

// One look at the machine -----

/// A process the system lists, opened for reading if it can be.
struct Seen {
    pid: u32,
    parent: u32,
    exe: String,
    created: Option<u64>,
    handle: Result<OwnedHandle, String>,
}

fn seen() -> Vec<Seen> {
    process_list::snapshot()
        .into_iter()
        .map(|entry| {
            // SAFETY: a plain open by id; the handle is closed by `OwnedHandle`.
            let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, entry.pid) }
                .map(OwnedHandle)
                .map_err(|e| e.to_string());
            let created = handle.as_ref().ok().and_then(|h| creation_time(h.0));
            Seen {
                pid: entry.pid,
                parent: entry.parent,
                exe: entry.exe,
                created,
                handle,
            }
        })
        .collect()
}

fn is_powershell(exe: &str) -> bool {
    exe.eq_ignore_ascii_case("pwsh.exe") || exe.eq_ignore_ascii_case("powershell.exe")
}

/// What is observed at one moment: the processes of the account, every PowerShell on the machine, the
/// logon sessions of the account, the shell's token, and the named objects.
fn observe(record: &mut Record, label: &str, account: &Account, mutex_name: Option<&str>) {
    record.line(format!("\n== {label}; at {} UTC", clock(now_filetime())));
    let everything = seen();
    let mut sessions: BTreeSet<u32> = everything.iter().filter_map(|p| session_of(p.pid)).collect();
    sessions.extend(session_of(std::process::id()));
    let owned_by_account = |p: &&Seen| {
        p.handle
            .as_ref()
            .is_ok_and(|h| process_list::owner_sddl(h.0).as_deref() == Some(account.sid_text.as_str()))
    };
    let mine: Vec<&Seen> = everything.iter().filter(owned_by_account).collect();
    record.line("processes of the account:");
    for process in &mine {
        let image = record_versions(record, process);
        record.line(format!("  {}", process_row(process, image)));
    }
    if mine.is_empty() {
        record.line("  none");
    }
    record.line("every pwsh.exe and powershell.exe on the machine, whoever owns it:");
    for process in everything.iter().filter(|p| is_powershell(&p.exe)) {
        let image = record_versions(record, process);
        record.line(format!("  {}", process_row(process, image)));
    }
    record.line(account_fixture::holders::report(&account.sid_text));
    match mine
        .iter()
        .filter(|p| is_powershell(&p.exe))
        .max_by_key(|p| p.created)
        .and_then(|p| p.handle.as_ref().ok().map(|h| (p.pid, h)))
    {
        None => record.line("the shell's token: no PowerShell of the account yet"),
        Some((pid, handle)) => {
            let report = token_report(handle.0).unwrap_or_else(|e| format!("unreadable: {e:#}"));
            record.line(format!("the shell's token (pid {pid}):\n{report}"));
        }
    }
    named_objects(record, &sessions);
    if let Some(name) = mutex_name {
        open_by_name(record, name);
    }
}

/// The image path of `process` if it is a PowerShell, with its file version printed once per image.
fn record_versions(record: &mut Record, process: &Seen) -> Option<String> {
    if !is_powershell(&process.exe) {
        return None;
    }
    let path = image_path(process.handle.as_ref().ok()?.0)?;
    if record.versions.insert(path.clone()) {
        let version = file_version(&path);
        record.line(format!("file version of {path}: {version}"));
    }
    Some(path)
}

fn process_row(process: &Seen, image: Option<String>) -> String {
    let detail = match &process.handle {
        Err(why) => format!("not opened: {why}"),
        Ok(handle) => process_token_summary(handle.0).unwrap_or_else(|e| format!("token unreadable: {e:#}")),
    };
    format!(
        "pid {} {} parent {} created {} session {}{}; {detail}",
        process.pid,
        process.exe,
        process.parent,
        process.created.map_or_else(|| "?".to_owned(), clock),
        session_text(process.pid),
        image.map(|path| format!(" image {path}")).unwrap_or_default()
    )
}

/// User, logon id, integrity level and elevation of the token of `process`.
fn process_token_summary(process: HANDLE) -> anyhow::Result<String> {
    let user = process_list::owner_sddl(process).unwrap_or_else(|| "?".to_owned());
    let token = process_token(process)?;
    let statistics = statistics_of(token.0)?;
    let integrity = ssh_broker::account::integrity_of(token.0)?;
    let elevation = ssh_broker::account::elevation_of(token.0)?;
    Ok(format!(
        "user {user} logon {:#x} integrity {integrity:#x} {elevation:?}",
        luid_value(statistics.AuthenticationId)
    ))
}

fn statistics_of(token: HANDLE) -> anyhow::Result<TOKEN_STATISTICS> {
    // SAFETY: every bit pattern is a valid `TOKEN_STATISTICS` (integers and newtypes of integers).
    unsafe { token_information(token, TokenStatistics)?.header::<TOKEN_STATISTICS>() }
}

fn luid_value(luid: LUID) -> u64 {
    (u64::from(luid.HighPart as u32) << 32) | u64::from(luid.LowPart)
}

/// What the token of the shell says, read with `TOKEN_QUERY` only.
fn token_report(process: HANDLE) -> anyhow::Result<String> {
    let token = process_token(process)?;
    let user = ssh_broker::acl::Sid::of_token(token.0)?;
    let logon = ssh_broker::acl::Sid::logon_of_token(token.0)?;
    let statistics = statistics_of(token.0)?;
    // SAFETY: each class below returns a plain integer (or a newtype of one) at the start of its data.
    let (session, kind, appcontainer) = unsafe {
        (
            token_information(token.0, TokenSessionId)?.header::<u32>()?,
            token_information(token.0, TokenElevationType)?.header::<TOKEN_ELEVATION_TYPE>()?,
            token_information(token.0, TokenIsAppContainer)?.header::<u32>()?,
        )
    };
    // SAFETY: the handle is a token with `TOKEN_QUERY`.
    let restricted = unsafe { IsTokenRestricted(token.0) }.is_ok();
    let mut report = format!(
        "  user {} (sid {})\n  logon SID {}; logon id {:#x}\n  token session id {session}; type {} (1 primary, 2 impersonation); \
         elevation type {} (1 default, 2 full, 3 limited); integrity {:#x}; elevation {:?}; restricted {restricted}; \
         app container {appcontainer}\n  groups (sid, attributes):\n",
        user.describe(),
        user.to_sddl()?,
        logon.to_sddl()?,
        luid_value(statistics.AuthenticationId),
        statistics.TokenType.0,
        kind.0,
        ssh_broker::account::integrity_of(token.0)?,
        ssh_broker::account::elevation_of(token.0)?,
    );
    find_group(token.0, |sid, attributes| {
        let _ = writeln!(
            report,
            "    {} {attributes:#x}{}",
            sid_text(sid),
            group_flags(attributes)
        );
        Ok::<Option<()>, anyhow::Error>(None)
    })?;
    report.push_str("  privileges (enabled bit 0x2 of attributes):\n");
    let buffer = token_information(token.0, TokenPrivileges)?;
    // SAFETY: the privilege count is a `u32`.
    let count = unsafe { buffer.header::<u32>() }?;
    // SAFETY: every bit pattern is a valid `LUID_AND_ATTRIBUTES` (integers).
    let privileges = unsafe {
        buffer.array::<LUID_AND_ATTRIBUTES>(std::mem::offset_of!(TOKEN_PRIVILEGES, Privileges), count as usize)
    }?;
    for privilege in privileges {
        let _ = writeln!(
            report,
            "    {} {:#x}",
            privilege_name(privilege.Luid),
            privilege.Attributes.0
        );
    }
    Ok(report)
}

fn group_flags(attributes: u32) -> String {
    const NAMES: [(u32, &str); 8] = [
        (0x1, "mandatory"),
        (0x2, "enabled-by-default"),
        (0x4, "enabled"),
        (0x8, "owner"),
        (0x10, "deny-only"),
        (0x20, "integrity"),
        (0x2000_0000, "resource"),
        (0xC000_0000, "logon-id"),
    ];
    let names: Vec<&str> = NAMES
        .iter()
        .filter(|(bit, _)| attributes & bit == *bit)
        .map(|(_, name)| *name)
        .collect();
    format!(" [{}]", names.join(", "))
}

fn privilege_name(luid: LUID) -> String {
    let mut name = [0u16; 128];
    let mut length = name.len() as u32;
    // SAFETY: a valid LUID and a buffer of `length` characters.
    match unsafe { LookupPrivilegeNameW(PCWSTR::null(), &luid, Some(PWSTR(name.as_mut_ptr())), &mut length) } {
        Ok(()) => String::from_utf16_lossy(&name[..length as usize]),
        Err(e) => format!("(privilege {:#x}: {e})", luid_value(luid)),
    }
}

/// `sid` as `S-1-5-...` text.
fn sid_text(sid: PSID) -> String {
    let mut text = PWSTR::null();
    // SAFETY: a valid SID the caller holds whole; the string is freed below.
    unsafe {
        if ConvertSidToStringSidW(sid, &mut text).is_err() {
            return "(unprintable SID)".to_owned();
        }
        let out = text.to_string().unwrap_or_default();
        let _ = LocalFree(Some(HLOCAL(text.0.cast())));
        out
    }
}

// Process and file facts -----

fn session_of(pid: u32) -> Option<u32> {
    let mut session = 0u32;
    // SAFETY: a valid out-pointer.
    unsafe { ProcessIdToSessionId(pid, &mut session) }.ok()?;
    Some(session)
}

fn session_text(pid: u32) -> String {
    session_of(pid).map_or_else(|| "?".to_owned(), |session| session.to_string())
}

fn creation_time(process: HANDLE) -> Option<u64> {
    let (mut created, mut exited, mut kernel, mut user) = Default::default();
    // SAFETY: a live handle with query access; valid out-pointers.
    unsafe { GetProcessTimes(process, &mut created, &mut exited, &mut kernel, &mut user) }.ok()?;
    Some((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
}

fn now_filetime() -> u64 {
    let since_epoch = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    (since_epoch.as_secs() + 11_644_473_600) * 10_000_000 + u64::from(since_epoch.subsec_nanos()) / 100
}

/// The time of day of a FILETIME, to the millisecond, in UTC.
fn clock(filetime: u64) -> String {
    let seconds = filetime / 10_000_000;
    let of_day = seconds % 86_400;
    format!(
        "{:02}:{:02}:{:02}.{:03}",
        of_day / 3600,
        of_day % 3600 / 60,
        of_day % 60,
        filetime / 10_000 % 1000
    )
}

fn image_path(process: HANDLE) -> Option<String> {
    let mut path = [0u16; 1024];
    let mut length = path.len() as u32;
    // SAFETY: a handle with query access and a buffer of `length` characters.
    unsafe { QueryFullProcessImageNameW(process, PROCESS_NAME_FORMAT(0), PWSTR(path.as_mut_ptr()), &mut length) }
        .ok()?;
    Some(String::from_utf16_lossy(&path[..length as usize]))
}

fn file_version(path: &str) -> String {
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: a NUL-terminated path.
    let size = unsafe { GetFileVersionInfoSizeW(PCWSTR(wide.as_ptr()), None) };
    if size == 0 {
        return format!("no version resource ({})", windows::core::Error::from_thread());
    }
    let mut data = vec![0u8; size as usize];
    // SAFETY: a buffer of `size` bytes.
    if let Err(e) = unsafe { GetFileVersionInfoW(PCWSTR(wide.as_ptr()), None, size, data.as_mut_ptr().cast()) } {
        return format!("version unreadable: {e}");
    }
    let mut at: *mut core::ffi::c_void = std::ptr::null_mut();
    let mut length = 0u32;
    // SAFETY: `data` holds the version block; on success `at` points into it.
    let found = unsafe { VerQueryValueW(data.as_ptr().cast(), w!("\\"), &mut at, &mut length) }.as_bool();
    if !found || at.is_null() || (length as usize) < size_of::<VS_FIXEDFILEINFO>() {
        return "no fixed file information".to_owned();
    }
    // SAFETY: the block holds a `VS_FIXEDFILEINFO` of `length` bytes at `at`, possibly unaligned.
    let info = unsafe { at.cast::<VS_FIXEDFILEINFO>().read_unaligned() };
    format!(
        "{}.{}.{}.{} (product {}.{}.{}.{})",
        info.dwFileVersionMS >> 16,
        info.dwFileVersionMS & 0xFFFF,
        info.dwFileVersionLS >> 16,
        info.dwFileVersionLS & 0xFFFF,
        info.dwProductVersionMS >> 16,
        info.dwProductVersionMS & 0xFFFF,
        info.dwProductVersionLS >> 16,
        info.dwProductVersionLS & 0xFFFF
    )
}

fn windows_version() -> String {
    let mut info = OSVERSIONINFOW {
        dwOSVersionInfoSize: size_of::<OSVERSIONINFOW>() as u32,
        ..Default::default()
    };
    // SAFETY: a valid structure with its size set.
    let status = unsafe { RtlGetVersion(&mut info) };
    format!(
        "{}.{}.{} (RtlGetVersion status {:#x})",
        info.dwMajorVersion, info.dwMinorVersion, info.dwBuildNumber, status.0
    )
}

// The object manager -----

const DIRECTORY_QUERY: u32 = 0x1;
const DIRECTORY_TRAVERSE: u32 = 0x2;
const SYMBOLIC_LINK_QUERY: u32 = 0x1;
const READ_CONTROL: u32 = 0x2_0000;
const SYNCHRONIZE: u32 = 0x10_0000;
const STATUS_MORE_ENTRIES: i32 = 0x105;
const STATUS_NO_MORE_ENTRIES: i32 = 0x8000_001Au32 as i32;

#[link(name = "ntdll", kind = "raw-dylib")]
unsafe extern "system" {
    fn NtOpenMutant(handle: *mut HANDLE, access: u32, attributes: *const OBJECT_ATTRIBUTES) -> NTSTATUS;
}

/// What `NtQueryDirectoryObject` writes, one per entry, ending with an entry of zeroes.
#[repr(C)]
struct DirectoryInformation {
    name: UNICODE_STRING,
    type_name: UNICODE_STRING,
}

struct DirectoryEntry {
    name: String,
    type_name: String,
}

fn status_text(status: i32) -> String {
    let name = match status as u32 {
        0xC000_0022 => " (access denied)",
        0xC000_0034 => " (name not found)",
        0xC000_003A => " (path not found)",
        0xC000_0024 => " (type mismatch)",
        _ => "",
    };
    format!("NTSTATUS {:#010x}{name}", status as u32)
}

/// `call` with the attributes that name `name` under `root` (the object manager's root if none).
fn with_name<R>(root: Option<HANDLE>, name: &str, call: impl FnOnce(&OBJECT_ATTRIBUTES) -> R) -> R {
    let mut units: Vec<u16> = name.encode_utf16().collect();
    let bytes = u16::try_from(units.len() * 2).expect("a short name");
    let name = UNICODE_STRING {
        Length: bytes,
        MaximumLength: bytes,
        Buffer: PWSTR(units.as_mut_ptr()),
    };
    call(&OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: root.unwrap_or_default(),
        ObjectName: &name,
        Attributes: OBJ_CASE_INSENSITIVE,
        ..Default::default()
    })
}

fn open_directory(root: Option<HANDLE>, name: &str, access: u32) -> Result<OwnedHandle, i32> {
    with_name(root, name, |attributes| {
        let mut handle = HANDLE::default();
        // SAFETY: every pointer is to a local that outlives the call.
        let status = unsafe { NtOpenDirectoryObject(&mut handle, access, attributes) };
        if status.0 >= 0 {
            Ok(OwnedHandle(handle))
        } else {
            Err(status.0)
        }
    })
}

fn open_mutant(root: HANDLE, name: &str, access: u32) -> Result<OwnedHandle, i32> {
    with_name(Some(root), name, |attributes| {
        let mut handle = HANDLE::default();
        // SAFETY: every pointer is to a local that outlives the call.
        let status = unsafe { NtOpenMutant(&mut handle, access, attributes) };
        if status.0 >= 0 {
            Ok(OwnedHandle(handle))
        } else {
            Err(status.0)
        }
    })
}

fn link_target(root: HANDLE, name: &str) -> String {
    with_name(Some(root), name, |attributes| {
        let mut link = HANDLE::default();
        // SAFETY: every pointer is to a local that outlives the call.
        let status = unsafe { NtOpenSymbolicLinkObject(&mut link, SYMBOLIC_LINK_QUERY, attributes) };
        if status.0 < 0 {
            return format!("(not opened: {})", status_text(status.0));
        }
        let link = OwnedHandle(link);
        let mut units = vec![0u16; 1024];
        let mut target = UNICODE_STRING {
            Length: 0,
            MaximumLength: u16::try_from(units.len() * 2).expect("a short buffer"),
            Buffer: PWSTR(units.as_mut_ptr()),
        };
        // SAFETY: `target` describes a buffer of `MaximumLength` bytes.
        let status = unsafe { NtQuerySymbolicLinkObject(link.0, &mut target, None) };
        if status.0 < 0 {
            return format!("(not read: {})", status_text(status.0));
        }
        String::from_utf16_lossy(&units[..usize::from(target.Length) / 2])
    })
}

fn list_directory(directory: HANDLE) -> Result<Vec<DirectoryEntry>, i32> {
    // Aligned for the `UNICODE_STRING`s the call writes at its start.
    let mut buffer = vec![0u64; 16 * 1024];
    let mut entries = Vec::new();
    let mut context = 0u32;
    let mut restart = true;
    loop {
        // SAFETY: the buffer is as long as the call is told; `context` and the flag carry the scan.
        let status = unsafe {
            NtQueryDirectoryObject(
                directory,
                Some(buffer.as_mut_ptr().cast()),
                (buffer.len() * size_of::<u64>()) as u32,
                false,
                restart,
                &mut context,
                None,
            )
        };
        restart = false;
        if status.0 == STATUS_NO_MORE_ENTRIES {
            return Ok(entries);
        }
        if status.0 < 0 {
            return Err(status.0);
        }
        let mut at = buffer.as_ptr().cast::<DirectoryInformation>();
        loop {
            // SAFETY: the call wrote entries from the start of the buffer, ending with one of zeroes; the
            // strings point into the buffer, which is not touched until the next call.
            let entry = unsafe { &*at };
            if entry.name.Buffer.is_null() {
                break;
            }
            // SAFETY: as above.
            let (name, type_name) = unsafe {
                (
                    std::slice::from_raw_parts(entry.name.Buffer.0, usize::from(entry.name.Length) / 2),
                    std::slice::from_raw_parts(entry.type_name.Buffer.0, usize::from(entry.type_name.Length) / 2),
                )
            };
            entries.push(DirectoryEntry {
                name: String::from_utf16_lossy(name),
                type_name: String::from_utf16_lossy(type_name),
            });
            // SAFETY: the entry before the terminating one of zeroes has a successor in the buffer.
            at = unsafe { at.add(1) };
        }
        if status.0 != STATUS_MORE_ENTRIES {
            return Ok(entries);
        }
    }
}

/// Owner, group, DACL and mandatory label of the object `handle` (opened with `READ_CONTROL`) as SDDL.
fn sddl_of_handle(handle: HANDLE) -> Result<String, String> {
    let which = OBJECT_SECURITY_INFORMATION(
        OWNER_SECURITY_INFORMATION.0
            | GROUP_SECURITY_INFORMATION.0
            | DACL_SECURITY_INFORMATION.0
            | LABEL_SECURITY_INFORMATION.0,
    );
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: a valid handle and out-pointer; the descriptor is freed below.
    let error = unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            which,
            None,
            None,
            None,
            None,
            Some(&mut descriptor),
        )
    };
    if error.0 != 0 {
        return Err(format!("GetSecurityInfo: win32 error {}", error.0));
    }
    let mut text = PWSTR::null();
    // SAFETY: the descriptor just read; the string is freed below.
    let converted = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor, SDDL_REVISION_1, which, &mut text, None)
    };
    let result = match converted {
        // SAFETY: a NUL-terminated string just made.
        Ok(()) => Ok(unsafe { text.to_string() }.unwrap_or_default()),
        Err(e) => Err(format!("ConvertSecurityDescriptorToStringSecurityDescriptor: {e}")),
    };
    // SAFETY: both allocations came from the calls above.
    unsafe {
        if !text.is_null() {
            let _ = LocalFree(Some(HLOCAL(text.0.cast())));
        }
        let _ = LocalFree(Some(HLOCAL(descriptor.0)));
    }
    result
}

/// The object directories that hold named objects, one per session in `sessions`, and what is in them:
/// their descriptors (each once), a count of their entries by type, their links, and every entry named
/// like PSReadLine's history mutex with its descriptor.
fn named_objects(record: &mut Record, sessions: &BTreeSet<u32>) {
    if !record.sessions_listed {
        record.sessions_listed = true;
        let listing = match open_directory(None, r"\Sessions", DIRECTORY_QUERY | DIRECTORY_TRAVERSE) {
            Ok(directory) => match list_directory(directory.0) {
                Ok(entries) => entries
                    .iter()
                    .map(|entry| format!("{} ({})", entry.name, entry.type_name))
                    .collect::<Vec<_>>()
                    .join(", "),
                Err(status) => format!("not listed: {}", status_text(status)),
            },
            Err(status) => format!("not opened: {}", status_text(status)),
        };
        record.line(format!("entries of \\Sessions: {listing}"));
    }
    let mut directories = vec![r"\BaseNamedObjects".to_owned()];
    directories.extend(
        sessions
            .iter()
            .map(|session| format!(r"\Sessions\{session}\BaseNamedObjects")),
    );
    for path in directories {
        record.line(format!("named objects in {path}:"));
        let (directory, readable) =
            match open_directory(None, &path, DIRECTORY_QUERY | DIRECTORY_TRAVERSE | READ_CONTROL) {
                Ok(directory) => (directory, true),
                Err(with_descriptor) => match open_directory(None, &path, DIRECTORY_QUERY | DIRECTORY_TRAVERSE) {
                    Ok(directory) => {
                        record.line(format!(
                            "  opened without READ_CONTROL only (with it: {})",
                            status_text(with_descriptor)
                        ));
                        (directory, false)
                    }
                    Err(status) => {
                        record.line(format!("  not opened: {}", status_text(status)));
                        continue;
                    }
                },
            };
        if readable && record.directories.insert(path.clone()) {
            let descriptor = sddl_of_handle(directory.0).unwrap_or_else(|why| format!("unreadable: {why}"));
            record.line(format!("  descriptor of the directory (read once): {descriptor}"));
        }
        let entries = match list_directory(directory.0) {
            Ok(entries) => entries,
            Err(status) => {
                record.line(format!("  not listed: {}", status_text(status)));
                continue;
            }
        };
        let mut by_type: BTreeMap<&str, usize> = BTreeMap::new();
        for entry in &entries {
            *by_type.entry(entry.type_name.as_str()).or_default() += 1;
        }
        record.line(format!("  {} entries by type: {by_type:?}", entries.len()));
        for entry in entries.iter().filter(|e| e.type_name == "SymbolicLink") {
            record.line(format!(
                "  link {} -> {}",
                entry.name,
                link_target(directory.0, &entry.name)
            ));
        }
        let mut found = false;
        for entry in entries.iter().filter(|e| {
            e.name
                .to_ascii_lowercase()
                .starts_with(&MUTEX_PREFIX.to_ascii_lowercase())
        }) {
            found = true;
            let descriptor = match open_mutant(directory.0, &entry.name, READ_CONTROL) {
                Ok(mutex) => sddl_of_handle(mutex.0).unwrap_or_else(|why| format!("unreadable: {why}")),
                Err(status) => format!("not opened with READ_CONTROL: {}", status_text(status)),
            };
            record.line(format!("  {} ({}): {descriptor}", entry.name, entry.type_name));
        }
        if !found {
            record.line(format!("  no entry named {MUTEX_PREFIX}*"));
        }
    }
}

/// Open the mutex `name` the way a Win32 caller does, by the session-local name and the `Local\` and
/// `Global\` forms, in this process's own session (see the header of the record), with `READ_CONTROL`, and
/// with `SYNCHRONIZE` when that is refused, so that "does not exist" and "access denied" are told apart.
fn open_by_name(record: &mut Record, name: &str) {
    record.line(format!("opening {name} by name from this test process:"));
    for prefix in ["", r"Local\", r"Global\"] {
        let full = format!("{prefix}{name}");
        let wide: Vec<u16> = full.encode_utf16().chain(std::iter::once(0)).collect();
        let open = |access: u32| {
            // SAFETY: a NUL-terminated name; the handle is closed by `OwnedHandle`.
            unsafe { OpenMutexW(SYNCHRONIZATION_ACCESS_RIGHTS(access), false, PCWSTR(wide.as_ptr())) }.map(OwnedHandle)
        };
        match open(READ_CONTROL) {
            Ok(mutex) => {
                let descriptor = sddl_of_handle(mutex.0).unwrap_or_else(|why| format!("unreadable: {why}"));
                record.line(format!("  {full}: opened with READ_CONTROL: {descriptor}"));
            }
            Err(refused) => {
                let with_synchronize = match open(SYNCHRONIZE) {
                    Ok(_) => "opened".to_owned(),
                    Err(e) => format!("refused: {e}"),
                };
                record.line(format!(
                    "  {full}: READ_CONTROL refused: {refused}; SYNCHRONIZE {with_synchronize}"
                ));
            }
        }
    }
}
