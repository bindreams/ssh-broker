//! SPIKE: what an elevated agent would rest on. Windows only; **Elevated (CI only)**. Never merged.
//!
//! Throwaway measurements. They create local accounts (made administrators), register scheduled tasks
//! with stored passwords, change sshd's `DefaultShell` and log accounts on. They need an elevated
//! administrator and refuse to run anywhere else, before they touch anything: run them in CI, never on
//! a workstation. Each measurement prints its facts as `key=value` lines under a `SPIKE <id>` heading
//! (to the log and to `hive::record`'s file, which CI prints at the end of the job), and a passing
//! test's output is shown (`.config/nextest.toml`). A measurement whose answer is "no" records it and
//! passes; one that cannot be made fails with the reason.
//!
//! - M1: which ways of starting a process for an administrator account give an elevated token with a
//!   loaded profile. Each way is one test with a fresh account (an earlier logon would leave the hive
//!   loaded and spoil the "profile loaded" fact of the next).
//! - M2: whether such a child can follow links. Every child of M1 tries the same three links, and so
//!   do a standard account's child and a child under the runner's real sshd (the baseline).
//! - M3: whether a mandatory integrity label keeps lower-integrity processes of the same user off the
//!   socket and out of its folder.
//!
//! Not exercised: the auto-login task of the product's design has a *logon trigger* and a group
//! principal (it starts when a user logs on interactively). A CI service context has no interactive
//! logon, so that start cannot be made here and is not faked. The M1 tasks have the shape of
//! `session_task::task_xml` (a boot trigger, a stored password) and are started on demand.
#![cfg(windows)]

use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use ssh_broker::acl::{self, Sid};
use ssh_broker::afunix::{self, Listener};
use ssh_broker::provision::probe;
use ssh_broker::provision::session_task::{requested_sddl, task_xml};
use ssh_broker::provision::taskscheduler;
use ssh_broker::socket_loc::{self, SocketLocation};
use ssh_broker::userdir;
use ssh_broker::winutil::OwnedHandle;
use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
    SetNamedSecurityInfoW,
};
use windows::Win32::Security::{
    ACL, DuplicateTokenEx, GetSecurityDescriptorSacl, GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation,
    LABEL_SECURITY_INFORMATION, LOGON32_LOGON, LOGON32_LOGON_BATCH, LOGON32_LOGON_INTERACTIVE,
    LOGON32_PROVIDER_DEFAULT, LogonUserW, PSECURITY_DESCRIPTOR, SecurityImpersonation, TOKEN_ALL_ACCESS, TOKEN_GROUPS,
    TOKEN_INFORMATION_CLASS, TOKEN_LINKED_TOKEN, TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TokenElevation,
    TokenElevationType, TokenGroups, TokenImpersonationLevel, TokenIntegrityLevel, TokenLinkedToken, TokenPrimary,
    TokenType,
};
use windows::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_USERS, KEY_QUERY_VALUE, RegCloseKey, RegOpenKeyExW,
};
use windows::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_PROCESS_LOGON_FLAGS, CreateProcessWithLogonW, GetCurrentProcess,
    GetProcessMitigationPolicy, LOGON_WITH_PROFILE, OpenProcessToken, PROCESS_INFORMATION,
    ProcessRedirectionTrustPolicy, STARTUPINFOW,
};
use windows::core::{BOOL, PCWSTR, PWSTR};

#[path = "common/account.rs"]
mod account_fixture;
#[path = "common/bounded_wait.rs"]
mod bounded_wait;
#[path = "common/child_entry.rs"]
mod child_entry;
#[path = "common/desktop.rs"]
mod desktop;
#[path = "common/fs_state.rs"]
mod fs_state;
#[path = "common/hard_errors.rs"]
mod hard_errors;
#[path = "common/integrity.rs"]
mod integrity;
#[path = "common/machine.rs"]
mod machine;
#[path = "common/password.rs"]
mod password;
#[path = "common/process_list.rs"]
mod process_list;
#[path = "common/sshd_rig.rs"]
mod sshd_rig;
#[path = "common/stand_in.rs"]
mod stand_in;

// `integrity.rs` names the account fixture `crate::account`; the sshd rig and the stand-in name it
// `crate::account_fixture`. One module, both names.
use account_fixture as account;

use account_fixture::{Account, ServiceLogon, SharedDir, Starter, hive, wide};
use sshd_rig::{Login, run_client, set_stock_shell};
use stand_in::Kit;

/// How long Task Scheduler may take to start the child of a task: an external event that may never
/// come (a logon that fails leaves no trace in the task's last result). Expiry fails the test.
const TASK_START_BOUND: std::time::Duration = std::time::Duration::from_secs(180);

/// The relative id of the High mandatory label, `S-1-16-12288`.
const HIGH: u32 = 0x3000;

// Reporting =====

/// Print and record one measurement.
fn record(heading: &str, facts: &str) {
    hive::record(&format!("SPIKE {heading}\n{}", facts.trim_end()));
}

/// The text of a panic, for a step whose failure is itself the answer (a start that is refused).
fn catch_panic<T>(f: impl FnOnce() -> T) -> Result<T, String> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).map_err(|payload| {
        payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
            .unwrap_or_else(|| "a panic with no text".to_owned())
    })
}

/// The value of `key` in a `key=value` text.
fn value<'a>(text: &'a str, key: &str) -> &'a str {
    text.lines()
        .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
        .unwrap_or_else(|| panic!("no {key} in:\n{text}"))
}

/// A Win32 error as text.
fn describe(code: windows::Win32::Foundation::WIN32_ERROR) -> String {
    format!("{} ({})", windows::core::Error::from(code.to_hresult()), code.0)
}

// What a token says about itself =====

/// The block of token information of `class`, 8-aligned so that a structure can be read in place.
fn token_info(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Result<Vec<u64>, String> {
    let mut len = 0u32;
    // SAFETY: a null buffer with a zero length is the documented size probe.
    let _ = unsafe { GetTokenInformation(token, class, None, 0, &mut len) };
    if len == 0 {
        return Err(format!("no length: {}", windows::core::Error::from_thread()));
    }
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: `buf` holds at least `len` bytes.
    unsafe { GetTokenInformation(token, class, Some(buf.as_mut_ptr().cast()), len, &mut len) }
        .map_err(|e| e.to_string())?;
    Ok(buf)
}

/// A token information class that is one DWORD.
fn token_u32(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Result<u32, String> {
    let (mut data, mut len) = (0u32, 0u32);
    // SAFETY: a 4-byte buffer for a 4-byte class.
    unsafe { GetTokenInformation(token, class, Some((&raw mut data).cast::<c_void>()), 4, &mut len) }
        .map_err(|e| e.to_string())?;
    Ok(data)
}

fn token_integrity(token: HANDLE) -> Result<u32, String> {
    let buf = token_info(token, TokenIntegrityLevel)?;
    // SAFETY: the buffer is a `TOKEN_MANDATORY_LABEL` and its SID, 8-aligned.
    unsafe {
        let label = &*buf.as_ptr().cast::<TOKEN_MANDATORY_LABEL>();
        let sid = label.Label.Sid;
        let count = *GetSidSubAuthorityCount(sid);
        Ok(*GetSidSubAuthority(sid, u32::from(count) - 1))
    }
}

/// Whether `BUILTIN\Administrators` is enabled in the token, deny-only (the filtered token of a UAC
/// split), disabled or absent.
fn administrators_state(token: HANDLE) -> String {
    const SE_GROUP_ENABLED: u32 = 0x4;
    const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x10;
    let buf = match token_info(token, TokenGroups) {
        Ok(buf) => buf,
        Err(e) => return format!("unreadable: {e}"),
    };
    // SAFETY: the buffer is a `TOKEN_GROUPS` with `GroupCount` entries after its header, 8-aligned.
    unsafe {
        let groups = &*buf.as_ptr().cast::<TOKEN_GROUPS>();
        let first = groups.Groups.as_ptr();
        for index in 0..groups.GroupCount as usize {
            let group = &*first.add(index);
            let mut text = PWSTR::null();
            if ConvertSidToStringSidW(group.Sid, &mut text).is_err() {
                continue;
            }
            let sid = text.to_string().unwrap_or_default();
            let _ = LocalFree(Some(HLOCAL(text.0.cast())));
            if sid == "S-1-5-32-544" {
                let attributes = group.Attributes;
                let state = if attributes & SE_GROUP_USE_FOR_DENY_ONLY != 0 {
                    "deny-only"
                } else if attributes & SE_GROUP_ENABLED != 0 {
                    "enabled"
                } else {
                    "disabled"
                };
                return format!("{state} (attributes {attributes:#x})");
            }
        }
    }
    "absent".to_owned()
}

/// What a token is, as `key=value` lines: integrity, elevation, the Administrators group, and its type.
fn token_facts(token: HANDLE) -> String {
    let show = |result: Result<String, String>| result.unwrap_or_else(|e| format!("unreadable: {e}"));
    let elevation_type = show(token_u32(token, TokenElevationType).map(|t| {
        let name = match t {
            1 => "Default (no split token)",
            2 => "Full (the elevated token of a split)",
            3 => "Limited (the filtered token of a split)",
            _ => "unknown",
        };
        format!("{name} [{t}]")
    }));
    let elevated = show(token_u32(token, TokenElevation).map(|e| (e != 0).to_string()));
    let integrity = show(token_integrity(token).map(|rid| format!("{rid:#x}")));
    let kind = show(token_u32(token, TokenType).map(|t| {
        if t == TokenPrimary.0 as u32 {
            "primary".to_owned()
        } else {
            let level = token_u32(token, TokenImpersonationLevel)
                .map_or_else(|e| format!("unreadable: {e}"), |l| l.to_string());
            format!("impersonation (level {level}: 0 anonymous, 1 identification, 2 impersonation, 3 delegation)")
        }
    }));
    format!(
        "integrity_rid={integrity}\nelevation_type={elevation_type}\nis_elevated={elevated}\nadministrators={}\ntoken_type={kind}\n",
        administrators_state(token)
    )
}

fn own_token() -> OwnedHandle {
    let mut token = HANDLE::default();
    // SAFETY: valid out-pointer; the token is closed by `OwnedHandle`.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.expect("open the process token");
    OwnedHandle(token)
}

/// The flags of `GetProcessMitigationPolicy(ProcessRedirectionTrustPolicy)`: bit 0 enforce, bit 1 audit.
fn redirection_trust() -> String {
    let mut flags = 0u32;
    // SAFETY: the policy structure is one DWORD of flags.
    let read = unsafe {
        GetProcessMitigationPolicy(
            GetCurrentProcess(),
            ProcessRedirectionTrustPolicy,
            (&raw mut flags).cast::<c_void>(),
            4,
        )
    };
    match read {
        Ok(()) => format!("{flags:#x} (enforce={}, audit={})", flags & 1, (flags >> 1) & 1),
        Err(e) => format!("failed: {e}"),
    }
}

fn registry_open(root: HKEY, subkey: &str) -> String {
    let mut key = HKEY::default();
    // SAFETY: a NUL-terminated name and a valid out-pointer; the key is closed below.
    let rc = unsafe { RegOpenKeyExW(root, PCWSTR(wide(subkey).as_ptr()), None, KEY_QUERY_VALUE, &mut key) };
    if rc == ERROR_SUCCESS {
        // SAFETY: the key just opened.
        let _ = unsafe { RegCloseKey(key) };
        "ok".to_owned()
    } else {
        format!("failed: {}", describe(rc))
    }
}

/// What the machine's UAC policy says, which decides whether an administrator's token is split at all.
fn uac_policy() -> String {
    let out = Command::new("reg")
        .args([
            "query",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        ])
        .output();
    let names = [
        "EnableLUA",
        "FilterAdministratorToken",
        "ConsentPromptBehaviorAdmin",
        "LocalAccountTokenFilterPolicy",
    ];
    match out {
        Ok(out) => {
            let text = String::from_utf8_lossy(&out.stdout);
            let lines: Vec<String> = text
                .lines()
                .map(str::trim)
                .filter(|line| names.iter().any(|name| line.starts_with(name)))
                .map(|line| format!("uac_policy {}", line.split_whitespace().collect::<Vec<_>>().join(" ")))
                .collect();
            if lines.is_empty() {
                "uac_policy=none of the values is set\n".to_owned()
            } else {
                lines.join("\n") + "\n"
            }
        }
        Err(e) => format!("uac_policy=reg did not run: {e}\n"),
    }
}

// The child halves =====

/// What this process is, as `key=value` lines: the facts every start of M1 is judged by, then M2's three
/// link reads. Never panics: a fact that cannot be read says why.
fn self_report(input: &str) -> String {
    let token = own_token();
    let mut out = token_facts(token.0);
    let mut put = |key: &str, text: String| out.push_str(&format!("{key}={text}\n"));

    put("session_id", probe::current_session_id().to_string());
    put(
        "logon_type",
        probe::current_logon_type().map_or("unreadable".to_owned(), |t| t.to_string()),
    );

    let user_sid = Sid::current_user()
        .and_then(|sid| sid.to_sddl())
        .unwrap_or_else(|e| format!("unreadable: {e:#}"));
    put("user_sid", user_sid.clone());
    put("hkcu_opens", registry_open(HKEY_CURRENT_USER, ""));
    put("hku_user_hive_opens", registry_open(HKEY_USERS, &user_sid));
    let userprofile = std::env::var("USERPROFILE").unwrap_or_else(|e| format!("unreadable: {e}"));
    let token_profile = userdir::profile_dir_of_token(token.0).map(|p| p.display().to_string());
    put("env_userprofile", userprofile.clone());
    put(
        "token_profile_dir",
        token_profile
            .as_ref()
            .map_or_else(|e| format!("failed: {e:#}"), Clone::clone),
    );
    put(
        "userprofile_is_the_accounts_profile",
        token_profile.as_ref().map_or("unknown".to_owned(), |p| {
            p.eq_ignore_ascii_case(&userprofile).to_string()
        }),
    );
    put("dpapi_round_trips", probe::dpapi_roundtrip(b"spike").to_string());
    put("redirection_trust_policy", redirection_trust());

    for key in ["junction_unelevated", "junction_elevated", "symlink_elevated"] {
        let link = PathBuf::from(value(input, key));
        let read = match std::fs::read_to_string(link.join("probe.txt")) {
            Ok(text) => format!("ok ({} bytes)", text.len()),
            Err(e) => format!("failed: os_error={:?}: {e}", e.raw_os_error()),
        };
        put(&format!("follow_{key}"), read);
    }
    out
}

/// Child half of the M1 and M2 measurements: reports what the process it runs in is.
#[test]
#[ignore = "run as the child of the M1 and M2 measurements"]
fn child_report() {
    let dir = child_entry::dir();
    let input = child_entry::input(&dir);
    child_entry::write_result(&dir, &self_report(&input));
}

// The files M1 and M2 start children on =====

/// A directory every account can use, holding a copy of this test binary (the child), a target
/// directory with a file in it, and three links to the target: a junction the account's own unelevated
/// token made, a junction this elevated process made, and a directory symlink this process made.
struct Fixture {
    dir: PathBuf,
    exe: PathBuf,
    input: String,
}

/// A child's own directory: its input and, if it ran, its result.
struct ChildDir {
    dir: PathBuf,
    command_line: String,
    /// The arguments alone, quoted, for a task's action.
    arguments: String,
}

fn system_exe(name: &str) -> PathBuf {
    PathBuf::from(std::env::var("SystemRoot").expect("SystemRoot is set"))
        .join("System32")
        .join(name)
}

/// `mklink /J link target` run as `account`'s network-logon token, which for an administrator account
/// is the token sshd gives it: unelevated unless UAC is off.
fn junction_as(account: &Account, link: &Path, target: &Path, cwd: &Path) {
    let command = format!(
        "cmd.exe /D /C mklink /J \"{}\" \"{}\"",
        link.display(),
        target.display()
    );
    let code = account.run(&system_exe("cmd.exe"), &command, cwd, &[]);
    assert_eq!(code, 0, "{command} as {} exited {code}", account.name);
}

impl Fixture {
    fn new(dir: &Path, account: &Account) -> Fixture {
        let exe = dir.join("spike.exe");
        std::fs::copy(std::env::current_exe().unwrap(), &exe).expect("copy the test binary");
        let target = dir.join("target");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("probe.txt"), "reached").unwrap();

        let by_the_account = dir.join("junction_unelevated");
        junction_as(account, &by_the_account, &target, dir);
        let by_an_administrator = dir.join("junction_elevated");
        fs_state::junction(&by_an_administrator, &target);
        let symlink = dir.join("symlink_elevated");
        std::os::windows::fs::symlink_dir(&target, &symlink)
            .unwrap_or_else(|e| panic!("symlink {} -> {}: {e}", symlink.display(), target.display()));

        // Who made the first link: its creator's token is the account's network token.
        let network = account.network_token();
        record(
            &format!("fixture for {}: the token that made junction_unelevated", account.name),
            &token_facts(network.0),
        );
        Fixture {
            dir: dir.to_owned(),
            exe,
            input: format!(
                "junction_unelevated={}\njunction_elevated={}\nsymlink_elevated={}\n",
                by_the_account.display(),
                by_an_administrator.display(),
                symlink.display()
            ),
        }
    }

    /// A directory for the child `label`, with its input written.
    fn child(&self, label: &str) -> ChildDir {
        let dir = self.dir.join(format!("child-{label}"));
        std::fs::create_dir_all(&dir).unwrap();
        child_entry::write_input(&dir, &self.input);
        let args = child_entry::args("child_report", &dir);
        let arguments: Vec<String> = args.iter().map(|a| format!("\"{a}\"")).collect();
        ChildDir {
            command_line: child_entry::command_line(&self.exe, "child_report", &dir),
            arguments: arguments.join(" "),
            dir,
        }
    }
}

/// An administrator account with a profile, whose group membership is in place before any logon.
fn administrator(tag: &str) -> Account {
    let account = Account::create(tag, true);
    account.make_administrator();
    account
}

/// How a start went.
enum Start {
    /// The child ran; `note` is what the parent knows about the run.
    Ran(String),
    /// The start was refused: the answer, not a failure.
    Refused(String),
    /// The start worked and no child reported: the measurement was not made.
    Lost(String),
}

/// Record the child's report under `heading`; a start that did not happen is recorded as an answer, a
/// child that ran and left no report is a failure of the measurement, pushed on `failures`.
fn report_child(heading: &str, child: &ChildDir, start: Start, failures: &mut Vec<String>) {
    match start {
        Start::Refused(why) => record(heading, &format!("start=refused: {why}")),
        Start::Lost(why) => {
            record(heading, &format!("start=ok\nmeasurement not made: {why}"));
            failures.push(format!("{heading}: {why}"));
        }
        Start::Ran(note) => match std::fs::read_to_string(child_entry::result_path(&child.dir)) {
            Ok(text) => record(heading, &format!("start=ok\n{note}\n{text}")),
            Err(e) => {
                let why = format!("the child ran and wrote no result ({e}); {note}");
                record(heading, &format!("start=ok\nmeasurement not made: {why}"));
                failures.push(format!("{heading}: {why}"));
            }
        },
    }
}

fn finish(failures: &[String]) {
    assert!(failures.is_empty(), "measurements not made:\n{}", failures.join("\n"));
}

/// The parent's own token and the UAC policy: what the rest of a test's facts are read against.
fn record_context(heading: &str) {
    let token = own_token();
    record(
        &format!("{heading}: the test process and the machine"),
        &format!("{}{}", token_facts(token.0), uac_policy()),
    );
}

/// The exit of a child run as `Start`.
fn exited(code: u32) -> Start {
    Start::Ran(format!("exit_code={}", hard_errors::describe_exit(code)))
}

// M1: ways to start a process for an account =====

/// (a) `CreateProcessWithLogonW(LOGON_WITH_PROFILE)` with the password: the call of `logon.rs`. The
/// product's `start_background_agent` starts only `agent --background`, so the call is made here.
fn start_with_logon(account: &Account, fixture: &Fixture, child: &ChildDir) -> Start {
    let mut command = wide(&child.command_line);
    let exe = wide(&fixture.exe.to_string_lossy());
    let cwd = wide(&fixture.dir.to_string_lossy());
    let user = wide(&account.name);
    let password = wide(&account.password);
    let startup = STARTUPINFOW {
        cb: size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut info = PROCESS_INFORMATION::default();
    // SAFETY: every pointer is to a local that outlives the call.
    let made = unsafe {
        CreateProcessWithLogonW(
            PCWSTR(user.as_ptr()),
            PCWSTR(wide(".").as_ptr()),
            PCWSTR(password.as_ptr()),
            LOGON_WITH_PROFILE,
            PCWSTR(exe.as_ptr()),
            Some(PWSTR(command.as_mut_ptr())),
            CREATE_NO_WINDOW,
            None,
            PCWSTR(cwd.as_ptr()),
            &startup,
            &mut info,
        )
    };
    if let Err(e) = made {
        return Start::Refused(format!("{e}"));
    }
    drop(OwnedHandle(info.hThread));
    let process = OwnedHandle(info.hProcess);
    let code = bounded_wait::wait_for_exit(
        process.0,
        info.dwProcessId,
        "the child of CreateProcessWithLogonW",
        bounded_wait::CHILD_EXIT_BOUND,
        std::slice::from_ref(&child.dir),
    );
    exited(code)
}

/// (c) A process started with `token` by `CreateProcessWithTokenW(flags)`, from this elevated process.
fn start_with_token(
    account: &Account,
    fixture: &Fixture,
    child: &ChildDir,
    token: HANDLE,
    flags: CREATE_PROCESS_LOGON_FLAGS,
) -> Start {
    let starter = Sid::current_user().unwrap().to_sddl().unwrap();
    let spawned = catch_panic(|| {
        let private = desktop::PrivateDesktop::create(&[&account.sid_text, &starter])
            .unwrap_or_else(|e| panic!("create a window station and desktop for {}: {e}", account.name));
        account_fixture::spawn_with_token(
            Starter::SecondaryLogon(flags),
            token,
            &account.name,
            Some(private),
            &fixture.exe,
            &child.command_line,
            &fixture.dir,
            std::slice::from_ref(&child.dir),
            None,
            None,
            CREATE_NO_WINDOW,
        )
    });
    match spawned {
        Err(why) => Start::Refused(why),
        Ok(child) => {
            child.resume();
            exited(child.wait())
        }
    }
}

/// `LogonUserW` of `logon_type` for the account: a primary token, or the reason there is none.
fn logon_token(account: &Account, logon_type: LOGON32_LOGON) -> Result<OwnedHandle, String> {
    let mut token = HANDLE::default();
    // SAFETY: NUL-terminated inputs and a valid out-pointer.
    unsafe {
        LogonUserW(
            PCWSTR(wide(&account.name).as_ptr()),
            PCWSTR(wide(".").as_ptr()),
            PCWSTR(wide(&account.password).as_ptr()),
            logon_type,
            LOGON32_PROVIDER_DEFAULT,
            &mut token,
        )
    }
    .map_err(|e| e.to_string())?;
    Ok(OwnedHandle(token))
}

/// Deletes the task when dropped, passing or failing.
struct TaskGuard(String);

impl Drop for TaskGuard {
    fn drop(&mut self) {
        let _ = taskscheduler::delete_task(&self.0);
    }
}

/// (b) A task for the account with a stored password, in the shape of `session_task::task_xml` with the
/// child as its action and `RunLevel` `LeastPrivilege` or `HighestAvailable`, started on demand.
fn start_with_task(account: &Account, fixture: &Fixture, child: &ChildDir, name: &str, highest: bool) -> Start {
    let exe = fixture.exe.to_string_lossy().into_owned();
    let mut xml = task_xml(&exe, &account.sid_text);
    let agent = format!("agent --background --expect-user {}", account.sid_text);
    assert!(xml.contains(&agent), "task_xml no longer has the agent's arguments");
    xml = xml.replace(&agent, &child.arguments);
    if highest {
        assert!(xml.contains("LeastPrivilege"), "task_xml no longer has a run level");
        xml = xml.replace("LeastPrivilege", "HighestAvailable");
    }
    let machine_user = match ssh_broker::account::computer_name() {
        Ok(machine) => format!("{machine}\\{}", account.name),
        Err(e) => panic!("the machine's name: {e:#}"),
    };
    let registered = taskscheduler::register_password_task(
        name,
        &xml,
        &machine_user,
        &password::password(&account.password),
        &requested_sddl(&account.sid_text),
    );
    if let Err(e) = registered {
        return Start::Refused(format!("registering the task: {e:#}"));
    }
    let readback = match taskscheduler::task_state(name) {
        Ok(Some(state)) => {
            let level = state
                .xml
                .split("RunLevel>")
                .nth(1)
                .and_then(|rest| rest.split('<').next())
                .unwrap_or("not in the read-back");
            format!("task_run_level_read_back={level}")
        }
        Ok(None) => "task_run_level_read_back=the task is not there".to_owned(),
        Err(e) => format!("task_run_level_read_back=unreadable: {e:#}"),
    };
    if let Err(e) = taskscheduler::run_task(name) {
        return Start::Refused(format!("running the task: {e:#}\n{readback}"));
    }
    let waited = catch_panic(|| {
        stand_in::file_signal::wait_for_file(
            &child_entry::result_path(&child.dir),
            None,
            Some(TASK_START_BOUND),
            "the child a scheduled task starts",
        )
    });
    let last = taskscheduler::task_state(name).map_or_else(
        |e| format!("unreadable: {e:#}"),
        |s| s.map_or("no task".to_owned(), |s| format!("{:#010x}", s.last_result)),
    );
    let note = format!("{readback}\ntask_last_result={last}");
    match waited {
        Ok(_) => Start::Ran(note),
        Err(why) => Start::Lost(format!(
            "no report from the task's child within {TASK_START_BOUND:?} (a refused logon leaves no trace here): {why}\n{note}"
        )),
    }
}

/// M1a for the administrator (`m1a_...`) and the comparison of M2 for a standard account.
fn logon_with_profile(tag: &str, as_administrator: bool, heading: &str) {
    let _machine = machine::shared();
    account_fixture::assert_elevated();
    let shared = SharedDir::new(tag);
    let account = if as_administrator {
        administrator(tag)
    } else {
        Account::create(tag, true)
    };
    record_context(heading);
    let fixture = Fixture::new(&shared.0, &account);
    let child = fixture.child("logon");
    let started = start_with_logon(&account, &fixture, &child);
    let mut failures = Vec::new();
    report_child(heading, &child, started, &mut failures);
    finish(&failures);
}

/// Elevated (CI only). M1a: `CreateProcessWithLogonW(LOGON_WITH_PROFILE)` with the administrator's
/// password, as `logon.rs` starts an agent.
#[test]
fn m1a_create_process_with_logon_w_for_an_administrator() {
    logon_with_profile(
        "m1a",
        true,
        "M1a CreateProcessWithLogonW(LOGON_WITH_PROFILE), administrator account",
    );
}

/// Elevated (CI only). The comparison for M2: the same call for a standard account, which is the
/// unelevated child that links are tried from.
#[test]
fn m2_create_process_with_logon_w_for_a_standard_account() {
    logon_with_profile(
        "m2std",
        false,
        "M2 CreateProcessWithLogonW(LOGON_WITH_PROFILE), standard account (unelevated comparison)",
    );
}

fn task(tag: &str, highest: bool, heading: &str) {
    let _machine = machine::shared();
    account_fixture::assert_elevated();
    let shared = SharedDir::new(tag);
    let account = administrator(tag);
    // A Batch logon whose hive Windows may keep loaded: the teardown must not require the profile to go.
    account.started_by(ServiceLogon::TaskScheduler);
    let name = format!("sb-spike-{tag}-{}", std::process::id());
    let _task = TaskGuard(name.clone());
    record_context(heading);
    let fixture = Fixture::new(&shared.0, &account);
    let child = fixture.child("task");
    let started = start_with_task(&account, &fixture, &child, &name, highest);
    let mut failures = Vec::new();
    report_child(heading, &child, started, &mut failures);
    finish(&failures);
}

/// Elevated (CI only). M1b: a stored-password task for the administrator with `RunLevel
/// LeastPrivilege` (what the product registers today), started on demand.
#[test]
fn m1b_task_with_least_privilege_for_an_administrator() {
    task(
        "m1bl",
        false,
        "M1b scheduled task, password logon, RunLevel LeastPrivilege, administrator account",
    );
}

/// Elevated (CI only). M1b: the same task with `RunLevel HighestAvailable`.
#[test]
fn m1b_task_with_highest_available_for_an_administrator() {
    task(
        "m1bh",
        true,
        "M1b scheduled task, password logon, RunLevel HighestAvailable, administrator account",
    );
}

/// Elevated (CI only). M1c: `LogonUserW(LOGON32_LOGON_BATCH)`, then `CreateProcessWithTokenW(LOGON_WITH_PROFILE)`.
#[test]
fn m1c_batch_logon_then_create_process_with_token_for_an_administrator() {
    let _machine = machine::shared();
    account_fixture::assert_elevated();
    let shared = SharedDir::new("m1cb");
    let account = administrator("m1cb");
    // The token's logon session may outlive its processes, like a task's Batch session.
    account.started_by(ServiceLogon::TaskScheduler);
    let heading = "M1c LogonUserW(BATCH) then CreateProcessWithTokenW(LOGON_WITH_PROFILE), administrator account";
    record_context(heading);
    let fixture = Fixture::new(&shared.0, &account);
    let mut failures = Vec::new();
    let token = match logon_token(&account, LOGON32_LOGON_BATCH) {
        Ok(token) => token,
        Err(e) => {
            record(heading, &format!("logon=refused: {e}"));
            return;
        }
    };
    record(&format!("{heading}: the logon token"), &token_facts(token.0));
    let child = fixture.child("token");
    let started = start_with_token(&account, &fixture, &child, token.0, LOGON_WITH_PROFILE);
    report_child(heading, &child, started, &mut failures);
    finish(&failures);
}

/// Elevated (CI only). M1c: `LogonUserW(LOGON32_LOGON_INTERACTIVE)`, then `CreateProcessWithTokenW`
/// with that token, and with its linked token if it has one.
#[test]
fn m1c_interactive_logon_then_create_process_with_token_for_an_administrator() {
    let _machine = machine::shared();
    account_fixture::assert_elevated();
    let shared = SharedDir::new("m1ci");
    let account = administrator("m1ci");
    account.started_by(ServiceLogon::TaskScheduler);
    let heading = "M1c LogonUserW(INTERACTIVE) then CreateProcessWithTokenW(LOGON_WITH_PROFILE), administrator account";
    record_context(heading);
    let fixture = Fixture::new(&shared.0, &account);
    let mut failures = Vec::new();
    let token = match logon_token(&account, LOGON32_LOGON_INTERACTIVE) {
        Ok(token) => token,
        Err(e) => {
            record(heading, &format!("logon=refused: {e}"));
            return;
        }
    };
    record(&format!("{heading}: the logon token"), &token_facts(token.0));

    // The linked token: whether there is one, what it is, and whether a process starts with it.
    let mut linked = TOKEN_LINKED_TOKEN::default();
    let mut len = 0u32;
    // SAFETY: a `TOKEN_LINKED_TOKEN` and its size; the handle is closed by `OwnedHandle`.
    let got = unsafe {
        GetTokenInformation(
            token.0,
            TokenLinkedToken,
            Some((&raw mut linked).cast::<c_void>()),
            size_of::<TOKEN_LINKED_TOKEN>() as u32,
            &mut len,
        )
    };
    let linked_heading = format!("{heading}: the linked token");
    let linked = match got {
        Ok(()) => Some(OwnedHandle(linked.LinkedToken)),
        Err(e) => {
            record(&linked_heading, &format!("linked_token=none: {e}"));
            None
        }
    };
    if let Some(linked) = &linked {
        record(
            &linked_heading,
            &format!(
                "linked_token=present
{}",
                token_facts(linked.0)
            ),
        );
    }

    let child = fixture.child("token");
    let started = start_with_token(&account, &fixture, &child, token.0, LOGON_WITH_PROFILE);
    report_child(heading, &child, started, &mut failures);

    if let Some(linked) = &linked {
        // The handle as it is: an impersonation token, which a process cannot be started with.
        let direct = fixture.child("linked");
        let started = start_with_token(&account, &fixture, &direct, linked.0, LOGON_WITH_PROFILE);
        report_child(
            &format!("{linked_heading}, as returned"),
            &direct,
            started,
            &mut failures,
        );

        // A primary copy of it.
        let mut copy = HANDLE::default();
        // SAFETY: valid in/out handles; the copy is closed by `OwnedHandle`.
        let duplicated = unsafe {
            DuplicateTokenEx(
                linked.0,
                TOKEN_ALL_ACCESS,
                None,
                SecurityImpersonation,
                TokenPrimary,
                &mut copy,
            )
        };
        let primary_heading = format!("{linked_heading}, duplicated as a primary token");
        match duplicated {
            Err(e) => record(&primary_heading, &format!("duplicate=refused: {e}")),
            Ok(()) => {
                let copy = OwnedHandle(copy);
                record(&format!("{primary_heading}: its facts"), &token_facts(copy.0));
                let primary = fixture.child("linked-primary");
                let started = start_with_token(&account, &fixture, &primary, copy.0, LOGON_WITH_PROFILE);
                report_child(&primary_heading, &primary, started, &mut failures);
            }
        }
    }
    finish(&failures);
}

/// Elevated (CI only). The control: the account's network-logon token (what sshd gives an
/// administrator account), started the way the suite starts every network-token child. It shows
/// what an unelevated administrator token does with the links.
#[test]
fn m1d_network_token_of_an_administrator_for_comparison() {
    let _machine = machine::shared();
    account_fixture::assert_elevated();
    let shared = SharedDir::new("m1d");
    let account = administrator("m1d");
    let heading = "M1d network-logon token (sshd's shape), administrator account";
    record_context(heading);
    let fixture = Fixture::new(&shared.0, &account);
    let child = fixture.child("network");
    let started = match catch_panic(|| {
        account.run(
            &fixture.exe,
            &child.command_line,
            &fixture.dir,
            std::slice::from_ref(&child.dir),
        )
    }) {
        Ok(code) => exited(code),
        Err(why) => Start::Refused(why),
    };
    let mut failures = Vec::new();
    report_child(heading, &child, started, &mut failures);
    finish(&failures);
}

// M2: the baseline under the runner's real sshd =====

/// Elevated (CI only). M2's baseline: the same child, started by the runner's real `sshd` for a standard
/// account (the rig puts a key in the profile, where sshd does not look for an administrator's, so an
/// administrator cannot be driven through it). Stock `cmd.exe` is sshd's shell, so the process under
/// sshd is the account's network token with whatever mitigation sshd gives its children.
#[test]
fn m2_baseline_under_the_real_sshd_for_a_standard_account() {
    let _machine = machine::exclusive();
    account_fixture::assert_elevated();
    let kit = Kit::new("m2ssh");
    let account = Account::create("m2ssh", true);
    account.started_by(ServiceLogon::Sshd);
    let heading = "M2 baseline: a child started by the real sshd, standard account";
    record_context(heading);
    let fixture = Fixture::new(kit.dir(), &account);
    let child = fixture.child("sshd");
    // cmd.exe's own quoting rules apply to the command sshd hands it: none of these paths has a space.
    let command = format!(
        "{} --exact child_report --ignored --nocapture {}{}",
        fixture.exe.display(),
        child_entry::SIGNAL,
        child.dir.display()
    );
    assert!(
        !fixture.exe.to_string_lossy().contains(' ') && !child.dir.to_string_lossy().contains(' '),
        "a path with a space would need cmd.exe quoting: {command}"
    );
    let login = Login::new(&kit, &account);
    set_stock_shell(&system_exe("cmd.exe"));
    let mut ssh = login.command();
    ssh.arg("-T").arg("--").arg(&command);
    let outcome = run_client(ssh, false, kit.dir());
    let note = format!(
        "ssh_exit={:?}\nssh_stderr_tail={}",
        outcome.code,
        outcome.stderr.lines().rev().take(3).collect::<Vec<_>>().join(" | ")
    );
    let mut failures = Vec::new();
    let start = if outcome.code.is_none() {
        Start::Lost(format!("ssh did not end\n{note}\n{}", (login.diagnostics())()))
    } else {
        Start::Ran(note)
    };
    report_child(heading, &child, start, &mut failures);
    finish(&failures);
}

// M3: an integrity label on the socket and its folder =====

/// A folder under the temp dir, removed on drop.
struct TempTree(PathBuf);

impl TempTree {
    fn new(tag: &str) -> TempTree {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("sb-spk-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        TempTree(root)
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The mandatory label of `path` as SDDL (`S:(ML;...)`), or `none`.
fn label_of(path: &Path) -> String {
    let path_w = wide(&path.to_string_lossy());
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: NUL-terminated path, valid out-pointers; both allocations are freed below.
    unsafe {
        let rc = GetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            LABEL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            &mut sd,
        );
        if rc != ERROR_SUCCESS {
            return format!("unreadable: {}", describe(rc));
        }
        let mut text = PWSTR::null();
        let converted = ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd,
            SDDL_REVISION_1,
            LABEL_SECURITY_INFORMATION,
            &mut text,
            None,
        );
        let out = match converted {
            Ok(()) => text.to_string().unwrap_or_default(),
            Err(e) => format!("unreadable: {e}"),
        };
        let _ = LocalFree(Some(HLOCAL(text.0.cast())));
        let _ = LocalFree(Some(HLOCAL(sd.0)));
        if out.is_empty() { "none".to_owned() } else { out }
    }
}

/// Set `path`'s mandatory label to the one in `sddl` (`S:(ML;...)`), or remove it with `None`.
fn set_label(path: &Path, sddl: Option<&str>) -> Result<(), String> {
    let path_w = wide(&path.to_string_lossy());
    let mut sd = PSECURITY_DESCRIPTOR::default();
    let mut sacl: *mut ACL = std::ptr::null_mut();
    // SAFETY: NUL-terminated inputs; the descriptor outlives the call and is freed after it.
    unsafe {
        if let Some(sddl) = sddl {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(wide(sddl).as_ptr()), 1, &mut sd, None)
                .map_err(|e| format!("parse {sddl}: {e}"))?;
            let (mut present, mut defaulted) = (BOOL(0), BOOL(0));
            GetSecurityDescriptorSacl(sd, &mut present, &mut sacl, &mut defaulted).map_err(|e| format!("{e}"))?;
        }
        let rc = SetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            LABEL_SECURITY_INFORMATION,
            None,
            None,
            None,
            Some(sacl as *const ACL),
        );
        if sddl.is_some() {
            let _ = LocalFree(Some(HLOCAL(sd.0)));
        }
        if rc == ERROR_SUCCESS { Ok(()) } else { Err(describe(rc)) }
    }
}

const SOCKET_HIGH: &str = "S:(ML;;NW;;;HI)";
const FOLDER_HIGH: &str = "S:(ML;OICI;NW;;;HI)";
const SOCKET_LOW: &str = "S:(ML;;NW;;;LW)";
const FOLDER_LOW: &str = "S:(ML;OICI;NW;;;LW)";

/// Where the label is put before the socket is used.
#[derive(Clone, Copy, Debug)]
enum Labelled {
    /// Nothing: the baseline.
    Nothing,
    /// The socket file, after the bind: High, no-write-up.
    SocketHigh,
    /// The folder, before the bind: High, no-write-up, inherited by what is made in it.
    FolderHigh,
}

/// The product's private folder and a bound `Listener` in a stand-in profile, removed on drop (the
/// listener first).
struct Arrangement {
    _listener: Listener,
    loc: SocketLocation,
    _root: TempTree,
}

fn ok_or_err<T: std::fmt::Debug>(result: anyhow::Result<T>) -> String {
    match result {
        Ok(value) => format!("{value:?}"),
        Err(e) => format!("error: {e:#}"),
    }
}

/// Make the arrangement for `labelled`. `Err` is the answer "the product refuses to bind", with the
/// facts so far. Failing to set a label as this elevated process is not an answer and panics.
fn arrange(labelled: Labelled, tag: &str) -> Result<(Arrangement, String), String> {
    let root = TempTree::new(tag);
    std::fs::create_dir_all(root.0.join("AppData").join("Local")).unwrap();
    let loc = socket_loc::for_profile(&root.0).expect("the stand-in profile path is short enough");
    let me = Sid::current_user().unwrap();
    let mut facts = String::new();
    userdir::ensure_socket_dir(&loc, &me).expect("make the private folder");
    if let Labelled::FolderHigh = labelled {
        set_label(loc.dir(), Some(FOLDER_HIGH)).unwrap_or_else(|e| panic!("label the folder High: {e}"));
        facts.push_str(&format!(
            "ensure_socket_dir_again_on_the_labelled_folder={}\n",
            ok_or_err(userdir::ensure_socket_dir(&loc, &me).map(|()| "ok"))
        ));
    }
    facts.push_str(&format!(
        "folder_label_before_bind={}\nverify_dir_acl_before_bind={}\n",
        label_of(loc.dir()),
        ok_or_err(acl::verify_dir_acl(loc.dir(), &me))
    ));
    let listener = match Listener::bind(loc.path()) {
        Ok(listener) => listener,
        Err(e) => return Err(format!("{facts}bind=refused: {e:#}")),
    };
    if let Labelled::SocketHigh = labelled {
        set_label(loc.path(), Some(SOCKET_HIGH)).unwrap_or_else(|e| panic!("label the socket High: {e}"));
    }
    facts.push_str(&format!(
        "bind=ok\nsocket_label={}\nverify_file_acl={}\nverify_dir_acl_after_bind={}\n",
        label_of(loc.path()),
        ok_or_err(acl::verify_file_acl(loc.path(), &me)),
        ok_or_err(acl::verify_dir_acl(loc.dir(), &me)),
    ));
    Ok((
        Arrangement {
            _listener: listener,
            loc,
            _root: root,
        },
        facts,
    ))
}

/// What is left of an arrangement after a child has acted on it, as seen by this elevated process.
fn state_after(arrangement: &Arrangement) -> String {
    let loc = &arrangement.loc;
    let me = Sid::current_user().unwrap();
    let mut entries: Vec<String> = std::fs::read_dir(loc.dir())
        .map(|dir| {
            dir.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    entries.sort();
    let connect = match afunix::connect(loc.path()) {
        Ok(_) => "ok".to_owned(),
        Err(e) => format!("failed: {e:#}"),
    };
    format!(
        "socket_exists={}\nthis_process_connects={connect}\nsocket_label_after={}\nfolder_label_after={}\nverify_file_acl_after={}\nfolder_entries={entries:?}\n",
        loc.path().exists(),
        label_of(loc.path()),
        label_of(loc.dir()),
        ok_or_err(acl::verify_file_acl(loc.path(), &me)),
    )
}

/// What a lower-integrity child of the elevated process tries, and at which level.
const OPS: [(&str, u32); 10] = [
    ("connect", integrity::MEDIUM),
    ("connect", HIGH),
    ("delete_socket", integrity::MEDIUM),
    ("rename_socket", integrity::MEDIUM),
    ("create_file", integrity::MEDIUM),
    ("create_dir", integrity::MEDIUM),
    ("lower_socket_label", integrity::MEDIUM),
    ("remove_socket_label", integrity::MEDIUM),
    ("lower_folder_label", integrity::MEDIUM),
    ("remove_folder_label", integrity::MEDIUM),
];

/// Child half of M3: one operation on the socket or its folder, at the integrity level it was started at.
#[test]
#[ignore = "run as the child of the M3 measurements"]
fn child_socket_op() {
    let dir = child_entry::dir();
    let input = child_entry::input(&dir);
    let (op, socket, folder) = (
        value(&input, "op"),
        PathBuf::from(value(&input, "socket")),
        PathBuf::from(value(&input, "folder")),
    );
    let describe_io = |result: std::io::Result<()>| match result {
        Ok(()) => "ok".to_owned(),
        Err(e) => format!("failed: os_error={:?}: {e}", e.raw_os_error()),
    };
    let label = |path: &Path, sddl: Option<&str>| match set_label(path, sddl) {
        Ok(()) => "ok".to_owned(),
        Err(e) => format!("failed: {e}"),
    };
    let result = match op {
        "connect" => match afunix::connect(&socket) {
            Ok(_) => "connected".to_owned(),
            Err(e) => {
                let os_error = e
                    .downcast_ref::<std::io::Error>()
                    .and_then(std::io::Error::raw_os_error);
                format!("failed: os_error={os_error:?}: {e:#}")
            }
        },
        "delete_socket" => describe_io(std::fs::remove_file(&socket)),
        "rename_socket" => describe_io(std::fs::rename(&socket, folder.join("renamed.sock"))),
        "create_file" => describe_io(std::fs::File::create_new(folder.join("created.txt")).map(drop)),
        "create_dir" => describe_io(std::fs::create_dir(folder.join("created-dir"))),
        "lower_socket_label" => label(&socket, Some(SOCKET_LOW)),
        "remove_socket_label" => label(&socket, None),
        "lower_folder_label" => label(&folder, Some(FOLDER_LOW)),
        "remove_folder_label" => label(&folder, None),
        other => panic!("no operation {other}"),
    };
    child_entry::write_result(
        &dir,
        &format!(
            "child_integrity={:#x}\nop={op}\nresult={result}\n",
            integrity::current_rid()
        ),
    );
}

/// Every operation of [`OPS`] on a fresh arrangement of `labelled`, each by a child at its level.
fn m3(labelled: Labelled, tag: &str) {
    account_fixture::assert_elevated();
    assert_eq!(
        integrity::current_rid(),
        HIGH,
        "the elevated test process is not at High integrity"
    );
    let me = Sid::current_user().unwrap();
    let exe = std::env::current_exe().unwrap();
    let scratch = TempTree::new(&format!("{tag}p"));
    let heading = format!("M3 {labelled:?}");
    let (first, facts) = match arrange(labelled, tag) {
        Ok(made) => made,
        Err(answer) => {
            record(&format!("{heading}: the arrangement"), &answer);
            return;
        }
    };
    record(
        &format!("{heading}: the arrangement"),
        &format!("user_sid={}\n{facts}", me.to_sddl().unwrap()),
    );
    drop(first);

    let mut failures = Vec::new();
    for (n, (op, level)) in OPS.iter().enumerate() {
        let (arrangement, _) = arrange(labelled, tag).unwrap_or_else(|why| panic!("the arrangement again: {why}"));
        let dir = scratch.0.join(n.to_string());
        std::fs::create_dir(&dir).unwrap();
        child_entry::write_input(
            &dir,
            &format!(
                "op={op}\nsocket={}\nfolder={}\n",
                arrangement.loc.path().display(),
                arrangement.loc.dir().display()
            ),
        );
        let code = integrity::run_at(
            *level,
            &exe,
            &child_entry::command_line(&exe, "child_socket_op", &dir),
            &dir,
            std::slice::from_ref(&dir),
        );
        let heading = format!("{heading}: {op} by a child at integrity {level:#x}");
        match std::fs::read_to_string(child_entry::result_path(&dir)) {
            Ok(text) => record(&heading, &format!("{text}{}", state_after(&arrangement))),
            Err(e) => {
                let why = format!("no result ({e}); exit {}", hard_errors::describe_exit(code));
                record(&heading, &format!("measurement not made: {why}"));
                failures.push(format!("{heading}: {why}"));
            }
        }
    }
    finish(&failures);
}

/// Elevated (CI only). M3a: the socket unlabelled, the baseline every other arrangement is read against.
#[test]
fn m3a_socket_unlabelled() {
    m3(Labelled::Nothing, "m3a");
}

/// Elevated (CI only). M3b: the socket labelled High, no-write-up, after the bind.
#[test]
fn m3b_socket_labelled_high() {
    m3(Labelled::SocketHigh, "m3b");
}

/// Elevated (CI only). M3c and M3d: the folder labelled High with `OICI` before the bind, and the
/// attempts to change a label from below.
#[test]
fn m3c_folder_labelled_high_before_the_bind() {
    m3(Labelled::FolderHigh, "m3c");
}
