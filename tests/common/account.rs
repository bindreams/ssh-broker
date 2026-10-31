//! The throwaway-account fixture shared by the Elevated test binaries. **CI only**: it creates
//! local accounts and profiles.
//!
//! The including test crate declares `bounded_wait`, `desktop` and `hard_errors` beside this module.
#![allow(dead_code)]

#[path = "hive.rs"]
pub mod hive;
#[path = "holders.rs"]
pub mod holders;
#[path = "profile.rs"]
pub mod profile;

use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use ssh_broker::acl::Sid;
use ssh_broker::winutil::OwnedHandle;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::NetManagement::{
    NetUserAdd, NetUserDel, NetUserSetInfo, UF_DONT_EXPIRE_PASSWD, UF_SCRIPT, USER_ACCOUNT_FLAGS, USER_INFO_1,
    USER_INFO_1003, USER_PRIV_USER,
};
use windows::Win32::Security::{
    DuplicateTokenEx, GetTokenInformation, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, LogonUserW,
    SecurityImpersonation, TOKEN_ALL_ACCESS, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation, TokenPrimary,
};
use windows::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_PROCESS_LOGON_FLAGS, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW,
    CreateProcessWithTokenW, GetCurrentProcess, OpenProcessToken, PROCESS_INFORMATION, ResumeThread,
    STARTF_USESTDHANDLES, STARTUPINFOW, TerminateProcess,
};
use windows::Win32::UI::Shell::CreateProfile;
use windows::core::{PCWSTR, PWSTR};

pub fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Fail loudly unless this process is an elevated administrator.
pub fn assert_elevated() {
    let mut token = HANDLE::default();
    // SAFETY: valid out-pointers; the token is closed by `OwnedHandle`.
    let elevated = unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).unwrap();
        let token = OwnedHandle(token);
        let mut info = TOKEN_ELEVATION::default();
        let mut len = 0u32;
        GetTokenInformation(
            token.0,
            TokenElevation,
            Some(&mut info as *mut _ as *mut core::ffi::c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
        .is_ok()
            && info.TokenIsElevated != 0
    };
    assert!(
        elevated,
        "this test needs an elevated administrator (CI runs it); not running it here"
    );
}

/// `sb<tag><pid>_<n>` in hex: at most 20 characters, as an account name must be, for a tag of up to
/// 5 characters and a counter below 65536 (more fails loudly). The separator keeps `(pid, n)`
/// pairs whose digits run together apart.
pub fn account_name(tag: &str, pid: u32, n: u32) -> String {
    let name = format!("sb{tag}{pid:x}_{n:x}");
    assert!(
        name.chars().count() <= 20,
        "{name} is longer than an account name may be"
    );
    name
}

/// A name no other account of this test run has, whichever thread asks: this process's id and a
/// process-wide counter. An account left behind by an aborted earlier run with the same id makes
/// `NetUserAdd` fail with "user exists"; nothing is overwritten.
pub fn next_account_name(tag: &str) -> String {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    account_name(
        tag,
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
    )
}

/// How a service logged the account on: the logons whose hive Windows keeps loaded after the product's
/// `logout`, as it does for a user who logged in at the console.
/// A test says which one it started, and what it checks at the end of the session follows from it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceLogon {
    /// A Task Scheduler task with a stored password (`auto-login on`): a Batch logon, whose session
    /// Windows sometimes keeps although no process of it is left.
    TaskScheduler,
    /// sshd's logon of an SSH connection.
    Sshd,
}

impl std::fmt::Display for ServiceLogon {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ServiceLogon::TaskScheduler => "Task Scheduler",
            ServiceLogon::Sshd => "sshd",
        })
    }
}

/// A throwaway local account, removed (profile first) when dropped.
pub struct Account {
    pub name: String,
    pub password: String,
    pub sid: Sid,
    pub sid_text: String,
    pub profile: Option<PathBuf>,
    /// Set by the test that has a service log the account on, see [`Account::started_by`].
    service_logon: std::sync::OnceLock<ServiceLogon>,
}

impl Account {
    /// Create the account; with a profile, create the profile too (so `ProfileList` has an entry).
    /// `tag` (at most 5 characters) names what the account is for.
    pub fn create(tag: &str, with_profile: bool) -> Account {
        Account::create_with(tag, with_profile, USER_ACCOUNT_FLAGS(0))
    }

    /// [`Account::create`] with `flags` added to the account's flags (`UF_ACCOUNTDISABLE`, ...).
    pub fn create_with(tag: &str, with_profile: bool, flags: USER_ACCOUNT_FLAGS) -> Account {
        assert_elevated();
        let name = next_account_name(tag);
        // Not the account name itself, which the password policy refuses.
        let password = format!("Pw-{}-Aa1!", &name[2..]);
        Account::build(name, password, with_profile, flags)
    }

    /// An account with this exact `name` (a space, non-ASCII letters) and `password` (non-BMP
    /// characters). An existing account of that name fails the test; nothing is overwritten.
    pub fn create_named(name: &str, password: &str, with_profile: bool) -> Account {
        assert_elevated();
        Account::build(
            name.to_owned(),
            password.to_owned(),
            with_profile,
            USER_ACCOUNT_FLAGS(0),
        )
    }

    /// Change the account's password to `password`; [`Account::password`] follows.
    pub fn set_password(&mut self, password: &str) {
        let mut password_w = wide(password);
        let mut name_w = wide(&self.name);
        let info = USER_INFO_1003 {
            usri1003_password: PWSTR(password_w.as_mut_ptr()),
        };
        // SAFETY: `info` and the strings outlive the call.
        let rc = unsafe {
            NetUserSetInfo(
                PCWSTR::null(),
                PCWSTR(name_w.as_mut_ptr()),
                1003,
                &info as *const _ as *const u8,
                None,
            )
        };
        assert_eq!(rc, 0, "NetUserSetInfo({}) failed with {rc}", self.name);
        self.password = password.to_owned();
    }

    fn build(name: String, password: String, with_profile: bool, flags: USER_ACCOUNT_FLAGS) -> Account {
        let name_w = wide(&name);
        let mut password_w = wide(&password);
        let mut name_mut = name_w.clone();
        let info = USER_INFO_1 {
            usri1_name: PWSTR(name_mut.as_mut_ptr()),
            usri1_password: PWSTR(password_w.as_mut_ptr()),
            usri1_password_age: 0,
            usri1_priv: USER_PRIV_USER,
            usri1_home_dir: PWSTR::null(),
            usri1_comment: PWSTR::null(),
            usri1_flags: UF_SCRIPT | UF_DONT_EXPIRE_PASSWD | flags,
            usri1_script_path: PWSTR::null(),
        };
        // SAFETY: `info` and the strings it points at outlive the call.
        let rc = unsafe { NetUserAdd(PCWSTR::null(), 1, &info as *const _ as *const u8, None) };
        assert_eq!(rc, 0, "NetUserAdd({name}) failed with {rc}");

        let sid = Sid::lookup(&name).unwrap();
        let sid_text = sid.to_sddl().unwrap();
        let mut account = Account {
            name,
            password,
            sid,
            sid_text,
            profile: None,
            service_logon: std::sync::OnceLock::new(),
        };
        if with_profile {
            let mut buf = [0u16; 260];
            // SAFETY: NUL-terminated inputs; `buf` is the output buffer and its length.
            unsafe {
                CreateProfile(
                    PCWSTR(wide(&account.sid_text).as_ptr()),
                    PCWSTR(name_w.as_ptr()),
                    &mut buf,
                )
            }
            .expect("CreateProfile");
            let len = buf.iter().position(|&u| u == 0).unwrap();
            account.profile = Some(PathBuf::from(std::ffi::OsString::from_wide(&buf[..len])));
            // The tests type PowerShell into the shell, and ssh-broker's default shell is cmd.exe: the
            // account's user config names `pwsh`. A test that wants another shell writes its own.
            account.write_user_config("shell: pwsh.exe\n");
        }
        account
    }

    /// Replace the account's `.config\ssh-broker\config.yaml` (what the shim and the agent read for
    /// this account) with `yaml`. The account must have a profile.
    pub fn write_user_config(&self, yaml: &str) {
        let dir = self.profile().join(".config").join("ssh-broker");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("config.yaml"), yaml).unwrap();
    }

    /// Grant the account "Log on as a batch job" (`SeBatchLogonRight`), which Task Scheduler needs
    /// to run a password task for a standard user. Machine policy: CI only, and the right goes with
    /// the account when it is deleted.
    pub fn grant_batch_logon_right(&self) {
        use windows::Win32::Foundation::{HLOCAL, LocalFree};
        use windows::Win32::Security::Authentication::Identity::{
            LSA_OBJECT_ATTRIBUTES, LSA_UNICODE_STRING, LsaAddAccountRights, LsaClose, LsaNtStatusToWinError,
            LsaOpenPolicy,
        };
        use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
        use windows::Win32::Security::PSID;

        assert_elevated();
        let mut sid = PSID::default();
        // SAFETY: a NUL-terminated string and a valid out-pointer; the SID is freed below.
        unsafe { ConvertStringSidToSidW(PCWSTR(wide(&self.sid_text).as_ptr()), &mut sid) }.expect("the account's SID");
        let attributes = LSA_OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<LSA_OBJECT_ATTRIBUTES>() as u32,
            ..Default::default()
        };
        let mut policy = Default::default();
        // POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES
        // SAFETY: valid pointers for the call; the policy handle is closed below.
        let opened = unsafe { LsaOpenPolicy(None, &attributes, 16 | 2048, &mut policy) };
        assert_eq!(opened.0, 0, "LsaOpenPolicy: {opened:?}");
        let mut right = wide("SeBatchLogonRight");
        let units = (right.len() - 1) as u16;
        let rights = [LSA_UNICODE_STRING {
            Length: units * 2,
            MaximumLength: units * 2 + 2,
            Buffer: PWSTR(right.as_mut_ptr()),
        }];
        // SAFETY: valid pointers for the call.
        let added = unsafe { LsaAddAccountRights(policy, sid, &rights) };
        // SAFETY: the handles and the SID from above.
        unsafe {
            let _ = LsaClose(policy);
            let _ = LocalFree(Some(HLOCAL(sid.0)));
        }
        assert_eq!(
            added.0,
            0,
            "LsaAddAccountRights failed with win32 error {}",
            // SAFETY: a plain status conversion.
            unsafe { LsaNtStatusToWinError(added) }
        );
    }

    /// Make the account a member of the local Administrators group. It is removed with the account.
    /// The member is given by SID (level 0): a name needs the machine's own name as its domain, and
    /// `.` there is answered with `ERROR_NO_SUCH_MEMBER` (1387).
    pub fn make_administrator(&self) {
        use windows::Win32::Foundation::{HLOCAL, LocalFree};
        use windows::Win32::NetworkManagement::NetManagement::{LOCALGROUP_MEMBERS_INFO_0, NetLocalGroupAddMembers};
        use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
        use windows::Win32::Security::PSID;

        assert_elevated();
        let mut sid = PSID::default();
        // SAFETY: a NUL-terminated string and a valid out-pointer; the SID is freed below.
        unsafe { ConvertStringSidToSidW(PCWSTR(wide(&self.sid_text).as_ptr()), &mut sid) }.expect("the account's SID");
        let info = LOCALGROUP_MEMBERS_INFO_0 { lgrmi0_sid: sid };
        // SAFETY: `info` and the SID it points at outlive the call.
        let rc = unsafe {
            NetLocalGroupAddMembers(
                PCWSTR::null(),
                PCWSTR(wide("Administrators").as_ptr()),
                0,
                &info as *const _ as *const u8,
                1,
            )
        };
        // SAFETY: the SID from above.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(sid.0)));
        }
        assert_eq!(rc, 0, "NetLocalGroupAddMembers({}) failed with {rc}", self.name);
    }

    /// The token sshd's key-authenticated logon gives: a network logon, no loaded profile.
    pub fn network_token(&self) -> OwnedHandle {
        let mut token = HANDLE::default();
        // SAFETY: NUL-terminated inputs, a valid out-pointer.
        unsafe {
            LogonUserW(
                PCWSTR(wide(&self.name).as_ptr()),
                PCWSTR(wide(".").as_ptr()),
                PCWSTR(wide(&self.password).as_ptr()),
                LOGON32_LOGON_NETWORK,
                LOGON32_PROVIDER_DEFAULT,
                &mut token,
            )
        }
        .unwrap_or_else(|e| panic!("LogonUser({}) failed: {e}", self.name));
        OwnedHandle(token)
    }

    /// Say that the test has `how` log the account on. The account's teardown then does not require the
    /// profile to be deletable (see [`profile::remove_or_clear`]). An account the test logs on by secondary
    /// logon (`run`, `spawn_with`, the prompt path) is not declared: Windows releases those.
    pub fn started_by(&self, how: ServiceLogon) {
        let declared = self.service_logon.get_or_init(|| how);
        assert_eq!(
            *declared, how,
            "{} was declared as logged on by {declared} and now by {how}",
            self.name
        );
    }

    /// How a service logged the account on, if the test said so.
    pub fn service_logon(&self) -> Option<ServiceLogon> {
        self.service_logon.get().copied()
    }

    /// The profile folder, if the account was made with one.
    pub fn try_profile(&self) -> Option<&Path> {
        self.profile.as_deref()
    }

    /// The profile `CreateProfile` made. Panics for an account made without one.
    pub fn profile(&self) -> &Path {
        self.profile.as_deref().expect("this account has no profile")
    }

    /// [`Account::run_with`] without loading the account's profile and with the environment the
    /// system makes for the account.
    pub fn run(&self, exe: &Path, command_line: &str, cwd: &Path, evidence: &[PathBuf]) -> u32 {
        self.run_with(exe, command_line, cwd, evidence, CREATE_PROCESS_LOGON_FLAGS(0), None)
    }

    /// Run `exe` with `command_line` under this account's network-logon token, the way sshd runs
    /// its shell, on a window station and desktop made for this one child (see [`desktop`]).
    /// `logon_flags` is `CreateProcessWithTokenW`'s `dwLogonFlags`: without [`LOGON_WITH_PROFILE`]
    /// the account's registry hive is not loaded. `environment` is a block from [`environment`]
    /// to pass as is; without one the system makes the account's, with `USERPROFILE=C:\Users\Default`
    /// unless the profile is loaded. Returns the exit code. A loader failure of the child ends it
    /// with its NTSTATUS as the exit code (see [`hard_errors`]) rather than a message box. A child
    /// still running after [`crate::bounded_wait::CHILD_EXIT_BOUND`] fails the test with the process tree,
    /// this account's ssh-broker folder and `evidence` printed, and is killed.
    pub fn run_with(
        &self,
        exe: &Path,
        command_line: &str,
        cwd: &Path,
        evidence: &[PathBuf],
        logon_flags: CREATE_PROCESS_LOGON_FLAGS,
        environment: Option<&[u16]>,
    ) -> u32 {
        let child = self.spawn_with(exe, command_line, cwd, evidence, logon_flags, environment);
        child.resume();
        child.wait()
    }

    /// [`Account::run_with`] up to the child's first instruction: the child is returned suspended,
    /// so the caller can put it in a job first. [`Spawned::resume`] starts it and [`Spawned::wait`]
    /// is the bounded wait for its exit.
    pub fn spawn_with(
        &self,
        exe: &Path,
        command_line: &str,
        cwd: &Path,
        evidence: &[PathBuf],
        logon_flags: CREATE_PROCESS_LOGON_FLAGS,
        environment: Option<&[u16]>,
    ) -> Spawned {
        self.spawn_with_stdio(exe, command_line, cwd, evidence, logon_flags, environment, None)
    }

    /// [`Account::spawn_with`] with the child's standard handles (input, output, error) given. They
    /// must be inheritable; the secondary logon service copies them into the child.
    #[allow(clippy::too_many_arguments)]
    pub fn spawn_with_stdio(
        &self,
        exe: &Path,
        command_line: &str,
        cwd: &Path,
        evidence: &[PathBuf],
        logon_flags: CREATE_PROCESS_LOGON_FLAGS,
        environment: Option<&[u16]>,
        stdio: Option<[HANDLE; 3]>,
    ) -> Spawned {
        self.spawn_inner(
            Starter::SecondaryLogon(logon_flags),
            exe,
            command_line,
            cwd,
            evidence,
            environment,
            stdio,
        )
    }

    /// [`Account::spawn_with`] the way sshd starts a session's shell: `CreateProcessAsUserW` from a
    /// service that holds `SeAssignPrimaryTokenPrivilege`, with no Secondary Logon service between, so
    /// the child's chain of jobs is the caller's and nothing else. Only a SYSTEM process may call it
    /// (the M3 cases run as one, see [`Starter::AsUser`]); anything else fails the test at the call.
    /// The child gets this process's environment.
    pub fn spawn_as_service(&self, exe: &Path, command_line: &str, cwd: &Path, evidence: &[PathBuf]) -> Spawned {
        self.spawn_inner(Starter::AsUser, exe, command_line, cwd, evidence, None, None)
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_inner(
        &self,
        starter_kind: Starter,
        exe: &Path,
        command_line: &str,
        cwd: &Path,
        evidence: &[PathBuf],
        environment: Option<&[u16]>,
        stdio: Option<[HANDLE; 3]>,
    ) -> Spawned {
        ssh_broker::ctrl_flag_spike::record(&format!("test process, before spawning {}", exe.display()));
        // The account's SID and the administrator's: the child runs as the first and is started by
        // the second.
        let starter = Sid::current_user().unwrap().to_sddl().unwrap();
        let private = crate::desktop::PrivateDesktop::create(&[&self.sid_text, &starter])
            .unwrap_or_else(|e| panic!("create a window station and desktop for {}: {e}", self.name));

        let network = self.network_token();
        let mut primary = HANDLE::default();
        // SAFETY: valid in/out handles.
        unsafe {
            DuplicateTokenEx(
                network.0,
                TOKEN_ALL_ACCESS,
                None,
                SecurityImpersonation,
                TokenPrimary,
                &mut primary,
            )
        }
        .expect("duplicate the token as a primary token");
        let primary = OwnedHandle(primary);

        let mut command = wide(command_line);
        let mut station_and_desktop = wide(private.name());
        let mut startup = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            lpDesktop: PWSTR(station_and_desktop.as_mut_ptr()),
            ..Default::default()
        };
        if let Some([input, output, error]) = stdio {
            startup.dwFlags = STARTF_USESTDHANDLES;
            startup.hStdInput = input;
            startup.hStdOutput = output;
            startup.hStdError = error;
        }
        let mut flags = CREATE_SUSPENDED | CREATE_NO_WINDOW;
        if environment.is_some() {
            flags |= CREATE_UNICODE_ENVIRONMENT;
        }
        let mut info = PROCESS_INFORMATION::default();
        let exe_w = wide(&exe.to_string_lossy());
        let cwd_w = wide(&cwd.to_string_lossy());
        let environment = environment.map(|block| block.as_ptr().cast::<core::ffi::c_void>());
        // SAFETY: every pointer is to a local that outlives the call.
        match starter_kind {
            Starter::SecondaryLogon(logon_flags) => unsafe {
                CreateProcessWithTokenW(
                    primary.0,
                    logon_flags,
                    PCWSTR(exe_w.as_ptr()),
                    Some(PWSTR(command.as_mut_ptr())),
                    flags,
                    environment,
                    PCWSTR(cwd_w.as_ptr()),
                    &startup,
                    &mut info,
                )
            },
            Starter::AsUser => unsafe {
                CreateProcessAsUserW(
                    Some(primary.0),
                    PCWSTR(exe_w.as_ptr()),
                    Some(PWSTR(command.as_mut_ptr())),
                    None,
                    None,
                    stdio.is_some(),
                    flags,
                    environment,
                    PCWSTR(cwd_w.as_ptr()),
                    &startup,
                    &mut info,
                )
            },
        }
        .unwrap_or_else(|e| panic!("start {exe:?} as {} ({starter_kind:?}): {e}", self.name));
        let process = OwnedHandle(info.hProcess);
        let thread = OwnedHandle(info.hThread);
        // Before its first instruction: a loader failure then ends the process, with the failing
        // status as its exit code, instead of waiting on a message box that nobody can answer.
        if let Err(e) = crate::hard_errors::suppress_hard_error_boxes(process.0) {
            // SAFETY: the handle is the live process this function just created.
            let _ = unsafe { TerminateProcess(process.0, 1) };
            panic!("switch off the hard-error boxes of {exe:?} as {}: {e}", self.name);
        }
        let mut evidence = evidence.to_vec();
        if let Some(profile) = &self.profile {
            evidence.push(profile.join("AppData").join("Local").join("ssh-broker"));
        }
        Spawned {
            process,
            thread,
            pid: info.dwProcessId,
            what: format!("{exe:?} as {}", self.name),
            evidence,
            _desktop: private,
        }
    }
}

/// The call that starts a child as an account.
#[derive(Clone, Copy, Debug)]
pub enum Starter {
    /// `CreateProcessWithTokenW` with these `dwLogonFlags`: the Secondary Logon service starts the child,
    /// and puts it in a job of its own besides the caller's.
    SecondaryLogon(CREATE_PROCESS_LOGON_FLAGS),
    /// `CreateProcessAsUserW` from this process, which must hold `SeAssignPrimaryTokenPrivilege` (a SYSTEM
    /// process does): what sshd, a service, does.
    AsUser,
}

/// A child started suspended by [`Account::spawn_with`]. Its window station and desktop live as long
/// as this does.
pub struct Spawned {
    pub process: OwnedHandle,
    thread: OwnedHandle,
    pub pid: u32,
    what: String,
    evidence: Vec<PathBuf>,
    _desktop: crate::desktop::PrivateDesktop,
}

impl Spawned {
    /// Start the child.
    pub fn resume(&self) {
        // SAFETY: the handle is the primary thread of the process just created.
        if unsafe { ResumeThread(self.thread.0) } == u32::MAX {
            // SAFETY: as above.
            let _ = unsafe { TerminateProcess(self.process.0, 1) };
            panic!("resume {}: {}", self.what, windows::core::Error::from_thread());
        }
    }

    /// Wait for the child to exit and return its exit code. A child still running after
    /// [`crate::bounded_wait::CHILD_EXIT_BOUND`] fails the test with the process tree and the
    /// evidence printed, and is killed.
    pub fn wait(&self) -> u32 {
        crate::bounded_wait::wait_for_exit(
            self.process.0,
            self.pid,
            &self.what,
            crate::bounded_wait::CHILD_EXIT_BOUND,
            &self.evidence,
        )
    }
}

impl Drop for Account {
    fn drop(&mut self) {
        // Nothing the account started may outlive its test: a background session holds the profile
        // and the socket, and the next test's logons share the machine.
        let left = crate::process_list::terminate_processes_of(&self.sid_text);
        if !left.is_empty() {
            eprintln!("processes of {} that could not be ended: {left:?}", self.name);
        }
        // Always, not only for an account made with a profile: a logon with `LOGON_WITH_PROFILE` makes the
        // profile of an account that had none. After a secondary logon the system unloads the profile a moment
        // after the account's last process has exited, so this waits for that (a delete right after the exit
        // fails with "in use" and leaves the profile, about 1.3 GB). After a service's logon
        // Windows keeps the hive loaded (see `profile`), so there the profile is deleted if Windows allows it,
        // and else cleared of what can be deleted.
        let removed = match self.service_logon.get() {
            None => profile::remove(&self.sid_text).map(|()| None),
            Some(how) => profile::remove_or_clear(&self.sid_text, self.profile.as_deref()).map(|r| Some((*how, r))),
        };
        // Measured before the account is deleted, while whatever holds the profile still does. A hive that stays
        // loaded is not unloaded by hand: `RegUnLoadKey` is refused. A test ends a background
        // session with its `logout` first (see `session_end`), which is what lets the system unload the hive
        // of a secondary logon.
        let holders = removed.as_ref().err().map(|_| {
            format!(
                "ProfileList: {}\n{}",
                hive::profile_list(&self.sid_text),
                holders::report(&self.sid_text)
            )
        });
        // SAFETY: NUL-terminated inputs.
        let deletion = unsafe { NetUserDel(PCWSTR::null(), PCWSTR(wide(&self.name).as_ptr())) };
        let account_left = (deletion != 0).then(|| {
            format!(
                "the account {} stays on the machine: NetUserDel returned {deletion}",
                self.name
            )
        });
        if let (Ok(Some((how, removal))), None) = (&removed, &account_left) {
            hive::record(&format!(
                "session end [account removed] {} ({}), logged on by {how}: {removal}; the account is deleted",
                self.name, self.sid_text
            ));
        }
        let mut problems = Vec::new();
        if let Err(why) = removed {
            problems.push(format!(
                "the profile of {} ({}) was not deleted and stays on the disk: {why}. Processes of the account that \
                 could not be ended: {left:?}. A handle this test process still holds on a process of the account \
                 also keeps its logon session, and so its profile, in use.\n{}",
                self.name,
                self.sid_text,
                holders.unwrap_or_default()
            ));
        }
        problems.extend(account_left);
        if !problems.is_empty() {
            let message = problems.join("\n");
            // A panic while unwinding would abort the test process.
            if std::thread::panicking() {
                eprintln!("{message}");
            } else {
                panic!("{message}");
            }
        }
    }
}

/// A fresh directory under the temp dir, removed on drop, that every account can read, run from
/// and write to: the place the test binary copy and its result files live.
pub struct SharedDir(pub PathBuf);

impl SharedDir {
    /// The directory, readable and writable by everyone.
    pub fn new(tag: &str) -> SharedDir {
        let shared = SharedDir::without_grant(tag);
        let status = crate::desktop::status(
            Command::new("icacls")
                .arg(&shared.0)
                .args(["/grant", "*S-1-1-0:(OI)(CI)M"]),
        )
        .unwrap();
        assert!(status.success(), "icacls on the shared directory");
        shared
    }

    /// The directory as the temp dir makes it: for a child that runs as this account.
    pub fn without_grant(tag: &str) -> SharedDir {
        let dir = std::env::temp_dir().join(format!("sb-iso-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        SharedDir(dir)
    }
}

impl Drop for SharedDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
