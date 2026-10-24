//! One account cannot reach another account's agent. Windows only; **Elevated (CI only)**.
//!
//! These tests create throwaway local accounts and profiles, log them on the way sshd does (a
//! network logon, which has no loaded profile), and start processes under those tokens. They need
//! an elevated administrator and refuse to run anywhere else, before they touch anything: run
//! them in CI, never on a workstation. The acceptance procedure repeats the central cases through
//! a real sshd.
//!
//! The central property: the shim derives its socket from its own token's profile and from
//! nothing else, and the socket file grants connect access to exactly its user, SYSTEM and
//! Administrators. So an administrator who SSHes in as bob lands in bob's session or in a local
//! shell, never in another user's.
#![cfg(windows)]

use std::os::windows::ffi::OsStringExt;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;

use ssh_broker::acl::{self, Sid};
use ssh_broker::afunix::{self, Listener};
use ssh_broker::agent_lock::{SessionSlot, UserLock};
use ssh_broker::socket_loc::SocketLocation;
use ssh_broker::userdir;
use ssh_broker::winutil::OwnedHandle;
use windows::Win32::Foundation::{HANDLE, HLOCAL, LocalFree};
use windows::Win32::NetworkManagement::NetManagement::{
    NetUserAdd, NetUserDel, UF_DONT_EXPIRE_PASSWD, UF_SCRIPT, USER_INFO_1, USER_PRIV_USER,
};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    GetNamedSecurityInfoW, SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, DuplicateTokenEx, GetSecurityDescriptorDacl, GetTokenInformation,
    LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, LogonUserW, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, SecurityImpersonation, SetTokenInformation, TOKEN_ALL_ACCESS, TOKEN_DEFAULT_DACL,
    TOKEN_DUPLICATE, TOKEN_ELEVATION, TOKEN_QUERY, TokenDefaultDacl, TokenElevation, TokenImpersonation, TokenPrimary,
};
use windows::Win32::System::LibraryLoader::LoadLibraryW;
use windows::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_PROCESS_LOGON_FLAGS, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
    CreateProcessWithTokenW, GetCurrentProcess, LOGON_WITH_PROFILE, OpenProcessToken, PROCESS_INFORMATION,
    ResumeThread, STARTUPINFOW, SetThreadToken, TerminateProcess,
};
use windows::Win32::UI::Shell::{CreateProfile, DeleteProfileW};
use windows::core::{BOOL, PCWSTR, PWSTR};

#[path = "common/bounded_wait.rs"]
mod bounded_wait;
#[path = "common/child_entry.rs"]
mod child_entry;
#[path = "common/desktop.rs"]
mod desktop;
#[path = "common/environment.rs"]
mod environment;
#[path = "common/hard_errors.rs"]
mod hard_errors;
#[path = "common/process_list.rs"]
mod process_list;

// Fixture ---------------------------------------------------------------------------------

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Fail loudly unless this process is an elevated administrator.
fn assert_elevated() {
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
fn account_name(tag: &str, pid: u32, n: u32) -> String {
    let name = format!("sb{tag}{pid:x}_{n:x}");
    assert!(
        name.chars().count() <= 20,
        "{name} is longer than an account name may be"
    );
    name
}

/// A name no other account of this test run has, whichever thread asks: this process's id and a
/// process-wide counter. (Across runs, ids are not reused while an account of the earlier run is
/// still there, since a run removes its accounts when it ends.)
fn next_account_name(tag: &str) -> String {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    account_name(
        tag,
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
    )
}

/// A throwaway local account, removed (profile first) when dropped.
struct Account {
    name: String,
    password: String,
    sid: Sid,
    sid_text: String,
    profile: Option<PathBuf>,
}

impl Account {
    /// Create the account; with a profile, create the profile too (so `ProfileList` has an entry).
    /// `tag` (at most 5 characters) names what the account is for.
    fn create(tag: &str, with_profile: bool) -> Account {
        assert_elevated();
        let name = next_account_name(tag);
        // Not the account name itself, which the password policy refuses.
        let password = format!("Pw-{}-Aa1!", &name[2..]);
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
            usri1_flags: UF_SCRIPT | UF_DONT_EXPIRE_PASSWD,
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
        }
        account
    }

    /// The token sshd's key-authenticated logon gives: a network logon, no loaded profile.
    fn network_token(&self) -> OwnedHandle {
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

    /// The profile `CreateProfile` made. Panics for an account made without one.
    fn profile(&self) -> &Path {
        self.profile.as_deref().expect("this account has no profile")
    }

    /// [`Account::run_with`] without loading the account's profile and with the environment the
    /// system makes for the account.
    fn run(&self, exe: &Path, command_line: &str, cwd: &Path, evidence: &[PathBuf]) -> u32 {
        self.run_with(exe, command_line, cwd, evidence, CREATE_PROCESS_LOGON_FLAGS(0), None)
    }

    /// Run `exe` with `command_line` under this account's network-logon token, the way sshd runs
    /// its shell, on a window station and desktop made for this one child (see [`desktop`]).
    /// `logon_flags` is `CreateProcessWithTokenW`'s `dwLogonFlags`: without [`LOGON_WITH_PROFILE`]
    /// the account's registry hive is not loaded. `environment` is a block from [`environment`]
    /// to pass as is; without one the system makes the account's, with `USERPROFILE=C:\Users\Default`
    /// unless the profile is loaded. Returns the exit code. A loader failure of the child ends it
    /// with its NTSTATUS as the exit code (see [`hard_errors`]) rather than a message box. A child
    /// still running after [`bounded_wait::CHILD_EXIT_BOUND`] fails the test with the process tree,
    /// this account's ssh-broker folder and `evidence` printed, and is killed.
    fn run_with(
        &self,
        exe: &Path,
        command_line: &str,
        cwd: &Path,
        evidence: &[PathBuf],
        logon_flags: CREATE_PROCESS_LOGON_FLAGS,
        environment: Option<&[u16]>,
    ) -> u32 {
        // The account's SID and the administrator's: the child runs as the first and is started by
        // the second.
        let starter = Sid::current_user().unwrap().to_sddl().unwrap();
        let private = desktop::PrivateDesktop::create(&[&self.sid_text, &starter])
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
        let startup = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            lpDesktop: PWSTR(station_and_desktop.as_mut_ptr()),
            ..Default::default()
        };
        let mut flags = CREATE_SUSPENDED | CREATE_NO_WINDOW;
        if environment.is_some() {
            flags |= CREATE_UNICODE_ENVIRONMENT;
        }
        let mut info = PROCESS_INFORMATION::default();
        // SAFETY: every pointer is to a local that outlives the call.
        unsafe {
            CreateProcessWithTokenW(
                primary.0,
                logon_flags,
                PCWSTR(wide(&exe.to_string_lossy()).as_ptr()),
                Some(PWSTR(command.as_mut_ptr())),
                flags,
                environment.map(|block| block.as_ptr().cast::<core::ffi::c_void>()),
                PCWSTR(wide(&cwd.to_string_lossy()).as_ptr()),
                &startup,
                &mut info,
            )
        }
        .unwrap_or_else(|e| panic!("start {exe:?} as {}: {e}", self.name));
        let process = OwnedHandle(info.hProcess);
        let thread = OwnedHandle(info.hThread);
        // Before its first instruction: a loader failure then ends the process, with the failing
        // status as its exit code, instead of waiting on a message box that nobody can answer.
        if let Err(e) = hard_errors::suppress_hard_error_boxes(process.0) {
            // SAFETY: the handle is the live process this function just created.
            let _ = unsafe { TerminateProcess(process.0, 1) };
            panic!("switch off the hard-error boxes of {exe:?} as {}: {e}", self.name);
        }
        // SAFETY: the handle is the primary thread of the process just created.
        if unsafe { ResumeThread(thread.0) } == u32::MAX {
            // SAFETY: as above.
            let _ = unsafe { TerminateProcess(process.0, 1) };
            panic!(
                "resume {exe:?} as {}: {}",
                self.name,
                windows::core::Error::from_thread()
            );
        }
        let mut evidence = evidence.to_vec();
        if let Some(profile) = &self.profile {
            evidence.push(profile.join("AppData").join("Local").join("ssh-broker"));
        }
        let what = format!("{exe:?} as {}", self.name);
        bounded_wait::wait_for_exit(
            process.0,
            info.dwProcessId,
            &what,
            bounded_wait::CHILD_EXIT_BOUND,
            &evidence,
        )
    }
}

impl Drop for Account {
    fn drop(&mut self) {
        // SAFETY: NUL-terminated inputs.
        unsafe {
            if self.profile.is_some() {
                let _ = DeleteProfileW(PCWSTR(wide(&self.sid_text).as_ptr()), PCWSTR::null(), PCWSTR::null());
            }
            let _ = NetUserDel(PCWSTR::null(), PCWSTR(wide(&self.name).as_ptr()));
        }
    }
}

/// A fresh directory under the temp dir, removed on drop, that every account can read, run from
/// and write to: the place the test binary copy and its result files live.
struct SharedDir(PathBuf);

impl SharedDir {
    /// The directory, readable and writable by everyone.
    fn new(tag: &str) -> SharedDir {
        let shared = SharedDir::without_grant(tag);
        let status = desktop::status(
            Command::new("icacls")
                .arg(&shared.0)
                .args(["/grant", "*S-1-1-0:(OI)(CI)M"]),
        )
        .unwrap();
        assert!(status.success(), "icacls on the shared directory");
        shared
    }

    /// The directory as the temp dir makes it: for a child that runs as this account.
    fn without_grant(tag: &str) -> SharedDir {
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

/// What `icacls` prints for `path`, for an assertion message.
fn icacls_report(path: &Path) -> String {
    match desktop::output(Command::new("icacls").arg(path)) {
        Ok(out) => String::from_utf8_lossy(&out.stdout).trim().to_owned(),
        Err(e) => format!("icacls did not run: {e}"),
    }
}

/// The DACL of `path` as SDDL, read through the security API (an inherited ACE carries `ID`, an
/// ACE that passes access down `OI` or `CI`), for an assertion message and for the precondition
/// of the control test.
fn dacl_sddl(path: &Path) -> String {
    let path_w = wide(&path.to_string_lossy());
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: NUL-terminated path, valid out-pointers; both allocations are freed below.
    unsafe {
        let rc = GetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            &mut sd,
        );
        if let Err(e) = rc.ok() {
            return format!("(cannot read the DACL: {e})");
        }
        let mut text = PWSTR::null();
        let converted =
            ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, 1, DACL_SECURITY_INFORMATION, &mut text, None);
        let out = match converted {
            Ok(()) => text.to_string().unwrap_or_else(|e| format!("(not UTF-16: {e})")),
            Err(e) => format!("(cannot convert the DACL: {e})"),
        };
        let _ = LocalFree(Some(HLOCAL(text.0.cast())));
        let _ = LocalFree(Some(HLOCAL(sd.0)));
        out
    }
}

/// Whether the DACL in `sddl` is protected, and none of its ACEs is inherited or passes access to
/// children (flags `ID`, `OI`, `CI`, `IO`, `NP`).
fn passes_nothing_down(sddl: &str) -> bool {
    let Some(dacl) = sddl.strip_prefix("D:") else {
        return false;
    };
    let Some((header, aces)) = dacl.split_once('(') else {
        return false;
    };
    // Protected, and not auto-inherited (`AI` is harmless but `AR` asks for inheritance).
    if !header.contains('P') || header.contains("AR") {
        return false;
    }
    format!("({aces}")
        .split(')')
        .filter(|ace| !ace.is_empty())
        .all(|ace| ace.trim_start_matches('(').split(';').nth(1).is_some_and(str::is_empty))
}

/// Give `dir` a protected DACL of exactly `user`, SYSTEM and Administrators with Full Control,
/// each ACE without inheritance flags: nothing is inherited into it and nothing passes down. Set
/// through the security API, so no tool's reading of "remove inheritance" is involved.
fn set_plain_protected_dacl(dir: &Path, user: &Sid) {
    let sddl = wide(&format!(
        "D:P(A;;FA;;;{})(A;;FA;;;SY)(A;;FA;;;BA)",
        user.to_sddl().unwrap()
    ));
    let dir_w = wide(&dir.to_string_lossy());
    // SAFETY: NUL-terminated inputs; the descriptor outlives the call and is freed after it.
    unsafe {
        let mut sd = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(sddl.as_ptr()), 1, &mut sd, None).unwrap();
        let (mut present, mut defaulted) = (BOOL(0), BOOL(0));
        let mut dacl: *mut ACL = std::ptr::null_mut();
        GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted).unwrap();
        let rc = SetNamedSecurityInfoW(
            PCWSTR(dir_w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl as *const ACL),
            None,
        );
        let _ = LocalFree(Some(HLOCAL(sd.0)));
        rc.ok().unwrap();
    }
}

/// A stand-in profile (`AppData\Local` exists) owned by the administrator running the test.
struct StandInProfile(PathBuf);

impl StandInProfile {
    fn new(tag: &str) -> StandInProfile {
        let root = std::env::temp_dir().join(format!("sb-iso-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("AppData").join("Local")).unwrap();
        StandInProfile(root)
    }

    fn location(&self) -> SocketLocation {
        ssh_broker::socket_loc::for_profile(&self.0).expect("the stand-in profile path is short enough")
    }
}

impl Drop for StandInProfile {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Run `f` on this thread with a token whose default DACL grants Everyone full control. Anything
/// created without an explicit or inherited DACL while it runs is world-accessible, so a socket
/// that is NOT world-accessible got that from the directory it was made in and from nothing else.
fn with_permissive_default_dacl<T>(f: impl FnOnce() -> T) -> T {
    let mut process = HANDLE::default();
    // SAFETY: valid out-pointers; every handle is closed by `OwnedHandle`; the descriptor and
    // ACL stay alive until after `SetTokenInformation` has copied them.
    unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &mut process).unwrap();
        let process = OwnedHandle(process);
        let mut copy = HANDLE::default();
        DuplicateTokenEx(
            process.0,
            TOKEN_ALL_ACCESS,
            None,
            SecurityImpersonation,
            TokenImpersonation,
            &mut copy,
        )
        .unwrap();
        let copy = OwnedHandle(copy);

        let mut sd = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(wide("D:(A;;GA;;;WD)").as_ptr()),
            1, // SDDL_REVISION_1
            &mut sd,
            None,
        )
        .unwrap();
        let (mut present, mut defaulted) = (BOOL(0), BOOL(0));
        let mut dacl: *mut ACL = std::ptr::null_mut();
        GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted).unwrap();
        let default_dacl = TOKEN_DEFAULT_DACL { DefaultDacl: dacl };
        SetTokenInformation(
            copy.0,
            TokenDefaultDacl,
            &default_dacl as *const _ as *const core::ffi::c_void,
            std::mem::size_of::<TOKEN_DEFAULT_DACL>() as u32,
        )
        .unwrap();

        SetThreadToken(None, Some(copy.0)).unwrap();
        let out = f();
        SetThreadToken(None, None).unwrap();
        out
    }
}

// Where the shim looks ---------------------------------------------------------------------

#[test]
fn network_logon_token_resolves_its_own_profile_socket() {
    // The measurement for the sshd case: a network logon has no loaded profile hive, and the
    // profile must still resolve from the ProfileList key.
    let bob = Account::create("bob", true);
    let token = bob.network_token();

    let loc = userdir::socket_location_of_token(token.0).unwrap();

    let expected = bob.profile().join("AppData").join("Local").join("ssh-broker");
    assert_eq!(
        loc.dir.to_string_lossy().to_lowercase(),
        expected.to_string_lossy().to_lowercase()
    );
    assert!(loc.path.ends_with("agent.sock"));
}

#[test]
fn an_admin_ssh_session_as_bob_resolves_bobs_socket_not_the_admins() {
    let alice = Account::create("alice", true);
    let bob = Account::create("bob", true);

    let from_bob = userdir::socket_location_of_token(bob.network_token().0).unwrap();
    let from_alice = userdir::socket_location_of_token(alice.network_token().0).unwrap();
    let admin = userdir::current_socket_location().unwrap();

    // Nothing in the call takes a path or an account name: the token is the only input.
    assert_ne!(from_bob, admin, "bob's session must not use the administrator's socket");
    assert_ne!(from_bob, from_alice, "bob's session must not use alice's socket");
    assert!(from_bob.path.starts_with(bob.profile()));
}

#[test]
fn a_user_with_no_profile_has_no_socket_location() {
    let nobody = Account::create("nop", false);
    let token = nobody.network_token();
    let err = userdir::socket_location_of_token(token.0).unwrap_err();
    assert!(
        !format!("{err:#}").is_empty(),
        "the shim reports this reason and fails open"
    );
}

// Who can connect --------------------------------------------------------------------------

#[test]
fn a_permissive_default_dacl_is_in_effect_where_nothing_is_inherited() {
    // The control for the next test: without inheritable ACEs the socket file would take the
    // creator's default DACL, which here is world-accessible.
    let me = Sid::current_user().unwrap();
    let dir = StandInProfile::new("control");
    let plain = dir.0.join("plain");
    std::fs::create_dir(&plain).unwrap();
    // Protected, with ACEs that do not propagate. `icacls` is not used: a runner's temporary
    // directory left inheritable ACEs on the result, so the precondition is read back.
    set_plain_protected_dacl(&plain, &me);
    let plain_dacl = dacl_sddl(&plain);
    assert!(
        passes_nothing_down(&plain_dacl),
        "the control directory must inherit nothing and pass nothing down: {plain_dacl}\n{}",
        icacls_report(&plain)
    );

    let file = plain.join("born.txt");
    with_permissive_default_dacl(|| std::fs::write(&file, "x").unwrap());

    let exact = acl::verify_file_acl(&file, &me).unwrap();
    let report = format!(
        "the file: {}\nits DACL: {}\nits directory: {}\nits DACL: {}",
        icacls_report(&file),
        dacl_sddl(&file),
        icacls_report(&plain),
        dacl_sddl(&plain)
    );
    assert!(
        !exact,
        "a file made under a permissive default DACL, in a directory that passes nothing down, is not exact\n{report}"
    );
}

#[test]
fn a_creator_whose_default_dacl_is_world_accessible_still_gets_an_exact_socket_and_lock() {
    // Needs no second account, so it also runs unelevated. It pins the isolating case: the dir's
    // inheritable ACEs, and nothing else, keep the socket file and the lock file private.
    let me = Sid::current_user().unwrap();
    let profile = StandInProfile::new("permissive");
    let loc = profile.location();

    with_permissive_default_dacl(|| {
        userdir::ensure_socket_dir(&loc, &me).unwrap();
        let _lock = UserLock::try_acquire(&loc.lock_path()).unwrap().unwrap();
        let _slot = SessionSlot::try_acquire(&loc.session_lock_path(1)).unwrap().unwrap();
        let _listener = Listener::bind(&loc.path).unwrap();

        assert!(acl::verify_file_acl(&loc.path, &me).unwrap(), "agent.sock");
        assert!(acl::verify_file_acl(&loc.lock_path(), &me).unwrap(), "agent.lock");
        assert!(
            acl::verify_file_acl(&loc.session_lock_path(1), &me).unwrap(),
            "session slot"
        );
        assert!(acl::verify_file_acl(&loc.logs_dir(), &me).unwrap(), "logs");
    });
}

#[test]
fn each_users_socket_dir_acl_is_exact() {
    let bob = Account::create("bob", false);
    let admin = Sid::current_user().unwrap();
    let profile = StandInProfile::new("exact");
    let loc = profile.location();

    with_permissive_default_dacl(|| {
        userdir::ensure_socket_dir(&loc, &admin).unwrap();
        let _lock = UserLock::try_acquire(&loc.lock_path()).unwrap().unwrap();
        let _slot = SessionSlot::try_acquire(&loc.session_lock_path(1)).unwrap().unwrap();
        let _listener = Listener::bind(&loc.path).unwrap();

        assert!(acl::verify_dir_acl(&loc.dir, &admin).unwrap());
        assert!(
            !acl::verify_dir_acl(&loc.dir, &bob.sid).unwrap(),
            "the dir is not bob's"
        );
        // Born with exactly the three, although the creating token would have let everyone in.
        assert!(acl::verify_file_acl(&loc.path, &admin).unwrap(), "agent.sock");
        assert!(acl::verify_file_acl(&loc.lock_path(), &admin).unwrap(), "agent.lock");
        assert!(
            acl::verify_file_acl(&loc.session_lock_path(1), &admin).unwrap(),
            "session slot"
        );
        assert!(!acl::verify_file_acl(&loc.path, &bob.sid).unwrap());
        assert!(
            !acl::verify_file_acl(&loc.session_lock_path(1), &bob.sid).unwrap(),
            "the session slot is not bob's"
        );
    });
}

#[test]
fn ensure_socket_dir_refuses_a_dir_owned_by_another_user() {
    let bob = Account::create("bob", false);
    let admin = Sid::current_user().unwrap();
    let profile = StandInProfile::new("foreign");
    let loc = profile.location();
    std::fs::create_dir(&loc.dir).unwrap();
    let status = desktop::status(
        Command::new("icacls")
            .arg(&loc.dir)
            .args(["/setowner", &format!("*{}", bob.sid_text)]),
    )
    .unwrap();
    assert!(status.success(), "icacls /setowner");

    let err = format!("{:#}", userdir::ensure_socket_dir(&loc, &admin).unwrap_err());

    assert!(err.contains("owner"), "{err}");
    assert!(
        !loc.logs_dir().exists(),
        "nothing was created inside a directory that is not ours"
    );
}

/// What [`child_connects_only_where_it_was_granted`] records once its checks have passed.
const CONNECT_RESULT: &str = "connected to the control socket\nrefused the other socket: access denied\n";

/// Child half of [`bob_cannot_connect_to_a_socket_in_another_users_dir`], started only by it as
/// bob (see [`child_entry`]). Connects where it was given a grant, is refused where it was not,
/// and only then records [`CONNECT_RESULT`].
#[test]
#[ignore = "run as a child of bob_cannot_connect_to_a_socket_in_another_users_dir"]
fn child_connects_only_where_it_was_granted() {
    let dir = child_entry::dir();
    let text = child_entry::input(&dir);
    let path_after = |key: &str| {
        PathBuf::from(
            text.lines()
                .find_map(|l| l.strip_prefix(key))
                .unwrap_or_else(|| panic!("the child's input has no {key}")),
        )
    };
    let allowed = path_after("allowed=");
    let denied = path_after("denied=");

    afunix::connect(&allowed).unwrap_or_else(|e| panic!("the control socket must be reachable: {e:#}"));
    let err = afunix::connect(&denied).expect_err("connected to a socket that grants bob nothing");
    let denied_by_acl = err
        .downcast_ref::<std::io::Error>()
        .is_some_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied);
    assert!(denied_by_acl, "expected access denied, got {err:#}");

    child_entry::write_result(&dir, CONNECT_RESULT);
}

#[test]
fn bob_cannot_connect_to_a_socket_in_another_users_dir() {
    let bob = Account::create("bob", false);
    let admin = Sid::current_user().unwrap();
    let shared = SharedDir::new("connect");
    let profile_a = StandInProfile::new("conn-a");
    let profile_b = StandInProfile::new("conn-b");
    let (denied, control) = (profile_a.location(), profile_b.location());

    // The creator's default DACL lets everyone in; only the directory's inheritable ACEs stand
    // between bob and these sockets.
    let (_listeners, _locks) = with_permissive_default_dacl(|| {
        let mut listeners = Vec::new();
        let mut locks = Vec::new();
        for loc in [&denied, &control] {
            userdir::ensure_socket_dir(loc, &admin).unwrap();
            locks.push(UserLock::try_acquire(&loc.lock_path()).unwrap().unwrap());
            listeners.push(Listener::bind(&loc.path).unwrap());
        }
        (listeners, locks)
    });
    assert!(acl::verify_file_acl(&denied.path, &admin).unwrap(), "control: exact");
    // The control socket additionally grants bob, so a refusal elsewhere is the ACL's doing and
    // not an unreachable path or a missing right.
    let status = desktop::status(
        Command::new("icacls")
            .arg(&control.path)
            .args(["/grant", &format!("*{}:(F)", bob.sid_text)]),
    )
    .unwrap();
    assert!(status.success());

    let exe = shared.0.join("isolation.exe");
    std::fs::copy(std::env::current_exe().unwrap(), &exe).unwrap();
    child_entry::write_input(
        &shared.0,
        &format!("allowed={}\ndenied={}\n", control.path.display(), denied.path.display()),
    );
    let command = child_entry::command_line(&exe, "child_connects_only_where_it_was_granted", &shared.0);

    let code = bob.run(&exe, &command, &shared.0, &[]);

    assert_eq!(code, 0, "the child, running as bob, failed: see its output above");
    assert_eq!(child_entry::result(&shared.0), CONNECT_RESULT);
}

#[test]
fn a_child_that_never_exits_is_reported_and_its_tree_killed() {
    use std::os::windows::io::AsRawHandle;
    use std::process::Stdio;

    let evidence = std::env::temp_dir().join(format!("sb-iso-bounded-{}.txt", std::process::id()));
    std::fs::write(&evidence, "left-behind-marker").unwrap();
    // cmd.exe runs ping.exe, so the tree has a grandchild; the ping outlives any test run.
    let mut child = desktop::spawn(
        Command::new("cmd.exe")
            .args(["/c", "ping -n 600 127.0.0.1 >nul"])
            .creation_flags(CREATE_NO_WINDOW.0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null()),
    )
    .unwrap();

    // The report must list the grandchild, so it has to exist before the bound starts. Re-check
    // the process list until cmd.exe has started ping.exe; stop if cmd.exe is gone instead.
    while !process_list::children_of(child.id())
        .iter()
        .any(|name| name.eq_ignore_ascii_case("ping.exe"))
    {
        assert!(
            child.try_wait().unwrap().is_none(),
            "cmd.exe exited before it started ping.exe"
        );
        std::thread::yield_now();
    }

    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        bounded_wait::wait_for_exit(
            HANDLE(child.as_raw_handle()),
            child.id(),
            "the ping tree",
            std::time::Duration::from_secs(3),
            std::slice::from_ref(&evidence),
        )
    }));
    let payload = outcome.expect_err("a child that never exits must fail the wait");
    let message = payload.downcast_ref::<String>().cloned().unwrap_or_default();
    let _ = std::fs::remove_file(&evidence);

    assert!(message.contains("the ping tree"), "names what was awaited: {message}");
    assert!(message.contains("did not exit within"), "{message}");
    assert!(
        message.to_lowercase().contains("ping.exe"),
        "lists the grandchild: {message}"
    );
    assert!(message.contains("left-behind-marker"), "prints the evidence: {message}");
    // Killed: this returns instead of waiting out the 600 pings.
    child.wait().unwrap();
}

#[test]
fn the_process_list_names_a_processs_children_and_no_others() {
    use std::process::Stdio;

    // ping.exe started directly has no ping.exe child (it has a conhost.exe); the cmd.exe running
    // one has it.
    let mut leaf = desktop::spawn(
        Command::new("ping")
            .args(["-n", "600", "127.0.0.1"])
            .creation_flags(CREATE_NO_WINDOW.0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null()),
    )
    .unwrap();
    let mut parent = desktop::spawn(
        Command::new("cmd.exe")
            .args(["/c", "ping -n 600 127.0.0.1 >nul"])
            .creation_flags(CREATE_NO_WINDOW.0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null()),
    )
    .unwrap();
    let has_ping = |pid: u32| {
        process_list::children_of(pid)
            .iter()
            .any(|name| name.eq_ignore_ascii_case("ping.exe"))
    };
    while !has_ping(parent.id()) {
        assert!(parent.try_wait().unwrap().is_none(), "cmd.exe exited early");
        std::thread::yield_now();
    }
    let leaf_has_ping = has_ping(leaf.id());
    // Only the two processes started here: the leaf, and the tree under the cmd.exe.
    let _ = leaf.kill();
    let _ = desktop::status(
        Command::new("taskkill")
            .args(["/T", "/F", "/PID", &parent.id().to_string()])
            .creation_flags(CREATE_NO_WINDOW.0)
            .stdout(Stdio::null())
            .stderr(Stdio::null()),
    );
    let _ = (leaf.wait(), parent.wait());

    assert!(!leaf_has_ping, "a ping.exe has no ping.exe child");
}

#[test]
fn a_suspended_child_has_its_hard_error_boxes_suppressed() {
    use std::os::windows::io::AsRawHandle;
    use std::process::Stdio;

    // Suspended, so it never runs and never opens anything. CREATE_DEFAULT_ERROR_MODE gives it
    // the system default, whatever this process's mode is.
    let mut child = desktop::spawn(
        Command::new("cmd.exe")
            .creation_flags(0x0000_0004 | CREATE_NO_WINDOW.0 | 0x0400_0000)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null()),
    )
    .unwrap();
    let process = HANDLE(child.as_raw_handle());

    let before = hard_errors::raises_hard_error_boxes(process);
    hard_errors::suppress_hard_error_boxes(process).unwrap();
    let after = hard_errors::raises_hard_error_boxes(process);
    child.kill().unwrap();
    child.wait().unwrap();

    assert!(before, "control: a default child raises hard-error boxes");
    assert!(!after, "the child no longer raises hard-error boxes");
}

#[test]
fn account_names_differ_for_every_process_and_counter_and_fit_the_limit() {
    let mut seen = std::collections::HashSet::new();
    // Pairs whose digits run together if the two numbers are joined without a separator.
    for (pid, n) in [(0x1a, 2), (0x1, 0xa2), (0x12, 0xa), (u32::MAX, 0xffff), (7, 0), (0, 7)] {
        let name = account_name("alice", pid, n);
        assert!(seen.insert(name.clone()), "{name} repeats");
        assert!(
            name.chars().count() <= 20,
            "{name} is longer than an account name may be"
        );
    }
}

#[test]
fn accounts_made_at_the_same_moment_on_many_threads_get_distinct_names() {
    let names: Vec<String> = std::thread::scope(|scope| {
        let threads: Vec<_> = (0..8)
            .map(|_| scope.spawn(|| (0..50).map(|_| next_account_name("bob")).collect::<Vec<_>>()))
            .collect();
        threads.into_iter().flat_map(|t| t.join().unwrap()).collect()
    });
    let distinct: std::collections::HashSet<_> = names.iter().collect();
    assert_eq!(distinct.len(), names.len());
}

#[test]
fn a_child_entry_run_without_its_signal_panics() {
    let outcome = std::panic::catch_unwind(|| child_entry::dir_from(["exe".to_owned(), "--exact".to_owned()]));
    let payload = outcome.expect_err("a child half without the signal must not pass");
    let message = payload.downcast_ref::<String>().cloned().unwrap_or_default();
    assert!(message.contains(child_entry::SIGNAL), "{message}");
}

#[test]
fn a_child_entry_takes_its_directory_from_the_signal() {
    let args = ["exe", "--exact", "x", &format!("{}C:\\a b\\c", child_entry::SIGNAL)].map(str::to_owned);
    assert_eq!(child_entry::dir_from(args), PathBuf::from("C:\\a b\\c"));
}

#[test]
fn a_child_entry_panics_when_its_input_is_unreadable() {
    let missing = std::env::temp_dir().join(format!("sb-iso-no-such-dir-{}", std::process::id()));
    let outcome = std::panic::catch_unwind(|| child_entry::input(&missing));
    assert!(outcome.is_err(), "an unreadable input must fail the child");
}

#[test]
fn a_parent_fails_when_the_child_wrote_no_result() {
    let missing = std::env::temp_dir().join(format!("sb-iso-no-such-dir-{}", std::process::id()));
    let outcome = std::panic::catch_unwind(|| child_entry::result(&missing));
    let payload = outcome.expect_err("no result must fail the parent");
    let message = payload.downcast_ref::<String>().cloned().unwrap_or_default();
    assert!(message.contains("wrote no result"), "{message}");
}

/// What libtest does with a stale filter: exit 0 having run nothing. Only the result file tells
/// that apart from a child that ran and passed.
#[test]
fn a_child_filter_that_matches_no_test_exits_0_and_leaves_no_result() {
    let shared = SharedDir::without_grant("nomatch");
    child_entry::write_input(&shared.0, "");
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(child_entry::args("no_such_child_entry", &shared.0))
        .creation_flags(CREATE_NO_WINDOW.0);
    let status = desktop::status(&mut command).unwrap();

    assert!(status.success(), "libtest exits 0 when nothing matched: {status:?}");
    assert!(!child_entry::result_path(&shared.0).exists());
}

/// The whole pair, started as the current account instead of bob: the signal reaches the child,
/// the child checks and records, and the result is the content the parent asserts.
#[test]
fn the_window_library_child_started_as_this_account_records_what_it_loaded() {
    let shared = SharedDir::without_grant("libs-self");
    child_entry::write_input(&shared.0, LIBS_INPUT);
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(child_entry::args("child_loads_the_window_libraries", &shared.0))
        .creation_flags(CREATE_NO_WINDOW.0);
    let status = desktop::status(&mut command).unwrap();

    assert!(status.success(), "{status:?}");
    assert_eq!(child_entry::result(&shared.0), LIBS_RESULT);
}

#[test]
fn a_grant_names_each_sid_with_the_rights_given() {
    assert_eq!(
        desktop::grant_sddl(&["S-1-5-18", "S-1-1-0"], 0x2_037F),
        "D:(A;;0x2037f;;;S-1-5-18)(A;;0x2037f;;;S-1-1-0)"
    );
}

#[test]
fn a_grant_is_a_descriptor_the_system_accepts() {
    // Parsing creates nothing: no window station, no desktop.
    desktop::Descriptor::parse(&desktop::grant_sddl(&["S-1-5-18", "BA"], desktop::DESKTOP_ACCESS))
        .expect("the desktop grant parses");
    desktop::Descriptor::parse(&desktop::grant_sddl(&["S-1-5-18", "BA"], desktop::STATION_ACCESS))
        .expect("the window station grant parses");
}

#[test]
fn an_environment_block_is_sorted_by_name_and_ends_in_two_nuls() {
    let vars = [("b", "2"), ("=C:", "C:\\x"), ("A", "1")].map(|(k, v)| (k.into(), v.into()));
    let block = environment::block(vars);
    let text = String::from_utf16(&block).unwrap();
    assert_eq!(text, "=C:=C:\\x\0A=1\0b=2\0\0");
}

#[test]
fn an_empty_environment_block_is_two_nuls() {
    assert_eq!(environment::block(std::iter::empty()), vec![0u16, 0u16]);
}

#[test]
fn a_child_gets_a_private_desktop_and_this_process_keeps_its_window_station() {
    assert_elevated();
    let me = Sid::current_user().unwrap().to_sddl().unwrap();
    let before = desktop::process_window_station();

    let private = desktop::PrivateDesktop::create(&[&me]).expect("create a private window station and desktop");
    let during = desktop::process_window_station();
    let name = private.name().to_owned();
    drop(private);

    assert_eq!(
        during, before,
        "creating one leaves this process's window station alone"
    );
    assert_eq!(desktop::process_window_station(), before, "and so does closing it");
    assert!(name.ends_with("\\Default"), "{name}");
}

/// Creating a [`desktop::PrivateDesktop`] switches this process's window station for a moment, and
/// a child started without a desktop of its own inherits whichever station is current. So every
/// start of a child goes through the guarded `desktop::{spawn, status, output}`, and the one
/// `CreateProcess*` call here names its desktop. This reads the sources of this binary and fails
/// on a start that bypasses the guard. `pty.rs` is left out: only binaries that never switch
/// the station use it.
#[test]
fn no_child_is_started_outside_the_window_station_guard() {
    // Built from pieces so that this test does not match itself.
    let direct = [
        concat!(".spa", "wn()"),
        concat!(".sta", "tus()"),
        concat!(".out", "put()"),
    ];
    let raw = [
        concat!("CreateProcess", "W("),
        concat!("CreateProcess", "AsUserW("),
        concat!("CreateProcess", "WithLogonW("),
    ];
    let tests = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut files = vec![tests.join("user_isolation_windows.rs")];
    for entry in std::fs::read_dir(tests.join("common")).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if name.ends_with(".rs") && name != "desktop.rs" && name != "pty.rs" {
            files.push(path);
        }
    }

    let mut bypasses = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file).unwrap();
        for (number, line) in text.lines().enumerate() {
            if direct.iter().chain(&raw).any(|needle| line.contains(needle)) {
                bypasses.push(format!("{}:{}: {}", file.display(), number + 1, line.trim()));
            }
        }
    }
    assert!(
        bypasses.is_empty(),
        "start children through desktop::spawn, status or output:\n{}",
        bypasses.join("\n")
    );
}

/// CI only (creating a window station needs an administrator). Under a process-wide station
/// switch that readers and spawns did not respect, a reader would see a private station here.
#[test]
fn creating_private_desktops_in_parallel_never_shows_a_reader_another_station() {
    use std::sync::atomic::{AtomicBool, Ordering};

    assert_elevated();
    let me = Sid::current_user().unwrap().to_sddl().unwrap();
    let original = desktop::process_window_station();
    let done = AtomicBool::new(false);

    let seen_other = std::thread::scope(|scope| {
        let creators: Vec<_> = (0..4)
            .map(|_| {
                scope.spawn(|| {
                    for _ in 0..5 {
                        desktop::PrivateDesktop::create(&[&me]).expect("create a private window station and desktop");
                    }
                })
            })
            .collect();
        let reader = scope.spawn(|| {
            let mut other = 0u32;
            while !done.load(Ordering::Acquire) {
                if desktop::process_window_station() != original {
                    other += 1;
                }
                std::thread::yield_now();
            }
            other
        });
        for creator in creators {
            creator.join().unwrap();
        }
        done.store(true, Ordering::Release);
        reader.join().unwrap()
    });

    assert_eq!(seen_other, 0, "a reader saw a window station other than the original");
    assert_eq!(desktop::process_window_station(), original);
}

#[test]
fn a_loader_status_in_an_exit_code_is_named() {
    assert_eq!(hard_errors::describe_exit(0), "0");
    assert_eq!(hard_errors::describe_exit(1), "1");
    assert_eq!(
        hard_errors::describe_exit(0xC000_0135),
        "0xc0000135 (STATUS_DLL_NOT_FOUND)"
    );
    assert_eq!(hard_errors::describe_exit(0xC123_4567), "0xc1234567");
}

#[test]
fn a_loader_failure_as_bob_ends_the_process_with_its_status_and_no_message_box() {
    let bob = Account::create("ldr", false);
    let shared = SharedDir::new("ldr");
    // A copy of the shim that imports a DLL that does not exist: the loader cannot start it.
    let broken = shared.0.join("broken.exe");
    let mut image = std::fs::read(env!("CARGO_BIN_EXE_ssh-broker")).unwrap();
    let (from, to) = (b"wtsapi32.dll\0", b"wtsapi99.dll\0");
    let at = image
        .windows(from.len())
        .position(|w| w == from)
        .expect("the shim imports wtsapi32.dll");
    image[at..at + to.len()].copy_from_slice(to);
    std::fs::write(&broken, &image).unwrap();

    let code = bob.run(&broken, &format!("\"{}\"", broken.display()), &shared.0, &[]);

    assert_eq!(
        hard_errors::describe_exit(code),
        hard_errors::describe_exit(0xC000_0135),
        "the loader ended the process with STATUS_DLL_NOT_FOUND"
    );
}

/// The libraries [`child_loads_the_window_libraries`] must load, one per line: what the parent
/// hands it.
const LIBS_INPUT: &str = "user32.dll\ngdi32.dll\ncombase.dll\nole32.dll\n";
/// What [`child_loads_the_window_libraries`] records once all of them have loaded.
const LIBS_RESULT: &str = "loaded user32.dll\nloaded gdi32.dll\nloaded combase.dll\nloaded ole32.dll\n";

/// Child half of [`a_child_as_bob_loads_the_window_libraries`], started only by it as bob (see
/// [`child_entry`]). Fails if a library named in its input will not load, and records
/// [`LIBS_RESULT`] only after all of them did.
#[test]
#[ignore = "run as a child of a_child_as_bob_loads_the_window_libraries"]
fn child_loads_the_window_libraries() {
    let dir = child_entry::dir();
    let input = child_entry::input(&dir);
    assert_eq!(input, LIBS_INPUT, "the child's input names the libraries to load");

    let mut result = String::new();
    let mut failed = Vec::new();
    for dll in input.lines() {
        // SAFETY: NUL-terminated name.
        match unsafe { LoadLibraryW(PCWSTR(wide(dll).as_ptr())) } {
            Ok(_) => result.push_str(&format!("loaded {dll}\n")),
            Err(e) => failed.push(format!("{dll}: {e}")),
        }
    }
    assert!(failed.is_empty(), "did not load: {failed:?}");

    child_entry::write_result(&dir, &result);
}

/// What the shim and `ssh` need from an account's processes: user32 and the libraries on top of
/// it (ole32) initialise. They do not where the process has no usable window station and desktop.
#[test]
fn a_child_as_bob_loads_the_window_libraries() {
    let bob = Account::create("bob", false);
    let shared = SharedDir::new("libs");
    let exe = shared.0.join("isolation.exe");
    std::fs::copy(std::env::current_exe().unwrap(), &exe).unwrap();
    child_entry::write_input(&shared.0, LIBS_INPUT);
    let command = child_entry::command_line(&exe, "child_loads_the_window_libraries", &shared.0);

    let code = bob.run(&exe, &command, &shared.0, &[]);

    assert_eq!(
        code,
        0,
        "the child, running as bob, failed ({}): see its output above",
        hard_errors::describe_exit(code)
    );
    assert_eq!(child_entry::result(&shared.0), LIBS_RESULT);
}

#[test]
fn shim_as_bob_never_reaches_another_users_listener() {
    // The administrator's agent is listening, and bob may open its socket. An administrator who
    // SSHes in as bob gets bob's shim, which looks in bob's profile, finds nothing, and fails
    // open.
    let bob = Account::create("bob", true);
    let shared = SharedDir::new("shim");

    let admin = Sid::current_user().unwrap();
    let admin_loc = userdir::current_socket_location().unwrap();
    userdir::ensure_socket_dir(&admin_loc, &admin).unwrap();
    let _lock = UserLock::try_acquire(&admin_loc.lock_path())
        .unwrap()
        .expect("no agent runs on the CI host");
    let listener = Listener::bind(&admin_loc.path).unwrap();
    // The file DACL would turn bob away on its own, which would hide a shim that looked in the
    // wrong profile. Grant bob the socket, so that only the path decides: a shim that followed
    // the administrator's environment would connect here and fail the sentinel check below.
    let status = desktop::status(
        Command::new("icacls")
            .arg(&admin_loc.path)
            .args(["/grant", &format!("*{}:(F)", bob.sid_text)]),
    )
    .unwrap();
    assert!(status.success(), "icacls /grant");

    // Records the first thing that connects and the first byte it sends.
    let (first_byte, seen) = mpsc::channel();
    let acceptor = std::thread::spawn(move || {
        use std::io::Read;
        let mut conn = listener.accept().unwrap();
        let mut byte = [0u8; 1];
        let n = conn.read(&mut byte).unwrap();
        first_byte.send((n, byte[0])).unwrap();
    });

    let shim = shared.0.join("ssh-broker.exe");
    std::fs::copy(env!("CARGO_BIN_EXE_ssh-broker"), &shim).unwrap();
    // Shaped like a non-PTY sshd session, which the shim tells from a PTY one by its stdin: a
    // console stdin (what `run` gives a process) makes it keep the quotes around the command, and
    // `"cmd.exe /c echo shim-ran"` names no program. So stdin is NUL. The redirections come first
    // because `cmd` leaves the space before a trailing one in the command line the shim reads.
    let script = shared.0.join("run.cmd");
    std::fs::write(
        &script,
        format!(
            "@echo off\r\n<nul >\"{out}\" 2>\"{err}\" \"{shim}\" -c \"cmd.exe /c echo shim-ran\"\r\n",
            out = shared.0.join("out.txt").display(),
            err = shared.0.join("err.txt").display(),
            shim = shim.display(),
        ),
    )
    .unwrap();
    let cmd = Path::new(&std::env::var_os("SystemRoot").unwrap()).join(r"System32\cmd.exe");
    let command = format!("\"{}\" /c \"{}\"", cmd.display(), script.display());

    let evidence = ["out.txt", "err.txt"].map(|name| shared.0.join(name));
    // With his profile loaded: `CreateProcessWithTokenW` loads it only when asked (Microsoft docs,
    // Remarks).
    // The administrator's own environment goes in as is (`USERPROFILE`, `LOCALAPPDATA` and all),
    // so the shim has to take bob's socket from his token and not from what it inherits.
    let admin_environment = environment::current_block();
    let code = bob.run_with(
        &cmd,
        &command,
        &shared.0,
        &evidence,
        LOGON_WITH_PROFILE,
        Some(&admin_environment),
    );
    assert!(
        code == 0,
        "the fail-open command ran; the shim run ended with {}
shim: {}
shared directory: {}",
        hard_errors::describe_exit(code),
        icacls_report(&shim),
        icacls_report(&shared.0)
    );

    let stderr = std::fs::read_to_string(shared.0.join("err.txt")).unwrap();
    let stdout = std::fs::read_to_string(shared.0.join("out.txt")).unwrap();
    assert!(
        stderr.contains("agent unavailable"),
        "the shim failed open and said so: {stderr}"
    );
    assert!(stdout.contains("shim-ran"), "and ran the command locally: {stdout}");

    // Connections are accepted in order, so if the shim had connected it would be first. Ours
    // comes second at best, and its marker byte is what the acceptor must see.
    let mut sentinel = afunix::connect(&admin_loc.path).unwrap();
    std::io::Write::write_all(&mut sentinel, b"S").unwrap();
    assert_eq!(
        seen.recv().unwrap(),
        (1, b'S'),
        "something else connected before the sentinel"
    );
    acceptor.join().unwrap();
    let _ = std::fs::remove_file(&admin_loc.path);
}
