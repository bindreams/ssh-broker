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
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;

use ssh_broker::acl::{self, Sid};
use ssh_broker::afunix::{self, Listener};
use ssh_broker::agent_lock::UserLock;
use ssh_broker::socket_loc::SocketLocation;
use ssh_broker::userdir;
use ssh_broker::winutil::OwnedHandle;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::NetManagement::{
    NetUserAdd, NetUserDel, UF_DONT_EXPIRE_PASSWD, UF_SCRIPT, USER_INFO_1, USER_PRIV_USER,
};
use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows::Win32::Security::{
    ACL, DuplicateTokenEx, GetSecurityDescriptorDacl, GetTokenInformation, LOGON32_LOGON_NETWORK,
    LOGON32_PROVIDER_DEFAULT, LogonUserW, PSECURITY_DESCRIPTOR, SecurityImpersonation, SetTokenInformation,
    TOKEN_ALL_ACCESS, TOKEN_DEFAULT_DACL, TOKEN_DUPLICATE, TOKEN_ELEVATION, TOKEN_QUERY, TokenDefaultDacl,
    TokenElevation, TokenImpersonation, TokenPrimary,
};
use windows::Win32::System::Threading::{
    CREATE_NO_WINDOW, CreateProcessWithTokenW, GetCurrentProcess, GetExitCodeProcess, INFINITE, OpenProcessToken,
    PROCESS_INFORMATION, STARTUPINFOW, SetThreadToken, WaitForSingleObject,
};
use windows::Win32::UI::Shell::{CreateProfile, DeleteProfileW};
use windows::core::{BOOL, PCWSTR, PWSTR};

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
    /// `tag` keeps names apart within one test run.
    fn create(tag: &str, with_profile: bool) -> Account {
        assert_elevated();
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        // At most 20 characters, as an account name must be.
        let name = format!("sb{tag}{}", unique % 1_000_000);
        let password = format!("Sb-{unique:x}-Aa1!");
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

    /// Run `exe` with `command_line` under this account's network-logon token, the way sshd runs
    /// its shell, with the CALLER's environment (so a stale `USERPROFILE` is in play). Returns the
    /// exit code.
    fn run(&self, exe: &Path, command_line: &str, cwd: &Path) -> u32 {
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
        let startup = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            ..Default::default()
        };
        let mut info = PROCESS_INFORMATION::default();
        // SAFETY: every pointer is to a local that outlives the call.
        unsafe {
            CreateProcessWithTokenW(
                primary.0,
                Default::default(),
                PCWSTR(wide(&exe.to_string_lossy()).as_ptr()),
                Some(PWSTR(command.as_mut_ptr())),
                CREATE_NO_WINDOW,
                None,
                PCWSTR(wide(&cwd.to_string_lossy()).as_ptr()),
                &startup,
                &mut info,
            )
        }
        .unwrap_or_else(|e| panic!("start {exe:?} as {}: {e}", self.name));
        let process = OwnedHandle(info.hProcess);
        let _thread = OwnedHandle(info.hThread);
        let mut code = 0u32;
        // SAFETY: the process handle is ours; INFINITE waits for the child itself to exit.
        unsafe {
            WaitForSingleObject(process.0, INFINITE);
            GetExitCodeProcess(process.0, &mut code).unwrap();
        }
        code
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
    fn new(tag: &str) -> SharedDir {
        let dir = std::env::temp_dir().join(format!("sb-iso-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let status = Command::new("icacls")
            .arg(&dir)
            .args(["/grant", "*S-1-1-0:(OI)(CI)M"])
            .status()
            .unwrap();
        assert!(status.success(), "icacls on the shared directory");
        SharedDir(dir)
    }
}

impl Drop for SharedDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
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
    // Protected and with ACEs that do not propagate.
    let status = Command::new("icacls")
        .arg(&plain)
        .args([
            "/inheritance:r",
            "/grant:r",
            &format!("*{}:F", me.to_sddl().unwrap()),
            "*S-1-5-18:F",
            "*S-1-5-32-544:F",
        ])
        .status()
        .unwrap();
    assert!(status.success());

    let file = plain.join("born.txt");
    with_permissive_default_dacl(|| std::fs::write(&file, "x").unwrap());

    assert!(
        !acl::verify_file_acl(&file, &me).unwrap(),
        "a file made under a permissive default DACL, in a directory that passes nothing down, is not exact"
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
        let _listener = Listener::bind(&loc.path).unwrap();

        assert!(acl::verify_file_acl(&loc.path, &me).unwrap(), "agent.sock");
        assert!(acl::verify_file_acl(&loc.lock_path(), &me).unwrap(), "agent.lock");
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
        let _listener = Listener::bind(&loc.path).unwrap();

        assert!(acl::verify_dir_acl(&loc.dir, &admin).unwrap());
        assert!(
            !acl::verify_dir_acl(&loc.dir, &bob.sid).unwrap(),
            "the dir is not bob's"
        );
        // Born with exactly the three, although the creating token would have let everyone in.
        assert!(acl::verify_file_acl(&loc.path, &admin).unwrap(), "agent.sock");
        assert!(acl::verify_file_acl(&loc.lock_path(), &admin).unwrap(), "agent.lock");
        assert!(!acl::verify_file_acl(&loc.path, &bob.sid).unwrap());
    });
}

#[test]
fn ensure_socket_dir_refuses_a_dir_owned_by_another_user() {
    let bob = Account::create("bob", false);
    let admin = Sid::current_user().unwrap();
    let profile = StandInProfile::new("foreign");
    let loc = profile.location();
    std::fs::create_dir(&loc.dir).unwrap();
    let status = Command::new("icacls")
        .arg(&loc.dir)
        .args(["/setowner", &format!("*{}", bob.sid_text)])
        .status()
        .unwrap();
    assert!(status.success(), "icacls /setowner");

    let err = format!("{:#}", userdir::ensure_socket_dir(&loc, &admin).unwrap_err());

    assert!(err.contains("owner"), "{err}");
    assert!(
        !loc.logs_dir().exists(),
        "nothing was created inside a directory that is not ours"
    );
}

/// Child half of [`bob_cannot_connect_to_a_socket_in_another_users_dir`]: runs only when started
/// from the shared directory with a `child.txt` beside the binary, as bob. Passes when it can
/// connect where it was given a grant and is refused where it was not.
#[test]
fn child_connects_only_where_it_was_granted() {
    let Some(exe_dir) = std::env::current_exe().unwrap().parent().map(Path::to_path_buf) else {
        return;
    };
    let Ok(text) = std::fs::read_to_string(exe_dir.join("child.txt")) else {
        return; // not started as the child
    };
    let path_after = |key: &str| {
        PathBuf::from(
            text.lines()
                .find_map(|l| l.strip_prefix(key))
                .unwrap_or_else(|| panic!("child.txt has no {key}")),
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
    let status = Command::new("icacls")
        .arg(&control.path)
        .args(["/grant", &format!("*{}:(F)", bob.sid_text)])
        .status()
        .unwrap();
    assert!(status.success());

    let exe = shared.0.join("isolation.exe");
    std::fs::copy(std::env::current_exe().unwrap(), &exe).unwrap();
    std::fs::write(
        shared.0.join("child.txt"),
        format!("allowed={}\ndenied={}\n", control.path.display(), denied.path.display()),
    )
    .unwrap();
    let command = format!(
        "\"{}\" --exact child_connects_only_where_it_was_granted --nocapture",
        exe.display()
    );

    let code = bob.run(&exe, &command, &shared.0);

    assert_eq!(code, 0, "the child, running as bob, failed: see its output above");
}

#[test]
fn shim_as_bob_never_reaches_another_users_listener() {
    // The administrator's agent is listening, and bob may open its socket. An administrator who
    // SSHes in as bob gets bob's shim, which looks in bob's profile, finds nothing, and fails
    // open. Run with the caller's environment, whose USERPROFILE and LOCALAPPDATA are the
    // administrator's.
    let bob = Account::create("bob", true);
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
    let status = Command::new("icacls")
        .arg(&admin_loc.path)
        .args(["/grant", &format!("*{}:(F)", bob.sid_text)])
        .status()
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

    let shared = SharedDir::new("shim");
    let shim = shared.0.join("ssh-broker.exe");
    std::fs::copy(env!("CARGO_BIN_EXE_ssh-broker"), &shim).unwrap();
    let script = shared.0.join("run.cmd");
    std::fs::write(
        &script,
        format!(
            "@\"{}\" -c \"cmd.exe /c echo shim-ran\" > \"{}\" 2> \"{}\"\r\n",
            shim.display(),
            shared.0.join("out.txt").display(),
            shared.0.join("err.txt").display()
        ),
    )
    .unwrap();
    let cmd = Path::new(&std::env::var_os("SystemRoot").unwrap()).join(r"System32\cmd.exe");
    let command = format!("\"{}\" /c \"{}\"", cmd.display(), script.display());

    let code = bob.run(&cmd, &command, &shared.0);
    assert_eq!(code, 0, "the fail-open command ran");

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
