//! One account cannot reach another account's agent. Windows only; **Elevated (CI only)**, except
//! the tests that create no account.
//!
//! The tests that create accounts make throwaway local accounts and profiles, log them on the way
//! sshd does (a network logon, which has no loaded profile), and start processes under those
//! tokens. They need an elevated administrator and refuse to run anywhere else, before they touch
//! anything: run them in CI, never on a workstation. The tests that create no account also run
//! unelevated. The acceptance procedure repeats the central cases through a real sshd.
//!
//! The central property: the shim derives its socket from its own token's profile and from
//! nothing else, and the socket file grants connect access to exactly its user, SYSTEM and
//! Administrators. So an administrator who SSHes in as bob lands in bob's session or in a local
//! shell, never in another user's.
#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;

use ssh_broker::account::{INTEGRITY_LOW, INTEGRITY_MEDIUM};
use ssh_broker::acl::{self, Sid};
use ssh_broker::afunix::Listener;
use ssh_broker::agent_lock::{SessionSlot, UserLock};
use ssh_broker::socket_loc::Integrity;
use ssh_broker::socket_loc::SocketLocation;
use ssh_broker::userdir;
use ssh_broker::winutil::OwnedHandle;
use windows::Win32::Foundation::{HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    GetNamedSecurityInfoW, SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, DuplicateTokenEx, GetSecurityDescriptorDacl, GetSecurityDescriptorSacl,
    LABEL_SECURITY_INFORMATION, OBJECT_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    SecurityImpersonation, SetTokenInformation, TOKEN_ALL_ACCESS, TOKEN_DEFAULT_DACL, TOKEN_DUPLICATE, TOKEN_QUERY,
    TokenDefaultDacl, TokenImpersonation,
};
use windows::Win32::System::Threading::{GetCurrentProcess, LOGON_WITH_PROFILE, OpenProcessToken, SetThreadToken};
use windows::core::{BOOL, PCWSTR, PWSTR};

#[path = "common/account.rs"]
mod account;
#[path = "common/bounded_wait.rs"]
mod bounded_wait;
#[path = "common/child_entry.rs"]
mod child_entry;
#[path = "common/desktop.rs"]
mod desktop;
#[path = "common/drain.rs"]
mod drain;
#[path = "common/environment.rs"]
mod environment;
#[path = "common/file_signal.rs"]
mod file_signal;
#[path = "common/hard_errors.rs"]
mod hard_errors;
#[path = "common/integrity.rs"]
mod integrity;
#[path = "common/process_list.rs"]
mod process_list;
#[path = "common/raw_connect.rs"]
mod raw_connect;
#[path = "common/token_copy.rs"]
mod token_copy;

use account::{Account, SharedDir, wide};

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
    sddl_of(path, DACL_SECURITY_INFORMATION)
}

/// The DACL and the mandatory integrity label of `path` as SDDL (`S:(ML;...)` when it has a label),
/// for an assertion message; assertions on contents use [`read_sddl`].
fn dacl_and_label_sddl(path: &Path) -> String {
    sddl_of(path, DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION)
}

/// [`read_sddl`], with a placeholder text (no `D:` prefix) for a descriptor that cannot be read.
fn sddl_of(path: &Path, info: OBJECT_SECURITY_INFORMATION) -> String {
    read_sddl(path, info).unwrap_or_else(|e| format!("(cannot read the security descriptor: {e})"))
}

/// The parts of `path`'s security descriptor named by `info`, as SDDL, or why they could not be read.
fn read_sddl(path: &Path, info: OBJECT_SECURITY_INFORMATION) -> Result<String, String> {
    let path_w = wide(&path.to_string_lossy());
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: NUL-terminated path, valid out-pointers; both allocations are freed below.
    unsafe {
        let rc = GetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            info,
            None,
            None,
            None,
            None,
            &mut sd,
        );
        if let Err(e) = rc.ok() {
            return Err(format!("read: {e}"));
        }
        let mut text = PWSTR::null();
        let converted = ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, 1, info, &mut text, None);
        let out = match converted {
            Ok(()) => text.to_string().map_err(|e| format!("not UTF-16: {e}")),
            Err(e) => Err(format!("convert: {e}")),
        };
        let _ = LocalFree(Some(HLOCAL(text.0.cast())));
        let _ = LocalFree(Some(HLOCAL(sd.0)));
        out
    }
}

/// The mandatory-label ACE that makes an object `level` (an SDDL alias: `LW` Low, `ME` Medium) with the
/// ACE flags `ace_flags`, as SDDL.
fn label_ace(ace_flags: &str, level: &str) -> String {
    format!("(ML;{ace_flags};NW;;;{level})")
}

/// Set `path`'s mandatory integrity label to `level` (`LW`, `ME`), with the ACE flags `ace_flags` (`OICI`
/// to pass it to children of a directory, empty for a file). Low lets a Low-integrity process of the user
/// write to it. Set through the security API: `icacls /setintegritylevel` reports success on a socket
/// file and leaves it unlabelled.
fn set_label(path: &Path, ace_flags: &str, level: &str) {
    let sddl = wide(&format!("S:{}", label_ace(ace_flags, level)));
    let path_w = wide(&path.to_string_lossy());
    // SAFETY: NUL-terminated inputs; the descriptor outlives the call and is freed after it.
    unsafe {
        let mut sd = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(sddl.as_ptr()), 1, &mut sd, None).unwrap();
        let (mut present, mut defaulted) = (BOOL(0), BOOL(0));
        let mut sacl: *mut ACL = std::ptr::null_mut();
        GetSecurityDescriptorSacl(sd, &mut present, &mut sacl, &mut defaulted).unwrap();
        let rc = SetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            LABEL_SECURITY_INFORMATION,
            None,
            None,
            None,
            Some(sacl as *const ACL),
        );
        let _ = LocalFree(Some(HLOCAL(sd.0)));
        rc.ok().unwrap_or_else(|e| panic!("label {path:?} {level}: {e}"));
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
    /// A fresh, empty stand-in under the temp dir, removed on drop.
    fn new(tag: &str) -> StandInProfile {
        let root = std::env::temp_dir().join(format!("sb-iso-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("AppData").join("Local")).unwrap();
        StandInProfile(root)
    }

    /// The socket location the product derives for this profile, for an agent below High.
    fn location(&self) -> SocketLocation {
        self.location_at(Integrity::Medium)
    }

    /// The location for processes at `integrity`.
    fn location_at(&self, integrity: Integrity) -> SocketLocation {
        ssh_broker::socket_loc::for_profile(&self.0, integrity).expect("the stand-in profile path is short enough")
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
        loc.dir().to_string_lossy().to_lowercase(),
        expected.to_string_lossy().to_lowercase()
    );
    assert!(loc.path().ends_with("agent.sock"));
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
    assert!(from_bob.path().starts_with(bob.profile()));
}

#[test]
fn a_user_with_no_profile_has_no_socket_location() {
    let nobody = Account::create("nop", false);
    let token = nobody.network_token();
    let err = userdir::socket_location_of_token(token.0).unwrap_err();
    assert!(
        format!("{err:#}").contains("no profile directory"),
        "the shim reports this reason and fails open: {err:#}"
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

    let exact = acl::verify_file_acl(&file, &me, Integrity::Medium).unwrap();
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
        let _slot = SessionSlot::try_acquire(&loc.sessions_lock_path(), 1).unwrap().unwrap();
        let _listener = Listener::bind(loc.path(), Integrity::Medium).unwrap();

        assert!(
            acl::verify_file_acl(loc.path(), &me, Integrity::Medium).unwrap(),
            "agent.sock"
        );
        assert!(
            acl::verify_file_acl(&loc.lock_path(), &me, Integrity::Medium).unwrap(),
            "agent.lock"
        );
        assert!(
            acl::verify_file_acl(&loc.sessions_lock_path(), &me, Integrity::Medium).unwrap(),
            "session slot"
        );
        assert!(
            acl::verify_file_acl(&loc.logs_dir(), &me, Integrity::Medium).unwrap(),
            "logs"
        );
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
        let _slot = SessionSlot::try_acquire(&loc.sessions_lock_path(), 1).unwrap().unwrap();
        let _listener = Listener::bind(loc.path(), Integrity::Medium).unwrap();

        assert!(acl::verify_dir_acl(loc.dir(), &admin, Integrity::Medium).unwrap());
        assert!(
            !acl::verify_dir_acl(loc.dir(), &bob.sid, Integrity::Medium).unwrap(),
            "the dir is not bob's"
        );
        // Born with exactly the three, although the creating token would have let everyone in.
        assert!(
            acl::verify_file_acl(loc.path(), &admin, Integrity::Medium).unwrap(),
            "agent.sock"
        );
        assert!(
            acl::verify_file_acl(&loc.lock_path(), &admin, Integrity::Medium).unwrap(),
            "agent.lock"
        );
        assert!(
            acl::verify_file_acl(&loc.sessions_lock_path(), &admin, Integrity::Medium).unwrap(),
            "session slot"
        );
        assert!(!acl::verify_file_acl(loc.path(), &bob.sid, Integrity::Medium).unwrap());
        assert!(
            !acl::verify_file_acl(&loc.sessions_lock_path(), &bob.sid, Integrity::Medium).unwrap(),
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
    std::fs::create_dir(loc.dir()).unwrap();
    let status = desktop::status(
        Command::new("icacls")
            .arg(loc.dir())
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

    raw_connect::raw_connect(&allowed).unwrap_or_else(|e| panic!("the control socket must be reachable: {e:#}"));
    let err = raw_connect::raw_connect(&denied).expect_err("connected to a socket that grants bob nothing");
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
            listeners.push(Listener::bind(loc.path(), Integrity::Medium).unwrap());
        }
        (listeners, locks)
    });
    assert!(
        acl::verify_file_acl(denied.path(), &admin, Integrity::Medium).unwrap(),
        "control: exact"
    );
    // The control socket additionally grants bob, so a refusal elsewhere is the ACL's doing and
    // not an unreachable path or a missing right.
    let status = desktop::status(
        Command::new("icacls")
            .arg(control.path())
            .args(["/grant", &format!("*{}:(F)", bob.sid_text)]),
    )
    .unwrap();
    assert!(status.success());

    let exe = shared.0.join("isolation.exe");
    std::fs::copy(std::env::current_exe().unwrap(), &exe).unwrap();
    child_entry::write_input(
        &shared.0,
        &format!(
            "allowed={}\ndenied={}\n",
            control.path().display(),
            denied.path().display()
        ),
    );
    let command = child_entry::command_line(&exe, "child_connects_only_where_it_was_granted", &shared.0);

    let code = bob.run(&exe, &command, &shared.0, &[]);

    assert_eq!(
        code, 0,
        "the child, running as bob, failed (its output is not captured: a CreateProcessWithTokenW child has no stdio here)"
    );
    assert_eq!(child_entry::result(&shared.0), CONNECT_RESULT);
}

// Who can connect: the integrity level --------------------------------------------------------

/// `WSAEACCES`, what `connect` fails with when the socket file refuses the caller's access.
const WSAEACCES: i32 = 10013;

/// What [`child_connects_at_its_integrity_level`] observed, one `key=value` line per fact.
fn child_facts(level: u32, stat: &str, create: &str, connect: &str, os_error: Option<i32>) -> String {
    let os_error = os_error.map_or("none".to_owned(), |code| code.to_string());
    format!("integrity={level}\nstat={stat}\ncreate={create}\nconnect={connect}\nconnect_os_error={os_error}\n")
}

/// The value of `key` in a child's result.
fn fact<'a>(result: &'a str, key: &str) -> &'a str {
    result
        .lines()
        .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
        .unwrap_or_else(|| panic!("the child's result has no {key}:\n{result}"))
}

/// Child: fail with `why`, which is also written as the result: the child has no stdio, so the
/// parent prints the result to name the cause.
fn child_fails(dir: &Path, why: &str) -> ! {
    child_entry::write_result(dir, &format!("error={why}\n"));
    panic!("{why}")
}

/// Child half of [`a_low_integrity_process_of_the_same_user_cannot_connect_to_the_agent_socket`].
/// Connects with the product's own client, as the shim does.
#[test]
#[ignore = "run as a child of a_low_integrity_process_of_the_same_user_cannot_connect_to_the_agent_socket"]
fn child_connects_at_its_integrity_level() {
    let dir = child_entry::dir();
    let text = child_entry::input(&dir);
    let value_after = |key: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(key))
            .unwrap_or_else(|| child_fails(&dir, &format!("the child's input has no {key}")))
            .to_owned()
    };
    let socket = PathBuf::from(value_after("socket="));
    let expected: u32 = value_after("integrity=")
        .parse()
        .unwrap_or_else(|e| child_fails(&dir, &format!("the child's integrity is not a number: {e}")));
    let level = integrity::current_rid();
    if level != expected {
        child_fails(
            &dir,
            &format!("the child runs at integrity {level:#x}, its parent meant {expected:#x}"),
        );
    }

    // The path itself is reachable at this level, and a socket can be made at it: only the
    // connect is in question.
    let stat = match std::fs::symlink_metadata(&socket) {
        Ok(_) => "ok".to_owned(),
        Err(e) => format!("failed: {e}"),
    };
    let create = match socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None) {
        Ok(_) => "ok".to_owned(),
        Err(e) => format!("failed: {e}"),
    };
    let (connect, os_error) = match raw_connect::raw_connect(&socket) {
        Ok(_) => ("connected".to_owned(), None),
        Err(e) => {
            let os_error = e
                .downcast_ref::<std::io::Error>()
                .and_then(std::io::Error::raw_os_error);
            (format!("failed: {e:#}"), os_error)
        }
    };
    child_entry::write_result(&dir, &child_facts(level, &stat, &create, &connect, os_error));
}

#[test]
fn a_low_integrity_process_of_the_same_user_cannot_connect_to_the_agent_socket() {
    // A sandboxed process (a renderer, a protected-mode viewer) runs as the user at Low
    // integrity. The socket file's ACL admits the user, so only the integrity check can refuse it.
    let me = Sid::current_user().unwrap();
    let profile = StandInProfile::new("low");
    let loc = profile.location();
    userdir::ensure_socket_dir(&loc, &me).unwrap();
    let _listener = Listener::bind(loc.path(), Integrity::Medium).unwrap();
    let security_of_file = |context: &str| {
        let info = DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION;
        read_sddl(loc.path(), info).unwrap_or_else(|e| panic!("read the socket file's security {context}: {e}"))
    };
    let file_security = security_of_file("before any child runs");
    let measured = format!(
        "the socket file: {}\n  {file_security}\nits folder: {}\n  {}",
        loc.path().display(),
        loc.dir().display(),
        dacl_and_label_sddl(loc.dir()),
    );
    println!("{measured}");
    assert!(
        acl::verify_file_acl(loc.path(), &me, Integrity::Medium).unwrap(),
        "the socket is exact\n{measured}"
    );
    // The refusal below rests on the file having no integrity label, which makes it Medium with
    // the default no-write-up policy.
    assert!(
        !file_security.contains("(ML;"),
        "the socket file carries a mandatory label\n{measured}"
    );

    // Each child writes its result into a directory of its own, labelled Low so the Low child may
    // write there.
    let exe = std::env::current_exe().unwrap();
    let run = |tag: &str, level: u32| {
        let dir = profile.0.join(format!("pair-{tag}"));
        std::fs::create_dir(&dir).unwrap();
        set_label(&dir, "OICI", "LW");
        child_entry::write_input(&dir, &format!("socket={}\nintegrity={level}\n", loc.path().display()));
        let name = "child_connects_at_its_integrity_level";
        let code = integrity::run_at(
            level,
            &exe,
            &child_entry::command_line(&exe, name, &dir),
            &dir,
            std::slice::from_ref(&dir),
        );
        assert_eq!(
            code,
            0,
            "the {tag} child failed: {}\nits result: {}",
            hard_errors::describe_exit(code),
            std::fs::read_to_string(child_entry::result_path(&dir)).unwrap_or_else(|e| format!("none ({e})")),
        );
        let result = child_entry::result(&dir);
        println!("{tag}-integrity child:\n{result}");
        result
    };

    // Control: the same child, started the same way at Medium, the user's usual level, reaches the
    // socket, so a refusal below is the integrity check's doing and not an unreachable path.
    let medium = run("medium", INTEGRITY_MEDIUM);
    let expected_medium = child_facts(INTEGRITY_MEDIUM, "ok", "ok", "connected", None);
    assert_eq!(medium, expected_medium, "the control child must connect\n{measured}");

    let low = run("low", INTEGRITY_LOW);
    assert_eq!(
        (fact(&low, "stat"), fact(&low, "create"), fact(&low, "connect_os_error")),
        ("ok", "ok", WSAEACCES.to_string().as_str()),
        "a Low-integrity process of the same user must reach the file and be refused by connect\n{measured}\n{low}"
    );

    // The label is the cause: with only the socket file's label lowered to Low, the same Low child
    // connects.
    set_label(loc.path(), "", "LW");
    let labelled = security_of_file("after it was labelled Low");
    assert!(
        labelled.contains(&label_ace("", "LW")) && acl::verify_file_acl(loc.path(), &me, Integrity::Medium).unwrap(),
        "the socket file must carry a Low label and keep its exact DACL\n{measured}\nnow: {labelled}"
    );
    let low_labelled = run("low-labelled", INTEGRITY_LOW);
    let expected_low_labelled = child_facts(INTEGRITY_LOW, "ok", "ok", "connected", None);
    assert_eq!(
        low_labelled, expected_low_labelled,
        "a Low-integrity process must connect once the socket file is labelled Low\n{measured}\nnow: {labelled}"
    );
}

// Who can connect: the elevated folder --------------------------------------------------------

/// `key=ok`, or `key=failed:<OS error>`, for the outcome of one act of a child on the elevated folder.
fn act_fact<T>(key: &str, outcome: std::io::Result<T>) -> String {
    match outcome {
        Ok(_) => format!("{key}=ok\n"),
        Err(e) => format!(
            "{key}=failed:{}\n",
            e.raw_os_error().map_or("none".to_owned(), |code| code.to_string())
        ),
    }
}

/// Child half of [`an_unelevated_process_of_the_account_is_refused_the_elevated_folder`]: connect to the
/// socket in the folder, create a file in it, rename and delete a file in it, and ask for the right to
/// write the folder's attributes, each with the plain file calls of the standard library and the
/// product's own client, and record what each said.
#[test]
#[ignore = "run as a child of an_unelevated_process_of_the_account_is_refused_the_elevated_folder"]
fn child_acts_in_the_elevated_folder() {
    use std::os::windows::fs::OpenOptionsExt;
    /// `FILE_WRITE_ATTRIBUTES`: what changing a folder's attributes asks for.
    const FILE_WRITE_ATTRIBUTES: u32 = 0x100;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

    let dir = child_entry::dir();
    let text = child_entry::input(&dir);
    let value_after = |key: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(key))
            .unwrap_or_else(|| child_fails(&dir, &format!("the child's input has no {key}")))
            .to_owned()
    };
    let folder = PathBuf::from(value_after("folder="));
    let expected: u32 = value_after("integrity=")
        .parse()
        .unwrap_or_else(|e| child_fails(&dir, &format!("the child's integrity is not a number: {e}")));
    let level = integrity::current_rid();
    if level != expected {
        child_fails(
            &dir,
            &format!("the child runs at integrity {level:#x}, its parent meant {expected:#x}"),
        );
    }

    let mut facts = format!("integrity={level}\n");
    facts += &act_fact(
        "connect",
        raw_connect::raw_connect(&folder.join("agent.sock")).map_err(|e| {
            e.downcast::<std::io::Error>()
                .unwrap_or_else(|e| std::io::Error::other(format!("{e:#}")))
        }),
    );
    facts += &act_fact("create", std::fs::File::create_new(folder.join("made-by-the-child")));
    facts += &act_fact(
        "rename",
        std::fs::rename(folder.join("kept-for-rename"), folder.join("renamed-by-the-child")),
    );
    facts += &act_fact("delete", std::fs::remove_file(folder.join("kept-for-delete")));
    facts += &act_fact(
        "attributes",
        std::fs::OpenOptions::new()
            .access_mode(FILE_WRITE_ATTRIBUTES)
            .share_mode(7)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(&folder),
    );
    child_entry::write_result(&dir, &facts);
}

/// Elevated (CI only). The elevated folder is born labelled High: a process of the same account below High
/// (an unelevated prompt, an `internal-unelevated` session) is refused the connect and every change to the
/// folder, and a High process of the account (the control) does all of them. Each is an act the child asks
/// for through the ordinary calls; none tries to get round the refusal.
#[test]
fn an_unelevated_process_of_the_account_is_refused_the_elevated_folder() {
    account::assert_elevated();
    let me = Sid::current_user().unwrap();
    let profile = StandInProfile::new("hi");
    let loc = profile.location_at(Integrity::High);
    userdir::ensure_socket_dir(&loc, &me).unwrap();
    let _listener = Listener::bind(loc.path(), Integrity::High).unwrap();
    assert!(
        acl::verify_dir_acl(loc.dir(), &me, Integrity::High).unwrap()
            && acl::verify_file_acl(loc.path(), &me, Integrity::High).unwrap(),
        "the folder and the socket carry the label\n{}",
        dacl_and_label_sddl(loc.dir())
    );
    let make_files = || {
        for name in ["kept-for-rename", "kept-for-delete"] {
            std::fs::write(loc.dir().join(name), "kept").unwrap();
        }
    };
    make_files();

    let exe = std::env::current_exe().unwrap();
    let run = |tag: &str, level: u32| {
        let dir = profile.0.join(format!("pair-{tag}"));
        std::fs::create_dir(&dir).unwrap();
        set_label(&dir, "OICI", "LW");
        child_entry::write_input(&dir, &format!("folder={}\nintegrity={level}\n", loc.dir().display()));
        let code = integrity::run_at(
            level,
            &exe,
            &child_entry::command_line(&exe, "child_acts_in_the_elevated_folder", &dir),
            &dir,
            std::slice::from_ref(&dir),
        );
        assert_eq!(
            code,
            0,
            "the {tag} child failed: {}\nits result: {}",
            hard_errors::describe_exit(code),
            std::fs::read_to_string(child_entry::result_path(&dir)).unwrap_or_else(|e| format!("none ({e})")),
        );
        let result = child_entry::result(&dir);
        println!("{tag}-integrity child:\n{result}");
        result
    };
    let measured = || {
        format!(
            "the folder: {}\n  {}",
            loc.dir().display(),
            dacl_and_label_sddl(loc.dir())
        )
    };

    let medium = run("medium", INTEGRITY_MEDIUM);
    assert_eq!(
        fact(&medium, "connect"),
        format!("failed:{WSAEACCES}"),
        "the connect is refused\n{}\n{medium}",
        measured()
    );
    for act in ["create", "rename", "delete", "attributes"] {
        assert!(
            fact(&medium, act).starts_with("failed:"),
            "a process below High must be refused: {act}\n{}\n{medium}",
            measured()
        );
    }
    for name in ["kept-for-rename", "kept-for-delete"] {
        assert!(loc.dir().join(name).is_file(), "{name} is still there\n{}", measured());
    }
    assert!(
        !loc.dir().join("made-by-the-child").exists(),
        "nothing was made\n{}",
        measured()
    );
    assert!(
        acl::verify_dir_acl(loc.dir(), &me, Integrity::High).unwrap(),
        "the folder is as it was\n{}",
        measured()
    );

    // The control: the same child at High, the account's elevated level, does each of them.
    let high = run("high", ssh_broker::account::INTEGRITY_HIGH);
    for act in ["connect", "create", "rename", "delete", "attributes"] {
        assert_eq!(
            fact(&high, act),
            "ok",
            "a High process of the account does {act}: the refusals above are the label's\n{}\n{high}",
            measured()
        );
    }
}

/// Elevated (CI only). The log folder inside the elevated folder is made with the High label, and the
/// walk judges it with that label: it passes for the folder as the agent makes it, and refuses one with
/// the right owner and DACL that lacks the label or carries another (here Medium), naming the log folder.
#[test]
fn the_log_folder_in_the_elevated_folder_carries_the_label() {
    account::assert_elevated();
    let me = Sid::current_user().unwrap();
    let profile = StandInProfile::new("hl");
    let loc = profile.location_at(Integrity::High);
    userdir::ensure_socket_dir(&loc, &me).unwrap();
    assert!(
        acl::verify_dir_acl(&loc.logs_dir(), &me, Integrity::High).unwrap(),
        "logs carries the label\n{}",
        dacl_and_label_sddl(&loc.logs_dir())
    );
    for walk in [userdir::open_socket_dir, userdir::inspect_socket_dir] {
        walk(&loc, &me)
            .unwrap()
            .logs
            .unwrap_or_else(|e| panic!("the walk judges logs as the agent made it: {e:#}"));
    }

    // Put in its place the `logs` the product makes for processes below High: the same owner and DACL, and
    // no label.
    let below = profile.location_at(Integrity::Medium);
    userdir::ensure_socket_dir(&below, &me).unwrap();
    std::fs::remove_dir(loc.logs_dir()).unwrap();
    std::fs::rename(below.logs_dir(), loc.logs_dir()).unwrap();
    assert!(
        acl::verify_dir_acl(&loc.logs_dir(), &me, Integrity::Medium).unwrap(),
        "the stand-in has the right owner and DACL\n{}",
        dacl_and_label_sddl(&loc.logs_dir())
    );
    let refused_for_the_label = |why: &str| {
        for walk in [userdir::open_socket_dir, userdir::inspect_socket_dir] {
            let opened = walk(&loc, &me).expect("the private folder itself is the elevated one");
            let err = format!(
                "{:#}",
                opened.logs.err().unwrap_or_else(|| panic!("logs {why} is refused"))
            );
            assert!(err.contains(&loc.logs_dir().display().to_string()), "{why}: {err}");
            assert!(err.contains("mandatory label"), "{why}: {err}");
        }
    };
    refused_for_the_label("without the label");

    // An explicit label that is not the High one is refused too.
    set_label(&loc.logs_dir(), "OICI", "ME");
    let sddl = dacl_and_label_sddl(&loc.logs_dir());
    assert!(sddl.contains(&label_ace("OICI", "ME")), "{sddl}");
    refused_for_the_label("labelled Medium");
}

/// Child half of [`a_folder_the_account_made_in_the_elevated_ones_place_is_refused`]: make the folder the
/// way any process of the account can, with the plain call.
#[test]
#[ignore = "run as a child of a_folder_the_account_made_in_the_elevated_ones_place_is_refused"]
fn child_makes_a_folder_in_the_elevated_ones_place() {
    let dir = child_entry::dir();
    let text = child_entry::input(&dir);
    let folder = text
        .lines()
        .find_map(|l| l.strip_prefix("folder="))
        .unwrap_or_else(|| child_fails(&dir, "the child's input has no folder="));
    if let Err(e) = std::fs::create_dir(folder) {
        child_fails(&dir, &format!("create {folder}: {e}"));
    }
    child_entry::write_result(&dir, "made\n");
}

/// Elevated (CI only), stated limit 4. A folder named `ssh-broker-elevated` that a process of the account
/// below High made, while no agent or shim held the place, is refused by the elevated walk like any folder
/// that is not exactly right: told where it is and what to do, and left as it is. The account does this to
/// itself and can undo it, since it owns what it made.
#[test]
fn a_folder_the_account_made_in_the_elevated_ones_place_is_refused() {
    account::assert_elevated();
    let me = Sid::current_user().unwrap();
    let profile = StandInProfile::new("hm");
    let loc = profile.location_at(Integrity::High);
    let exe = std::env::current_exe().unwrap();
    let dir = profile.0.join("pair-makes");
    std::fs::create_dir(&dir).unwrap();
    set_label(&dir, "OICI", "LW");
    child_entry::write_input(&dir, &format!("folder={}\n", loc.dir().display()));
    let code = integrity::run_at(
        INTEGRITY_MEDIUM,
        &exe,
        &child_entry::command_line(&exe, "child_makes_a_folder_in_the_elevated_ones_place", &dir),
        &dir,
        std::slice::from_ref(&dir),
    );
    assert_eq!(code, 0, "the child failed: {}", hard_errors::describe_exit(code));
    assert_eq!(child_entry::result(&dir), "made\n");
    let before = dacl_and_label_sddl(loc.dir());

    for walk in [userdir::open_socket_dir, userdir::inspect_socket_dir] {
        let err = format!(
            "{:#}",
            walk(&loc, &me).err().expect("the account's own folder is refused")
        );
        assert!(err.contains(&loc.dir().display().to_string()), "{err}");
        assert!(
            err.contains("It is left as it is: inspect it, remove it, and it is created again"),
            "{err}"
        );
    }
    assert_eq!(dacl_and_label_sddl(loc.dir()), before, "left as it was");
    assert!(
        !acl::verify_dir_acl(loc.dir(), &me, Integrity::High).unwrap(),
        "and still not the elevated folder"
    );
    std::fs::remove_dir(loc.dir()).expect("the account can remove what it made");
    userdir::ensure_socket_dir(&loc, &me).expect("and the folder is made again, born labelled");
    assert!(acl::verify_dir_acl(loc.dir(), &me, Integrity::High).unwrap());
}

/// What the shim prints on stderr when it finds no agent behind the location it resolved and
/// has no reason to add: a location that resolved, and a shim whose log works.
const NO_AGENT_LINE: &str = "ssh-broker: agent unavailable \u{2014} falling back to a local shell\n";

/// The files [`run_shim_as`] leaves behind.
struct ShimRun {
    code: u32,
    stdout: String,
    stderr: String,
}

/// Run a copy of the shim as `bob`, started by this administrator, in the shape sshd gives it: a
/// non-PTY `-c "cmd.exe /c echo shim-ran"`. Guarantees that bob's profile is loaded and that the
/// administrator's own environment (`USERPROFILE`, `LOCALAPPDATA` and all) is passed in as is, so
/// the shim has to take bob's socket from his token and not from what it inherits.
fn run_shim_as(bob: &Account, shared: &SharedDir) -> ShimRun {
    let shim = shared.0.join("ssh-broker.exe");
    std::fs::copy(env!("CARGO_BIN_EXE_ssh-broker"), &shim).unwrap();
    // The shim tells a non-PTY sshd session from a PTY one by its stdin: a console stdin (what
    // `run` gives a process) makes it keep the quotes around the command, and
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
    let admin_environment = environment::current_block();
    let code = bob.run_with(
        &cmd,
        &command,
        &shared.0,
        &evidence,
        LOGON_WITH_PROFILE,
        Some(&admin_environment),
    );
    ShimRun {
        code,
        stdout: std::fs::read_to_string(shared.0.join("out.txt")).unwrap(),
        stderr: std::fs::read_to_string(shared.0.join("err.txt")).unwrap(),
    }
}

const SENTINEL: &[u8] = b"sentinel: not a frame";

/// A listener that records what each connection to it sends, in the order accepted, and keeps
/// listening until the connection that sends [`SENTINEL`] has been read. Raw sockets, so that it
/// can listen in a directory hardened for another account, which `Listener::bind` refuses.
struct Recorder {
    path: PathBuf,
    seen: mpsc::Receiver<Vec<u8>>,
    thread: std::thread::JoinHandle<()>,
}

impl Recorder {
    fn listen(path: &Path) -> Recorder {
        let socket = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None).unwrap();
        socket.bind(&socket2::SockAddr::unix(path).unwrap()).unwrap();
        socket.listen(8).unwrap();
        let (sent, seen) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            use std::io::Read;
            loop {
                let (mut conn, _) = socket.accept().unwrap();
                let mut buf = [0u8; 256];
                let n = conn.read(&mut buf).unwrap();
                let message = buf[..n].to_vec();
                let ours = message == SENTINEL;
                sent.send(message).unwrap();
                if ours {
                    return;
                }
            }
        });
        Recorder {
            path: path.to_owned(),
            seen,
            thread,
        }
    }

    /// What the first connection sent, after a connection of our own that sends [`SENTINEL`]:
    /// the connections are accepted in order, so anything that connected before this call comes
    /// first, and [`SENTINEL`] coming back means that nothing did. The listener is open for
    /// every connection up to ours, so a connection made earlier is not turned away. Removes the
    /// socket file.
    fn first_sender(self) -> Vec<u8> {
        let mut ours = raw_connect::raw_connect(&self.path).unwrap();
        std::io::Write::write_all(&mut ours, SENTINEL).unwrap();
        let first = self.seen.recv().unwrap();
        self.thread.join().unwrap();
        let _ = std::fs::remove_file(&self.path);
        first
    }
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
    let listener = Recorder::listen(admin_loc.path());
    // The file DACL would turn bob away on its own, which would hide a shim that looked in the
    // wrong profile. Grant bob the socket, so that only the path decides: a shim that followed
    // the administrator's environment would connect here and fail the sentinel check below.
    let status = desktop::status(
        Command::new("icacls")
            .arg(admin_loc.path())
            .args(["/grant", &format!("*{}:(F)", bob.sid_text)]),
    )
    .unwrap();
    assert!(status.success(), "icacls /grant");

    let run = run_shim_as(&bob, &shared);

    assert!(
        run.code == 0,
        "the fail-open command ran; the shim run ended with {}\nshim: {}\nshared directory: {}",
        hard_errors::describe_exit(run.code),
        icacls_report(&shared.0.join("ssh-broker.exe")),
        icacls_report(&shared.0)
    );
    // The location resolved (to bob's own) and nothing listens there: no reason, no log failure.
    // A command session of an account with no session says so once, then gives the usual fallback line.
    let notice = format!("ssh-broker: {} has no Windows session on this PC", bob.name);
    assert!(
        run.stderr.starts_with(&notice) && run.stderr.ends_with(NO_AGENT_LINE),
        "the shim failed open for the wrong reason: {:?}",
        run.stderr
    );
    assert_eq!(
        run.stderr.matches("ssh-broker: ").count(),
        2,
        "the notice and the fallback line, once each: {:?}",
        run.stderr
    );
    assert!(
        run.stdout.contains("shim-ran"),
        "and ran the command locally: {}",
        run.stdout
    );
    assert_eq!(
        listener.first_sender(),
        SENTINEL,
        "something else connected before the sentinel"
    );
}

/// Child half of [`shim_as_bob_reaches_a_listener_in_bobs_own_location`], started only by it as
/// bob (see [`child_entry`]). Makes the private folder of its own token's socket location, as
/// bob's agent does, and only then records the socket path. Setting bob as the folder's owner
/// takes `SeRestorePrivilege`, which an administrator does not enable by default.
#[test]
#[ignore = "run as a child of shim_as_bob_reaches_a_listener_in_bobs_own_location"]
fn child_makes_its_own_socket_dir() {
    let dir = child_entry::dir();
    let loc = userdir::current_socket_location().unwrap_or_else(|e| panic!("resolve the socket location: {e:#}"));
    let me = Sid::current_user().unwrap();
    userdir::ensure_socket_dir(&loc, &me).unwrap_or_else(|e| panic!("make the private folder: {e:#}"));

    child_entry::write_result(&dir, &format!("{}\n", loc.path().display()));
}

/// The control for the test above: the same shim, run the same way, does connect when a listener
/// is in bob's own location. Without it, the refusal above could be a shim that never connects.
#[test]
fn shim_as_bob_reaches_a_listener_in_bobs_own_location() {
    let bob = Account::create("bob", true);
    let shared = SharedDir::new("shim-own");
    let bob_loc = userdir::socket_location_of_token(bob.network_token().0).unwrap();

    // Bob makes his own folder, as his agent does: it is exactly bob, SYSTEM and Administrators,
    // and the socket file made in it inherits the same, so bob may connect.
    let exe = shared.0.join("isolation.exe");
    std::fs::copy(std::env::current_exe().unwrap(), &exe).unwrap();
    let command = child_entry::command_line(&exe, "child_makes_its_own_socket_dir", &shared.0);
    let code = bob.run(&exe, &command, &shared.0, &[]);
    assert_eq!(
        code, 0,
        "the child, running as bob, failed (its output is not captured: a CreateProcessWithTokenW child has no stdio here)"
    );
    assert_eq!(
        PathBuf::from(child_entry::result(&shared.0).trim_end()),
        bob_loc.path(),
        "the child resolved a different location than his token gives the administrator"
    );

    let listener = Recorder::listen(bob_loc.path());

    let run = run_shim_as(&bob, &shared);

    let first = listener.first_sender();
    assert_ne!(
        first,
        SENTINEL,
        "the shim run as bob did not connect to bob's own socket {}\nits stderr: {}\nits exit: {}",
        bob_loc.path().display(),
        run.stderr,
        hard_errors::describe_exit(run.code)
    );
    assert!(!first.is_empty(), "the shim connected but sent nothing");
}

// Spike 5: a socket made at High in the plain folder (throwaway) -----

/// Child half of [`spike5_q2_a_socket_in_the_plain_folder_made_at_high_is_reached_from_below_high`]: started with
/// the unelevated token, it connects to the socket and sends one byte, publishes what happened, and then waits
/// for the listener to close the connection.
#[test]
#[ignore = "run as a child of spike5_q2_a_socket_in_the_plain_folder_made_at_high_is_reached_from_below_high"]
fn spike5_q2_child_connects_and_sends_one_byte() {
    use std::io::Read as _;

    let dir = child_entry::dir();
    let socket = PathBuf::from(child_entry::input(&dir).trim());
    let token = ssh_broker::winutil::own_token().expect("open the child's token");
    let mut facts = format!(
        "integrity={:#x}\nelevation={:?}\n",
        ssh_broker::account::integrity_of(token.0).unwrap(),
        ssh_broker::account::elevation_of(token.0).unwrap()
    );
    let result = child_entry::result_path(&dir);
    match raw_connect::raw_connect(&socket) {
        Ok(connection) => {
            let sent = connection.send(&[0x78]);
            facts += &format!("connect=connected\nsend={sent:?}\n");
            file_signal::publish(&result, &facts);
            // The connection stays open until the listener has read the byte and closes its end.
            let mut buf = [0u8; 1];
            let _ = (&connection).read(&mut buf);
        }
        Err(e) => {
            let os_error = e
                .downcast_ref::<std::io::Error>()
                .and_then(std::io::Error::raw_os_error);
            facts += &format!("connect=failed: {e:#}\nconnect_os_error={os_error:?}\n");
            file_signal::publish(&result, &facts);
        }
    }
}

/// Elevated (CI only). Spike 5, Q2: a process at High makes the plain folder (`Integrity::Medium`) and binds a
/// socket in it, as a Medium agent would; a child of the same account below High (`UnelevatedToken`) connects and
/// sends one byte, which the listener reads. Each fact goes to the measurement file; the test asserts only that the
/// listener bound and the child ran.
#[test]
fn spike5_q2_a_socket_in_the_plain_folder_made_at_high_is_reached_from_below_high() {
    use std::io::Read as _;

    account::assert_elevated();
    let record = |text: String| account::hive::record(&format!("SPIKE5 Q2: {text}"));
    let me = Sid::current_user().unwrap();
    let profile = StandInProfile::new("s5");
    let loc = profile.location();
    let own = ssh_broker::winutil::own_token().unwrap();
    record(format!(
        "this process: integrity {:#x}, elevation {:?}; stand-in profile {}",
        ssh_broker::account::integrity_of(own.0).unwrap(),
        ssh_broker::account::elevation_of(own.0).unwrap(),
        profile.0.display()
    ));

    let made = userdir::ensure_socket_dir(&loc, &me);
    record(format!(
        "userdir::ensure_socket_dir for Integrity::Medium made {}: {}",
        loc.dir().display(),
        made.as_ref()
            .map_or_else(|e| format!("failed: {e:#}"), |()| "ok".to_owned())
    ));
    record(format!(
        "the plain folder: dir ACL as the product verifies it (verify_dir_acl, Medium): {:?}; security {}",
        acl::verify_dir_acl(loc.dir(), &me, Integrity::Medium).map_err(|e| format!("{e:#}")),
        dacl_and_label_sddl(loc.dir())
    ));

    let socket = loc.dir().join("request.sock");
    let bound = Listener::bind(&socket, Integrity::Medium);
    record(format!(
        "Listener::bind({}, Integrity::Medium) with its own check of the socket file (socket_file_acl_ok): {}",
        socket.display(),
        bound.as_ref().map_or_else(
            |e| format!("failed: {e:#}"),
            |_| "passed, the listener is up".to_owned()
        )
    ));
    record(format!(
        "the socket file: verify_file_acl (the body of socket_file_acl_ok), Medium: {:?}",
        acl::verify_file_acl(&socket, &me, Integrity::Medium).map_err(|e| format!("{e:#}"))
    ));
    let label = sddl_of(&socket, LABEL_SECURITY_INFORMATION);
    record(format!(
        "the socket file's mandatory label as Windows reports it: {label:?} (an ML ACE present: {}); DACL and label: {}",
        label.contains("(ML;"),
        dacl_and_label_sddl(&socket)
    ));
    let listener = bound.expect("the listener bound: the measurement cannot run without it");

    let token = ssh_broker::winutil::UnelevatedToken::of_this_process().expect("make the unelevated token");
    let dir = profile.0.join("pair-s5");
    std::fs::create_dir(&dir).unwrap();
    child_entry::write_input(&dir, &socket.display().to_string());
    let exe = std::env::current_exe().unwrap();
    let line = child_entry::command_line(&exe, "spike5_q2_child_connects_and_sends_one_byte", &dir);
    let child = ssh_broker::pipes::ExecChild::spawn(&line, None, Some(&token)).expect("start the child on pipes");
    let (out, err) = (
        drain::drain(child.stdout_read_raw()),
        drain::drain(child.stderr_read_raw()),
    );
    // The child ends by itself when it is refused; when it connects, it publishes first and waits for us.
    file_signal::wait_for_file(
        &child_entry::result_path(&dir),
        None,
        Some(bounded_wait::CHILD_EXIT_BOUND),
        "the child's result",
    );
    let result = child_entry::result(&dir);
    for line in result.lines() {
        record(format!("child: {line}"));
    }
    if fact(&result, "connect") == "connected" {
        let connection = listener.accept();
        record(format!(
            "the listener accepted: {}",
            connection.as_ref().map_or_else(|e| e.to_string(), |_| "ok".to_owned())
        ));
        if let Ok(mut connection) = connection {
            let mut byte = [0u8; 1];
            let read = connection.read(&mut byte);
            record(format!("the listener read one byte: {read:?}, byte {byte:#x?}"));
        }
    }
    let waited = child.wait();
    let said = format!("{}{}", drain::text_of(out), drain::text_of(err));
    record(format!("the child ended with {waited:?}; it said:\n{said}"));
    waited.expect("wait for the child");
}
