//! The user's private folder against a link under the profile, where only an elevated administrator
//! or the real `sshd` reaches. Windows only; **Elevated (CI only)**.
//!
//! - An elevated token, which may re-own a folder that an administrator owns (the install directory
//!   is one), must not be led to one by a link at `AppData\Local`: `ensure_socket_dir` refuses and
//!   changes nothing. The unit tests cannot make such a folder.
//! - A session through the runner's real `sshd`, whose shim runs under RedirectionGuard, with each kind
//!   of link at `AppData\Local` (a junction the account made, a junction an administrator made, a
//!   directory symlink): nothing outside the profile changes. The account is a standard one: the rig
//!   puts an account's key in its profile, where sshd does not look for an administrator's, so the shim
//!   of an administrator (an elevated one) is not driven through sshd here.
//!
//! The sshd tests change sshd's `DefaultShell` and take the machine alone (`machine::exclusive()`); the
//! runner is discarded after the job, so it is not put back.
#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use ssh_broker::acl::{Sid, WellKnown};
use ssh_broker::provision::registry::{OPENSSH_KEY, set_default_shell_under};
use ssh_broker::{socket_loc, userdir};

#[path = "common/account.rs"]
mod account_fixture;
#[path = "common/agent_conn.rs"]
mod agent_conn;
#[path = "common/bounded_wait.rs"]
mod bounded_wait;
#[path = "common/desktop.rs"]
mod desktop;
#[path = "common/fs_state.rs"]
mod fs_state;
#[path = "common/hard_errors.rs"]
mod hard_errors;
#[path = "common/logon_session.rs"]
mod logon_session;
#[path = "common/machine.rs"]
mod machine;
#[path = "common/password.rs"]
mod password;
#[path = "common/process_list.rs"]
mod process_list;
#[path = "common/session_end.rs"]
mod session_end;
#[path = "common/sshd_rig.rs"]
mod sshd_rig;
#[path = "common/stand_in.rs"]
mod stand_in;

use account_fixture::{Account, ServiceLogon};
use fs_state::{junction, owner_sid_of, sddl_of, tree_state};
use sshd_rig::{Login, no_shell_to_carry, run_client};
use stand_in::Kit;

// What a test compares =====

/// A stand-in `ssh-broker` folder as an administrator owns it (the install directory's shape): owned
/// by Administrators, with an ACL that gives `BUILTIN\Users` read, which is not the private ACL, and
/// two files in it.
fn administrators_folder(parent: &Path) -> PathBuf {
    let folder = parent.join(socket_loc::SOCKET_DIR_NAME);
    std::fs::create_dir_all(&folder).unwrap();
    let status = Command::new("icacls")
        .arg(&folder)
        .args(["/grant", "*S-1-5-32-545:(OI)(CI)R"])
        .status()
        .unwrap();
    assert!(status.success(), "icacls on {}", folder.display());
    std::fs::write(folder.join(socket_loc::LOCK_FILE_NAME), "kept").unwrap();
    std::fs::write(folder.join("note.txt"), "kept").unwrap();
    let administrators = Sid::well_known(WellKnown::Administrators).unwrap().to_sddl().unwrap();
    assert_eq!(
        owner_sid_of(&folder),
        administrators,
        "the elevated token's default owner is not Administrators, so this folder is not the shape under test: {}",
        sddl_of(&folder)
    );
    folder
}

// Links =====

/// What a link under the profile is, and who made it.
#[derive(Clone, Copy, Debug)]
enum LinkKind {
    /// A junction made by the account's own non-administrator token.
    JunctionByTheAccount,
    /// A junction made by an elevated administrator.
    JunctionByAnAdministrator,
    /// A directory symlink, which only a privileged token can make.
    DirectorySymlink,
}

// The elevated token =====

/// A folder holding a stand-in profile whose `AppData\Local` is a junction, removed on drop: the
/// junction first, so that nothing behind it is touched.
struct LinkedTree(PathBuf);

impl LinkedTree {
    fn profile(&self) -> PathBuf {
        self.0.join("profile")
    }
}

impl Drop for LinkedTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir(self.profile().join(r"AppData\Local"));
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The folder behind `AppData\Local` belongs to an administrator, and the
/// token that calls `ensure_socket_dir` is elevated and so could re-own it. The call refuses, and
/// the folder, its ACL and its files are what they were.
#[test]
fn a_junction_at_local_does_not_let_an_elevated_ensure_reown_an_administrators_folder() {
    account_fixture::assert_elevated();
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let tree = LinkedTree(std::env::temp_dir().join(format!("sb-pe-{}-{n}", std::process::id())));
    let _ = std::fs::remove_dir_all(&tree.0);
    let outside = tree.0.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    administrators_folder(&outside);
    std::fs::create_dir_all(tree.profile().join("AppData")).unwrap();
    junction(&tree.profile().join(r"AppData\Local"), &outside);
    let before = tree_state(&outside);
    let location = socket_loc::for_profile(&tree.profile()).expect("the stand-in profile path is short enough");
    let user = Sid::current_user().unwrap();

    let made = userdir::ensure_socket_dir(&location, &user);
    let looked = userdir::open_existing_socket_dir(&location);

    let outcome = (
        made.as_ref().map_err(|e| format!("{e:#}")),
        looked.as_ref().map(|_| ()).map_err(|e| format!("{e:#}")),
    );
    assert_eq!(
        tree_state(&outside),
        before,
        "the folder behind the link was changed (results: {outcome:?})"
    );
    let made = made.expect_err("a junction at Local must be refused");
    assert!(format!("{made:#}").contains("reparse point"), "{made:#}");
    assert!(
        looked.is_err(),
        "a junction at Local must be refused by the shim's look too"
    );
}

// A session through the real sshd =====

/// Runs `cmd.exe /D /C <what>` as `account` (its non-administrator token) in the kit's folder.
fn cmd_as(account: &Account, kit: &Kit, what: &str) {
    let system_root = std::env::var("SystemRoot").expect("SystemRoot is set");
    let cmd = Path::new(&system_root).join(r"System32\cmd.exe");
    let code = account.run(&cmd, &format!("cmd.exe /D /C {what}"), kit.dir(), &[]);
    assert_eq!(code, 0, "cmd /C {what} as {} exited {code}", account.name);
}

/// Puts the account's real `AppData\Local` back when dropped, so that the profile goes without a
/// link in it.
struct LinkAtLocal {
    local: PathBuf,
    real: PathBuf,
}

impl Drop for LinkAtLocal {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir(&self.local);
        let _ = std::fs::rename(&self.real, &self.local);
    }
}

/// A session through the real sshd, with the shim as `DefaultShell` and `kind` of link at the account's
/// `AppData\Local` leading to a folder the account owns, which is not hardened: the folder an unfixed
/// shim would check and re-ACL if it followed the link. The session runs a command and ends; nothing
/// outside the profile is changed, added or removed. The command ran, so the shim was reached.
fn session_with_a_link_at_local(tag: &str, kind: LinkKind) {
    let _machine = machine::exclusive();
    account_fixture::assert_elevated();
    let kit = Kit::broker_with_helper(tag);
    let account = Account::create(tag, true);
    let _end = session_end::LogOutOnDrop::new(&kit.exe, &account, ServiceLogon::Sshd);

    let outside = kit.path("outside");
    let folder = outside.join(socket_loc::SOCKET_DIR_NAME);
    let (folder, lock, note) = (
        folder.display(),
        folder.join(socket_loc::LOCK_FILE_NAME),
        folder.join("note.txt"),
    );
    cmd_as(
        &account,
        &kit,
        &format!(
            "mkdir {folder}&echo kept>{}&echo kept>{}",
            lock.display(),
            note.display()
        ),
    );

    let local = account.profile().join(r"AppData\Local");
    let real = account.profile().join(r"AppData\Local.real");
    std::fs::rename(&local, &real)
        .unwrap_or_else(|e| panic!("move {} aside (a profile has an AppData\\Local): {e}", local.display()));
    let _link = LinkAtLocal {
        local: local.clone(),
        real,
    };
    match kind {
        LinkKind::JunctionByTheAccount => cmd_as(
            &account,
            &kit,
            &format!("mklink /J {} {}", local.display(), outside.display()),
        ),
        LinkKind::JunctionByAnAdministrator => junction(&local, &outside),
        LinkKind::DirectorySymlink => std::os::windows::fs::symlink_dir(&outside, &local)
            .unwrap_or_else(|e| panic!("symlink {} -> {}: {e}", local.display(), outside.display())),
    }
    let before = tree_state(&outside);

    set_default_shell_under(OPENSSH_KEY, &kit.exe.to_string_lossy(), &no_shell_to_carry())
        .expect("set the shim as DefaultShell");
    let login = Login::new(&kit, &account);
    let mut ssh = login.command();
    ssh.arg("-T").arg("--").arg("echo sb-session-ran");
    let outcome = run_client(ssh, false, kit.dir());
    let shown = String::from_utf8_lossy(&outcome.stdout).into_owned();
    assert!(
        outcome.code == Some(0) && shown.contains("sb-session-ran"),
        "{kind:?}: the command did not run through the shim (exit {:?}); stdout:\n{shown}\nstderr:\n{}\n{}",
        outcome.code,
        outcome.stderr,
        (login.diagnostics())()
    );

    assert_eq!(
        tree_state(&outside),
        before,
        "{kind:?}: something outside the profile was changed"
    );
}

#[test]
fn a_junction_the_account_made_at_local_changes_nothing_outside_the_profile_in_a_session() {
    session_with_a_link_at_local("lnka", LinkKind::JunctionByTheAccount);
}

#[test]
fn a_junction_an_administrator_made_at_local_changes_nothing_outside_the_profile_in_a_session() {
    session_with_a_link_at_local("lnkb", LinkKind::JunctionByAnAdministrator);
}

#[test]
fn a_directory_symlink_at_local_changes_nothing_outside_the_profile_in_a_session() {
    session_with_a_link_at_local("lnkc", LinkKind::DirectorySymlink);
}
