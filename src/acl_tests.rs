//! Unit tests for the `acl` module. Windows-only (the module is `#[cfg(windows)]`);
//! they run on a real Windows host via the cross-compile -> scp -> run loop and fail loudly if the
//! ACL primitives are broken (no skip-on-missing).
use super::*;

#[test]
fn current_user_sid_resolves() {
    assert!(Sid::current_user().is_ok());
}

#[test]
fn well_known_sids_resolve() {
    assert!(Sid::well_known(WellKnown::System).is_ok());
    assert!(Sid::well_known(WellKnown::Administrators).is_ok());
}

#[test]
fn harden_then_verify_roundtrips() {
    let dir = std::env::temp_dir().join(format!("ssh-broker-acltest-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let me = Sid::current_user().unwrap();
    harden_dir(&dir, &me).unwrap();
    assert!(verify_dir_acl(&dir, &me).unwrap(), "a freshly hardened dir must verify");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn unhardened_dir_does_not_verify() {
    // A default temp dir carries inherited/broad perms (not PROTECTED); the exact-match
    // verifier must reject it.
    let dir = std::env::temp_dir().join(format!("ssh-broker-acl-bad-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let me = Sid::current_user().unwrap();
    assert!(
        !verify_dir_acl(&dir, &me).unwrap(),
        "an un-hardened dir must NOT verify"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn hardened_dir_with_extra_everyone_ace_does_not_verify() {
    // The load-bearing security assertion: after hardening, injecting an over-broad
    // Everyone:F grant must break verification (the verifier rejects any grantee outside
    // {target, SYSTEM, Administrators}). This is the local-EoP vector the ACL prevents.
    let dir = std::env::temp_dir().join(format!("ssh-broker-acl-eve-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let me = Sid::current_user().unwrap();
    harden_dir(&dir, &me).unwrap();
    assert!(
        verify_dir_acl(&dir, &me).unwrap(),
        "sanity: a freshly hardened dir must verify before we corrupt it"
    );

    // Add an explicit Everyone (S-1-1-0) Full-Control ACE; the protected DACL is kept.
    let status = std::process::Command::new("icacls")
        .arg(&dir)
        .arg("/grant")
        .arg("*S-1-1-0:(OI)(CI)F")
        .status()
        .expect("run icacls");
    assert!(status.success(), "icacls /grant should succeed");

    assert!(
        !verify_dir_acl(&dir, &me).unwrap(),
        "a dir granting Everyone must NOT verify"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn hardened_dir_with_deny_ace_does_not_verify() {
    // A DENY ACE (any) must break the exact-match (all-ALLOW) verifier.
    let dir = std::env::temp_dir().join(format!("ssh-broker-acl-deny-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let me = Sid::current_user().unwrap();
    harden_dir(&dir, &me).unwrap();
    let status = std::process::Command::new("icacls")
        .arg(&dir)
        .arg("/deny")
        .arg("*S-1-1-0:(F)")
        .status()
        .expect("run icacls");
    assert!(status.success(), "icacls /deny should succeed");
    assert!(
        !verify_dir_acl(&dir, &me).unwrap(),
        "a DENY ACE must break verification"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn hardened_dir_with_inheritance_enabled_does_not_verify() {
    // Re-enabling inheritance clears the PROTECTED flag and merges inherited parent ACEs;
    // the verifier must reject the now-non-protected DACL.
    let dir = std::env::temp_dir().join(format!("ssh-broker-acl-inh-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let me = Sid::current_user().unwrap();
    harden_dir(&dir, &me).unwrap();
    let status = std::process::Command::new("icacls")
        .arg(&dir)
        .arg("/inheritance:e")
        .status()
        .expect("run icacls");
    assert!(status.success(), "icacls /inheritance:e should succeed");
    assert!(
        !verify_dir_acl(&dir, &me).unwrap(),
        "a non-protected (inheritance-enabled) DACL must NOT verify"
    );
    std::fs::remove_dir_all(&dir).ok();
}

// install directory ------------------------------------------------------------------

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use windows::Win32::Foundation::{ERROR_SUCCESS, GetLastError, LUID};
use windows::Win32::Security::{
    AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED, SE_RESTORE_NAME,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
};

/// A not-yet-created path under the temp dir that is removed on drop.
struct TempPath(PathBuf);

impl TempPath {
    fn new(tag: &str) -> TempPath {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        TempPath(std::env::temp_dir().join(format!("ssh-broker-install-{tag}-{}-{n}", std::process::id())))
    }
}

impl Drop for TempPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn icacls(args: &[&std::ffi::OsStr]) -> String {
    let out = Command::new("icacls").args(args).output().expect("run icacls");
    assert!(
        out.status.success(),
        "icacls {args:?} failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn icacls_str(dir: &Path, rest: &[&str]) -> String {
    let mut args: Vec<&std::ffi::OsStr> = vec![dir.as_os_str()];
    args.extend(rest.iter().map(std::ffi::OsStr::new));
    icacls(&args)
}

/// A fresh install directory that `ensure_install_dir` made.
fn hardened_install_dir(tag: &str) -> TempPath {
    let dir = TempPath::new(tag);
    ensure_install_dir(&dir.0).unwrap();
    assert!(
        verify_install_dir_acl(&dir.0).unwrap(),
        "sanity: a fresh install dir must verify"
    );
    dir
}

#[test]
fn ensure_install_dir_creates_a_directory_that_verifies() {
    let dir = TempPath::new("create");
    ensure_install_dir(&dir.0).unwrap();
    assert!(dir.0.is_dir());
    assert!(verify_install_dir_acl(&dir.0).unwrap());
}

#[test]
fn ensure_install_dir_accepts_its_own_previous_result() {
    let dir = hardened_install_dir("again");
    let before = icacls_str(&dir.0, &[]);
    ensure_install_dir(&dir.0).unwrap();
    assert_eq!(icacls_str(&dir.0, &[]), before, "the DACL must not change");
    assert!(verify_install_dir_acl(&dir.0).unwrap());
}

#[test]
fn ensure_install_dir_rejects_a_default_inherited_directory_and_leaves_it_unchanged() {
    let dir = TempPath::new("default");
    std::fs::create_dir_all(&dir.0).unwrap();
    let before = icacls_str(&dir.0, &[]);

    let err = format!("{:#}", ensure_install_dir(&dir.0).unwrap_err());

    assert!(
        err.contains(&dir.0.display().to_string()),
        "the error must name the directory: {err}"
    );
    assert!(err.contains("owner"), "the error must name the owner found: {err}");
    assert!(err.contains("remove"), "the error must say how to fix it: {err}");
    assert_eq!(icacls_str(&dir.0, &[]), before, "the DACL must be left unchanged");
    assert_eq!(
        std::fs::read_dir(&dir.0).unwrap().count(),
        0,
        "nothing may be written into it"
    );
}

/// Give `dir` the install-directory policy ([`INSTALL_DIR_SDDL`]) with `owner` as its owner.
/// Setting an owner other than the caller's needs SeRestorePrivilege, so the caller enables it.
fn set_install_policy(dir: &Path, owner: &Sid) {
    set_security(
        dir,
        &INSTALL_DIR_SDDL.replace("O:BA", &format!("O:{}", owner.to_sddl().unwrap())),
    );
}

/// Replace `dir`'s owner and protected DACL with those of `sddl`.
fn set_security(dir: &Path, sddl: &str) {
    let sddl_w: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
    let path_w = wide(dir);
    unsafe {
        let mut psd = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(sddl_w.as_ptr()), SDDL_REVISION_1, &mut psd, None)
            .unwrap();
        let _sd = LocalSd(psd);
        let (mut present, mut defaulted) = (BOOL(0), BOOL(0));
        let mut dacl: *mut ACL = std::ptr::null_mut();
        GetSecurityDescriptorDacl(psd, &mut present, &mut dacl, &mut defaulted).unwrap();
        let mut sd_owner = PSID::default();
        GetSecurityDescriptorOwner(psd, &mut sd_owner, &mut defaulted).unwrap();
        SetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
            Some(sd_owner),
            None,
            Some(dacl as *const ACL),
            None,
        )
        .ok()
        .unwrap();
    }
}

/// Enable SeRestorePrivilege on this process token (held, disabled, by an elevated administrator).
fn enable_restore_privilege() {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token).unwrap();
        let _token = OwnedHandle(token);
        let mut luid = LUID::default();
        LookupPrivilegeValueW(PCWSTR::null(), SE_RESTORE_NAME, &mut luid).unwrap();
        let privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        AdjustTokenPrivileges(token, false, Some(&privileges), 0, None, None).unwrap();
        // AdjustTokenPrivileges succeeds even when it assigned nothing; that case is an error here.
        assert_eq!(
            GetLastError(),
            ERROR_SUCCESS,
            "SeRestorePrivilege is not held: run elevated"
        );
    }
}

#[test]
fn install_dir_problem_blames_only_the_owner_of_an_otherwise_exact_directory() {
    // Host-safe: the owner is this user, who is not Administrators.
    let dir = TempPath::new("owner-me");
    std::fs::create_dir(&dir.0).unwrap();
    let me = Sid::current_user().unwrap();
    set_install_policy(&dir.0, &me);

    let problem = install_dir_problem(&dir.0)
        .unwrap()
        .expect("a foreign owner is a problem");
    assert!(
        problem.contains(&me.to_sddl().unwrap()),
        "it must name the owner found: {problem}"
    );
    assert!(
        problem.contains("Administrators"),
        "it must name the owner wanted: {problem}"
    );
    assert!(
        !problem.contains("ACL is not") && !problem.contains("not the hardened"),
        "the ACL is exact, so the message must not blame it: {problem}"
    );
}

/// Elevated (CI only): setting an owner other than the caller's needs SeRestorePrivilege.
#[test]
fn a_trusted_owner_is_accepted_and_a_users_owner_is_refused_with_the_same_acl() {
    let dir = TempPath::new("owner-control");
    std::fs::create_dir(&dir.0).unwrap();
    enable_restore_privilege();

    set_install_policy(&dir.0, &Sid::well_known(WellKnown::Administrators).unwrap());
    assert!(
        verify_install_dir_acl(&dir.0).unwrap(),
        "control: the policy with an Administrators owner must verify"
    );
    assert_eq!(install_dir_problem(&dir.0).unwrap(), None);

    set_install_policy(&dir.0, &Sid::well_known(WellKnown::Users).unwrap());
    assert!(
        !verify_install_dir_acl(&dir.0).unwrap(),
        "the same policy with a Users owner must not verify"
    );
    assert!(install_dir_problem(&dir.0).unwrap().is_some());
}

#[test]
fn ensure_install_dir_rejects_a_users_owned_directory_with_the_exact_acl() {
    let dir = hardened_install_dir("owner-users");
    enable_restore_privilege();
    set_install_policy(&dir.0, &Sid::well_known(WellKnown::Users).unwrap());
    assert!(
        !verify_install_dir_acl(&dir.0).unwrap(),
        "a Users-owned dir must not verify"
    );
    assert!(ensure_install_dir(&dir.0).is_err());
}

/// Elevated (CI only). `create_install_dir` is nothing but the creation call, so a directory that
/// verifies the moment it returns got its final DACL from that call and not from a later step.
#[test]
fn create_install_dir_gives_the_directory_its_final_acl_at_creation() {
    let dir = TempPath::new("at-creation");
    create_install_dir(&dir.0).unwrap();
    assert!(
        verify_install_dir_acl(&dir.0).unwrap(),
        "the directory must verify straight after the creation call"
    );
}

/// Elevated (CI only). Races an observer against creation; the deterministic check above is the
/// one that pins the property, this one catches a window the creation call itself opens.
#[test]
fn ensure_install_dir_is_never_observable_unhardened() {
    const ROUNDS: usize = 200;
    let checked = AtomicUsize::new(0);
    for _ in 0..ROUNDS {
        let dir = TempPath::new("atomic");
        let start = std::sync::Barrier::new(2);
        let done = std::sync::atomic::AtomicBool::new(false);
        std::thread::scope(|s| {
            let observer = s.spawn(|| {
                start.wait();
                // Re-checks the real condition; once creation is over it looks one last time.
                while !dir.0.exists() {
                    if done.load(Ordering::Acquire) {
                        if !dir.0.exists() {
                            return;
                        }
                        break;
                    }
                    std::hint::spin_loop();
                }
                assert!(
                    verify_install_dir_acl(&dir.0).unwrap(),
                    "the directory was observable before it was hardened"
                );
                checked.fetch_add(1, Ordering::Relaxed);
            });
            start.wait();
            let created = ensure_install_dir(&dir.0);
            done.store(true, Ordering::Release);
            created.unwrap();
            observer.join().unwrap();
        });
    }
    assert!(
        checked.load(Ordering::Relaxed) >= 1,
        "the observer never saw a directory, so nothing was checked"
    );
}

#[test]
fn ensure_install_dir_rejects_a_junction() {
    let target = hardened_install_dir("junction-target");
    let link = TempPath::new("junction");
    let out = Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&link.0)
        .arg(&target.0)
        .output()
        .expect("run mklink");
    assert!(
        out.status.success(),
        "mklink /J failed: {}",
        String::from_utf8_lossy(&out.stdout)
    );

    let err = format!("{:#}", ensure_install_dir(&link.0).unwrap_err());
    assert!(err.contains("reparse point"), "the error must say why: {err}");

    // Remove the junction itself before `target` goes, never through it.
    std::fs::remove_dir(&link.0).unwrap();
    assert!(target.0.is_dir());
}

#[test]
fn verify_install_dir_acl_rejects_an_added_users_write_grant() {
    let dir = hardened_install_dir("users-write");
    icacls_str(&dir.0, &["/grant", "*S-1-5-32-545:(OI)(CI)M"]);
    assert!(!verify_install_dir_acl(&dir.0).unwrap());
}

#[test]
fn verify_install_dir_acl_rejects_an_extra_grantee() {
    let dir = hardened_install_dir("everyone");
    icacls_str(&dir.0, &["/grant", "*S-1-1-0:(OI)(CI)(R)"]);
    assert!(!verify_install_dir_acl(&dir.0).unwrap());
}

#[test]
fn verify_install_dir_acl_rejects_a_deny_ace() {
    let dir = hardened_install_dir("deny");
    icacls_str(&dir.0, &["/deny", "*S-1-1-0:(W)"]);
    assert!(!verify_install_dir_acl(&dir.0).unwrap());
}

#[test]
fn verify_install_dir_acl_rejects_a_non_inheritable_ace() {
    let dir = hardened_install_dir("noninherit");
    // Same grantee and mask as the policy's Users ACE, but without OI/CI.
    icacls_str(&dir.0, &["/remove:g", "*S-1-5-32-545"]);
    icacls_str(&dir.0, &["/grant", "*S-1-5-32-545:(RX)"]);
    assert!(!verify_install_dir_acl(&dir.0).unwrap());
}

#[test]
fn verify_install_dir_acl_rejects_a_missing_users_grant() {
    let dir = hardened_install_dir("nousers");
    icacls_str(&dir.0, &["/remove:g", "*S-1-5-32-545"]);
    assert!(!verify_install_dir_acl(&dir.0).unwrap());
}

#[test]
fn verify_install_dir_acl_rejects_enabled_inheritance() {
    let dir = hardened_install_dir("inherit");
    icacls_str(&dir.0, &["/inheritance:e"]);
    assert!(!verify_install_dir_acl(&dir.0).unwrap());
}

#[test]
fn ensure_install_dir_is_safe_under_concurrent_callers() {
    const CALLERS: usize = 8;
    let dir = TempPath::new("race");
    let start = std::sync::Barrier::new(CALLERS);
    std::thread::scope(|s| {
        let handles: Vec<_> = (0..CALLERS)
            .map(|_| {
                s.spawn(|| {
                    start.wait();
                    ensure_install_dir(&dir.0)
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap().unwrap();
        }
    });
    assert!(verify_install_dir_acl(&dir.0).unwrap());
}

/// Elevated (CI only): setting an owner other than the caller's needs SeRestorePrivilege.
#[test]
fn a_system_owned_directory_with_the_exact_acl_is_refused() {
    let dir = TempPath::new("owner-system");
    std::fs::create_dir(&dir.0).unwrap();
    enable_restore_privilege();
    set_install_policy(&dir.0, &Sid::well_known(WellKnown::System).unwrap());

    let problem = install_dir_problem(&dir.0)
        .unwrap()
        .expect("only Administrators may own the install directory");
    assert!(problem.contains("Administrators"), "{problem}");
    assert!(!problem.contains("not the hardened"), "{problem}");
    assert!(ensure_install_dir(&dir.0).is_err());
}

fn ace_count(dir: &Path) -> u32 {
    let security = Security::from_path(dir).unwrap();
    let mut info = ACL_SIZE_INFORMATION::default();
    unsafe {
        GetAclInformation(
            security.dacl,
            &mut info as *mut _ as *mut core::ffi::c_void,
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
        .unwrap();
    }
    info.AceCount
}

/// Elevated (CI only). The policy with one ACE changed, owned as `ensure_install_dir` owns it.
fn assert_refused_with_acl_problem(tag: &str, sddl: String) {
    assert_ne!(sddl, INSTALL_DIR_SDDL, "the test must change the policy");
    let dir = TempPath::new(tag);
    std::fs::create_dir(&dir.0).unwrap();
    enable_restore_privilege();
    set_security(&dir.0, &sddl);
    assert_eq!(
        ace_count(&dir.0) as usize,
        sddl.matches("(A;").count(),
        "the DACL must keep every ACE"
    );

    assert!(!verify_install_dir_acl(&dir.0).unwrap(), "{sddl} must not verify");
    let problem = install_dir_problem(&dir.0).unwrap().expect("a problem");
    assert!(problem.contains("ACL is not the hardened one"), "{problem}");
    assert!(
        !problem.contains("not the Administrators"),
        "the owner is fine: {problem}"
    );
}

#[test]
fn verify_install_dir_acl_rejects_a_reduced_mask_for_system() {
    assert_refused_with_acl_problem(
        "mask-sy",
        INSTALL_DIR_SDDL.replace("(A;OICI;FA;;;SY)", "(A;OICI;FRFX;;;SY)"),
    );
}

#[test]
fn verify_install_dir_acl_rejects_a_reduced_mask_for_administrators() {
    assert_refused_with_acl_problem(
        "mask-ba",
        INSTALL_DIR_SDDL.replace("(A;OICI;FA;;;BA)", "(A;OICI;FRFX;;;BA)"),
    );
}

#[test]
fn verify_install_dir_acl_rejects_a_duplicate_ace() {
    let sddl = INSTALL_DIR_SDDL.replace("(A;OICI;FA;;;SY)", "(A;OICI;FA;;;SY)(A;OICI;FA;;;SY)");
    assert_refused_with_acl_problem("dup", sddl);
}

#[test]
fn ensure_install_dir_rejects_a_regular_file() {
    let path = TempPath::new("file");
    std::fs::write(&path.0, "x").unwrap();

    let err = format!("{:#}", ensure_install_dir(&path.0).unwrap_err());

    assert!(err.contains("not a directory"), "{err}");
    assert_eq!(std::fs::read_to_string(&path.0).unwrap(), "x");
    std::fs::remove_file(&path.0).unwrap();
}

#[test]
fn ensure_install_dir_reports_a_missing_parent_as_a_creation_error() {
    let parent = TempPath::new("no-parent");
    let dir = parent.0.join("child");

    let err = format!("{:#}", ensure_install_dir(&dir).unwrap_err());

    assert!(err.contains("create the install directory"), "{err}");
    assert!(!parent.0.exists(), "no parent may be created on the way");
}

/// Needs symlink creation rights (an elevated administrator or Developer Mode).
#[test]
fn ensure_install_dir_rejects_a_symlink() {
    let target = hardened_install_dir("symlink-target");
    let link = TempPath::new("symlink");
    std::os::windows::fs::symlink_dir(&target.0, &link.0)
        .expect("create a directory symlink: needs an elevated administrator or Developer Mode");

    let err = format!("{:#}", ensure_install_dir(&link.0).unwrap_err());
    assert!(err.contains("reparse point"), "the error must say why: {err}");

    std::fs::remove_dir(&link.0).unwrap();
    assert!(target.0.is_dir());
}

// A hostile directory must be refused with a reason, not fail the inspection itself ------

/// A plain directory this user owns (no elevation needed), with the deny ACE a local attacker
/// would plant. `/deny (W)` includes SYNCHRONIZE, which `CreateFileW` always requests.
fn plain_dir_denying(tag: &str) -> TempPath {
    let dir = TempPath::new(tag);
    std::fs::create_dir(&dir.0).unwrap();
    icacls_str(&dir.0, &["/deny", "*S-1-1-0:(W)"]);
    dir
}

#[test]
fn install_dir_problem_is_reported_for_a_dir_denying_everyone_write() {
    let dir = plain_dir_denying("deny-w");
    assert!(
        open_for_inspection(&dir.0).unwrap().is_some(),
        "the deny covers SYNCHRONIZE, which the inspection open must not request"
    );
    let problem = install_dir_problem(&dir.0).unwrap().expect("a deny ACE is a problem");
    assert!(problem.contains("not the hardened one"), "{problem}");
    icacls_str(&dir.0, &["/remove:d", "*S-1-1-0"]);
}

/// Elevated (CI only): the owner is SYSTEM, so this user has no implicit READ_CONTROL, and the
/// DACL denies it to everyone. Administrators keep DELETE and listing so the test can clean up.
#[test]
fn install_dir_problem_says_so_when_the_acl_cannot_be_read() {
    let dir = TempPath::new("no-read-control");
    std::fs::create_dir(&dir.0).unwrap();
    enable_restore_privilege();
    set_security(&dir.0, "O:SYD:P(D;;RC;;;WD)(A;;0x10001;;;BA)(A;;FA;;;SY)");

    assert!(open_for_inspection(&dir.0).unwrap().is_none());
    let problem = install_dir_problem(&dir.0)
        .unwrap()
        .expect("an unreadable ACL is a problem");
    assert!(problem.contains("denied access to read its ACL"), "{problem}");
    assert!(ensure_install_dir(&dir.0).is_err());
}

#[test]
fn nt_path_prefixes_each_win32_path_form() {
    let nt = |p: &str| String::from_utf16(&nt_path(Path::new(p)).unwrap()).unwrap();
    assert_eq!(nt(r"C:\a\b"), r"\??\C:\a\b");
    assert_eq!(nt(r"\\?\C:\a\b"), r"\??\C:\a\b");
    assert_eq!(nt(r"\\.\C:\a\b"), r"\??\C:\a\b");
    assert_eq!(nt(r"\\server\share\a"), r"\??\UNC\server\share\a");
    assert_eq!(nt(r"\\?\UNC\server\share\a"), r"\??\UNC\server\share\a");
}
