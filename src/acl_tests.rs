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

#[test]
fn ensure_install_dir_rejects_a_foreign_owner() {
    let dir = hardened_install_dir("owner");
    // Needs SeRestorePrivilege, which icacls enables when the token holds it.
    icacls_str(&dir.0, &["/setowner", "*S-1-5-32-545"]);
    assert!(
        !verify_install_dir_acl(&dir.0).unwrap(),
        "a Users-owned dir must not verify"
    );
    assert!(ensure_install_dir(&dir.0).is_err());
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

#[test]
fn is_trusted_install_owner_accepts_only_system_and_administrators() {
    let sid = |s: &str| Sid::lookup(s).unwrap();
    assert!(is_trusted_install_owner(&Sid::well_known(WellKnown::System).unwrap()).unwrap());
    assert!(is_trusted_install_owner(&Sid::well_known(WellKnown::Administrators).unwrap()).unwrap());
    assert!(!is_trusted_install_owner(&sid("Users")).unwrap());
    assert!(!is_trusted_install_owner(&sid("Everyone")).unwrap());
    assert!(!is_trusted_install_owner(&Sid::current_user().unwrap()).unwrap());
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
    let problem = install_dir_problem(&dir.0).unwrap().expect("a deny ACE is a problem");
    assert!(problem.contains("not the hardened one"), "{problem}");
    icacls_str(&dir.0, &["/remove:d", "*S-1-1-0"]);
}

#[test]
fn nt_path_prefixes_each_win32_path_form() {
    let nt = |p: &str| String::from_utf16(&nt_path(Path::new(p)).unwrap()).unwrap();
    assert_eq!(nt(r"C:\a\b"), r"\??\C:\a\b");
    assert_eq!(nt(r"\\?\C:\a\b"), r"\??\C:\a\b");
    assert_eq!(nt(r"\\server\share\a"), r"\??\UNC\server\share\a");
    assert_eq!(nt(r"\\?\UNC\server\share\a"), r"\??\UNC\server\share\a");
}
