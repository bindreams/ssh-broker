//! Unit tests for the `acl` module. Windows-only (the module is `#[cfg(windows)]`);
//! they run on winhost via the cross-compile -> scp -> run loop and fail loudly if the
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
    assert!(
        verify_dir_acl(&dir, &me).unwrap(),
        "a freshly hardened dir must verify"
    );
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
