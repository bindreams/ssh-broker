//! Tests for `layout`. Windows-only, like the module.
use super::*;
use crate::acl::{self, Sid};
use crate::provision::config::Config;
use std::sync::atomic::{AtomicUsize, Ordering};

/// A not-yet-created base directory under the temp dir that is removed on drop.
struct TempBase(PathBuf);

impl TempBase {
    fn new(tag: &str) -> TempBase {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        TempBase(std::env::temp_dir().join(format!("ssh-broker-layout-{tag}-{}-{n}", std::process::id())))
    }
    fn layout(&self) -> Layout {
        Layout { base: self.0.clone() }
    }
}

impl Drop for TempBase {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn names_in(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn production_socket_dir_matches_afunix() {
    assert_eq!(Layout::production().socket_dir(), crate::afunix::socket_dir());
}

#[test]
fn production_logs_dir_matches_shim_pty() {
    assert_eq!(Layout::production().logs_dir(), crate::shim_pty::log_dir());
}

#[test]
fn ensure_base_writes_nothing_into_a_hostile_preexisting_base() {
    let base = TempBase::new("hostile");
    std::fs::create_dir_all(&base.0).unwrap();
    std::fs::write(base.0.join("planted.txt"), "x").unwrap();

    let err = format!("{:#}", ensure_base(&base.layout()).unwrap_err());

    assert!(err.contains(&base.0.display().to_string()), "{err}");
    assert_eq!(names_in(&base.0), ["planted.txt"], "ensure_base must not write into it");
}

#[test]
fn resolve_user_fails_at_ensure_base_before_it_reads_config() {
    let base = TempBase::new("order");
    std::fs::create_dir_all(&base.0).unwrap();
    std::fs::write(
        base.0.join("config.toml"),
        Config {
            target_user: "planted-user".into(),
        }
        .to_toml()
        .unwrap(),
    )
    .unwrap();

    // Read first, the planted config would supply "planted-user" and this would be Ok.
    let err = format!("{:#}", resolve_user(&base.layout(), None, None).unwrap_err());

    assert!(err.contains(&base.0.display().to_string()), "{err}");
}

#[test]
fn resolve_user_reads_the_saved_config_of_a_hardened_base() {
    let base = TempBase::new("saved");
    let layout = base.layout();
    ensure_base(&layout).unwrap();
    std::fs::write(
        layout.config_path(),
        Config {
            target_user: "saved-user".into(),
        }
        .to_toml()
        .unwrap(),
    )
    .unwrap();

    assert_eq!(resolve_user(&layout, None, None).unwrap(), "saved-user");
    assert_eq!(resolve_user(&layout, Some("cli-user"), None).unwrap(), "cli-user");
}

#[test]
fn populate_builds_a_verified_layout() {
    let base = TempBase::new("populate");
    let layout = base.layout();
    let me = Sid::current_user().unwrap();
    ensure_base(&layout).unwrap();

    let exe = populate(&layout, &std::env::current_exe().unwrap(), "layout-test-user", &me).unwrap();

    assert_eq!(exe, layout.canonical_exe());
    assert!(exe.is_file());
    assert!(acl::verify_install_dir_acl(&layout.base).unwrap());
    assert!(acl::verify_dir_acl(&layout.socket_dir(), &me).unwrap());
    let saved = Config::from_toml(&std::fs::read_to_string(layout.config_path()).unwrap()).unwrap();
    assert_eq!(saved.target_user, "layout-test-user");

    // logs\ inherits the install directory DACL: Users read and execute, nothing that writes.
    assert!(layout.logs_dir().is_dir());
    let out = std::process::Command::new("icacls")
        .arg(layout.logs_dir())
        .output()
        .expect("run icacls");
    let listing = String::from_utf8_lossy(&out.stdout).into_owned();
    let users: Vec<&str> = listing.lines().filter(|l| l.contains(r"BUILTIN\Users")).collect();
    assert_eq!(users.len(), 1, "expected one Users ACE in:\n{listing}");
    for write_right in ["(F)", "(M)", "(W)", "(WD)", "(AD)", "(DC)"] {
        assert!(
            !users[0].contains(write_right),
            "Users must not write to the logs directory: {listing}"
        );
    }
}
