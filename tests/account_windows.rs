//! The identity ssh-broker prompts for comes from the process token and from nothing else. Windows
//! only. Creates no account and logs nobody on, so it is safe to run on a workstation.
#![cfg(windows)]

use std::process::Command;

use ssh_broker::account::current_account;

#[path = "common/child_entry.rs"]
mod child_entry;

/// The user name `whoami` prints (`DOMAIN\name`), without the domain.
fn whoami_name() -> String {
    let out = Command::new("whoami").output().expect("run whoami");
    assert!(out.status.success(), "whoami failed: {out:?}");
    let text = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    text.rsplit_once('\\').map_or(text.clone(), |(_, name)| name.to_owned())
}

#[test]
fn current_account_name_matches_whoami_all() {
    let account = current_account().unwrap();
    assert!(
        account.name.eq_ignore_ascii_case(&whoami_name()),
        "{} != {}",
        account.name,
        whoami_name()
    );
    assert!(account.sid.starts_with("S-1-"), "{}", account.sid);
}

/// Parent half: the child runs with a `USERNAME` that names nobody.
#[test]
fn current_account_ignores_the_username_variable() {
    let dir = std::env::temp_dir().join(format!("sb-acct-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    child_entry::write_input(&dir, &whoami_name());
    let status = Command::new(std::env::current_exe().unwrap())
        .args(child_entry::args(
            "current_account_ignores_the_username_variable_child",
            &dir,
        ))
        .env("USERNAME", "not-this-user")
        .status()
        .unwrap();
    assert!(status.success(), "the child half failed: {status}");
    assert_eq!(child_entry::result(&dir), "ok");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[ignore = "child half of current_account_ignores_the_username_variable"]
fn current_account_ignores_the_username_variable_child() {
    let dir = child_entry::dir();
    let expected = child_entry::input(&dir);
    assert_eq!(std::env::var("USERNAME").unwrap(), "not-this-user");
    let account = current_account().unwrap();
    assert!(
        account.name.eq_ignore_ascii_case(&expected),
        "{} != {expected}",
        account.name
    );
    child_entry::write_result(&dir, "ok");
}
