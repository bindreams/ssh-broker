//! Session on demand: the prompt path, the background agent and `logout`. Windows only;
//! **Elevated (CI only)**.
//!
//! These tests create throwaway local accounts, log them on and start processes under them. They
//! need an elevated administrator and refuse to run anywhere else, before they touch anything: run
//! them in CI, never on a workstation. Every test holds `machine::shared()` or
//! `machine::exclusive()` for as long as it touches machine-wide state.
#![cfg(windows)]

use ssh_broker::account::{self, AccountKind};
use ssh_broker::userdir::{self, NoProfile};

#[path = "common/account.rs"]
mod account_fixture;
#[path = "common/bounded_wait.rs"]
mod bounded_wait;
#[path = "common/desktop.rs"]
mod desktop;
#[path = "common/hard_errors.rs"]
mod hard_errors;
#[path = "common/machine.rs"]
mod machine;
#[path = "common/process_list.rs"]
mod process_list;

use account_fixture::Account;

// Account identity ---------------------------------------------------------------------------

/// Elevated (CI only).
#[test]
fn profile_dir_of_token_reports_no_profile_for_an_account_that_never_logged_on() {
    let _machine = machine::shared();
    let never = Account::create("nopro", false);
    let token = never.network_token();
    let err = userdir::profile_dir_of_token(token.0).unwrap_err();
    assert!(
        err.downcast_ref::<NoProfile>().is_some(),
        "an account without a profile must fail with NoProfile, got: {err:#}"
    );
}

/// Elevated (CI only).
#[test]
fn account_named_resolves_a_fixture_account_with_a_space_in_its_name() {
    let _machine = machine::shared();
    let name = format!("sb sp{:x}", std::process::id());
    let fixture = Account::create_named(&name, "Pw-Sp-Aa1!-x", false);
    let resolved = account::account_named(&name).unwrap();
    assert!(resolved.name.eq_ignore_ascii_case(&name), "{} != {name}", resolved.name);
    assert_eq!(resolved.sid, fixture.sid_text);
    assert_eq!(resolved.kind, AccountKind::Local);
}

/// Elevated (CI only).
#[test]
fn is_elevated_is_true_for_the_ci_token() {
    let _machine = machine::shared();
    account_fixture::assert_elevated();
    assert!(account::is_elevated().unwrap());
}
