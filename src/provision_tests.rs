//! Host tests for `apply`'s argument handling.
use super::*;

fn args(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

#[test]
fn check_apply_args_accepts_no_arguments_without_a_warning() {
    assert_eq!(check_apply_args(&[]).unwrap(), Vec::<String>::new());
}

#[test]
fn check_apply_args_accepts_the_removed_user_flag_with_a_warning() {
    // The old boot-time self-heal task runs `apply --user <name>`. During a half-done migration
    // it still does, with the new exe, and it must still repair the install.
    let warnings = check_apply_args(&args(&["--user", "someone"])).unwrap();
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(warnings[0].contains("--user"), "{}", warnings[0]);
    assert!(warnings[0].contains("per logged-on user"), "{}", warnings[0]);
    assert!(
        !warnings[0].contains("someone"),
        "the account is not echoed: {}",
        warnings[0]
    );
}

#[test]
fn check_apply_args_ignores_the_value_of_the_removed_user_flag() {
    // The value is not an argument of its own, and is not an error.
    assert!(check_apply_args(&args(&["--user", "Two Words"])).is_ok());
    assert!(
        check_apply_args(&args(&["--user"])).is_ok(),
        "a bare flag is ignored too"
    );
}

#[test]
fn check_apply_args_refuses_any_other_argument() {
    let err = check_apply_args(&args(&["--force"])).unwrap_err().to_string();
    assert!(err.contains("--force"), "{err}");
    let err = check_apply_args(&args(&["--user", "x", "stray"]))
        .unwrap_err()
        .to_string();
    assert!(err.contains("stray"), "{err}");
}

// The shell config row and the probe =====

use crate::shell::test_host::{TestHost, USER_CONFIG};

#[test]
fn the_shell_config_row_passes_with_the_program_and_its_origin() {
    let host = TestHost::new()
        .with_program("pwsh.exe", r"C:\p\pwsh.exe")
        .with_user_config("shell: pwsh.exe\n");
    let row = shell_config_row(&crate::shell::effective(&host));
    assert!(row.pass, "{}", row.detail);
    assert_eq!(row.name, "shell config");
    assert!(
        row.detail.contains(r"C:\p\pwsh.exe") && row.detail.contains(USER_CONFIG),
        "{}",
        row.detail
    );

    let built_in = shell_config_row(&crate::shell::effective(&TestHost::new()));
    assert!(
        built_in.pass && built_in.detail.contains("built-in"),
        "{}",
        built_in.detail
    );
}

#[test]
fn the_shell_config_row_fails_only_when_a_fallback_is_in_effect() {
    let broken = TestHost::new().with_user_config("shell: {strt: x}\n");
    let row = shell_config_row(&crate::shell::effective(&broken));
    assert!(!row.pass);
    assert!(
        row.detail.contains(USER_CONFIG) && row.detail.contains("strt"),
        "{}",
        row.detail
    );

    let missing = TestHost::new().with_user_config("shell: nonesuch.exe\n");
    let row = shell_config_row(&crate::shell::effective(&missing));
    assert!(!row.pass && row.detail.contains("nonesuch.exe"), "{}", row.detail);

    let mut nothing = TestHost::new();
    nothing.entries.clear();
    let row = shell_config_row(&crate::shell::effective(&nothing));
    assert!(!row.pass, "even the built-in cmd.exe is missing");
}

#[test]
fn the_probe_handshake_is_direct() {
    use crate::protocol::{Launch, Mode};
    let hs = probe_handshake(std::path::Path::new(r"C:\Program Files\ssh-broker\ssh-broker.exe"));
    assert_eq!(
        hs.launch,
        Launch::Direct,
        "the probe is ssh-broker's own, not a user command"
    );
    assert_eq!(hs.mode, Mode::Exec);
    assert_eq!(
        hs.command.as_deref(),
        Some(r#""C:\Program Files\ssh-broker\ssh-broker.exe" verify-probe"#)
    );
}
