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
