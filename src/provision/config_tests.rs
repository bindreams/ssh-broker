//! Host tests for the pure config logic.
use super::{Config, resolve_target_user};

#[test]
fn config_toml_round_trips() {
    let c = Config {
        target_user: "Test.User".into(),
    };
    let parsed = Config::from_toml(&c.to_toml().unwrap()).unwrap();
    assert_eq!(parsed, c);
}

#[test]
fn resolve_prefers_cli_then_config_then_interactive() {
    assert_eq!(
        resolve_target_user(Some("cli"), Some("cfg"), Some("me")).unwrap(),
        "cli"
    );
    assert_eq!(resolve_target_user(None, Some("cfg"), Some("me")).unwrap(), "cfg");
    assert_eq!(resolve_target_user(None, None, Some("me")).unwrap(), "me");
}

#[test]
fn resolve_treats_empty_strings_as_absent() {
    // An empty CLI/config value must not shadow a real fallback.
    assert_eq!(resolve_target_user(Some(""), Some("cfg"), None).unwrap(), "cfg");
    assert_eq!(resolve_target_user(Some(""), Some(""), Some("me")).unwrap(), "me");
}

#[test]
fn resolve_errors_when_no_source() {
    // The SYSTEM-with-no-config case must fail loudly, never guess.
    assert!(resolve_target_user(None, None, None).is_err());
    assert!(resolve_target_user(Some(""), None, Some("")).is_err());
}
