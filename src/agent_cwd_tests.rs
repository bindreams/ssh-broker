//! Host tests for `child_cwd` (pure; runs on any platform, unlike the Windows-only
//! integration tests in `agent_tests.rs`).

use super::child_cwd;
use std::path::PathBuf;

#[test]
fn empty_handshake_cwd_falls_back_to_home() {
    let home = Some(PathBuf::from(r"C:\Users\me"));
    assert_eq!(child_cwd("", home.clone()), home);
}

#[test]
fn explicit_handshake_cwd_wins_over_home() {
    assert_eq!(
        child_cwd(r"C:\work", Some(PathBuf::from(r"C:\Users\me"))),
        Some(PathBuf::from(r"C:\work"))
    );
}

#[test]
fn empty_cwd_and_no_home_is_none() {
    // No worse than today's behaviour (inherit the agent's cwd) when home is unresolvable.
    assert_eq!(child_cwd("", None), None);
}
