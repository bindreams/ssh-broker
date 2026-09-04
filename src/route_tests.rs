//! Host tests for argv dispatch (pure; runs on any platform).

use super::{Route, route};

#[test]
fn bare_is_interactive_shim() {
    assert_eq!(route(&[]), Route::Shim { exec: None });
}

#[test]
fn dash_c_is_exec_shim() {
    assert_eq!(
        route(&["-c".into(), "echo hi".into()]),
        Route::Shim {
            exec: Some("echo hi".into())
        }
    );
}

#[test]
fn dash_c_joins_multiword_command() {
    // Resolves the truncation defect: everything after `-c` is reassembled,
    // not just args[1].
    assert_eq!(
        route(&["-c".into(), "git".into(), "commit -m".into(), "x y".into()]),
        Route::Shim {
            exec: Some("git commit -m x y".into())
        }
    );
}

#[test]
fn dash_c_with_no_command_is_none() {
    assert_eq!(route(&["-c".into()]), Route::Shim { exec: None });
}

#[test]
fn agent_verb_is_agent() {
    assert_eq!(route(&["agent".into()]), Route::Agent);
}

#[test]
fn apply_and_verify_verbs() {
    assert_eq!(route(&["apply".into()]), Route::Apply);
    assert_eq!(route(&["verify".into()]), Route::Verify);
    assert_eq!(route(&["verify-probe".into()]), Route::VerifyProbe);
}

#[test]
fn ssh_exec_of_verify_probe_word_is_still_shim_exec() {
    // `ssh host "verify-probe"` arrives as `-c "verify-probe"` → shim-exec, NOT the verb.
    assert_eq!(
        route(&["-c".into(), "verify-probe".into()]),
        Route::Shim {
            exec: Some("verify-probe".into())
        }
    );
}

#[test]
fn ssh_exec_of_word_agent_is_still_shim_exec() {
    // `ssh host "agent"` arrives as `-c "agent"`, so argv[1] is `-c` -> shim-exec
    // running the command `agent`. No collision with the `agent` verb.
    assert_eq!(
        route(&["-c".into(), "agent".into()]),
        Route::Shim {
            exec: Some("agent".into())
        }
    );
}
