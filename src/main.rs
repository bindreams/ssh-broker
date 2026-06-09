//! ssh-broker entrypoint: argv dispatch.
//!
//! The **shim** (the SSH `DefaultShell`) is the default action; `agent`/`apply`/
//! `verify` are explicit verbs. `DefaultShell` is a bare path and cannot carry a
//! subcommand argument, which is exactly why the shim is the default: a known verb
//! in first position selects a subcommand, anything else (bare, or sshd's
//! `-c "cmd"`) is the shim.

#[cfg(windows)]
mod acl;
mod afunix;
mod agent;
#[cfg(windows)]
mod conpty;
#[cfg(windows)]
mod pipes;
mod protocol;
mod provision;
mod relay;
mod shim;
#[cfg(windows)]
mod shim_pty;
mod vtinput;
#[cfg(windows)]
mod winutil;

#[cfg(all(windows, feature = "spike"))]
mod spike;

#[derive(Debug, PartialEq, Eq)]
pub enum Route {
    /// The SSH DefaultShell. `exec` is `Some(command)` for `-c "cmd"`, `None` for
    /// an interactive (PTY) session.
    Shim { exec: Option<String> },
    Agent,
    Apply,
    Verify,
}

/// Dispatch `argv[1..]` (the args after the program name). A known verb in first
/// position wins; otherwise it is the shim. For `-c`, the exec command is
/// `args[1..]` joined with spaces — so a command that arrives split across argv
/// (rather than as a single string) is reassembled instead of truncated.
pub fn route(args: &[String]) -> Route {
    match args.first().map(String::as_str) {
        Some("agent") => Route::Agent,
        Some("apply") => Route::Apply,
        Some("verify") => Route::Verify,
        Some("-c") => {
            // Reassemble the command from args[1..] so a command that arrives split
            // across argv is not truncated. `-c` with nothing after it degrades to an
            // interactive shim (no command).
            let exec = if args.len() > 1 {
                Some(args[1..].join(" "))
            } else {
                None
            };
            Route::Shim { exec }
        }
        _ => Route::Shim { exec: None },
    }
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // Spike subcommands (diag/ptytest/conpty) are only present under `--features spike`.
    #[cfg(all(windows, feature = "spike"))]
    if let Some(result) = spike::try_dispatch(&args) {
        return result;
    }

    match route(&args) {
        Route::Shim { exec } => shim::run(exec),
        Route::Agent => agent::run(),
        Route::Apply => provision::apply(),
        Route::Verify => provision::verify(),
    }
}

#[cfg(test)]
mod route_tests {
    use super::{Route, route};

    #[test]
    fn bare_is_interactive_shim() {
        assert_eq!(route(&[]), Route::Shim { exec: None });
    }

    #[test]
    fn dash_c_is_exec_shim() {
        assert_eq!(
            route(&["-c".into(), "echo hi".into()]),
            Route::Shim { exec: Some("echo hi".into()) }
        );
    }

    #[test]
    fn dash_c_joins_multiword_command() {
        // Resolves the truncation defect: everything after `-c` is reassembled,
        // not just args[1].
        assert_eq!(
            route(&[
                "-c".into(),
                "git".into(),
                "commit -m".into(),
                "x y".into()
            ]),
            Route::Shim { exec: Some("git commit -m x y".into()) }
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
    }

    #[test]
    fn ssh_exec_of_word_agent_is_still_shim_exec() {
        // `ssh host "agent"` arrives as `-c "agent"`, so argv[1] is `-c` -> shim-exec
        // running the command `agent`. No collision with the `agent` verb.
        assert_eq!(
            route(&["-c".into(), "agent".into()]),
            Route::Shim { exec: Some("agent".into()) }
        );
    }
}
