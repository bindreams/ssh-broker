//! argv dispatch.
//!
//! The **shim** (the SSH `DefaultShell`) is the default action; `agent`/`apply`/
//! `verify` are explicit verbs. `DefaultShell` is a bare path and cannot carry a
//! subcommand argument, which is exactly why the shim is the default: a known verb
//! in first position selects a subcommand, anything else (bare, or sshd's
//! `-c "cmd"`) is the shim.

#[derive(Debug, PartialEq, Eq)]
pub enum Route {
    /// The SSH DefaultShell. `exec` is `Some(command)` for `-c "cmd"`, `None` for
    /// an interactive (PTY) session.
    Shim {
        exec: Option<String>,
    },
    Agent,
    Apply,
    Verify,
    /// Hidden: the parity-probe child the agent spawns in session 1 (used by `verify`).
    VerifyProbe,
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
        Some("verify-probe") => Route::VerifyProbe,
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

#[cfg(test)]
#[path = "route_tests.rs"]
mod route_tests;
