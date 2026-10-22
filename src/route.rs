//! argv dispatch.
//!
//! The **shim** (the SSH `DefaultShell`) is the default action; `agent`/`apply`/
//! `verify` are explicit verbs. `DefaultShell` is a bare path and cannot carry a
//! subcommand argument, which is exactly why the shim is the default: a known verb
//! in first position selects a subcommand, anything else (bare, or sshd's
//! `-c "cmd"`) is the shim.

use crate::cmdline::{self, RawExec};

#[derive(Debug, PartialEq, Eq)]
pub enum Route {
    /// The SSH DefaultShell. `exec` is `Some(command)` for `-c "cmd"`, `None` for
    /// an interactive (PTY) session.
    Shim {
        exec: Option<RawExec>,
    },
    Agent,
    Apply,
    Verify,
    /// Hidden: the parity-probe child the agent spawns in session 1 (used by `verify`).
    VerifyProbe,
}

/// Dispatch `args` (the arguments after the program name). A known verb in first position
/// wins; otherwise it is the shim.
///
/// For `-c` the exec command is the text after `-c` in `command_line`, the process's raw command
/// line, not `args`: sshd does not always quote the command, and `args` has lost the quotes and
/// spaces it carried. The tail is kept as written; `cmdline::resolve_exec` decodes it once the
/// shim knows how sshd wrote it. Both come from the same command line, so it shows the `-c` that
/// `args` reports; if it does not, the command is `args[1..]` joined with spaces.
pub fn route(args: &[String], command_line: &str) -> Route {
    match args.first().map(String::as_str) {
        Some("agent") => Route::Agent,
        Some("apply") => Route::Apply,
        Some("verify") => Route::Verify,
        Some("verify-probe") => Route::VerifyProbe,
        Some("-c") => {
            // `-c` was given, so this is an exec request even when the command is empty.
            let exec = match cmdline::dash_c_tail(command_line) {
                Some(tail) => RawExec::Tail(tail.to_string()),
                None => {
                    debug_assert!(
                        false,
                        "argv starts with -c but the raw command line has no `-c`: {command_line:?}"
                    );
                    RawExec::Argv(args[1..].join(" "))
                }
            };
            Route::Shim { exec: Some(exec) }
        }
        _ => Route::Shim { exec: None },
    }
}

#[cfg(test)]
#[path = "route_tests.rs"]
mod route_tests;
