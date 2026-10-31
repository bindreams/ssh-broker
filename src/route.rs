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
    /// The per-user agent: in the user's desktop session, or with `--background`.
    Agent(AgentArgs),
    /// A known verb with arguments it does not take: print its usage and stop. The verb is
    /// known, so this never falls through to the shim.
    Usage(Verb),
    /// End the invoking user's background session.
    Logout,
    /// `auto-login on|off [<account>]`; `None` when the arguments are not that: print the usage.
    AutoLogin(Option<AutoLoginArgs>),
    Apply,
    Verify,
    /// Hidden: the parity-probe child the agent spawns in session 1 (used by `verify`).
    VerifyProbe,
    /// Hidden: the fallback shell of a terminal session through the agent. `file` holds a notice and
    /// a line (see `fallback_file`); the verb prints the notice on its console, starts the line on
    /// that console and exits with the code of the line.
    ConsoleFallback {
        file: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    Agent,
    Logout,
    ConsoleFallback,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct AgentArgs {
    /// `Some` for `agent --background`.
    pub background: Option<BackgroundArgs>,
}

/// The flags of `agent --background`, which the shim passes when it starts the agent through a
/// logon. Each is optional here; `agent_background::check_start` decides what a start needs.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct BackgroundArgs {
    /// SID text the agent's own token must have.
    pub expect_user: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Toggle {
    On,
    Off,
}

#[derive(Debug, PartialEq, Eq)]
pub struct AutoLoginArgs {
    pub toggle: Toggle,
    /// The account to act on; the invoking user when absent.
    pub account: Option<String>,
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
        Some("agent") => agent_args(&args[1..]).map_or(Route::Usage(Verb::Agent), Route::Agent),
        Some("logout") if args.len() == 1 => Route::Logout,
        Some("logout") => Route::Usage(Verb::Logout),
        Some("auto-login") => Route::AutoLogin(auto_login_args(&args[1..])),
        Some("apply") => Route::Apply,
        Some("verify") => Route::Verify,
        Some("verify-probe") => Route::VerifyProbe,
        Some("console-fallback") => match &args[1..] {
            [file] => Route::ConsoleFallback { file: file.clone() },
            _ => Route::Usage(Verb::ConsoleFallback),
        },
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

/// `[]` or `--background [--expect-user <sid>]`, the flag at most once. A
/// flag is accepted only after `--background`.
fn agent_args(rest: &[String]) -> Option<AgentArgs> {
    let Some((first, flags)) = rest.split_first() else {
        return Some(AgentArgs::default());
    };
    if first != "--background" {
        return None;
    }
    let mut background = BackgroundArgs::default();
    let mut flags = flags.iter();
    while let Some(flag) = flags.next() {
        let slot = match flag.as_str() {
            "--expect-user" => &mut background.expect_user,
            _ => return None,
        };
        let value = flags.next().filter(|value| !value.starts_with("--"))?;
        if slot.replace(value.clone()).is_some() {
            return None;
        }
    }
    Some(AgentArgs {
        background: Some(background),
    })
}

/// `on|off [<account>]`.
fn auto_login_args(rest: &[String]) -> Option<AutoLoginArgs> {
    let (toggle, account) = match rest {
        [toggle] => (toggle, None),
        [toggle, account] if !account.starts_with('-') => (toggle, Some(account.clone())),
        _ => return None,
    };
    let toggle = match toggle.as_str() {
        "on" => Toggle::On,
        "off" => Toggle::Off,
        _ => return None,
    };
    Some(AutoLoginArgs { toggle, account })
}

#[cfg(test)]
#[path = "route_tests.rs"]
mod route_tests;
