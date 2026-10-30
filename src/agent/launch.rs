//! What a handshake asks the agent to start: the line, and the warning to show first.
//!
//! Pure over a [`shell::Host`], so it builds and tests on every platform.

use crate::protocol::{Handshake, Launch, Mode, Stream};
use crate::shell::{self, Session};

/// The line to spawn, and a warning for the user when the configured shell could not be used.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Launched<'a> {
    pub line: String,
    /// The warning's text, without its line end (see [`notice_frame`]).
    pub notice: Option<String>,
    /// What [`start`] needs to replace a shell that cannot start; `None` for a direct launch.
    shell: Option<(Session<'a>, shell::Plan)>,
}

/// Why a handshake cannot be carried out.
#[derive(Debug)]
pub(super) enum Refusal {
    /// The request does not make sense (a command is missing).
    BadRequest(anyhow::Error),
    /// The request is fine and the line cannot be made.
    Failed(anyhow::Error),
}

/// The line for `hs`. [`Launch::Direct`] spawns the command as given. [`Launch::Shell`] reads the
/// shell configuration once, now, and packs the session for the shell it names: a terminal with a
/// command appends it as written; a command without a terminal is packed per the shell's
/// `escaping`.
pub(super) fn launch_line<'a>(hs: &'a Handshake, host: &dyn shell::Host) -> Result<Launched<'a>, Refusal> {
    let bad = |what: &str| Refusal::BadRequest(anyhow::anyhow!("{what}"));
    match (hs.launch, hs.mode, hs.command.as_deref()) {
        (Launch::Direct, _, Some(line)) => Ok(Launched {
            line: line.to_owned(),
            notice: None,
            shell: None,
        }),
        (Launch::Direct, _, None) => Err(bad("a direct launch needs a command")),
        (Launch::Shell, Mode::Exec, None) => Err(bad("an exec request needs a command")),
        (Launch::Shell, Mode::Logout, _) => Err(bad("a logout request starts nothing")),
        (Launch::Shell, mode, command) => {
            let session = match command {
                Some(text) => Session::Command {
                    text,
                    terminal: mode == Mode::Pty,
                },
                None => Session::Interactive,
            };
            let plan = shell::plan(host, &session).map_err(Refusal::Failed)?;
            Ok(Launched {
                notice: plan.notice(),
                line: plan.command_line.clone(),
                shell: Some((session, plan)),
            })
        }
    }
}

/// Start `launched` with `spawn`. A configured shell that resolves but cannot start (a truncated
/// file, the wrong architecture, AppLocker) is replaced by the built-in `cmd.exe`
/// ([`shell::start_or_fall_back`]); `warn` gets the text of that warning just before the
/// replacement starts.
pub(super) fn start<T>(
    host: &dyn shell::Host,
    launched: &Launched<'_>,
    mut spawn: impl FnMut(&str) -> anyhow::Result<T>,
    warn: impl FnOnce(&str),
) -> anyhow::Result<T> {
    match &launched.shell {
        None => spawn(&launched.line),
        Some((session, plan)) => shell::start_or_fall_back(host, session, plan, spawn, |replacement| {
            if let Some(text) = replacement.notice() {
                warn(&text);
            }
        }),
    }
}

/// The first data frame of a session whose shell could not be used: where it goes and what it
/// carries. A terminal needs the carriage return; stderr is plain.
pub(super) fn notice_frame(mode: Mode, text: &str) -> (Stream, Vec<u8>) {
    match mode {
        Mode::Pty => (Stream::Pty, format!("{text}\r\n").into_bytes()),
        _ => (Stream::Stderr, format!("{text}\n").into_bytes()),
    }
}

#[cfg(test)]
#[path = "launch_tests.rs"]
mod launch_tests;
