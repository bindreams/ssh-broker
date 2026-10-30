//! What a handshake asks the agent to start: the line, and the warning to show first.
//!
//! Pure over a [`shell::Host`], so it builds and tests on every platform.

use crate::protocol::{Handshake, Launch, Mode, Stream};
use crate::shell::{self, Session};

/// The line to spawn, and a warning for the user when the configured shell could not be used.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Launched {
    pub line: String,
    /// The warning's text, without its line end (see [`notice_frame`]).
    pub notice: Option<String>,
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
pub(super) fn launch_line(hs: &Handshake, host: &dyn shell::Host) -> Result<Launched, Refusal> {
    let bad = |what: &str| Refusal::BadRequest(anyhow::anyhow!("{what}"));
    match (hs.launch, hs.mode, hs.command.as_deref()) {
        (Launch::Direct, _, Some(line)) => Ok(Launched {
            line: line.to_owned(),
            notice: None,
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
                line: plan.command_line,
            })
        }
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
