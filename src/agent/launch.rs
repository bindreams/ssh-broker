//! What a handshake asks the agent to start: the line, and the warning to show first.
//!
//! Pure over a [`shell::Host`], so it builds and tests on every platform.

use std::cell::Cell;
use std::path::Path;

use crate::cmdline;
use crate::fallback_file::{self, Staged};
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

/// Where a terminal session's fallback warning is printed from: this program, which has the hidden
/// `console-fallback` verb, and the user's private folder, where the verb's file is made.
#[derive(Debug, Clone, Copy)]
pub(super) struct Console<'a> {
    pub exe: &'a Path,
    pub dir: &'a Path,
}

/// Start `launched` with `spawn`. A configured shell that resolves but cannot start (a truncated
/// file, the wrong architecture, AppLocker) is replaced by the built-in `cmd.exe`
/// ([`shell::start_or_fall_back`]).
///
/// The warning for a shell that could not be used reaches the user one of two ways. With
/// `console`, the session is a pseudoconsole, which clears the screen after anything written ahead
/// of the shell: the line that starts is the hidden `console-fallback` verb, which prints the
/// warning from inside it and then starts the shell. Otherwise, or when the verb's file cannot be
/// made, `warn` gets the warning's text just before the shell starts.
pub(super) fn start<T>(
    host: &dyn shell::Host,
    launched: &Launched<'_>,
    console: Option<Console<'_>>,
    mut spawn: impl FnMut(&str) -> anyhow::Result<T>,
    mut warn: impl FnMut(&str),
) -> anyhow::Result<T> {
    let Some((session, plan)) = &launched.shell else {
        return spawn(&launched.line);
    };
    // The warning for the line `start_or_fall_back` spawns next.
    let pending = Cell::new(launched.notice.clone());
    shell::start_or_fall_back(
        host,
        session,
        plan,
        |line| match pending.take() {
            None => spawn(line),
            Some(text) => match console.and_then(|console| console_fallback_line(console, &text, line)) {
                Some((wrapped, file)) => {
                    tracing::warn!("{text}");
                    let started = spawn(&wrapped);
                    // The verb removes the file once it has read it; one that never ran cannot.
                    if started.is_ok() {
                        file.hand_over();
                    }
                    started
                }
                None => {
                    warn(&text);
                    spawn(line)
                }
            },
        },
        |replacement| pending.set(replacement.notice()),
    )
}

/// The line that starts `line` after printing `notice` on the console it is started on: the
/// `console-fallback` verb, given a file in the private folder that holds both. `None` when that
/// cannot be done: the file cannot be made, or the verb's line does not fit in a command line (a
/// program path of nearly 32,767 units).
fn console_fallback_line(console: Console<'_>, notice: &str, line: &str) -> Option<(String, Staged)> {
    let file = fallback_file::stage(console.dir, notice, line)
        .inspect_err(|e| {
            tracing::warn!(
                "could not make the fallback shell's file in {}: {e}",
                console.dir.display()
            )
        })
        .ok()?;
    let wrapped = cmdline::join_args(&[
        &*console.exe.to_string_lossy(),
        "console-fallback",
        &file.path().to_string_lossy(),
    ]);
    (wrapped.encode_utf16().count() < shell::pack::MAX_LINE_UNITS).then_some((wrapped, file))
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
