//! Defaults, program resolution and the spawn line.
//!
//! [`effective`] settles what the chosen block means on this machine (which file the program is,
//! what the unwritten values default to); [`plan`] packs a session into the line to start.

use std::path::{Path, PathBuf};

use super::layers::{self, Origin, Problem};
use super::{Escaping, Host, is_absolute_windows};
use crate::cmdline::join_args;

/// The most UTF-16 units `CreateProcessW` takes in a command line, with its terminating NUL.
const MAX_LINE_UNITS: usize = 32_767;

/// What kind of session to start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Session<'a> {
    /// A login shell: no command.
    Interactive,
    /// A command, exactly as the client sent it. `terminal`: the client asked for a terminal
    /// (`ssh -t host command`).
    Command { text: &'a str, terminal: bool },
}

/// What `with-command` and `escaping` are when the config does not say: they depend on whether
/// the program is the system `cmd.exe`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Defaults {
    pub escaping: Escaping,
    pub with_command: Vec<String>,
}

/// The defaults for the system `cmd.exe` (`cmd` escaping, `/c`) or for any other program (`msvc`,
/// `-c`). The commands `without-command` defaults to nothing for both.
pub fn defaults(is_system_cmd: bool) -> Defaults {
    if is_system_cmd {
        Defaults {
            escaping: Escaping::Cmd,
            with_command: vec!["/c".into()],
        }
    } else {
        Defaults {
            escaping: Escaping::Msvc,
            with_command: vec!["-c".into()],
        }
    }
}

/// Where one effective value comes from, for `verify`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    User(PathBuf),
    System(PathBuf),
    /// The built-in `cmd.exe` block.
    BuiltIn,
    /// Not written; the default for the system `cmd.exe`.
    SystemCmd,
    /// Not written; the default for any other program.
    OtherProgram,
}

/// The [`Source`] of each effective value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Why {
    pub start: Source,
    pub without_command: Source,
    pub with_command: Source,
    pub escaping: Source,
}

/// The shell as it will run: every value settled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Effective {
    /// The program `start[0]` names, found.
    pub program: PathBuf,
    /// As written (or the built-in's); `program` is the file `start[0]` resolved to.
    pub start: Vec<String>,
    pub without_command: Vec<String>,
    pub with_command: Vec<String>,
    pub escaping: Escaping,
    pub why: Why,
    pub origin: Origin,
    /// Set when a configured shell could not be used and the built-in `cmd.exe` is in its place.
    pub problem: Option<Problem>,
}

/// The line to start for a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub command_line: String,
    pub effective: Effective,
}

impl Plan {
    /// The warning to show before the line starts, when the configured shell could not be used.
    pub fn notice(&self) -> Option<String> {
        self.effective.problem.as_ref().map(Problem::notice)
    }
}

/// Resolve the shell for this process: choose the block, find its program, settle the defaults.
/// A program that cannot be used falls to the built-in `cmd.exe` with a [`Problem`]. Fails only
/// when even the built-in `cmd.exe` is missing.
pub fn effective(host: &dyn Host) -> anyhow::Result<Effective> {
    let mut chosen = layers::choose(host);
    let program = match resolve_program(host, &chosen.block.start) {
        Ok(program) => program,
        Err(reason) => {
            let file = match &chosen.origin {
                Origin::User(file) | Origin::System(file) => file.clone(),
                Origin::Default => {
                    anyhow::bail!(
                        "the built-in shell {} cannot be used: {reason}",
                        host.system_cmd().display()
                    )
                }
            };
            chosen.problem = Some(Problem {
                file,
                value: chosen.block.start.first().cloned(),
                reason,
            });
            chosen.block = layers::built_in(host);
            chosen.origin = Origin::Default;
            resolve_program(host, &chosen.block.start).map_err(|reason| {
                anyhow::anyhow!(
                    "the built-in shell {} cannot be used: {reason}",
                    host.system_cmd().display()
                )
            })?
        }
    };

    let is_system_cmd = host.is_system_cmd(&program).unwrap_or_else(|error| {
        tracing::warn!(
            "cannot tell whether {} is the system cmd.exe ({error}); treating it as another program",
            program.display()
        );
        false
    });
    let d = defaults(is_system_cmd);
    let default_source = if is_system_cmd {
        Source::SystemCmd
    } else {
        Source::OtherProgram
    };
    let written = match &chosen.origin {
        Origin::User(file) => Source::User(file.clone()),
        Origin::System(file) => Source::System(file.clone()),
        Origin::Default => Source::BuiltIn,
    };
    let pick = |value: Option<Vec<String>>, default: Vec<String>| match value {
        Some(value) => (value, written.clone()),
        None => (default, default_source.clone()),
    };
    let (without_command, without_source) = pick(chosen.block.without_command, Vec::new());
    let (with_command, with_source) = pick(chosen.block.with_command, d.with_command);
    let (escaping, escaping_source) = match chosen.block.escaping {
        Some(escaping) => (escaping, written.clone()),
        None => (d.escaping, default_source),
    };
    Ok(Effective {
        program,
        start: chosen.block.start,
        without_command,
        with_command,
        escaping,
        why: Why {
            start: written,
            without_command: without_source,
            with_command: with_source,
            escaping: escaping_source,
        },
        origin: chosen.origin,
        problem: chosen.problem,
    })
}

/// The file `start[0]` names. A bare name is searched on `PATH`; anything with a separator or a
/// drive must be an absolute path. `Err` is the reason, for the warning.
fn resolve_program(host: &dyn Host, start: &[String]) -> Result<PathBuf, String> {
    let name = start.first().map(String::as_str).unwrap_or("");
    if name.is_empty() {
        return Err("the program name is empty".into());
    }
    if name.contains(['\\', '/', ':']) {
        let path = Path::new(name);
        if !is_absolute_windows(path) {
            return Err("a relative path; use an absolute path or a bare name to search PATH".into());
        }
        return if host.is_file(path) {
            Ok(path.to_path_buf())
        } else {
            Err("there is no such file".into())
        };
    }
    host.find_program(name).ok_or_else(|| "not found on PATH".to_string())
}

/// The line to start for `session`. Fails when the line cannot be a command line: it is longer
/// than `CreateProcessW` takes, or the command holds a NUL.
pub fn plan(host: &dyn Host, session: &Session<'_>) -> anyhow::Result<Plan> {
    let effective = effective(host)?;
    let program = effective.program.to_string_lossy();
    let mut head: Vec<&str> = vec![&program];
    head.extend(effective.start.iter().skip(1).map(String::as_str));

    let command_line = match session {
        Session::Interactive => {
            head.extend(effective.without_command.iter().map(String::as_str));
            join_args(&head)
        }
        Session::Command { text, terminal } => {
            anyhow::ensure!(!text.contains('\0'), "the command holds a NUL character");
            // The leading edge goes: `CreateProcessW` fails on a line that starts with it.
            let text = crate::shim::spawn_line(text);
            head.extend(effective.with_command.iter().map(String::as_str));
            if *terminal {
                // As OpenSSH does on a terminal: the text follows the arguments, as written.
                format!("{} {text}", join_args(&head))
            } else {
                match effective.escaping {
                    Escaping::Cmd => format!("{} \"{text}\"", join_args(&head)),
                    Escaping::Msvc => {
                        head.push(text);
                        join_args(&head)
                    }
                }
            }
        }
    };
    let units = command_line.encode_utf16().count();
    anyhow::ensure!(
        units < MAX_LINE_UNITS,
        "the command line for {} is {units} UTF-16 units; Windows takes at most 32,767 with the terminating NUL",
        effective.program.display()
    );
    Ok(Plan {
        command_line,
        effective,
    })
}

#[cfg(test)]
#[path = "pack_tests.rs"]
mod pack_tests;
