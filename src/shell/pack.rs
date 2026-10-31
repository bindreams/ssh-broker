//! Defaults, program resolution and the spawn line.
//!
//! [`effective`] settles what the chosen block means on this machine (which file the program is,
//! what the unwritten values default to); [`plan`] packs a session into the line to start.

use std::path::{Path, PathBuf};

use super::config::{Notes, ShellBlock, render_annotated};
use super::layers::{self, Origin, Problem};
use super::{Escaping, Host, is_absolute_windows};
use crate::cmdline::join_args;

/// The most UTF-16 units `CreateProcessW` takes in a command line, with its terminating NUL.
pub(crate) const MAX_LINE_UNITS: usize = 32_767;

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
/// `-c`). `without-command` defaults to nothing for both.
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

impl Source {
    /// How `verify` names the source.
    fn label(&self) -> String {
        match self {
            Source::User(file) => format!("user: {}", file.display()),
            Source::System(file) => format!("system: {}", file.display()),
            Source::BuiltIn => "built-in".into(),
            Source::SystemCmd => "the system cmd.exe".into(),
            Source::OtherProgram => "any other program".into(),
        }
    }
}

/// The effective shell as a config file, each key followed by where its value comes from, then
/// the program `start` resolved to and, when a configured shell could not be used, the warning,
/// as comments. What `verify` prints; the config parser reads it back as the values it shows.
pub fn render(effective: &Effective) -> String {
    let why = &effective.why;
    let block = ShellBlock {
        start: effective.start.clone(),
        without_command: Some(effective.without_command.clone()),
        with_command: Some(effective.with_command.clone()),
        escaping: Some(effective.escaping),
    };
    let labels = [
        why.start.label(),
        why.without_command.label(),
        why.with_command.label(),
        why.escaping.label(),
    ];
    let notes = Notes {
        start: Some(&labels[0]),
        without_command: Some(&labels[1]),
        with_command: Some(&labels[2]),
        escaping: Some(&labels[3]),
    };
    let mut text = render_annotated(&block, &notes)
        .unwrap_or_else(|error| format!("# the shell cannot be shown as a config: {error}\n"));
    let comment = |text: &mut String, label: &str, value: &str| {
        // YAML ends a comment at a CR as well as at an LF.
        for (i, line) in value.split(['\r', '\n']).filter(|line| !line.is_empty()).enumerate() {
            let label = if i == 0 { label } else { "" };
            text.push_str(&format!("# {label}{line}\n"));
        }
    };
    comment(&mut text, "program: ", &effective.program.display().to_string());
    if let Some(problem) = &effective.problem {
        comment(&mut text, "warning: ", &problem.describe());
    }
    text.truncate(text.trim_end_matches('\n').len());
    text
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
    settle(host, layers::choose(host)?)
}

/// [`effective`] for a block already chosen.
fn settle(host: &dyn Host, mut chosen: layers::Chosen) -> anyhow::Result<Effective> {
    let program = match resolve_program(host, chosen.block.start.first().map_or("", String::as_str)) {
        Ok(program) => program,
        Err(reason) => {
            let file = match &chosen.origin {
                Origin::User(file) | Origin::System(file) => file.clone(),
                Origin::Default => {
                    anyhow::bail!("the built-in shell {} cannot be used: {reason}", built_in_name(host))
                }
            };
            chosen.problem = Some(Problem {
                file,
                value: chosen.block.start.first().cloned(),
                reason,
            });
            chosen.block = layers::built_in(host)?;
            chosen.origin = Origin::Default;
            resolve_program(host, chosen.block.start.first().map_or("", String::as_str)).map_err(|reason| {
                anyhow::anyhow!("the built-in shell {} cannot be used: {reason}", built_in_name(host))
            })?
        }
    };

    // The built-in block is the system `cmd.exe` by construction, so no file is opened to find out.
    let is_system_cmd = matches!(chosen.origin, Origin::Default)
        || host.is_system_cmd(&program).unwrap_or_else(|error| {
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

/// The built-in shell's path for a message.
fn built_in_name(host: &dyn Host) -> String {
    host.system_cmd().map_or_else(
        |error| format!("cmd.exe ({error:#})"),
        |path| path.display().to_string(),
    )
}

/// The file `start[0]` names. A bare name is searched on `PATH`; anything with a separator or a
/// drive must be an absolute path, and one whose file name has no extension may also name the file
/// with `.exe` appended, as `CreateProcess` (and so sshd) finds it. `Err` is the reason, for the
/// warning.
pub fn resolve_program(host: &dyn Host, name: &str) -> Result<PathBuf, String> {
    resolve_program_in(host, &[], name)
}

/// [`resolve_program`] for a bare name that is searched in `first`, in order, before `PATH`: the
/// directories a program that is not this one searches first (see `CreateProcess`). A name with a
/// separator is a path, and `first` does not matter to it.
pub fn resolve_program_in(host: &dyn Host, first: &[PathBuf], name: &str) -> Result<PathBuf, String> {
    if name.is_empty() {
        return Err("the program name is empty".into());
    }
    if name.contains(['\\', '/', ':']) {
        let path = Path::new(name);
        if !is_absolute_windows(path) {
            return Err("a relative path; use an absolute path or a bare name to search PATH".into());
        }
        let is_file = |path: &Path| {
            host.is_file(path)
                .map_err(|e| format!("cannot tell whether {} is a file: {e}", path.display()))
        };
        if is_file(path)? {
            return Ok(path.to_path_buf());
        }
        let file_name = name.rsplit(['\\', '/']).next().unwrap_or(name);
        if !file_name.contains('.') {
            let mut with_exe = path.as_os_str().to_owned();
            with_exe.push(".exe");
            let with_exe = PathBuf::from(with_exe);
            if is_file(&with_exe)? {
                return Ok(with_exe);
            }
        }
        return Err("there is no such file".into());
    }
    host.find_program_in(first, name)
        .ok_or_else(|| "not found on PATH".to_string())
}

/// The line to start for `session`. Fails when the line cannot be a command line: it is longer
/// than `CreateProcessW` takes, or the command holds a NUL.
pub fn plan(host: &dyn Host, session: &Session<'_>) -> anyhow::Result<Plan> {
    pack(session, effective(host)?)
}

/// The line for `session` under the shell `effective`.
fn pack(session: &Session<'_>, effective: Effective) -> anyhow::Result<Plan> {
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
            head.extend(effective.with_command.iter().map(String::as_str));
            if *terminal {
                // As OpenSSH does on a terminal: the text follows the arguments, as written. It is not
                // at the start of the line, so only the separators before it go, which are not part of
                // any argument; a line break stays, as it does in sshd's line.
                let text = text.trim_start_matches([' ', '\t']);
                format!("{} {text}", join_args(&head))
            } else {
                // The leading edge goes: `CreateProcessW` fails on a line that starts with it.
                let text = crate::shim::spawn_line(text);
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

/// Why a line did not start. A spawn reports `Ok` only once the program is running, so a program
/// that has run is never started again because of a failure that came after.
#[derive(Debug)]
pub enum StartError {
    /// The OS could not start the program: a file that resolves and cannot be started (a truncated
    /// file, the wrong architecture, AppLocker). A configured shell falls back to the built-in.
    Program(anyhow::Error),
    /// Something else failed (the working directory, the pseudoconsole, the job): the shell is not
    /// at fault, and the built-in would meet the same failure.
    Other(anyhow::Error),
}

impl StartError {
    /// The cause, whichever kind it is.
    pub fn into_cause(self) -> anyhow::Error {
        match self {
            StartError::Program(cause) | StartError::Other(cause) => cause,
        }
    }
}

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StartError::Program(cause) | StartError::Other(cause) => write!(f, "{cause:#}"),
        }
    }
}

/// The line for `session` under the built-in `cmd.exe`, whatever the configuration says. `problem`
/// is why the configured shell is not used, for the notice ([`Plan::notice`]).
pub fn built_in_plan(host: &dyn Host, session: &Session<'_>, problem: Option<Problem>) -> anyhow::Result<Plan> {
    let block = layers::built_in(host)?;
    let chosen = layers::Chosen {
        block,
        origin: Origin::Default,
        problem,
    };
    pack(session, settle(host, chosen)?)
}

/// Start `plan` with `spawn`. When the program cannot be started ([`StartError::Program`]) and
/// `plan` is a configured shell, the built-in `cmd.exe` is started instead, with a [`Problem`]
/// that names the file, the value and the OS error. `warn` gets that replacement plan
/// ([`Plan::notice`]) just before it is started, so the warning precedes the shell. Any other
/// failure, a failure of the built-in itself and a failure of the replacement are the error: there
/// is nothing left to fall to, and one try is all each gets.
pub fn start_or_fall_back<T>(
    host: &dyn Host,
    session: &Session<'_>,
    plan: &Plan,
    mut spawn: impl FnMut(&str) -> Result<T, StartError>,
    warn: impl FnOnce(&Plan),
) -> anyhow::Result<T> {
    let error = match spawn(&plan.command_line) {
        Ok(started) => return Ok(started),
        Err(StartError::Other(cause)) => return Err(cause),
        Err(StartError::Program(error)) => error,
    };
    let file = match &plan.effective.origin {
        Origin::User(file) | Origin::System(file) => file.clone(),
        Origin::Default => return Err(error),
    };
    let replacement = built_in_plan(
        host,
        session,
        Some(Problem {
            file,
            value: plan.effective.start.first().cloned(),
            reason: format!("it cannot be started: {error:#}"),
        }),
    );
    let replacement = match replacement {
        Ok(replacement) => replacement,
        Err(unplanned) => {
            tracing::warn!("no built-in cmd.exe line to replace a shell that cannot start: {unplanned:#}");
            return Err(error);
        }
    };
    warn(&replacement);
    spawn(&replacement.command_line).map_err(StartError::into_cause)
}

#[cfg(test)]
#[path = "pack_tests.rs"]
mod pack_tests;
