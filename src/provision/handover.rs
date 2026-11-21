//! The proof that `install` kept or showed the shell sshd used before it makes ssh-broker `DefaultShell`.
//!
//! [`registry::set_default_shell_under`](super::registry::set_default_shell_under) takes a
//! [`Handover`], and the only ways to get one are here: the config was written from the previous
//! values (carried), the text that holds every previous value was emitted (printed), or there is
//! nothing to carry. No path through `install` can replace the shell with the values neither kept nor shown.
//! [`registry::remove_shell_arguments_under`](super::registry::remove_shell_arguments_under) is the same
//! for the one value that is deleted afterwards: it takes a [`ShownValue`], which only the print of the
//! value makes.
//!
//! What keeps that guarantee is the notice: it is written to standard error strictly ([`show_to`], as `eprintln!`
//! does), so a write that fails ends `install` there, before the shell is replaced or the value removed. Every other
//! line goes through [`Say`], whose write may fail without a consequence.

use std::io::Write;
use std::path::Path;

use super::registry::{SshdShell, UnreadShell};
use super::system_config::{self, ArgumentsPlan, ConfigKind, CreateOutcome, Decision, Skip};
use crate::shell::config::ShellBlock;

/// Where a line goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    Out,
    Err,
}

/// The sink for `install`'s lines: a `say` that takes the stream and the line. A step line (it ends in `...`, is said
/// before the step starts and goes to stdout) says what is about to take a while; a warning goes to stderr and says
/// what the person must know. A line that cannot be written is lost and nothing else is ([`say_to`]). The two notices
/// that keep a value ([`Handover::printed`], [`ShownValue::print`]) do not go through it.
pub type Say<'a> = dyn FnMut(Stream, &str) + 'a;

/// Writes a line to `out` or to `err`, by `stream`. A write that fails loses the line and nothing else: `install`
/// run over an SSH connection that has gone has a closed stdout, and `println!` would panic on it.
pub fn say_to(out: &mut impl Write, err: &mut impl Write, stream: Stream, text: &str) {
    let _ = match stream {
        Stream::Out => writeln!(out, "{text}"),
        Stream::Err => writeln!(err, "{text}"),
    };
}

/// Writes a line to the console: standard output or standard error. The [`Say`] `install` has.
pub fn say_to_console(stream: Stream, text: &str) {
    say_to(&mut std::io::stdout(), &mut std::io::stderr(), stream, text);
}

/// Writes a notice that is the only record of a value to `err`, and does not return if the write fails, as
/// `eprintln!` does not.
pub fn show_to(err: &mut impl Write, text: &str) {
    if let Err(e) = writeln!(err, "{text}") {
        panic!("failed printing to stderr: {e}");
    }
}

/// Writes a notice to standard error: the `show` that `install` passes to [`hand_over`] and [`remove_arguments`].
pub fn show_to_console(text: &str) {
    show_to(&mut std::io::stderr(), text);
}

/// The previous shell's values were carried into the config, or printed, or there were none to keep.
#[must_use = "the DefaultShell flip takes it"]
#[derive(Debug)]
pub struct Handover(());

impl Handover {
    /// The proof for a previous shell that is ssh-broker's own, or none (sshd ran the built-in `cmd.exe`):
    /// no value is lost by replacing it ([`system_config::nothing_to_carry`]). Any other shell gets `None`.
    pub fn nothing_to_carry(previous: &SshdShell) -> Option<Self> {
        system_config::nothing_to_carry(previous).then_some(Self(()))
    }

    /// The config now holds the previous shell. Nothing is said: the config is the record.
    fn carried() -> Self {
        Self(())
    }

    /// `text` holds every previous value and was emitted before the shell is replaced: `show` does not return
    /// when the write fails.
    fn printed(show: &mut dyn FnMut(&str), text: &str) -> Self {
        show(text);
        Self(())
    }
}

/// The text with a value that is about to be deleted was emitted.
#[must_use = "the removal takes it"]
#[derive(Debug)]
pub struct ShownValue(());

impl ShownValue {
    /// `text` holds the value and is emitted before the value is deleted: `show` does not return when the write
    /// fails.
    fn print(show: &mut dyn FnMut(&str), text: &str) -> Self {
        show(text);
        Self(())
    }
}

/// Replace the shell sshd uses: read it with `read`, `carry` its values (or print them), and only
/// then `flip`, which takes the [`Handover`] that `carry` returned. A shell that could not be read in
/// full is an error and `carry` and `flip` are not called: what cannot be read can be neither carried
/// nor printed, so the shell is left as it is, and the error says so. ssh-broker's own shell is no such
/// case (see [`SshdShellReading::into_shell`](super::registry::SshdShellReading::into_shell)): replacing it loses nothing.
pub fn replace_shell<T>(
    read: impl FnOnce() -> Result<SshdShell, UnreadShell>,
    carry: impl FnOnce(&SshdShell) -> Handover,
    flip: impl FnOnce(&Handover) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    let previous = read().map_err(|unread| anyhow::anyhow!("{unread}. DefaultShell was not changed"))?;
    let handover = carry(&previous);
    flip(&handover).map_err(|e| e.context("DefaultShell was not changed"))
}

/// Act on `decision` for `previous`: write the config with `create` (which says whether it created the
/// file, and is called only for a [`Decision::Write`]), or print what is not carried.
/// `config` is the config's path. A previous shell with nothing to carry ([`system_config::nothing_to_carry`]) is known
/// from `previous` alone, whatever `decision` says; a decision that claims it for any other shell is
/// printed, not believed. What is printed goes through `show`, which does not return when the write fails (see
/// [`show_to`]).
pub fn hand_over(
    config: &Path,
    previous: &SshdShell,
    decision: Decision,
    create: impl FnOnce(&ShellBlock) -> anyhow::Result<CreateOutcome>,
    show: &mut dyn FnMut(&str),
) -> Handover {
    if let Some(handover) = Handover::nothing_to_carry(previous) {
        return handover;
    }
    let skip = match decision {
        Decision::Write(block) => match create(&block) {
            Ok(CreateOutcome::Created) => return Handover::carried(),
            // Someone else created the config between the check and the create: it is never rewritten.
            Ok(CreateOutcome::FileExists) => Skip::FileExists,
            Ok(CreateOutcome::NotAFile) => Skip::NotAFile,
            Err(e) => {
                return Handover::printed(show, &system_config::not_written(config, previous, &format!("{e:#}")));
            }
        },
        Decision::Skip(skip) => skip,
    };
    Handover::printed(show, &system_config::skip_notice(config, previous, &skip))
}

/// Remove `DefaultShellArguments` once `DefaultShell` is ssh-broker (see [`system_config::plan_arguments`]
/// for what is read and left). `config` is the config's path and `key` the registry key. The text with the
/// value is emitted first and `remove`, which takes the [`ShownValue`] that makes, runs after it; a failed
/// removal is said with its cause and leaves the value for the next `install`, and one that worked says nothing.
/// The text with the value goes through `show`, which does not return when the write fails (see [`show_to`]); the
/// other lines go through `say`.
pub fn remove_arguments(
    config: &Path,
    key: &str,
    read: Result<Option<String>, String>,
    config_is_file: impl FnOnce() -> Result<ConfigKind, String>,
    remove: impl FnOnce(&ShownValue) -> anyhow::Result<()>,
    say: &mut Say<'_>,
    show: &mut dyn FnMut(&str),
) {
    match system_config::plan_arguments(config, key, read, config_is_file) {
        ArgumentsPlan::Nothing => {}
        ArgumentsPlan::Leave(notice) => say(Stream::Err, &notice),
        ArgumentsPlan::Remove(value) => {
            let shown = ShownValue::print(show, &system_config::arguments_removing(key, &value));
            if let Err(e) = remove(&shown) {
                say(
                    Stream::Err,
                    &system_config::arguments_not_removed(key, &value, &format!("{e:#}")),
                );
            }
        }
    }
}

#[cfg(test)]
#[path = "handover_tests.rs"]
mod handover_tests;
