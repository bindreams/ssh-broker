//! The proof that `apply` kept or showed the shell sshd used before it makes ssh-broker `DefaultShell`.
//!
//! [`registry::set_default_shell_under`](super::registry::set_default_shell_under) takes a
//! [`Handover`], and the only ways to get one are here: the config was written from the previous
//! values (carried), the text that holds every previous value was emitted (printed), or there is
//! nothing to carry. No path through `apply` can replace the shell with the values neither kept nor shown.
//! [`registry::remove_shell_arguments_under`](super::registry::remove_shell_arguments_under) is the same
//! for the one value that is deleted afterwards: it takes a [`ShownValue`], which only the print of the
//! value makes.

use std::path::Path;

use super::registry::{SshdShell, UnreadShell};
use super::system_config::{self, ArgumentsPlan, Decision};
use crate::shell::config::ShellBlock;

/// Where a notice goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    Out,
    Err,
}

/// Writes a notice to the console: standard output or standard error.
pub fn say_to_console(stream: Stream, text: &str) {
    match stream {
        Stream::Out => println!("{text}"),
        Stream::Err => eprintln!("{text}"),
    }
}

/// The previous shell's values were carried into the config, or printed, or there were none to keep.
#[must_use = "the DefaultShell flip takes it"]
#[derive(Debug)]
pub struct Handover(());

impl Handover {
    /// The previous shell is ssh-broker's own, or there is none (sshd ran the built-in `cmd.exe`):
    /// no value is lost by replacing it. [`hand_over`] decides that from the shell itself; this is `pub`
    /// only for the integration tests, which have no way into the crate's `cfg(test)` code, and no
    /// production code calls it.
    pub fn nothing_to_carry() -> Self {
        Self(())
    }

    /// The config now holds the previous shell; `text` says so.
    fn carried(say: &mut dyn FnMut(Stream, &str), text: &str) -> Self {
        say(Stream::Out, text);
        Self(())
    }

    /// `text` holds every previous value and was emitted before the shell is replaced.
    fn printed(say: &mut dyn FnMut(Stream, &str), text: &str) -> Self {
        say(Stream::Err, text);
        Self(())
    }
}

/// The text with a value that is about to be deleted was emitted.
#[must_use = "the removal takes it"]
#[derive(Debug)]
pub struct ShownValue(());

impl ShownValue {
    /// `text` holds the value and is emitted before the value is deleted.
    fn print(say: &mut dyn FnMut(Stream, &str), text: &str) -> Self {
        say(Stream::Err, text);
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
    let previous = read().map_err(|unread| {
        anyhow::anyhow!(
            "{unread}. DefaultShell was not changed: fix the value or its permissions, or delete it, then run \
             `apply` again"
        )
    })?;
    let handover = carry(&previous);
    flip(&handover).map_err(|e| e.context("DefaultShell was not changed"))
}

/// Act on `decision` for `previous`: write the config with `create` (which says whether it created the
/// file, and is called only for a [`Decision::Write`]), or print what is not carried. `config` is the
/// config's path. A previous shell with nothing to carry ([`system_config::nothing_to_carry`]) is known
/// from `previous` alone, whatever `decision` says; a decision that claims it for any other shell is
/// printed, not believed.
pub fn hand_over(
    config: &Path,
    previous: &SshdShell,
    decision: Decision,
    create: impl FnOnce(&ShellBlock) -> anyhow::Result<bool>,
    say: &mut dyn FnMut(Stream, &str),
) -> Handover {
    if system_config::nothing_to_carry(previous) {
        return Handover::nothing_to_carry();
    }
    let skip = match decision {
        Decision::Write(block) => match create(&block) {
            Ok(true) => {
                return Handover::carried(
                    say,
                    &format!(
                        "apply: wrote {} from the shell sshd used before ({})",
                        config.display(),
                        previous.shell.as_deref().unwrap_or_default()
                    ),
                );
            }
            // Someone else created the config between the check and the create: it is never rewritten.
            Ok(false) => system_config::Skip::FileExists,
            Err(e) => {
                return Handover::printed(say, &system_config::not_written(config, previous, &format!("{e:#}")));
            }
        },
        Decision::Skip(skip) => skip,
    };
    Handover::printed(say, &system_config::skip_notice(config, previous, &skip))
}

/// Remove `DefaultShellArguments` once `DefaultShell` is ssh-broker (see [`system_config::plan_arguments`]
/// for what is read and left). `config` is the config's path and `key` the registry key. The text with the
/// value is emitted first and `remove`, which takes the [`ShownValue`] that makes, runs after it; then the
/// removal, or its failure with the cause, is said. A failed removal leaves the value for the next `apply`.
pub fn remove_arguments(
    config: &Path,
    key: &str,
    read: Result<Option<String>, String>,
    config_is_file: impl FnOnce() -> Result<bool, String>,
    remove: impl FnOnce(&ShownValue) -> anyhow::Result<()>,
    say: &mut dyn FnMut(Stream, &str),
) {
    match system_config::plan_arguments(config, key, read, config_is_file) {
        ArgumentsPlan::Nothing => {}
        ArgumentsPlan::Leave(notice) => say(Stream::Err, &notice),
        ArgumentsPlan::Remove(value) => {
            let shown = ShownValue::print(say, &system_config::arguments_removing(key, &value));
            match remove(&shown) {
                Ok(()) => say(Stream::Out, &system_config::arguments_removed(config, key, &value)),
                Err(e) => say(
                    Stream::Err,
                    &system_config::arguments_not_removed(key, &value, &format!("{e:#}")),
                ),
            }
        }
    }
}

#[cfg(test)]
#[path = "handover_tests.rs"]
mod handover_tests;
