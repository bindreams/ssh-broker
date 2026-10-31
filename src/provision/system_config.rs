//! The system config `apply` creates from the shell sshd used before: what it carries, and the
//! one-time, atomic creation.
//!
//! `apply` is about to make ssh-broker sshd's `DefaultShell`, which loses the old value. The old
//! shell, with the options sshd ran it with, is written once to `config.yaml` in the install
//! directory so that sessions keep starting the same shell. Only values that differ from what
//! ssh-broker defaults to for that program are written, so the file says what the user's setup
//! needs and nothing more. The file is never rewritten.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Context;

use super::layout::TrustedBase;
use super::registry::SshdShell;
use crate::shell::config::{ShellBlock, render_file};
use crate::shell::{Escaping, Host, defaults};

/// The kind of shell sshd takes a `DefaultShell` for, which decides how it packs a command
/// (`w32-doexec.c`): it lowercases the path, turns `/` into `\`, and the first substring below that
/// matches decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshdClass {
    Cmd,
    PowerShell,
    ShellHost,
    Bash,
    Cygwin,
    Other,
}

/// sshd's class for `shell`.
pub fn classify(shell: &str) -> SshdClass {
    let path = shell.to_lowercase().replace('/', "\\");
    if path.contains("system32\\cmd") {
        SshdClass::Cmd
    } else if path.contains("powershell") {
        SshdClass::PowerShell
    } else if path.contains("ssh-shellhost") {
        SshdClass::ShellHost
    } else if path.contains("\\bash") {
        SshdClass::Bash
    } else if path.contains("cygwin") {
        SshdClass::Cygwin
    } else {
        SshdClass::Other
    }
}

/// The block that makes ssh-broker start `prev.shell` the way sshd did. `shell_is_system_cmd`:
/// that file is the system `cmd.exe`, which decides the defaults the values are compared with.
/// `prev.shell` must be set.
pub fn carried_block(prev: &SshdShell, shell_is_system_cmd: bool) -> ShellBlock {
    let shell = prev.shell.as_deref().expect("a previous shell to carry");
    let class = classify(shell);
    let ours = defaults(shell_is_system_cmd);

    // What sshd did: its option, else its own default for the class; escaped unless the class
    // never is (cmd and ssh-shellhost), always is (PowerShell, bash, Cygwin), or the flag says.
    let sshd_option = prev
        .command_option
        .clone()
        .unwrap_or_else(|| if class == SshdClass::Cmd { "/c" } else { "-c" }.into());
    let sshd_escaping = match class {
        SshdClass::Cmd | SshdClass::ShellHost => Escaping::Cmd,
        SshdClass::PowerShell | SshdClass::Bash | SshdClass::Cygwin => Escaping::Msvc,
        SshdClass::Other if prev.escape_arguments => Escaping::Msvc,
        SshdClass::Other => Escaping::Cmd,
    };

    // sshd pastes the option as text into the lines it builds for a terminal and for `cmd.exe`, so
    // `/d /c` is two arguments there, as `DefaultShellArguments` is split: split it the same way.
    let with_command = split_arguments(&sshd_option).unwrap_or_default();
    ShellBlock {
        start: vec![shell.to_owned()],
        without_command: prev.arguments.as_deref().and_then(split_arguments),
        with_command: (with_command != ours.with_command).then_some(with_command),
        escaping: (sshd_escaping != ours.escaping).then_some(sshd_escaping),
    }
}

/// A `DefaultShellArguments` or `DefaultShellCommandOption` value as the arguments sshd's lines
/// paste after the shell: split as a command line. `None` when there are none.
fn split_arguments(arguments: &str) -> Option<Vec<String>> {
    // `split_wide` returns the program name too; a stand-in goes first and is dropped.
    let wide: Vec<u16> = format!("x {arguments}").encode_utf16().collect();
    let mut parts = cosca::quote::windows::split_wide(&wide).expect("CommandLineToArgvW has no error states");
    parts.remove(0);
    let args: Vec<String> = parts.iter().map(|p| String::from_utf16_lossy(p)).collect();
    (!args.is_empty()).then_some(args)
}

/// Why nothing is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Skip {
    /// The previous shell is ssh-broker's own (an `apply` over an install) or none (sshd ran the system
    /// `cmd.exe`, which is the built-in): see [`nothing_to_carry`].
    NothingToCarry,
    /// A config is already there, and is never rewritten.
    FileExists,
    /// A directory or other non-file is at the config's path: it holds no config, and writing one needs it gone.
    NotAFile,
    /// The previous shell is not a file that exists, found as sshd finds it (the string is why not);
    /// a config naming it would not start.
    PreviousMissing(String),
    /// What the decision needs could not be found out (whether the config is there, or the
    /// directories to look for the shell in); the string says what.
    Unchecked(String),
}

/// Finds the file a shell names in the directories given, or says why there is none.
pub type Find<'a> = dyn Fn(&[PathBuf], &Path) -> Result<PathBuf, String> + 'a;

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Write(ShellBlock),
    Skip(Skip),
}

/// Finds the directories sshd searches for a bare shell name, or says why they are not known.
pub type SearchDirs<'a> = dyn Fn() -> Result<Vec<PathBuf>, String> + 'a;

/// Whether `apply` writes the config, and what. `config_is_file` is what is at its path (see
/// [`config_is_file`]), or why that is not known. `search_dirs` is called only once the decision needs the directories, so
/// a failure to find them is not reported when nothing depends on it. `find` finds the file the
/// previous shell names in them, as sshd finds it ([`sshd_search_dirs`]), or says why there is none;
/// `is_system_cmd` says whether that file is the system `cmd.exe`. A bare name is carried as
/// the file found, because a session searches `PATH` alone and sshd searched more. Nothing that
/// could not be found out is reported while it does not matter: with no previous shell, or ssh-broker's
/// own, nothing is replaced, and a config that is there, or a path that is not a file, is not written.
pub fn decide(
    prev: &SshdShell,
    config_is_file: Result<ConfigKind, String>,
    search_dirs: &SearchDirs,
    find: &Find,
    is_system_cmd: &dyn Fn(&Path) -> bool,
) -> Decision {
    if nothing_to_carry(prev) {
        return Decision::Skip(Skip::NothingToCarry);
    }
    let shell = prev.shell.as_deref().unwrap_or_default();
    match config_is_file {
        Err(cause) => return Decision::Skip(Skip::Unchecked(cause)),
        Ok(ConfigKind::File) => return Decision::Skip(Skip::FileExists),
        Ok(ConfigKind::Other) => return Decision::Skip(Skip::NotAFile),
        Ok(ConfigKind::Missing) => {}
    }
    let dirs = match search_dirs() {
        Ok(dirs) => dirs,
        Err(cause) => return Decision::Skip(Skip::Unchecked(cause)),
    };
    let found = match find(&dirs, Path::new(shell)) {
        Ok(found) => found,
        Err(why) => return Decision::Skip(Skip::PreviousMissing(why)),
    };
    // The options are judged by the name sshd was given; only the program is replaced.
    let mut block = carried_block(prev, is_system_cmd(&found));
    if !shell.contains(['\\', '/', ':']) {
        block.start = vec![found.to_string_lossy().into_owned()];
    }
    Decision::Write(block)
}

/// The values of the shell `apply` replaces, as they are in the registry: what nothing else keeps.
fn previous_values(previous: &SshdShell) -> String {
    let value = |value: &Option<String>| value.as_ref().map_or("not set".to_owned(), |v| format!("\"{v}\""));
    let escape = if previous.escape_arguments { "yes" } else { "no" };
    format!(
        "HKLM\\{key}: DefaultShell = {shell}, DefaultShellCommandOption = {option}, DefaultShellArguments = \
         {arguments}, escape arguments = {escape}",
        key = super::registry::OPENSSH_KEY,
        shell = value(&previous.shell),
        option = value(&previous.command_option),
        arguments = value(&previous.arguments),
    )
}

/// The warning for a previous shell that is not carried. `apply` prints it before it replaces
/// `DefaultShell`, which can still fail, so it says what `apply` does next and holds every value of
/// the shell, which nothing else keeps. `reason` says why it is not carried, `in_config` how to put the shell
/// in the config instead.
fn not_carried(config: &Path, previous: &SshdShell, reason: &str, in_config: &str) -> String {
    format!(
        "apply: {reason}, so this apply does not carry the shell sshd used before into {config}; apply replaces \
         DefaultShell next. To restore the shell, {in_config} or under {values}",
        config = config.display(),
        values = previous_values(previous),
    )
}

const PUT_IN_CONFIG: &str = "put it in that config";

/// The warning for a config that could not be written.
pub fn not_written(config: &Path, previous: &SshdShell, cause: &str) -> String {
    not_carried(
        config,
        previous,
        &format!("could not write {}: {cause}", config.display()),
        PUT_IN_CONFIG,
    )
}

/// Whether replacing `previous` loses nothing: sshd ran no shell of its own (the built-in `cmd.exe`) or
/// ssh-broker. The one place `apply` asks this.
pub fn nothing_to_carry(previous: &SshdShell) -> bool {
    previous.shell.as_deref().is_none_or(super::is_ssh_broker)
}

/// The warning for a [`Skip`] that leaves the previous shell uncarried while `apply` replaces it.
/// [`Skip::NothingToCarry`] is no reason for a shell that has something to carry, and says so.
pub fn skip_notice(config: &Path, previous: &SshdShell, skip: &Skip) -> String {
    let mut in_config = PUT_IN_CONFIG;
    let reason = match skip {
        Skip::NothingToCarry => format!(
            "the shell sshd uses now ({}) was taken for one with nothing to carry, which it is not",
            previous.shell.as_deref().unwrap_or_default()
        ),
        Skip::FileExists => format!("{} is already there and is never rewritten", config.display()),
        Skip::NotAFile => {
            in_config = "replace what is at that path with a config that holds it (README, \"Shell configuration\")";
            format!("{} is not a file", config.display())
        }
        Skip::PreviousMissing(why) => format!(
            "the shell sshd uses now ({}) cannot be used: {why}",
            previous.shell.as_deref().unwrap_or_default()
        ),
        Skip::Unchecked(cause) => cause.clone(),
    };
    not_carried(config, previous, &reason, in_config)
}

/// What is at the system config's path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigKind {
    /// A regular file, which is what the loader can read.
    File,
    /// Nothing.
    Missing,
    /// A directory or anything else: it holds no config, and writing one there needs it gone.
    Other,
}

/// What is at `config`, or why that is not known: a failed check is not an absent file, so the cause
/// is kept and worded as one that cannot tell. The one answer to "is the system config there" in `apply`.
pub fn config_is_file(config: &Path) -> Result<ConfigKind, String> {
    match std::fs::metadata(config) {
        Ok(metadata) if metadata.is_file() => Ok(ConfigKind::File),
        Ok(_) => Ok(ConfigKind::Other),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ConfigKind::Missing),
        Err(e) => Err(format!("cannot tell whether {} is a file: {e}", config.display())),
    }
}

/// What `apply` does with `DefaultShellArguments` once `DefaultShell` is ssh-broker.
#[derive(Debug, PartialEq, Eq)]
pub enum ArgumentsPlan {
    /// Sshd ignores the value (absent, empty or too long): nothing to pass on.
    Nothing,
    /// The value stays; the string is what `apply` says about it.
    Leave(String),
    /// The value is removed; the string is how it was read, for the notice.
    Remove(String),
}

/// Decide what to do with `DefaultShellArguments` from how it was `arguments` read and whether the config
/// that carries it is a file (`config_is_file`, asked only when the value is read and set). A value that
/// was not read is never removed, since it could be neither shown nor carried; one with no config to hold
/// it, or none known, is left too.
pub fn plan_arguments(
    config: &Path,
    key: &str,
    arguments: Result<Option<String>, String>,
    config_is_file: impl FnOnce() -> Result<ConfigKind, String>,
) -> ArgumentsPlan {
    let arguments = match arguments {
        Ok(Some(arguments)) => arguments,
        Ok(None) => return ArgumentsPlan::Nothing,
        Err(cause) => return ArgumentsPlan::Leave(arguments_unreadable(key, &cause)),
    };
    let value = format!("{arguments:?}");
    const WRITE: &str = "write the config (README, \"Shell configuration\")";
    match config_is_file() {
        Ok(ConfigKind::File) => ArgumentsPlan::Remove(value),
        Ok(ConfigKind::Missing) => ArgumentsPlan::Leave(arguments_left(
            key,
            &value,
            &format!("there is no {} to hold it", config.display()),
            WRITE,
        )),
        Ok(ConfigKind::Other) => ArgumentsPlan::Leave(arguments_left(
            key,
            &value,
            &format!("{} is not a file, so it cannot hold it", config.display()),
            "replace what is at that path with the config (README, \"Shell configuration\")",
        )),
        Err(cause) => ArgumentsPlan::Leave(arguments_left(
            key,
            &value,
            &format!("{cause}, so it is not known whether there is a config to hold it"),
            "fix what stops that check",
        )),
    }
}

/// The notice for a `DefaultShellArguments` `apply` leaves: `DefaultShell` is ssh-broker by now, `why`
/// says why there is no config to hold the value, `fix` what to do about that, and `value` is how it was read.
pub fn arguments_left(key: &str, value: &str, why: &str, fix: &str) -> String {
    format!(
        "apply: left DefaultShellArguments ({value}) under HKLM\\{key}: {why}, and sshd passes it to ssh-broker \
         ahead of -c; {fix} and run apply again, which removes it"
    )
}

/// The notice for a `DefaultShellArguments` `apply` leaves because it could not read it, with the `cause`.
/// What sshd does with a value nobody could read is not known, so the text says none of it.
pub fn arguments_unreadable(key: &str, cause: &str) -> String {
    format!(
        "apply: left DefaultShellArguments under HKLM\\{key}: it could not be read ({cause}), so it can be neither \
         shown nor carried; fix its permissions or delete it, then run apply again: a value that can be read is \
         removed once the system config is a file"
    )
}

/// The text `apply` emits before it removes `DefaultShellArguments`, with the `value` as it was read.
pub fn arguments_removing(key: &str, value: &str) -> String {
    format!(
        "apply: removing DefaultShellArguments ({value}) from HKLM\\{key}, since sshd would pass it to ssh-broker \
         ahead of -c"
    )
}

/// The notice for a `DefaultShellArguments` `apply` removed.
pub fn arguments_removed(config: &Path, key: &str, value: &str) -> String {
    format!(
        "apply: removed DefaultShellArguments ({value}) from HKLM\\{key}, since sshd would pass it to ssh-broker \
         ahead of -c; put it in {} if the shell needs it",
        config.display()
    )
}

/// The notice for a `DefaultShellArguments` `apply` could not remove, with the `cause`.
pub fn arguments_not_removed(key: &str, value: &str, cause: &str) -> String {
    format!(
        "apply: could not remove DefaultShellArguments ({value}) under HKLM\\{key}, and sshd passes it to \
         ssh-broker ahead of -c; the next apply tries again: {cause}"
    )
}

/// The directories sshd's `CreateProcess` searches for a bare `DefaultShell` before `PATH`, in its
/// order: the directory of sshd itself (`image_path`, the service's `ImagePath`, when it is known),
/// the system directory and the Windows directory. The working directory is not listed: sshd's is not
/// the system directory but the drive root (the service) or the account's profile (the process running as
/// the account), as `tests/shell_sshd_windows.rs` measures, and `apply` runs for no one account.
pub fn sshd_search_dirs(host: &dyn Host, image_path: Option<&str>) -> anyhow::Result<Vec<PathBuf>> {
    let system_dir = host
        .system_cmd()?
        .parent()
        .context("the system directory has no name")?
        .to_path_buf();
    let windows_dir = system_dir
        .parent()
        .context("the system directory is not in a Windows directory")?
        .to_path_buf();
    let mut dirs: Vec<PathBuf> = image_path.and_then(image_dir).into_iter().collect();
    dirs.extend([system_dir, windows_dir]);
    Ok(dirs)
}

/// The directory of the program a service's `ImagePath` starts. The value is a command line:
/// the program is quoted, or runs up to its `.exe`, and arguments may follow.
pub(super) fn image_dir(image_path: &str) -> Option<PathBuf> {
    let image_path = image_path.trim();
    let program = match image_path.strip_prefix('"') {
        Some(quoted) => quoted.split('"').next()?,
        None => {
            let end = image_path
                .to_ascii_lowercase()
                .find(".exe")
                .map_or(image_path.len(), |at| at + ".exe".len());
            &image_path[..end]
        }
    };
    let (dir, _) = program.rsplit_once(['\\', '/'])?;
    (!dir.is_empty()).then(|| PathBuf::from(dir))
}

/// The file's text: a note on where it came from, then the block.
pub fn render(block: &ShellBlock) -> anyhow::Result<String> {
    let body = render_file(block).map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(format!(
        "# Created once by `ssh-broker apply` from the shell sshd used before ssh-broker. Edit it freely;\n\
         # `apply` never rewrites it. `ssh-broker verify` shows the shell in effect.\n{body}"
    ))
}

/// Write the system config for `block` if there is none: `None` when it did, else why it did not
/// ([`Skip::FileExists`], or [`Skip::NotAFile`] for a path that holds a directory or other non-file).
///
/// The text goes to a temporary file in the same directory first and is then linked to the final
/// name, which fails if the name is taken: the config appears whole or not at all, and a file that
/// is there is never replaced. The new file inherits the install directory's ACL, which `base`
/// proves was checked.
pub fn create_once(base: &TrustedBase<'_>, block: &ShellBlock) -> anyhow::Result<Option<Skip>> {
    create_once_at(&base.layout().system_config_path(), block)
}

/// Remove the temporary file. A refusal leaves it in the install directory, so it is logged with
/// the path; a file that is not there was never created, or is gone already.
fn remove_temp(temp: &Path) {
    match std::fs::remove_file(temp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => tracing::warn!("could not remove the temporary file {}: {e}", temp.display()),
    }
}

/// [`create_once`] for a path: the part that does not depend on the install directory.
pub(super) fn create_once_at(target: &Path, block: &ShellBlock) -> anyhow::Result<Option<Skip>> {
    let text = render(block)?;
    let mut temp = target.as_os_str().to_owned();
    temp.push(format!(".tmp-{}", std::process::id()));
    let temp = std::path::PathBuf::from(temp);

    let written = (|| -> anyhow::Result<()> {
        let mut file = std::fs::File::create(&temp).with_context(|| format!("create {}", temp.display()))?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        Ok(())
    })();
    let linked = match written {
        Ok(()) => std::fs::hard_link(&temp, target),
        Err(e) => {
            remove_temp(&temp);
            return Err(e);
        }
    };
    remove_temp(&temp);
    match linked {
        Ok(()) => Ok(None),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(Some(match config_is_file(target) {
            Ok(ConfigKind::Other) => Skip::NotAFile,
            _ => Skip::FileExists,
        })),
        Err(e) => Err(e).with_context(|| format!("create {}", target.display())),
    }
}

#[cfg(test)]
#[path = "system_config_tests.rs"]
mod system_config_tests;
