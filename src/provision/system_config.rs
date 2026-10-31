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
    /// The previous shell is ssh-broker's own: an `apply` over an install has nothing to carry.
    PreviousIsSshBroker,
    /// No `DefaultShell`: sshd ran the system `cmd.exe`, which is the built-in.
    NoPreviousShell,
    /// A config is already there, and is never rewritten.
    FileExists,
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

/// Whether `apply` writes the config, and what. `config_exists` is whether the config is there, or
/// why that is not known. `search_dirs` is called only once the decision needs the directories, so
/// a failure to find them is not reported when nothing depends on it. `find` finds the file the
/// previous shell names in them, as sshd finds it ([`sshd_search_dirs`]), or says why there is none; `is_system_cmd` says whether that file is the system `cmd.exe`. A bare name is carried as
/// the file found, because a session searches `PATH` alone and sshd searched more. Nothing that
/// could not be found out is reported while it does not matter: with no previous shell, or ssh-broker's
/// own, nothing is replaced, and a config that is there is never rewritten.
pub fn decide(
    prev: &SshdShell,
    config_exists: Result<bool, String>,
    search_dirs: &SearchDirs,
    find: &Find,
    is_system_cmd: &dyn Fn(&Path) -> bool,
) -> Decision {
    let Some(shell) = prev.shell.as_deref() else {
        return Decision::Skip(Skip::NoPreviousShell);
    };
    let file_name = shell.rsplit(['\\', '/']).next().unwrap_or(shell);
    if file_name.eq_ignore_ascii_case(super::EXE_NAME) {
        return Decision::Skip(Skip::PreviousIsSshBroker);
    }
    match config_exists {
        Err(cause) => return Decision::Skip(Skip::Unchecked(cause)),
        Ok(true) => return Decision::Skip(Skip::FileExists),
        Ok(false) => {}
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

/// The warning for a previous shell that is not carried: `apply` still replaces `DefaultShell`, so
/// this holds every value of the shell it replaces, which nothing else keeps. `reason` says why it is
/// not carried.
fn not_carried(config: &Path, previous: &SshdShell, reason: &str) -> String {
    format!(
        "apply: {reason}, so this apply does not carry the shell sshd used before into {config}; DefaultShell is \
         replaced all the same. To restore it, put it in that config or under {values}",
        config = config.display(),
        values = previous_values(previous),
    )
}

/// The warning for a config that could not be written.
pub fn not_written(config: &Path, previous: &SshdShell, cause: &str) -> String {
    not_carried(
        config,
        previous,
        &format!("could not write {}: {cause}", config.display()),
    )
}

/// The warning for a [`Skip`] that leaves the previous shell uncarried while `apply` replaces it;
/// none for a skip that replaces nothing.
pub fn skip_notice(config: &Path, previous: &SshdShell, skip: &Skip) -> Option<String> {
    let reason = match skip {
        Skip::PreviousIsSshBroker | Skip::NoPreviousShell => return None,
        Skip::FileExists => format!("{} is already there and is never rewritten", config.display()),
        Skip::PreviousMissing(why) => format!(
            "the shell sshd uses now ({}) cannot be used: {why}",
            previous.shell.as_deref().unwrap_or_default()
        ),
        Skip::Unchecked(cause) => cause.clone(),
    };
    Some(not_carried(config, previous, &reason))
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

/// Write the system config for `block` if there is none, and say whether it did.
///
/// The text goes to a temporary file in the same directory first and is then linked to the final
/// name, which fails if the name is taken: the config appears whole or not at all, and a file that
/// is there is never replaced. The new file inherits the install directory's ACL, which `base`
/// proves was checked.
pub fn create_once(base: &TrustedBase<'_>, block: &ShellBlock) -> anyhow::Result<bool> {
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
pub(super) fn create_once_at(target: &Path, block: &ShellBlock) -> anyhow::Result<bool> {
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
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(e).with_context(|| format!("create {}", target.display())),
    }
}

#[cfg(test)]
#[path = "system_config_tests.rs"]
mod system_config_tests;
