//! The system config `apply` creates from the shell sshd used before: what it carries, and the
//! one-time, atomic creation.
//!
//! `apply` is about to make ssh-broker sshd's `DefaultShell`, which loses the old value. The old
//! shell, with the options sshd ran it with, is written once to `config.yaml` in the install
//! directory so that sessions keep starting the same shell. Only values that differ from what
//! ssh-broker defaults to for that program are written, so the file says what the user's setup
//! needs and nothing more. The file is never rewritten.

use std::io::Write;
use std::path::Path;

use anyhow::Context;

use super::layout::TrustedBase;
use super::registry::SshdShell;
use crate::shell::config::{ShellBlock, render_file};
use crate::shell::{Escaping, defaults};

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skip {
    /// The previous shell is ssh-broker's own: an `apply` over an install has nothing to carry.
    PreviousIsSshBroker,
    /// No `DefaultShell`: sshd ran the system `cmd.exe`, which is the built-in.
    NoPreviousShell,
    /// A config is already there, and is never rewritten.
    FileExists,
    /// The previous shell is not a file that exists; a config naming it would not start.
    PreviousMissing,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Write(ShellBlock),
    Skip(Skip),
}

/// Whether `apply` writes the config, and what. `file_exists` says whether the previous shell
/// exists (a bare name is looked up on `PATH` by the caller); `is_system_cmd` whether it is the
/// system `cmd.exe`.
pub fn decide(
    prev: &SshdShell,
    config_exists: bool,
    file_exists: &dyn Fn(&Path) -> bool,
    is_system_cmd: &dyn Fn(&Path) -> bool,
) -> Decision {
    let Some(shell) = prev.shell.as_deref() else {
        return Decision::Skip(Skip::NoPreviousShell);
    };
    let file_name = shell.rsplit(['\\', '/']).next().unwrap_or(shell);
    if file_name.eq_ignore_ascii_case(super::EXE_NAME) {
        return Decision::Skip(Skip::PreviousIsSshBroker);
    }
    if config_exists {
        return Decision::Skip(Skip::FileExists);
    }
    let path = Path::new(shell);
    if !file_exists(path) {
        return Decision::Skip(Skip::PreviousMissing);
    }
    Decision::Write(carried_block(prev, is_system_cmd(path)))
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
            let _ = std::fs::remove_file(&temp);
            return Err(e);
        }
    };
    let _ = std::fs::remove_file(&temp);
    match linked {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(e).with_context(|| format!("create {}", target.display())),
    }
}

#[cfg(test)]
#[path = "system_config_tests.rs"]
mod system_config_tests;
