//! The user's shell: what `ssh-broker` starts for a session, and how it packs the command.
//!
//! Configured by `config.yaml` (see [`config`]), resolved through layers ([`layers`]) and turned
//! into a spawn line. Everything here is pure over a [`Host`], so it builds and tests on every
//! platform. Paths are Windows paths whatever the host platform is: they are joined and judged
//! as text, never with `std::path`'s platform rules.

pub mod config;
pub mod layers;
pub mod pack;
#[cfg(windows)]
mod windows;

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub use layers::{Chosen, Origin, Problem, choose, user_config_path};
pub use pack::{
    Defaults, Effective, Plan, Session, Source, StartError, Why, built_in_plan, defaults, effective, plan, render,
    resolve_program, resolve_program_in, start_or_fall_back,
};
#[cfg(windows)]
pub use windows::WindowsHost;

/// How the broker packs the already-decoded command for the shell it starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Escaping {
    /// The command wrapped in quotes, otherwise as written: what `cmd.exe /c` reads.
    Cmd,
    /// Standard `CommandLineToArgvW` quoting: one exact argument.
    Msvc,
}

/// Everything resolution asks of the machine: the environment, files, the program search and the
/// identity of the system `cmd.exe`. The one boundary of this module; the production
/// implementation is `WindowsHost`, tests answer from a table.
pub trait Host {
    /// A variable of the resolving process's own environment.
    fn env(&self, name: &str) -> Option<OsString>;
    /// The profile directory of the account the process runs as, from its token and not from
    /// `USERPROFILE`.
    fn profile_dir(&self) -> anyhow::Result<PathBuf>;
    /// The file's bytes; `Ok(None)` when it does not exist. A directory, or a file that cannot
    /// be read, is an error.
    fn read_file(&self, path: &Path) -> std::io::Result<Option<Vec<u8>>>;
    /// Whether `path` names an existing file: `Ok(false)` for a path that is missing or is a
    /// directory, an error with the system's reason for a path that cannot be examined.
    fn is_file(&self, path: &Path) -> std::io::Result<bool>;
    /// The first file named `name` in `first`, in order, and then along the process's `PATH`;
    /// `.exe` is appended when `name` has no extension.
    fn find_program_in(&self, first: &[PathBuf], name: &str) -> Option<PathBuf>;
    /// The first file named `name` along the process's `PATH`.
    fn find_program(&self, name: &str) -> Option<PathBuf> {
        self.find_program_in(&[], name)
    }
    /// Whether `path` is the system `cmd.exe` by file identity.
    fn is_system_cmd(&self, path: &Path) -> std::io::Result<bool>;
    /// `cmd.exe` in the system directory: the built-in shell. An error when the system directory
    /// cannot be found.
    fn system_cmd(&self) -> anyhow::Result<PathBuf>;
    /// `C:\ProgramData\ssh-broker\config.yaml`.
    fn system_config_path(&self) -> PathBuf;
}

/// `base` and `parts`, joined with `\` as text. `Path::join` would use the platform's separator,
/// and these are Windows paths on every host.
pub(crate) fn join_windows(base: &Path, parts: &[&str]) -> PathBuf {
    let mut joined = base.as_os_str().to_owned();
    for part in parts {
        if !joined.to_string_lossy().ends_with(['\\', '/']) {
            joined.push("\\");
        }
        joined.push(part);
    }
    PathBuf::from(joined)
}

/// Whether `path` is a drive-absolute (`C:\...`, `C:/...`) or UNC (`\\server\...`) Windows path.
/// `C:foo` and `\foo` are relative to something and are not.
pub(crate) fn is_absolute_windows(path: &Path) -> bool {
    let text = path.as_os_str().to_string_lossy();
    let mut chars = text.chars();
    match (chars.next(), chars.next(), chars.next()) {
        (Some(d), Some(':'), Some('\\' | '/')) => d.is_ascii_alphabetic(),
        (Some('\\' | '/'), Some('\\' | '/'), _) => true,
        _ => false,
    }
}

#[cfg(test)]
pub(crate) mod test_host;

#[cfg(test)]
#[path = "shell_tests.rs"]
mod shell_tests;
