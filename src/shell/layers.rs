//! Which `shell` block applies: the user's, the system's, or the built-in `cmd.exe`.
//!
//! A layer that has a `shell` block replaces the layers below it whole. A layer that is broken
//! (unreadable, not valid, or invalid) does not fall one layer up: it falls to the built-in
//! `cmd.exe`, with a [`Problem`] for the caller to show.

use std::path::{Path, PathBuf};

use super::config::{self, ShellBlock};
use super::{Host, is_absolute_windows, join_windows};

/// Where the chosen block came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    User(PathBuf),
    System(PathBuf),
    /// The built-in `cmd.exe`: no layer had a `shell`, or a layer was broken.
    Default,
}

/// Why the built-in `cmd.exe` is in use in place of a configured shell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    pub file: PathBuf,
    /// The configured value at fault, when one is known (the program that cannot be started).
    pub value: Option<String>,
    pub reason: String,
}

impl Problem {
    /// What is wrong and what runs instead, as a sentence.
    pub fn describe(&self) -> String {
        let value = self.value.as_ref().map(|v| format!(" ({v})")).unwrap_or_default();
        format!(
            "cannot use the shell from {}{value}: {}; using the built-in cmd.exe",
            self.file.display(),
            self.reason
        )
    }

    /// The warning a session shows before the built-in `cmd.exe` starts.
    pub fn notice(&self) -> String {
        format!("ssh-broker: {}", self.describe())
    }
}

/// The block that applies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chosen {
    pub block: ShellBlock,
    pub origin: Origin,
    /// Set when a layer was broken and `block` is the built-in one.
    pub problem: Option<Problem>,
}

/// The user's config file: `%XDG_CONFIG_HOME%\ssh-broker\config.yaml` when that variable holds an
/// absolute path, else `<profile>\.config\ssh-broker\config.yaml`. The profile is the token's,
/// not `USERPROFILE`. Fails only when there is no variable and no profile.
pub fn user_config_path(host: &dyn Host) -> anyhow::Result<PathBuf> {
    // XDG: an empty or relative value is ignored.
    let xdg = host
        .env("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|dir| is_absolute_windows(dir));
    Ok(match xdg {
        Some(dir) => join_windows(&dir, &["ssh-broker", "config.yaml"]),
        None => join_windows(&host.profile_dir()?, &[".config", "ssh-broker", "config.yaml"]),
    })
}

/// The built-in block: the system `cmd.exe`, every other value left to its defaults.
pub(super) fn built_in(host: &dyn Host) -> ShellBlock {
    ShellBlock {
        start: vec![host.system_cmd().to_string_lossy().into_owned()],
        ..ShellBlock::default()
    }
}

/// Read each layer fresh and pick the block. Called once per session: an edit shows in the next
/// session, and one session sees one snapshot.
pub fn choose(host: &dyn Host) -> Chosen {
    let fallback = |problem| Chosen {
        block: built_in(host),
        origin: Origin::Default,
        problem: Some(problem),
    };

    match user_config_path(host) {
        Ok(path) => match layer(host, &path) {
            Layer::Block(block) => {
                return Chosen {
                    block,
                    origin: Origin::User(path),
                    problem: None,
                };
            }
            Layer::Broken(problem) => return fallback(problem),
            Layer::NoShell => {}
        },
        // No variable and no profile: there is no user file to look for.
        Err(error) => tracing::warn!("no user config file ({error:#}); using the system layer"),
    }

    let path = host.system_config_path();
    match layer(host, &path) {
        Layer::Block(block) => Chosen {
            block,
            origin: Origin::System(path),
            problem: None,
        },
        Layer::Broken(problem) => fallback(problem),
        Layer::NoShell => Chosen {
            block: built_in(host),
            origin: Origin::Default,
            problem: None,
        },
    }
}

enum Layer {
    Block(ShellBlock),
    NoShell,
    Broken(Problem),
}

fn layer(host: &dyn Host, path: &Path) -> Layer {
    let broken = |reason: String| {
        Layer::Broken(Problem {
            file: path.to_path_buf(),
            value: None,
            reason,
        })
    };
    let bytes = match host.read_file(path) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return Layer::NoShell,
        Err(error) => return broken(format!("cannot read it: {error}")),
    };
    match config::parse(&bytes) {
        Ok(Some(block)) => Layer::Block(block),
        Ok(None) => Layer::NoShell,
        Err(error) => broken(error.reason),
    }
}

#[cfg(test)]
#[path = "layers_tests.rs"]
mod layers_tests;
