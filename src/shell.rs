//! The user's shell: what `ssh-broker` starts for a session, and how it packs the command.
//!
//! Configured by `config.yaml` (see [`config`]), resolved through layers and turned into a
//! spawn line; everything here is pure over a host trait, so it builds and tests on every
//! platform.

pub mod config;

use serde::{Deserialize, Serialize};

/// How the broker packs the already-decoded command for the shell it starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Escaping {
    /// The command wrapped in quotes, otherwise as written: what `cmd.exe /c` reads.
    Cmd,
    /// Standard `CommandLineToArgvW` quoting: one exact argument.
    Msvc,
}
