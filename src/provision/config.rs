//! provision::config — the persisted install config (pure; host-testable).
//!
//! Its load-bearing field is the Windows account the agent runs as. A later SYSTEM-run
//! `apply` (the ONSTART self-heal) must harden the socket dir for the SAME account the agent
//! binds as — otherwise the agent's fail-closed ACL gate (`afunix::Listener::bind`) rejects
//! the dir and SSH is stuck on the thin shell. SYSTEM cannot derive that account from its own
//! token, so the first interactive `apply` records it here (and bakes it into the self-heal
//! task's argv).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// The account the agent task runs as, == the socket-dir ACL grantee.
    pub target_user: String,
}

impl Config {
    pub fn to_toml(&self) -> anyhow::Result<String> {
        Ok(toml::to_string(self)?)
    }
    pub fn from_toml(s: &str) -> anyhow::Result<Config> {
        Ok(toml::from_str(s)?)
    }
}

/// Resolve the target account NAME, preferring an explicit source so a SYSTEM-run `apply`
/// never derives it from its own (SYSTEM) token. Precedence: CLI `--user` > persisted config
/// > the current interactive user (only meaningful when `apply` is run interactively). Errors
/// if none is available — `apply` must bail loudly rather than harden for the wrong account.
pub fn resolve_target_user(
    cli: Option<&str>,
    cfg: Option<&str>,
    interactive_current: Option<&str>,
) -> anyhow::Result<String> {
    cli.filter(|s| !s.is_empty())
        .or(cfg.filter(|s| !s.is_empty()))
        .or(interactive_current.filter(|s| !s.is_empty()))
        .map(str::to_string)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "cannot resolve the target user: pass --user <account> \
                 (required when apply runs as SYSTEM with no saved config)"
            )
        })
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod config_tests;
