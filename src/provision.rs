//! provision: self-install (`apply`) and self-check (`verify`) — DefaultShell pair,
//! logon + ONSTART tasks, socket dir + ACL, DPAPI/symlink parity probes.

/// `apply` subcommand: idempotently assert all desired state. Implemented in Phase 7.
pub fn apply() -> anyhow::Result<()> {
    anyhow::bail!("apply: not yet implemented (Phase 7)")
}

/// `verify` subcommand: self-check + parity probes through the agent. Implemented in Phase 7.
pub fn verify() -> anyhow::Result<()> {
    anyhow::bail!("verify: not yet implemented (Phase 7)")
}
