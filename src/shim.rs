//! shim: the SSH `DefaultShell` (default action). Relays the terminal/streams to
//! the agent over AF_UNIX; fails open to a local shell if the agent is unreachable.

/// Shim entrypoint. `exec` is `Some(command)` for the `-c "cmd"` EXEC path, `None`
/// for an interactive PTY session. Implemented in Phase 6.
pub fn run(_exec: Option<String>) -> anyhow::Result<()> {
    anyhow::bail!("shim: not yet implemented (Phase 6)")
}
