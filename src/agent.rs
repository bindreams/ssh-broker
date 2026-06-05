//! agent: resident in session 1; accepts socket connections and hosts the shell
//! (ConPTY for PTY mode, redirected pipes for EXEC) bridged to the SSH-side shim.

/// `agent` subcommand entrypoint. Implemented in Phase 4 (accept loop + PTY/EXEC handlers).
pub fn run() -> anyhow::Result<()> {
    anyhow::bail!("agent: not yet implemented (Phase 4)")
}
