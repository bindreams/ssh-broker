//! Test stand-in for the processes of the prompt path. **CI only**: `tests/session_on_demand_windows.rs`
//! and `tests/prompt_path_windows.rs` copy it into a directory every account can run from and start it
//! as throwaway accounts.
//!
//! Four roles, picked by the first argument. Everything it learns goes to files beside the exe, because
//! the processes are started as other accounts with no console.
//!
//! - `agent --background --ready-event <name> --expect-user <sid>`: what `start_background_agent`
//!   starts. Records who it runs as in `agent.info`, signals the ready event, then, if `agent.plan`
//!   exists, waits for the `go` event it names and signals the `ack` event.
//! - `pty <dir> <command line>`: hosts the command (the real shim) in a pseudoconsole, the way the agent
//!   hosts a shell, reading key sequences on stdin and writing the console on stdout.
//! - `connect <socket> <result file>`: connects to an AF_UNIX socket and writes the outcome to the file.
//! - `shim <dir>`: a stand-in for the shim under sshd. Reads `shim.input` (the account's password, the
//!   agent exe, the name of a "reported" event), makes the ready event, starts the agent through the
//!   logon, waits for it, writes `shim.result`, and signals "reported". With `shim.hold` present it
//!   then blocks until it is killed.

#[cfg(windows)]
mod windows;

#[cfg(windows)]
fn main() {
    windows::main()
}

#[cfg(not(windows))]
fn main() {
    std::process::exit(2)
}
