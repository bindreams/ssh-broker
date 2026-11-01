//! Test stand-in for the processes of the prompt path. **CI only**: `tests/session_on_demand_windows.rs`
//! and `tests/prompt_path_windows.rs` copy it into a directory every account can run from and start it
//! as throwaway accounts.
//!
//! Five roles, picked by the first argument. Everything it learns goes to files beside the exe, because
//! the processes are started as other accounts with no console.
//!
//! - `agent --background --expect-user <sid>`: what `start_background_agent` starts. Records who it
//!   runs as in `agent.info`, makes its socket folder and writes the `serving` marker, then, if
//!   `agent.plan` exists, waits for the file `agent.go` and writes the file `agent.ack`.
//! - `pty <dir> <command line>`: hosts the command (the real shim) in a pseudoconsole, in the job sshd keeps
//!   its session in (kill-on-close, breakaway allowed), reading key sequences on stdin and writing the
//!   console on stdout.
//! - `connect <socket> <result file>`: connects to an AF_UNIX socket and writes the outcome to the file.
//! - `console-size`: prints `size=<columns>x<rows>` of its console, waits for the console to be resized
//!   and prints it again.
//! - `shim <dir>`: a stand-in for the shim under sshd. Reads `shim.input` (the account's password, the
//!   agent exe), starts the agent through the logon, waits for the agent's marker with the product's
//!   own `SocketWatch`, and writes `shim.result` (the file appearing is the "reported" signal); what
//!   the logon logs goes to `shim.log`. With
//!   `shim.hold` present it then blocks until it is killed.
//!
//! The `shim` and `agent` roles do only what the logon-call tests need of the production shim and agent;
//! they are not those programs. The tests that use them cover `logon` and `SocketWatch`. The production
//! shim's own flow (the prompt, the wait for a starting agent, the fallbacks) is covered only by
//! `tests/prompt_path_windows.rs`.

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
