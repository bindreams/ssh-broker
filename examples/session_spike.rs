//! Throwaway CI-only spike for ssh-broker U1-B, Task 0. Never merged.
//!
//! One binary, several roles chosen by the first argument:
//!
//! - `<group>...` (`env m1 m3 m4 m5 m6 m7 m8`): the orchestrator. Creates throwaway accounts, so it
//!   refuses to run outside GitHub Actions or without elevation.
//! - `stand-in <rundir> <scenario>`: plays sshd's shim for one account (started by the orchestrator
//!   with a network-logon token, in a kill-on-close job; or by a real sshd for M8).
//! - `child <rundir> <name> ...`: the process the logon starts, standing in for
//!   `ssh-broker agent --background`.
//! - `capture <outfile> <event> <program> ...`: runs a program with its output in a file (SYSTEM task).
//!
//! Every measurement is a line `SPIKE <run>.<process>.<key>=<value>` in the job log (also in the job
//! summary). See `.github/workflows/session-spike.yaml`.

#[cfg(windows)]
#[path = "session_spike/account.rs"]
mod account;
#[cfg(windows)]
#[path = "session_spike/capture.rs"]
mod capture;
#[cfg(windows)]
#[path = "session_spike/child.rs"]
mod child;
#[cfg(windows)]
#[path = "../tests/common/desktop.rs"]
mod desktop;
#[cfg(windows)]
#[path = "session_spike/groups.rs"]
mod groups;
#[cfg(windows)]
#[path = "../tests/common/hard_errors.rs"]
mod hard_errors;
#[cfg(windows)]
#[path = "session_spike/harness.rs"]
mod harness;
#[cfg(windows)]
#[path = "session_spike/logon.rs"]
mod logon;
#[cfg(windows)]
#[path = "session_spike/m5.rs"]
mod m5;
#[cfg(windows)]
#[path = "session_spike/m8.rs"]
mod m8;
#[cfg(windows)]
#[path = "session_spike/orchestrate.rs"]
mod orchestrate;
#[cfg(windows)]
#[path = "session_spike/rec.rs"]
mod rec;
#[cfg(windows)]
#[path = "session_spike/stand_in.rs"]
mod stand_in;
#[cfg(windows)]
#[path = "session_spike/tasks.rs"]
mod tasks;
#[cfg(windows)]
#[path = "session_spike/win.rs"]
mod win;

#[cfg(windows)]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("stand-in") if args.len() == 3 => stand_in::run(std::path::Path::new(&args[1]), &args[2]),
        Some("child") if args.len() >= 3 => child::run(&args[1..]),
        Some("capture") if args.len() >= 4 => capture::run(&args[1..]),
        Some(_) => orchestrate::run(&args),
        None => {
            eprintln!("usage: session_spike <group>... (env m1 m3 m4 m5 m6 m7 m8)");
            2
        }
    };
    std::process::exit(code);
}

#[cfg(not(windows))]
fn main() {}
