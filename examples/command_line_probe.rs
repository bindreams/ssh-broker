//! Test probe: writes the raw command line this process was started with to the file named by
//! `PROBE_OUT`, or to `<this exe>.line` when that is not set (a copy of the probe in a directory
//! of its own then has an output of its own). `tests/conhost_windows.rs` runs it under
//! `conhost.exe`; the agent tests use it as the configured shell.
//!
//! With no `PROBE_OUT` it also writes `<this exe>.env`: what `cmdline::detect` says of the session
//! and the SSH variables the shell was given (`present:<value>` or `absent`), one `key=value` per line.

/// The variables `<this exe>.env` reports.
const REPORTED: [&str; 5] = [
    "SSH_ORIGINAL_COMMAND",
    "SSH_CLIENT",
    "SSH_CONNECTION",
    "SSH_TTY",
    "SB_SPIKE",
];

fn main() {
    let line = ssh_broker::cmdline::current();
    if let Some(out) = std::env::var_os("PROBE_OUT") {
        std::fs::write(out, line).expect("write the command line");
        return;
    }
    let mut beside = std::env::current_exe().expect("the probe's own path").into_os_string();
    let mut env_file = beside.clone();
    beside.push(".line");
    env_file.push(".env");
    let mut report = format!("encoding={:?}\n", ssh_broker::cmdline::detect());
    for name in REPORTED {
        let state = match std::env::var_os(name) {
            Some(value) => format!("present:{}", value.to_string_lossy()),
            None => "absent".to_owned(),
        };
        report.push_str(&format!("{name}={state}\n"));
    }
    std::fs::write(env_file, report).expect("write the environment report");
    std::fs::write(beside, line).expect("write the command line");
}
