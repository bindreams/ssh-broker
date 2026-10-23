//! Test probe: writes the raw command line this process was started with to the file named by
//! `PROBE_OUT`. `tests/conhost_windows.rs` runs it under `conhost.exe`.

fn main() {
    let out = std::env::var_os("PROBE_OUT").expect("PROBE_OUT names the file to write");
    std::fs::write(out, ssh_broker::cmdline::current()).expect("write the command line");
}
