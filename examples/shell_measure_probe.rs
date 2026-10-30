//! Spike probe (Task 0, never merged). Writes the raw command line it was started with, and the argv the
//! C runtime made of it, to `<this exe>.line`. sshd starts it as the `DefaultShell`, where no environment
//! variable of the test reaches it.

fn main() {
    let exe = std::env::current_exe().expect("own path");
    let mut out = exe.clone().into_os_string();
    out.push(".line");
    let argv: Vec<String> = std::env::args().collect();
    let text = format!("LINE={:?}\nARGV={:?}\n", ssh_broker::cmdline::current(), argv);
    std::fs::write(out, text).expect("write the line");
}
