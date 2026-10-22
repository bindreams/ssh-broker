//! Runs a command line on a pseudoconsole, for the tests that need the process to see a console.
#![allow(dead_code)]

use ssh_broker::conpty::{PtySession, read_handle};

/// Run `command_line` on a pseudoconsole until it exits; return its exit code and everything it
/// wrote to the console.
pub fn run_on_pseudoconsole(command_line: &str) -> (i32, String) {
    let mut session = PtySession::spawn(command_line, 200, 24, None).expect("spawn on a pseudoconsole");
    let out_raw = session.out_read_raw();
    let reader = std::thread::spawn(move || {
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = read_handle(out_raw, &mut buf);
            if n == 0 {
                break out;
            }
            out.extend_from_slice(&buf[..n]);
        }
    });
    let code = session.wait().unwrap();
    // The output pipe reaches EOF once the pseudoconsole closes.
    session.close_pty();
    let out = String::from_utf8_lossy(&reader.join().unwrap()).into_owned();
    (code, out)
}
