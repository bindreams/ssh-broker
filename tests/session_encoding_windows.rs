//! How the shim tells a PTY session from a non-PTY one, measured rather than assumed.
//!
//! Win32-OpenSSH appends the command to the shell's line as written in a PTY session and
//! escapes it otherwise (`w32-doexec.c`), so `cmdline::detect` must report which. Its signal
//! is whether stdin is a console: a PTY session runs the shell on a pseudoconsole
//! (`win32_pty.c`, `conhost.exe --headless`), while a non-PTY session gives it the pipes
//! `posix_spawn` set up (`w32fd.c`).
//!
//! Windows-only: runs in CI's `Test (windows/amd64)` job, which hosts a pseudoconsole. Each test
//! runs this test binary again as the probe, once under a pseudoconsole and once under pipes.
#![cfg(windows)]

use ssh_broker::cmdline::{self, Encoding};

#[path = "common/pty.rs"]
mod pty;

/// The probe: prints what `cmdline::detect` reports for this process. It is `#[ignore]`d so a
/// plain run does not execute it; the tests below run it by name.
#[test]
#[ignore = "run as a child of the tests below"]
fn probe() {
    println!("encoding={:?}", cmdline::detect().encoding);
}

fn probe_args() -> [&'static str; 4] {
    ["--exact", "probe", "--ignored", "--nocapture"]
}

#[test]
fn a_shell_on_a_pseudoconsole_is_verbatim() {
    let exe = std::env::current_exe().unwrap();
    let command = format!("\"{}\" {}", exe.display(), probe_args().join(" "));
    let (code, out) = pty::run_on_pseudoconsole(&command);

    assert_eq!(code, 0, "the probe failed under the pseudoconsole:\n{out}");
    assert!(
        out.contains(&format!("encoding={:?}", Encoding::Verbatim)),
        "stdin on a pseudoconsole must read as a PTY session.\noutput: {out:?}"
    );
}

#[test]
fn a_shell_on_pipes_is_not_verbatim() {
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args(probe_args())
        .stdin(std::process::Stdio::piped())
        .output()
        .expect("run the probe on pipes");
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(out.status.success(), "the probe failed on pipes:\n{stdout}");
    // Which of the two non-PTY forms depends on the machine's DefaultShellEscapeArguments.
    assert!(
        stdout.contains("encoding=Escaped") || stdout.contains("encoding=Wrapped"),
        "stdin on a pipe must read as a non-PTY session.\nstdout: {stdout:?}"
    );
}
