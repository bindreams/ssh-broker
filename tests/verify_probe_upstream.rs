//! End-to-end test of `verify-probe`'s upstream (client → child) byte-transparency check,
//! through the REAL binary.
//!
//! Windows-only: `verify-probe` is `#[cfg(windows)]`. This runs in CI's `Test (windows/amd64)`
//! job.
//!
//! Why an integration test rather than a unit test: `probe::upstream_payload_ok` — the
//! comparison itself — is already pure and host-tested in `src/provision/probe_tests.rs`. What
//! is UNTESTED is its call site, `provision::imp::verify_probe`, which is `#[cfg(windows)]` with
//! no test module of its own. The exact one-line mutation this file exists to catch is that call
//! site's
//! ```ignore
//! let upstream_ok = match probe::upstream_payload_ok(&mut std::io::stdin()) { Ok(ok) => ok, .. };
//! ```
//! collapsing to a bare `let upstream_ok = true;` — which would make `verify` print a passing
//! "binary upload" row unconditionally, with the entire suite (including the pure
//! `probe_tests.rs` coverage of the untouched comparison function) still green. Only running the
//! actual binary, stdin in and stdout out, traverses that call site and can catch it.
//!
//! `verify-probe`'s own exit code is deliberately NOT asserted anywhere in this file: on a CI
//! runner it runs directly (not agent-spawned) in session 0 with no interactive user profile, so
//! its unrelated session-id/DPAPI/symlink parity checks legitimately fail and it exits 1
//! regardless of the upstream-payload outcome under test here (see `verify_probe`'s `pass`
//! computation, which never gates on `upstream_ok`). Only stdout — specifically the `PROBE`
//! line's `upstream=` token — is under test.
#![cfg(windows)]

use std::io::Write;
use std::process::{Command, Stdio};

/// Run `verify-probe`, feed it `input` on stdin, close stdin, and return everything it wrote to
/// stdout.
fn run_verify_probe(input: &[u8]) -> String {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ssh-broker"))
        .arg("verify-probe")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the verify-probe binary");

    // Write, then let the handle drop at the end of this statement — closing it and delivering
    // EOF, which unblocks `upstream_payload_ok`'s `read_to_end` on the child side.
    child
        .stdin
        .take()
        .expect("stdin was piped")
        .write_all(input)
        .expect("write the probe payload to verify-probe's stdin");

    let out = child.wait_with_output().expect("wait for verify-probe to exit");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The single `PROBE ...` line out of `stdout`, panicking (with the full output attached) if
/// there isn't one — a missing line is itself a failure worth seeing, not something to silently
/// treat as `upstream=fail`.
fn probe_line(stdout: &str) -> &str {
    stdout
        .lines()
        .find(|l| l.trim_start().starts_with("PROBE "))
        .unwrap_or_else(|| panic!("no PROBE line in verify-probe's stdout:\n{stdout}"))
}

/// The exact payload `verify` sends upstream (every byte value once, ascending), fed back
/// unchanged, must report `upstream=ok`.
#[test]
fn exact_payload_reports_upstream_ok() {
    let payload: Vec<u8> = (0..=255u8).collect();
    let stdout = run_verify_probe(&payload);
    let line = probe_line(&stdout);
    assert!(line.contains("upstream=ok"), "expected upstream=ok, got: {line}");
}

/// A single flipped byte anywhere in the payload must be caught — this is what makes the check a
/// byte-for-byte comparison rather than a length or checksum-only test that a transposition could
/// slip past.
#[test]
fn one_flipped_byte_reports_upstream_fail() {
    let mut payload: Vec<u8> = (0..=255u8).collect();
    payload[128] ^= 0xFF;
    let stdout = run_verify_probe(&payload);
    let line = probe_line(&stdout);
    assert!(line.contains("upstream=fail"), "expected upstream=fail, got: {line}");
}

/// Empty stdin (as if the upstream write never happened, or the connection dropped before
/// sending anything) must default-deny, not be silently treated as vacuously matching.
#[test]
fn empty_stdin_reports_upstream_fail() {
    let stdout = run_verify_probe(&[]);
    let line = probe_line(&stdout);
    assert!(line.contains("upstream=fail"), "expected upstream=fail, got: {line}");
}
