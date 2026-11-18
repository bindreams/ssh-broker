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
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Run `verify-probe`, feed it `input` on stdin, close stdin, and return everything it wrote to
/// stdout.
fn run_verify_probe(input: &[u8]) -> String {
    run_verify_probe_with(&[], &std::env::temp_dir(), input)
}

/// [`run_verify_probe`] with `args` after the verb and `temp` as the probe's temp directory.
fn run_verify_probe_with(args: &[&str], temp: &Path, input: &[u8]) -> String {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ssh-broker"))
        .arg("verify-probe")
        .args(args)
        .env("TEMP", temp)
        .env("TMP", temp)
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

/// A temp directory of one test's own, removed on drop (`remove_dir_all` removes a junction itself and does
/// not follow it).
struct Temp(PathBuf);

impl Temp {
    fn new(tag: &str) -> Temp {
        let path = std::env::temp_dir().join(format!("sb-probe-junction-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Temp(path)
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A probe told nothing about a junction makes none and picks no directory of its own: the PROBE line
/// has no link outcome and nothing is made in the temp directory.
#[test]
fn a_probe_with_no_flag_makes_no_junction_and_reports_none() {
    let temp = Temp::new("none-given");
    let stdout = run_verify_probe_with(&[], &temp.0, &(0..=255u8).collect::<Vec<_>>());
    let line = probe_line(&stdout);
    assert!(!line.contains("symlink="), "no link outcome expected, got: {line}");
    assert_eq!(std::fs::read_dir(&temp.0).unwrap().count(), 0, "nothing is made");
}

/// A probe makes the junction in the directory it is given and reports no path; the other probe follows it
/// by the same directory. Both read it, neither removes it.
#[test]
fn a_probe_makes_a_junction_in_the_directory_it_is_given_and_another_follows_it() {
    let temp = Temp::new("make");
    let dir = temp.0.join("named");
    let dir = dir.to_str().unwrap();
    let made = run_verify_probe_with(&["--make-junction", dir], &temp.0, b"");
    let made_line = probe_line(&made);
    assert!(made_line.contains("symlink=ok"), "{made_line}");
    assert!(!made_line.contains("junction="), "no path is reported: {made_line}");
    assert!(Path::new(dir).is_dir(), "the directory is made where it was named");

    let followed = run_verify_probe_with(&["--follow", dir], &temp.0, b"");
    let followed_line = probe_line(&followed);
    assert!(followed_line.contains("symlink=ok"), "{followed_line}");
    assert!(!followed_line.contains("junction="), "{followed_line}");
    assert!(Path::new(dir).exists(), "the follower leaves the junction to `verify`");
}

/// A path that exists is not made over and not cleared: the probe reports the junction as not made and
/// leaves what is there alone.
#[test]
fn a_probe_given_a_path_that_exists_makes_no_junction_and_leaves_it_alone() {
    let temp = Temp::new("exists");
    let dir = temp.0.join("exists");
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(dir.join("keep.txt"), b"keep").unwrap();

    let stdout = run_verify_probe_with(&["--make-junction", dir.to_str().unwrap()], &temp.0, b"");

    let line = probe_line(&stdout);
    assert!(
        line.contains("symlink=notmade"),
        "expected symlink=notmade, got: {line}"
    );
    assert_eq!(std::fs::read(dir.join("keep.txt")).unwrap(), b"keep");
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1, "nothing was added");
}

/// A directory with no junction in it is a failed link check, not a pass and not a block.
#[test]
fn a_probe_that_follows_a_directory_with_no_junction_reports_a_failure() {
    let temp = Temp::new("none");
    let stdout = run_verify_probe_with(&["--follow", &temp.0.to_string_lossy()], &temp.0, b"");
    let line = probe_line(&stdout);
    assert!(line.contains("symlink=fail"), "expected symlink=fail, got: {line}");
}

/// The probe reports its own token: the line names an elevation and an integrity level, which `verify`
/// reads to say whether the session is elevated.
#[test]
fn the_probe_line_names_the_probes_own_elevation_and_integrity() {
    let stdout = run_verify_probe(b"");
    let line = probe_line(&stdout);
    assert!(
        ["elevation=full", "elevation=filtered", "elevation=standard"]
            .iter()
            .any(|word| line.contains(word)),
        "no elevation in: {line}"
    );
    assert!(line.contains(" integrity=0x"), "no integrity level in: {line}");
}
