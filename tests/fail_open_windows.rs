//! End-to-end test of the shim's EXEC fail-open path, through the REAL binary.
//!
//! Windows-only: the shim is `#[cfg(windows)]`. This runs in CI's `Test (windows/amd64)` job.
//!
//! Why an integration test rather than a unit test: the property being gated is a wiring fact
//! about `shim_pty::run_on` — that the command a client sent reaches `CreateProcessW` with no
//! shell in between — and `run_on` ends in `process::exit`, so nothing in-process can observe it.
//! A unit test that calls `spawn_contained` directly cannot gate this: it bypasses `run_on`
//! entirely, so the mutation that matters
//! (`FailOpen::Passthrough(cmd) => run_local_passthrough(&format!("pwsh -Command {cmd}"))`)
//! leaves such a test green. Only running the actual binary traverses the real path.
#![cfg(windows)]

/// An `ssh host "cmd"` session that fails open must run the command ITSELF, with no shell
/// interposed to re-parse its quoting.
///
/// This matters because nothing is routed around the relay any more, so fail-open is the only
/// local execution left — and an `sftp`/`scp` session landing here carries a binary stream that a
/// `pwsh -Command` hop would mangle by re-quoting. It is also a deliberate behaviour change from
/// `main`, where EXEC fail-open DID go through `pwsh -Command`; this test is what stops that being
/// silently restored as a "simplification".
///
/// Mechanism: `cmd.exe` exposes its own VERBATIM launch command line as `%CMDCMDLINE%`, so the
/// child reports exactly what `CreateProcessW` received. Note `pwsh`'s `[Environment]::CommandLine`
/// is NOT usable for this and was measured failing on CI: .NET Core reconstructs that string from
/// parsed argv, reporting the `pwsh.dll` path as argv[0] and discarding the caller's quoting, so it
/// describes .NET's reconstruction rather than the real command line.
///
/// The test ASSERTS it took the fail-open path rather than assuming it. That matters because the
/// relay path is also a bare `CreateProcessW` with the verbatim command line (`src/pipes.rs`), so
/// on a machine where `apply` has run and the agent is up, `%CMDCMDLINE%` would come back
/// byte-identical having exercised the relay instead — and the mutation this file exists to catch
/// would go undetected. Only the fail-open path emits the "agent unavailable" warning on stderr
/// for EXEC (`shim_pty::try_relay`), so checking for it pins which path ran.
///
/// If a future change made the shim wrap the command in a shell, `cmd.exe` would report the
/// wrapper's reconstructed line instead and the command-line assertion would fail — .NET's
/// `BuildCommandLine` always quotes the resolved program, and `cmd /c` likewise rewrites it.
#[test]
fn exec_fail_open_runs_the_command_with_no_shell_in_between() {
    let probe = r"cmd.exe /c echo %CMDCMDLINE%";

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_ssh-broker"))
        .args(["-c", probe])
        .output()
        .expect("run the shim binary");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("agent unavailable"),
        "this assertion is the test's precondition, not a nicety: without it the RELAY path — \
         also a bare CreateProcessW with a verbatim command line — satisfies everything below \
         while never exercising fail-open at all.\nstderr: {stderr}"
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    let got = stdout.trim_end();
    assert_eq!(
        got,
        probe,
        "the command line cmd.exe actually received must be byte-identical to what the client \
         sent — a shell hop in between would re-quote it.\nstderr: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    );
}
