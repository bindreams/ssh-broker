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

#[path = "common/pty.rs"]
mod pty;
#[path = "common/sshd_encoder.rs"]
mod sshd_encoder;

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

/// Create `<tmp>\<tag>-<pid>\Spaced Dir\sftp-server.exe`, a copy of `cmd.exe`, and return the
/// root and the program path. A copy of `cmd.exe` needs no fixture binary.
fn spaced_program(tag: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let root = std::env::temp_dir().join(format!("{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let program_dir = root.join("Spaced Dir");
    std::fs::create_dir_all(&program_dir).unwrap();
    let program = program_dir.join("sftp-server.exe");
    let system_root = std::env::var_os("SystemRoot").expect("SystemRoot is set on Windows");
    std::fs::copy(
        std::path::PathBuf::from(system_root).join(r"System32\cmd.exe"),
        &program,
    )
    .unwrap();
    (root, program)
}

/// Assert that the shim, launched as `cmd`, took the fail-open path and ran the program.
fn assert_unquoted_program_ran(out: &std::process::Output) {
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("agent unavailable"),
        "precondition: the fail-open path must be the one that ran, not the relay.\nstderr: {stderr}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("unquoted-ok"),
        "the unquoted spaced program did not run.\nstdout: {stdout}\nstderr: {stderr}"
    );
}

/// The same path, with the agent unreachable: an unquoted program path containing spaces, with
/// arguments after it, must still launch. `CreateProcessW` resolves it by prefix widening, so the
/// shim must pass the command line through without tokenizing it (see
/// `src/agent_program_path_tests.rs` for the relayed twin).
///
/// The command arrives as one argument, which is how sshd passes it in a session without a PTY.
#[test]
fn exec_fail_open_runs_an_unquoted_program_path_containing_spaces() {
    let (root, program) = spaced_program("sb-failopen-spaced");
    let command = format!("{} /c echo unquoted-ok", program.display());
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_ssh-broker"))
        .args(["-c", &command])
        .output()
        .expect("run the shim binary");
    let _ = std::fs::remove_dir_all(&root);

    assert_unquoted_program_ran(&out);
}

/// As above, but the command is appended to the command line verbatim, which is how sshd passes
/// it in a PTY session (`ssh -t host cmd`). The C runtime then splits it at the space inside the
/// path, so only the raw command line still holds the program path whole.
///
/// `raw_arg` is what makes this the PTY shape: `.arg` would wrap the text in quotes.
#[test]
fn exec_fail_open_runs_an_unquoted_program_path_appended_to_the_command_line() {
    use std::os::windows::process::CommandExt;

    let (root, program) = spaced_program("sb-failopen-spaced-raw");
    let command = format!("{} /c echo unquoted-ok", program.display());
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_ssh-broker"))
        .arg("-c")
        .raw_arg(&command)
        .output()
        .expect("run the shim binary");
    let _ = std::fs::remove_dir_all(&root);

    assert_unquoted_program_ran(&out);
}

/// `cmd.exe /c` text for the command of the two tests below: a quoted spaced program path, and
/// an argument with a double space inside quotes. `cmd` echoes the quotes it is given.
fn quoted_command(program: &std::path::Path) -> String {
    format!(r#""{}" /c echo "quoted  ok""#, program.display())
}

/// A PTY session (`ssh -t host cmd`): sshd appends the command to the shell's line as written
/// and runs the shell on a pseudoconsole, so the shim must keep the quotes. The shim runs under
/// a real pseudoconsole here, because that is what tells it the command is verbatim
/// (`tests/session_encoding_windows.rs` measures the signal).
///
/// The program writes to a file rather than the console, so the assertion does not depend on how
/// the pseudoconsole renders a double space.
#[test]
fn exec_fail_open_keeps_the_quotes_of_a_pty_command() {
    let (root, program) = spaced_program("sb-failopen-quoted-pty");
    let out_file = root.join("out.txt");
    let command = format!("{}>\"{}\"", quoted_command(&program), out_file.display());
    let shim = env!("CARGO_BIN_EXE_ssh-broker");
    let (code, console) = pty::run_on_pseudoconsole(&sshd_encoder::verbatim_line(shim, &command));
    let written = std::fs::read_to_string(&out_file).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&root);

    assert!(
        console.contains("agent unavailable"),
        "precondition: the fail-open path must be the one that ran, not the relay.\nconsole: {console}"
    );
    assert_eq!(code, 0, "the command failed.\nconsole: {console}");
    assert!(
        written.contains(r#""quoted  ok""#),
        "the quoted argument lost its quotes or its double space.\nwritten: {written:?}\nconsole: {console}"
    );
}

/// A session without a PTY: sshd escapes the command into one argument of the shell's line (with
/// `DefaultShellEscapeArguments` on, which is the default), so the shim must undo that and run
/// the command as the client sent it. Piped stdio is what tells the shim the command is escaped.
///
/// The encoder is the port of sshd's in `tests/common/sshd_encoder.rs`.
#[test]
fn exec_fail_open_decodes_the_escaped_command_of_a_session_without_a_pty() {
    use std::os::windows::process::CommandExt;

    let (root, program) = spaced_program("sb-failopen-quoted-escaped");
    let shim = env!("CARGO_BIN_EXE_ssh-broker");
    let argument = sshd_encoder::escaped_argument(&quoted_command(&program));
    let out = std::process::Command::new(shim)
        .arg("-c")
        .raw_arg(argument)
        .output()
        .expect("run the shim binary");
    let _ = std::fs::remove_dir_all(&root);

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("agent unavailable"),
        "precondition: the fail-open path must be the one that ran, not the relay.\nstderr: {stderr}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(r#""quoted  ok""#),
        "the quoted argument lost its quotes or its double space.\nstdout: {stdout}\nstderr: {stderr}"
    );
}
