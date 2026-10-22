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
//!
//! The shim decides how sshd encoded its command line from the machine's OpenSSH registry
//! settings, so a test whose result depends on the form runs `shim_child` instead: the same
//! entry point (`route`, then `shim_pty::run_on`) with the form given to it. The tests that run
//! the binary use commands that decode the same in every form, or a PTY session, which is
//! recognized by its console.
#![cfg(windows)]

use std::path::{Path, PathBuf};

use ssh_broker::cmdline::{Detected, Encoding, split_args};
use ssh_broker::route::{Route, route};

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
fn spaced_program(tag: &str) -> (PathBuf, PathBuf) {
    let root = std::env::temp_dir().join(format!("{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let program_dir = root.join("Spaced Dir");
    std::fs::create_dir_all(&program_dir).unwrap();
    let program = program_dir.join("sftp-server.exe");
    let system_root = std::env::var_os("SystemRoot").expect("SystemRoot is set on Windows");
    std::fs::copy(PathBuf::from(system_root).join(r"System32\cmd.exe"), &program).unwrap();
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

/// What a PTY session of the shim produced.
struct PtyRun {
    console: String,
    written: String,
}

/// Run `command` as a PTY session of the shim does: `ssh -t host <command>` makes sshd start
/// `conhost.exe --headless ... -- "shim" -c <command>`, and the shim runs on its console. The
/// command writes to `out` itself, so a result does not depend on how the console renders it.
fn run_pty_session(command: &str, out: &Path) -> PtyRun {
    let shim = env!("CARGO_BIN_EXE_ssh-broker");
    let run = pty::run_under_conhost(&sshd_encoder::pty_line(shim, command), &[]);
    PtyRun {
        console: run.console,
        written: std::fs::read_to_string(out).unwrap_or_default(),
    }
}

/// A PTY session whose command is an unquoted spaced program path, appended as the client wrote
/// it. conhost splits it at the space inside the path and joins the pieces again, so only the
/// raw command line still holds the path whole.
#[test]
fn exec_fail_open_runs_an_unquoted_program_path_in_a_pty_session() {
    let (root, program) = spaced_program("sb-failopen-spaced-pty");
    let out = root.join("out.txt");
    let command = format!("{} /c echo unquoted-ok > \"{}\"", program.display(), out.display());
    let run = run_pty_session(&command, &out);
    let _ = std::fs::remove_dir_all(&root);

    assert!(
        run.console.contains("agent unavailable"),
        "precondition: the fail-open path must be the one that ran, not the relay.\nconsole: {}",
        run.console
    );
    assert!(
        run.written.contains("unquoted-ok"),
        "the unquoted spaced program did not run.\nwritten: {:?}\nconsole: {}",
        run.written,
        run.console
    );
}

/// `cmd.exe /c` text for the commands of the tests below: a quoted spaced program path and an
/// argument with a double space inside quotes. `cmd` echoes the quotes it is given.
fn quoted_command(program: &Path) -> String {
    format!(r#""{}" /c echo "quoted  ok""#, program.display())
}

/// A PTY session keeps the quotes of an argument with a space, and its double space inside them.
#[test]
fn exec_fail_open_keeps_the_quotes_of_a_pty_command() {
    let (root, program) = spaced_program("sb-failopen-quoted-pty");
    let out = root.join("out.txt");
    let command = format!("{} > \"{}\"", quoted_command(&program), out.display());
    let run = run_pty_session(&command, &out);
    let _ = std::fs::remove_dir_all(&root);

    assert!(
        run.console.contains("agent unavailable"),
        "precondition: the fail-open path must be the one that ran, not the relay.\nconsole: {}",
        run.console
    );
    assert!(
        run.written.contains(r#""quoted  ok""#),
        "the quoted argument lost its quotes or its double space.\nwritten: {:?}\nconsole: {}",
        run.written,
        run.console
    );
}

/// A PTY session's command arrives as conhost rebuilt it, and the shim runs that: runs of spaces
/// between arguments become one, and quotes around an argument with no space go.
#[test]
fn exec_fail_open_runs_a_pty_command_as_conhost_rebuilt_it() {
    let (root, program) = spaced_program("sb-failopen-conhost-pty");
    let out = root.join("out.txt");
    let command = format!(
        "{} /c echo   spread    out \"tight\" > \"{}\"",
        program.display(),
        out.display()
    );
    let run = run_pty_session(&command, &out);
    let _ = std::fs::remove_dir_all(&root);

    assert_eq!(
        run.written.trim_end(),
        "spread out tight",
        "the command should have run as conhost rebuilt it.\nconsole: {}",
        run.console
    );
}

// A session without a PTY =====

/// The child of the tests below. It does what `main` does with the command line it is given —
/// `route`, then `shim_pty::run_on` — but takes the form sshd used from the environment, rather
/// than detecting it from the machine's registry, and exits as the shim does.
#[test]
#[ignore = "run as a child of the tests below"]
fn shim_child() {
    let line = std::env::var("SB_TEST_LINE").expect("SB_TEST_LINE: the command line");
    let encoding = match std::env::var("SB_TEST_ENCODING").expect("SB_TEST_ENCODING").as_str() {
        "Escaped" => Encoding::Escaped,
        "Wrapped" => Encoding::Wrapped,
        other => panic!("unknown SB_TEST_ENCODING {other:?}"),
    };
    let args = split_args(&line);
    let Route::Shim { exec } = route(&args[1..], &line) else {
        panic!("{line:?} must select the shim");
    };
    ssh_broker::shim_pty::run_on(exec, || Detected {
        encoding,
        warning: None,
    })
    .expect("run the shim");
}

/// Run the shim on `line` (a whole command line) as sshd's `encoding` form, without a PTY.
fn run_shim_child(line: &str, encoding: Encoding) -> std::process::Output {
    std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "shim_child", "--ignored", "--nocapture"])
        .env("SB_TEST_LINE", line)
        .env("SB_TEST_ENCODING", format!("{encoding:?}"))
        .output()
        .expect("run the shim child")
}

/// A session without a PTY: sshd turns the command into one argument of the shell's line, escaped
/// (`DefaultShellEscapeArguments` on, the default) or wrapped in quotes and nothing else (off), and
/// the shim must undo that and run the command as the client sent it.
///
/// The encoders are the port of sshd's in `tests/common/sshd_encoder.rs`.
#[test]
fn exec_fail_open_decodes_the_command_of_a_session_without_a_pty() {
    let shim = env!("CARGO_BIN_EXE_ssh-broker");
    for encoding in [Encoding::Escaped, Encoding::Wrapped] {
        let (root, program) = spaced_program("sb-failopen-quoted-piped");
        let command = quoted_command(&program);
        let line = match encoding {
            Encoding::Escaped => sshd_encoder::escaped_line(shim, &command),
            _ => sshd_encoder::wrapped_line(shim, &command),
        };
        let out = run_shim_child(&line, encoding);
        let _ = std::fs::remove_dir_all(&root);

        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("agent unavailable"),
            "{encoding:?}: precondition: the fail-open path must be the one that ran, not the relay.\nstderr: {stderr}"
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains(r#""quoted  ok""#),
            "{encoding:?}: the quoted argument lost its quotes or its double space.\nstdout: {stdout}\nstderr: {stderr}"
        );
    }
}

/// An exec whose command is empty or whitespace-only runs nothing and exits 0 with no output, as
/// the shell does for `-c ""`, rather than failing at `CreateProcessW("")` with 255. The check
/// comes before the agent is consulted, so this holds with or without one, and the shim stays
/// silent: no command needed the agent, so there is nothing to warn about.
#[test]
fn exec_of_a_blank_command_runs_nothing_and_exits_zero() {
    for blank in ["", " ", "   ", "\t "] {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_ssh-broker"))
            .args(["-c", blank])
            .output()
            .expect("run the shim binary");
        assert_eq!(out.status.code(), Some(0), "{blank:?}");
        assert!(
            out.stdout.is_empty() && out.stderr.is_empty(),
            "{blank:?} produced output.\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
