//! End-to-end test of the shim's fail-open path, through the REAL binary.
//!
//! Windows-only: the shim is `#[cfg(windows)]`. This runs in CI's `Test (windows/amd64)` job.
//!
//! Why an integration test rather than a unit test: the property being gated is a wiring fact
//! about `shim_pty::run_on` — that the session fails open through the configured shell, with the
//! command packed the way the agent would have packed it — and `run_on` ends in `process::exit`,
//! so nothing in-process can observe it. Only running the actual binary traverses the real path.
//!
//! The shell is a copy of the `command_line_probe` example, named by a user config under
//! `XDG_CONFIG_HOME` (set on the child only), so each test reads back the exact line the shell was
//! started with. The shim tells a PTY session from a non-PTY one by its console and reads no registry
//! value, so these tests do not depend on the machine's OpenSSH settings. `shim_child` runs the same
//! entry point as the binary (`route`, then `shim_pty::run_on`) on a line the test built.
#![cfg(windows)]

use std::path::PathBuf;

use ssh_broker::cmdline::{join_args, split_args};
use ssh_broker::route::{Route, route};

#[path = "common/command_line_probe.rs"]
mod command_line_probe;
#[path = "common/pty.rs"]
mod pty;
#[path = "common/sshd_encoder.rs"]
mod sshd_encoder;

/// A directory holding a shell for the shim to find through `XDG_CONFIG_HOME`.
struct Home {
    root: PathBuf,
}

impl Home {
    /// A home whose `ssh-broker/config.yaml` holds `config`, with `{PROBE}` replaced by the path of
    /// a copy of the probe that is in the home too.
    fn with_config(tag: &str, config: &str) -> Home {
        let root = std::env::temp_dir().join(format!("{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("xdg").join("ssh-broker")).unwrap();
        let home = Home { root };
        std::fs::copy(command_line_probe::path(), home.probe()).unwrap();
        let config = config.replace("{PROBE}", &home.probe().display().to_string());
        std::fs::write(home.xdg().join("ssh-broker").join("config.yaml"), config).unwrap();
        home
    }

    /// A home whose shell is the probe.
    fn probe_shell(tag: &str) -> Home {
        Home::with_config(tag, "shell: '{PROBE}'\n")
    }

    fn xdg(&self) -> PathBuf {
        self.root.join("xdg")
    }

    fn probe(&self) -> PathBuf {
        self.root.join("probe.exe")
    }

    /// The line the probe was started with.
    fn recorded_line(&self) -> String {
        let mut file = self.probe().into_os_string();
        file.push(".line");
        std::fs::read_to_string(&file).unwrap_or_else(|e| panic!("the probe recorded nothing at {file:?}: {e}"))
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Assert that the shim took the fail-open path rather than the relay: only fail-open says so.
fn assert_failed_open(stderr: &str) {
    assert!(
        stderr.contains("agent unavailable"),
        "precondition: the fail-open path must be the one that ran, not the relay.\nstderr: {stderr}"
    );
}

// A session without a PTY =====

/// The child of the tests below. It does what `main` does with the command line it is given —
/// `route`, then `shim_pty::run_on` — and exits as the shim does.
#[test]
#[ignore = "run as a child of the tests below"]
fn shim_child() {
    let line = std::env::var("SB_TEST_LINE").expect("SB_TEST_LINE: the command line");
    let args = split_args(&line);
    let Route::Shim { exec } = route(&args[1..], &line) else {
        panic!("{line:?} must select the shim");
    };
    ssh_broker::shim_pty::run_on(exec, ssh_broker::cmdline::detect).expect("run the shim");
}

/// Run the shim on `line` (a whole command line) with stdin on a pipe, as sshd gives it without a
/// PTY, and `XDG_CONFIG_HOME` at `home`.
fn run_shim_child(line: &str, home: &Home) -> std::process::Output {
    std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "shim_child", "--ignored", "--nocapture"])
        .env("SB_TEST_LINE", line)
        .env("XDG_CONFIG_HOME", home.xdg())
        .stdin(std::process::Stdio::piped())
        .output()
        .expect("run the shim child")
}

/// A session without a PTY that fails open hands the shell the command as one argument, exactly
/// as the client sent it: the same line the agent would have started, which `shell::plan` makes.
///
/// sshd turns the command into one escaped argument of the shim's line (`apply` sets
/// `DefaultShellEscapeArguments`) and the shim undoes that; the encoder is the port of sshd's in
/// `tests/common/sshd_encoder.rs`. Each command is run in a home of its own, because the probe
/// records one line.
#[test]
fn exec_fail_open_hands_the_shell_the_command_as_one_argument() {
    for command in [
        "echo  two  spaces",
        r#"echo "a b" x"#,
        r#"git commit -m "a b""#,
        r"echo C:\a b\",
        r#"echo \"quoted\""#,
        "echo héllo wörld ✓",
        "echo %PATH% & echo b",
        "cmd /c echo a   b",
    ] {
        let home = Home::probe_shell("sb-failopen-argument");
        let line = sshd_encoder::escaped_line(env!("CARGO_BIN_EXE_ssh-broker"), command);
        let out = run_shim_child(&line, &home);
        assert_failed_open(&String::from_utf8_lossy(&out.stderr));
        assert_eq!(
            home.recorded_line(),
            join_args(&[home.probe().to_str().unwrap(), "-c", command]),
            "{command:?}"
        );
        assert_eq!(out.status.code(), Some(0), "{command:?}");
    }
}

/// With the system `cmd.exe` as the shell, the command is wrapped in quotes and otherwise left as
/// the client wrote it, as sshd does: a quoted spaced program path and its quoted argument arrive
/// whole.
#[test]
fn exec_fail_open_through_cmd_exe_wraps_the_command_in_quotes() {
    let system_root = std::env::var_os("SystemRoot").expect("SystemRoot is set on Windows");
    let cmd = PathBuf::from(system_root).join(r"System32\cmd.exe");
    let home = Home::with_config("sb-failopen-cmd", &format!("shell: '{}'\n", cmd.display()));
    let copy = home.root.join("Spaced Dir").join("sftp-server.exe");
    std::fs::create_dir_all(copy.parent().unwrap()).unwrap();
    std::fs::copy(&cmd, &copy).unwrap();
    let command = format!(r#""{}" /c echo "quoted  ok""#, copy.display());
    let line = sshd_encoder::escaped_line(env!("CARGO_BIN_EXE_ssh-broker"), &command);

    let out = run_shim_child(&line, &home);

    let (stdout, stderr) = (
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert_failed_open(&stderr);
    assert!(
        stdout.contains(r#""quoted  ok""#),
        "the quoted argument lost its quotes or its double space.\nstdout: {stdout}\nstderr: {stderr}"
    );
}

/// A shell that cannot be used is one warning, naming the file and the value, and the built-in
/// `cmd.exe` runs the command.
#[test]
fn exec_fail_open_with_a_missing_shell_warns_once_and_runs_cmd_exe() {
    let home = Home::with_config("sb-failopen-missing", "shell: no-such-shell-for-ssh-broker.exe\n");
    let line = sshd_encoder::escaped_line(env!("CARGO_BIN_EXE_ssh-broker"), "echo built-in-ok");

    let out = run_shim_child(&line, &home);

    let (stdout, stderr) = (
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert_failed_open(&stderr);
    assert!(stdout.contains("built-in-ok"), "stdout: {stdout}\nstderr: {stderr}");
    assert_eq!(stderr.matches("cannot use the shell").count(), 1, "stderr: {stderr}");
    assert!(
        stderr.contains("config.yaml") && stderr.contains("no-such-shell-for-ssh-broker.exe"),
        "the warning names the file and the value.\nstderr: {stderr}"
    );
    assert_eq!(out.status.code(), Some(0));
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

// A session with a PTY =====

/// What a PTY session of the shim produced.
struct PtyRun {
    console: String,
}

/// Run `command` as a PTY session of the shim does: `ssh -t host <command>` makes sshd start
/// `conhost.exe --headless ... -- "shim" -c <command>`, and the shim runs on its console.
fn run_pty_session(command: &str, home: &Home) -> PtyRun {
    let shim = env!("CARGO_BIN_EXE_ssh-broker");
    let xdg = home.xdg().into_os_string();
    let run = pty::run_under_conhost(
        &sshd_encoder::pty_line(shim, command),
        &[("XDG_CONFIG_HOME", xdg.as_os_str())],
    );
    PtyRun { console: run.console }
}

/// A PTY session's command is appended to the shell's arguments as it arrived, which is conhost's
/// rebuild of what the client wrote (see `tests/conhost_windows.rs`): runs of spaces become one and
/// quotes around an argument with no space go. An unquoted spaced program path arrives whole,
/// because conhost splits it at the space and joins the pieces again.
#[test]
fn exec_fail_open_appends_a_pty_command_as_conhost_rebuilt_it() {
    let spaced = r"C:\Spaced Dir\sftp-server.exe /c echo unquoted-ok";
    for (command, rebuilt) in [
        (spaced, spaced),
        (r#"echo   spread    out "tight""#, "echo spread out tight"),
        ("echo hi", "echo hi"),
    ] {
        let home = Home::probe_shell("sb-failopen-pty");
        let run = run_pty_session(command, &home);
        assert_failed_open(&run.console);
        assert_eq!(
            home.recorded_line(),
            format!("{} -c {rebuilt}", join_args(&[home.probe().to_str().unwrap()])),
            "{command:?}\nconsole: {}",
            run.console
        );
    }
}

/// A login (no command) that fails open starts the shell with its `without-command` arguments and
/// nothing else.
#[test]
fn interactive_fail_open_starts_the_shell_with_its_login_arguments() {
    let home = Home::with_config(
        "sb-failopen-login",
        "shell: {start: ['{PROBE}', -NoLogo], append: {without-command: [-NoExit]}}\n",
    );
    // An interactive fail-open says nothing on the console, so the probe's record is the proof that it
    // ran: only the shim's own fail-open reads this home (an agent has its own environment).
    run_session_without_command(&home);
    assert_eq!(
        home.recorded_line(),
        join_args(&[home.probe().to_str().unwrap(), "-NoLogo", "-NoExit"])
    );
}

/// `ssh host` with no command, run on pipes: on a console the shim would offer to start a session and wait
/// for a password (`Prompting`), which is not the fail-open under test. What the shell is started with does
/// not depend on the console.
fn run_session_without_command(home: &Home) {
    std::process::Command::new(env!("CARGO_BIN_EXE_ssh-broker"))
        .env("XDG_CONFIG_HOME", home.xdg())
        .output()
        .expect("run the shim");
}

// The fallback shell of a terminal session through the agent =====

/// `console-fallback` writes its notice, runs its line on the same standard handles and exits with the
/// line's code.
#[test]
fn console_fallback_prints_the_notice_then_runs_the_line_and_exits_with_its_code() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_ssh-broker"))
        .args([
            "console-fallback",
            "the notice",
            r#"cmd.exe /c "echo from-shell& exit /b 7""#,
        ])
        .output()
        .expect("run console-fallback");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.starts_with("the notice\r\n"), "{stdout:?}");
    assert!(stdout.contains("from-shell"), "{stdout:?}");
    assert_eq!(out.status.code(), Some(7), "{stdout:?}");
}

/// A line that cannot start is the broker's failure (255), told on stderr, and not the notice's.
#[test]
fn console_fallback_with_a_line_that_cannot_start_exits_255() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_ssh-broker"))
        .args(["console-fallback", "the notice", r"C:\no\such\shell.exe"])
        .output()
        .expect("run console-fallback");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(255), "{stderr:?}");
    assert!(stderr.contains("could not start the shell"), "{stderr:?}");
}
