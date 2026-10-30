//! `apply` over a machine with background sessions: it ends them, restarts the auto-login ones, and
//! leaves SSH sessions alone. Windows only; **Elevated (CI only)**.
//!
//! This installs into the machine's real install directory, registers the real tasks and writes
//! sshd's DefaultShell, so it takes the machine alone (`machine::exclusive()`) and puts everything
//! back. It refuses to start where an install exists.
#![cfg(windows)]

use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use ssh_broker::autologin::{self, PasswordSource, WindowsEnv};
use ssh_broker::provision::{self, procwait, schtasks, taskscheduler};
use windows::Win32::Foundation::{HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation, WAIT_TIMEOUT};
use windows::Win32::System::Threading::{
    CREATE_PROCESS_LOGON_FLAGS, GetExitCodeProcess, TerminateProcess, WaitForSingleObject,
};

#[path = "common/account.rs"]
mod account_fixture;
#[path = "common/agent_conn.rs"]
mod agent_conn;
#[path = "common/bounded_wait.rs"]
mod bounded_wait;
#[path = "common/desktop.rs"]
mod desktop;
#[path = "common/hard_errors.rs"]
mod hard_errors;
#[path = "common/logon_session.rs"]
mod logon_session;
#[path = "common/machine.rs"]
mod machine;
#[path = "common/password.rs"]
mod password;
#[path = "common/process_list.rs"]
mod process_list;
#[path = "common/session_end.rs"]
mod session_end;
#[path = "common/stand_in.rs"]
mod stand_in;

use account_fixture::{Account, ServiceLogon};
use agent_conn::{BackgroundAgent, local_account};
use stand_in::Kit;

/// How long a scheduled start may take before the test calls it failed; the start is an external event.
const TASK_START_BOUND: Duration = Duration::from_secs(180);

const OPENSSH_KEY: &str = r"HKLM\SOFTWARE\OpenSSH";
const SHELL_VALUES: [&str; 4] = [
    "DefaultShell",
    "DefaultShellCommandOption",
    "DefaultShellArguments",
    "DefaultShellEscapeArguments",
];

fn reg(args: &[&str]) -> std::process::Output {
    desktop::output(Command::new("reg").args(args)).expect("run reg.exe")
}

/// Puts the machine back as `capture` found it: the real tasks, the install directory, sshd's
/// DefaultShell values.
struct Install {
    exported: Option<PathBuf>,
}

impl Install {
    fn capture() -> Install {
        assert!(
            !Path::new(provision::BASE_DIR).exists(),
            "{} exists: this test installs there and would remove it",
            provision::BASE_DIR
        );
        let file = std::env::temp_dir().join(format!("sb-openssh-{}.reg", std::process::id()));
        let _ = std::fs::remove_file(&file);
        let exported = reg(&["export", OPENSSH_KEY, &file.to_string_lossy(), "/y"])
            .status
            .success();
        Install {
            exported: exported.then_some(file),
        }
    }
}

impl Drop for Install {
    fn drop(&mut self) {
        let canonical = provision::canonical_exe();
        let _ = taskscheduler::stop_instances(schtasks::AGENT_TASK, &canonical);
        for task in [schtasks::AGENT_TASK, schtasks::SELFHEAL_TASK] {
            let _ = desktop::output(Command::new("schtasks").args(["/Delete", "/TN", task, "/F"]));
        }
        if let Ok(agents) = procwait::background_agents(&canonical) {
            for agent in &agents {
                let _ = agent.terminate();
            }
            let _ = procwait::wait_all_exited(&agents, procwait::EXIT_BOUND);
        }
        for value in SHELL_VALUES {
            let _ = reg(&["delete", OPENSSH_KEY, "/v", value, "/f"]);
        }
        if let Some(file) = &self.exported {
            let _ = reg(&["import", &file.to_string_lossy()]);
            let _ = std::fs::remove_file(file);
        }
        let _ = std::fs::remove_dir_all(provision::BASE_DIR);
    }
}

/// The process ids of the `agent --background --expect-user <sid>` processes of one account.
fn agent_pids(sid: &str) -> Vec<u32> {
    let out = desktop::output(Command::new("powershell").args([
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'ssh-broker.exe' } | \
         ForEach-Object { \"$($_.ProcessId) $($_.CommandLine)\" }",
    ]))
    .unwrap();
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|line| line.contains("agent --background") && line.contains(sid))
        .filter_map(|line| line.split_whitespace().next()?.parse().ok())
        .collect()
}

/// Run `exe apply` and return its output.
fn apply(exe: &Path) -> std::process::Output {
    desktop::output(Command::new(exe).arg("apply")).expect("run apply")
}

/// What the upgrade tests start from: the old build installed, an auto-login session running it from a
/// task, and a session the prompt started (no task behind it).
struct Scene {
    broker: &'static Path,
    /// The build that is installed, as a file outside the install directory: `apply` of it is an
    /// `apply` of the installed build.
    old: PathBuf,
    installed: PathBuf,
    kit: Kit,
    /// The processes of the auto-login agent before the upgrade.
    before: Vec<u32>,
    session: BackgroundAgent,
    // Fields drop in order, and an account's profile stays in use while this test holds a handle on a process
    // of the account: `session` is the prompt-path agent of `prompted`, so `prompted` comes after it.
    _prompted: Account,
    // Ends the auto-login session with the product's `logout` before `auto` goes (see `session_end`).
    _end_auto: session_end::LogOutOnDrop,
    auto: Account,
    _install: Install,
}

fn scene() -> Scene {
    let install = Install::capture();
    let broker = Path::new(env!("CARGO_BIN_EXE_ssh-broker"));

    // The installed build: this exe with a few bytes appended, so the next build differs from it.
    let kit = Kit::copy_of_broker("up");
    let old = kit.dir().join("old").join("ssh-broker.exe");
    std::fs::create_dir_all(old.parent().unwrap()).unwrap();
    let mut bytes = std::fs::read(broker).unwrap();
    bytes.extend_from_slice(b"an older build");
    std::fs::write(&old, bytes).unwrap();
    let installed = provision::canonical_exe();
    let first = apply(&old);
    assert!(
        first.status.success(),
        "installing the old build failed:\n{}{}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(installed.is_file());

    // An auto-login session, from a task, running the installed exe.
    let auto = Account::create("up1", true);
    auto.grant_batch_logon_right();
    let end_auto = session_end::LogOutOnDrop::new(&installed, &auto, ServiceLogon::TaskScheduler);
    autologin::on(
        &mut WindowsEnv::new(PasswordSource::Given(Some(password::password(&auto.password)))),
        &local_account(&auto),
    )
    .unwrap();
    let before = {
        let location = ssh_broker::socket_loc::for_profile(auto.profile()).unwrap();
        stand_in::wait_for_serving_marker_of_a_task(&location, TASK_START_BOUND);
        agent_pids(&auto.sid_text)
    };
    assert_eq!(
        before.len(),
        1,
        "one auto-login agent runs before the upgrade: {before:?}"
    );

    // A session the prompt started, with no task behind it.
    let prompted = Account::create("up2", true);
    let mut installed_kit = Kit::copy_of_broker("up2");
    installed_kit.exe = installed.clone();
    let session = BackgroundAgent::start(&installed_kit, &prompted);
    Scene {
        broker,
        old,
        installed,
        kit,
        before,
        session,
        _prompted: prompted,
        _end_auto: end_auto,
        auto,
        _install: install,
    }
}

impl Scene {
    /// The prompt-path session was ended by `apply`.
    fn assert_prompt_session_ended(&self) {
        bounded_wait::wait_for_exit(
            self.session.process.0,
            // SAFETY: a valid process handle.
            unsafe { windows::Win32::System::Threading::GetProcessId(self.session.process.0) },
            "the prompt-path background agent after apply",
            bounded_wait::CHILD_EXIT_BOUND,
            &[],
        );
    }

    /// The auto-login session was ended and started again: a different process serves the account.
    fn assert_auto_login_restarted(&self, apply_output: &str) {
        let started = Instant::now();
        loop {
            let now = agent_pids(&self.auto.sid_text);
            if now.iter().any(|pid| !self.before.contains(pid)) {
                break;
            }
            assert!(
                started.elapsed() < TASK_START_BOUND,
                "the auto-login agent was not started again after apply (before {:?}, now {now:?})\n{apply_output}",
                self.before
            );
            std::thread::yield_now();
        }
    }
}

impl Drop for Scene {
    /// The auto-login task is removed before the account goes, whether the test passed or not: a task left
    /// behind starts the agent again as the account, and its session holds the profile.
    fn drop(&mut self) {
        let _ = autologin::off(
            &mut WindowsEnv::new(PasswordSource::Given(None)),
            &local_account(&self.auto),
        );
    }
}

/// Elevated (CI only). With a background session the prompt started, an auto-login task, and an open
/// SSH-session shim all present: the prompt-path session ends, the shim survives (and holds the exe,
/// so the copy reports it), and the auto-login session is running again afterwards. The install
/// fails here, by design; the upgrade that succeeds is the next test.
#[test]
fn apply_upgrade_that_fails_on_a_held_exe_still_restarts_auto_login() {
    let _machine = machine::exclusive();
    let scene = scene();
    let installed = &scene.installed;

    // An open SSH session: the shim holds the installed exe. It is the shim of an account that has no
    // agent (as sshd would run it, under that account's network token): it fails open and runs its
    // command itself, for as long as the command lasts. A shim relayed through an agent would end
    // when `apply` ends that agent (exit 254, measured in CI), and so would not hold the exe.
    let no_agent = Account::create("up3", true);
    // Its standard handles are the null device: a shim with none cannot write the command's first line
    // of output and ends with it.
    let null = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("NUL")
        .expect("open NUL");
    let null_handle = HANDLE(null.as_raw_handle());
    // SAFETY: a valid handle; the service copies inheritable handles into the child.
    unsafe { SetHandleInformation(null_handle, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT) }
        .expect("make NUL inheritable");
    let shim = no_agent.spawn_with_stdio(
        installed,
        &format!("\"{}\" -c \"cmd.exe /c ping -n 100000 127.0.0.1\"", installed.display()),
        scene.kit.dir(),
        &[],
        CREATE_PROCESS_LOGON_FLAGS(0),
        None,
        Some([null_handle; 3]),
    );
    shim.resume();
    let shim_has_ended = || {
        // SAFETY: a valid process handle.
        let state = unsafe { WaitForSingleObject(shim.process.0, 0) }; // sleep-ok: zero-timeout state check of a process handle, not a wait
        state != WAIT_TIMEOUT
    };

    let shim_exit_code = || {
        let mut code = 0u32;
        // SAFETY: a valid process handle and out-pointer; the code is STILL_ACTIVE (259) while it runs.
        unsafe { GetExitCodeProcess(shim.process.0, &mut code) }
            .ok()
            .map(|()| code)
    };

    // A state check, not a wait: the shim runs for as long as its command does, and holds the exe from
    // its creation. If it has ended, the copy below has nothing to fail on.
    assert!(
        !shim_has_ended(),
        "the shim ended by itself before apply ran, so it cannot hold the exe"
    );

    // The new build: the copy of this exe. It cannot replace the installed one while the shim runs.
    let output = apply(scene.broker);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !output.status.success(),
        "the shim holds the exe, so the copy fails (shim ended by now: {}, exit code {:?}):\n{text}",
        shim_has_ended(),
        shim_exit_code()
    );
    assert!(
        text.contains("in use"),
        "today's message for a shim that holds the exe:\n{text}"
    );

    scene.assert_prompt_session_ended();
    // The shim was left alone.
    assert!(!shim_has_ended(), "apply must not end an SSH session's shim");
    scene.assert_auto_login_restarted(&text);

    // SAFETY: a valid process handle; ending a shim that already ended is harmless.
    let _ = unsafe { TerminateProcess(shim.process.0, 1) };
}

/// Elevated (CI only). The upgrade that succeeds: nothing holds the installed exe (no SSH session is
/// open), so `apply` ends the prompt-path session and the auto-login one, replaces the exe with the new
/// build, and enables and starts the auto-login task again.
#[test]
fn apply_upgrade_that_succeeds_ends_a_background_session_and_restarts_auto_login() {
    let _machine = machine::exclusive();
    let scene = scene();
    let old_bytes = std::fs::read(&scene.installed).unwrap();

    let output = apply(scene.broker);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "the upgrade failed:\n{text}");

    // The new build is installed.
    let new_bytes = std::fs::read(&scene.installed).unwrap();
    assert_ne!(new_bytes, old_bytes, "the installed exe is still the old build");
    assert_eq!(
        new_bytes,
        std::fs::read(scene.broker).unwrap(),
        "the installed exe is not the build that ran apply"
    );

    scene.assert_prompt_session_ended();
    // The auto-login session runs again, from the new exe: a different process serves the account, and
    // the task is still enabled.
    scene.assert_auto_login_restarted(&text);
    let tasks = taskscheduler::session_tasks().unwrap();
    assert!(
        !tasks.is_empty() && tasks.iter().all(|task| task.enabled),
        "an auto-login task is not enabled after apply: {tasks:?}"
    );
}

/// Elevated (CI only). An `apply` of the build that is already installed repairs an auto-login task
/// that an interrupted upgrade left disabled with no session: it enables the task and starts its
/// session.
#[test]
fn apply_of_the_installed_build_enables_a_disabled_auto_login_task_and_starts_its_session() {
    let _machine = machine::exclusive();
    let scene = scene();
    let tasks = taskscheduler::session_tasks().unwrap();
    assert!(!tasks.is_empty(), "the scene registers an auto-login task");
    for task in &tasks {
        // Disables the task and returns once its session has exited: what a killed upgrade leaves.
        taskscheduler::stop_instances(&task.name, &scene.installed).unwrap();
    }
    assert!(
        taskscheduler::session_tasks().unwrap().iter().all(|task| !task.enabled),
        "control: every auto-login task is disabled"
    );
    assert!(
        agent_pids(&scene.auto.sid_text).is_empty(),
        "control: the auto-login session is not running"
    );

    let output = apply(&scene.old);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "the apply failed:\n{text}");

    let tasks = taskscheduler::session_tasks().unwrap();
    assert!(
        !tasks.is_empty() && tasks.iter().all(|task| task.enabled),
        "an auto-login task is not enabled after apply: {tasks:?}"
    );
    scene.assert_auto_login_restarted(&text);
}

/// Elevated (CI only). An `apply` of the build that is already installed leaves a running auto-login
/// session running: the same process serves the account afterwards.
#[test]
fn apply_of_the_installed_build_leaves_a_running_auto_login_session_running() {
    let _machine = machine::exclusive();
    let scene = scene();

    let output = apply(&scene.old);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "the apply failed:\n{text}");

    assert_eq!(
        agent_pids(&scene.auto.sid_text),
        scene.before,
        "the auto-login session was stopped or restarted by an apply that replaced nothing\n{text}"
    );
}

/// Set one of sshd's values under the real key (`Install` puts them back).
fn set_sshd_value(name: &str, kind: &str, data: &str) {
    let out = reg(&["add", OPENSSH_KEY, "/v", name, "/t", kind, "/d", data, "/f"]);
    assert!(
        out.status.success(),
        "reg add {name}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Elevated (CI only). `apply` over a machine whose sshd runs another shell with options writes the
/// system config from all four values, before it overwrites them, and a second `apply` (even over
/// yet another shell) leaves the file as it is.
#[test]
fn apply_carries_all_four_values_and_a_second_apply_does_not_rewrite_them() {
    use ssh_broker::shell::Escaping;
    use ssh_broker::shell::config::{ShellBlock, parse};

    let _machine = machine::exclusive();
    let _install = Install::capture();
    let dir = std::env::temp_dir().join(format!("sb-carry-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Files that exist; `apply` never runs them.
    let (pwsh, other) = (dir.join("pwsh.exe"), dir.join("other.exe"));
    for file in [&pwsh, &other] {
        std::fs::write(file, b"MZ").unwrap();
    }
    let broker = Path::new(env!("CARGO_BIN_EXE_ssh-broker"));
    let config = Path::new(provision::BASE_DIR).join("config.yaml");

    set_sshd_value("DefaultShell", "REG_SZ", &pwsh.to_string_lossy());
    set_sshd_value("DefaultShellCommandOption", "REG_SZ", "-Command");
    set_sshd_value("DefaultShellArguments", "REG_SZ", r#"-NoLogo -File "C:\a b\x.ps1""#);
    set_sshd_value("DefaultShellEscapeArguments", "REG_DWORD", "0");

    let first = apply(broker);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(first.status.success(), "the apply failed:\n{text}");
    assert!(text.contains("wrote"), "{text}");
    let written = std::fs::read(&config).unwrap_or_else(|e| panic!("no config after apply: {e}\n{text}"));
    assert_eq!(
        parse(&written).unwrap(),
        Some(ShellBlock {
            start: vec![pwsh.to_string_lossy().into_owned()],
            without_command: Some(vec!["-NoLogo".into(), "-File".into(), r"C:\a b\x.ps1".into()]),
            with_command: Some(vec!["-Command".into()]),
            escaping: Some(Escaping::Cmd),
        })
    );

    // The reads came before the overwrites: sshd now runs ssh-broker with its own option and flag.
    let (shell, option) = provision::registry::read_default_shell_under(provision::registry::OPENSSH_KEY).unwrap();
    assert!(
        shell.ends_with("ssh-broker.exe") && option == "-c",
        "{shell:?} {option:?}"
    );
    assert!(provision::registry::escape_arguments_under(provision::registry::OPENSSH_KEY).unwrap());
    // The arguments are in the config now, so sshd may not pass them to ssh-broker as well.
    let remaining = reg(&["query", OPENSSH_KEY, "/v", "DefaultShellArguments"]);
    assert!(
        !remaining.status.success(),
        "DefaultShellArguments is still set:
{}",
        String::from_utf8_lossy(&remaining.stdout)
    );

    // Another shell in the registry and a second apply: the file stays byte for byte.
    set_sshd_value("DefaultShell", "REG_SZ", &other.to_string_lossy());
    let second = apply(broker);
    assert!(
        second.status.success(),
        "{}{}",
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr)
    );
    assert_eq!(
        std::fs::read(&config).unwrap(),
        written,
        "the second apply rewrote the config"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
