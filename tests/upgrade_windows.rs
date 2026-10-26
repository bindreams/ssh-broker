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
#[path = "common/machine.rs"]
mod machine;
#[path = "common/password.rs"]
mod password;
#[path = "common/process_list.rs"]
mod process_list;
#[path = "common/stand_in.rs"]
mod stand_in;

use account_fixture::Account;
use agent_conn::{BackgroundAgent, local_account};
use stand_in::Kit;

/// How long a scheduled start may take before the test calls it failed; the start is an external event.
const TASK_START_BOUND: Duration = Duration::from_secs(180);

const OPENSSH_KEY: &str = r"HKLM\SOFTWARE\OpenSSH";
const SHELL_VALUES: [&str; 3] = [
    "DefaultShell",
    "DefaultShellCommandOption",
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

/// Elevated (CI only). With a background session the prompt started, an auto-login task, and an open
/// SSH-session shim all present: the prompt-path session ends, the shim survives (and holds the exe,
/// so the copy reports it), and the auto-login session is running again afterwards.
#[test]
fn apply_upgrade_ends_a_background_session_and_restarts_auto_login() {
    let _machine = machine::exclusive();
    let _install = Install::capture();
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
        &installed,
        &format!("\"{}\" -c \"cmd.exe /c ping -n 100000 127.0.0.1\"", installed.display()),
        kit.dir(),
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
    let output = apply(broker);
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

    // The prompt-path session was ended, by apply.
    bounded_wait::wait_for_exit(
        session.process.0,
        // SAFETY: a valid process handle.
        unsafe { windows::Win32::System::Threading::GetProcessId(session.process.0) },
        "the prompt-path background agent after apply",
        bounded_wait::CHILD_EXIT_BOUND,
        &[],
    );
    // The shim was left alone.
    assert!(!shim_has_ended(), "apply must not end an SSH session's shim");

    // The auto-login session was ended and started again: a different process serves the account.
    let started = Instant::now();
    loop {
        let now = agent_pids(&auto.sid_text);
        if now.iter().any(|pid| !before.contains(pid)) {
            break;
        }
        assert!(
            started.elapsed() < TASK_START_BOUND,
            "the auto-login agent was not started again after apply (before {before:?}, now {now:?})\n{text}"
        );
        std::thread::yield_now();
    }

    // SAFETY: a valid process handle; ending a shim that already ended is harmless.
    let _ = unsafe { TerminateProcess(shim.process.0, 1) };
    let _ = autologin::off(&mut WindowsEnv::new(PasswordSource::Given(None)), &local_account(&auto));
}
