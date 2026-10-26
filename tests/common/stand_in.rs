//! Helpers around `examples/session_stand_in.rs`: a directory every account can run from, the stand-in
//! shim started as an account's network token, and a guard that stops or disables `seclogon`.
//!
//! The including crate declares `account_fixture` (the account fixture), `desktop` and `machine`.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

use ssh_broker::socket_loc::SocketLocation;
use ssh_broker::socket_watch::SocketWatch;
use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::System::Threading::{
    CREATE_PROCESS_LOGON_FLAGS, TerminateProcess, WaitForMultipleObjects, WaitForSingleObject,
};

use crate::account_fixture::{Account, SharedDir, Spawned};

#[path = "file_signal.rs"]
pub mod file_signal;
use file_signal::FileWaited;

/// The stand-in example, which `cargo test` builds.
pub fn example_exe() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let example = exe
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("examples")
        .join("session_stand_in.exe");
    assert!(
        example.is_file(),
        "the stand-in {example:?} is not built: run `cargo build --examples` (`cargo test` builds it)"
    );
    example
}

/// A directory every account can read and write, holding a copy of the stand-in. The stand-in
/// writes what it learns into this directory, so one kit serves one test.
pub struct Kit {
    dir: SharedDir,
    pub exe: PathBuf,
    /// A copy of the stand-in example, in a kit whose `exe` is the real broker.
    pub helper: PathBuf,
}

impl Kit {
    pub fn new(tag: &str) -> Kit {
        Kit::with_exe(tag, &example_exe())
    }

    /// A kit holding a copy of the real `ssh-broker.exe`.
    pub fn copy_of_broker(tag: &str) -> Kit {
        Kit::with_exe(tag, Path::new(env!("CARGO_BIN_EXE_ssh-broker")))
    }

    /// A kit holding the real `ssh-broker.exe` as `exe` and the stand-in example as `helper`.
    pub fn broker_with_helper(tag: &str) -> Kit {
        let mut kit = Kit::copy_of_broker(tag);
        kit.helper = kit.dir.0.join("helper.exe");
        std::fs::copy(example_exe(), &kit.helper).unwrap();
        kit
    }

    fn with_exe(tag: &str, source: &Path) -> Kit {
        let dir = SharedDir::new(tag);
        let exe = dir.0.join("stand_in.exe");
        std::fs::copy(source, &exe).unwrap();
        Kit {
            dir,
            helper: exe.clone(),
            exe,
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir.0
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.0.join(name)
    }

    /// The stand-in's file `name`, or a note that it is missing.
    pub fn read(&self, name: &str) -> String {
        std::fs::read_to_string(self.path(name)).unwrap_or_else(|e| format!("(no {name}: {e})"))
    }

    /// The value of `key` in the `key=value` lines of the stand-in agent's `agent.info`.
    pub fn agent_info(&self, key: &str) -> String {
        let info = self.read("agent.info");
        info.lines()
            .find_map(|l| l.strip_prefix(&format!("{key}=")))
            .unwrap_or_else(|| panic!("agent.info has no {key}: {info}"))
            .to_owned()
    }
}

/// The stand-in shim, running as `account`'s network token (the token sshd gives it).
pub struct ShimRun {
    pub process: Spawned,
    pub result: String,
}

/// Start the stand-in shim as `account`'s network token with `before_resume` called while it is
/// still suspended (to put it in a job), wait until it reports, and return what it recorded. The
/// report is the appearance of `shim.result`, awaited together with the shim's own exit, so a shim
/// that dies is a failure and not a hang. With `hold` the shim then stays alive until it is killed.
pub fn start_shim(kit: &Kit, account: &Account, hold: bool, before_resume: impl FnOnce(&Spawned)) -> ShimRun {
    start_shim_typing(kit, account, &account.password, hold, before_resume)
}

/// [`start_shim`] with the shim typing `typed` as the password, which may be wrong.
pub fn start_shim_typing(
    kit: &Kit,
    account: &Account,
    typed: &str,
    hold: bool,
    before_resume: impl FnOnce(&Spawned),
) -> ShimRun {
    std::fs::write(kit.path("shim.input"), format!("{typed}\n{}\n", kit.exe.display())).unwrap();
    if hold {
        std::fs::write(kit.path("shim.hold"), "").unwrap();
    }
    let command_line = format!("\"{}\" shim \"{}\"", kit.exe.display(), kit.dir().display());
    let process = account.spawn_with(
        &kit.exe,
        &command_line,
        kit.dir(),
        &[kit.dir().to_path_buf()],
        CREATE_PROCESS_LOGON_FLAGS(0),
        None,
    );
    before_resume(&process);
    process.resume();
    match file_signal::wait_for_file(
        &kit.path("shim.result"),
        Some(process.process.0),
        Some(SERVING_BOUND),
        "the stand-in shim's report",
    ) {
        FileWaited::Appeared => {}
        FileWaited::ProcessEnded(code) => panic!("the stand-in shim ended with {code:#x} before it reported"),
    }
    ShimRun {
        process,
        result: kit.read("shim.result"),
    }
}

/// `seclogon` stopped, or stopped and disabled; put back as it was, also when the test panics.
pub struct SeclogonGuard {
    start_type: String,
    was_running: bool,
}

fn powershell(script: &str) -> String {
    let out =
        crate::desktop::output(Command::new("powershell").args(["-NoProfile", "-NonInteractive", "-Command", script]))
            .unwrap_or_else(|e| panic!("powershell did not run: {e}"));
    assert!(
        out.status.success(),
        "powershell `{script}` failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

impl SeclogonGuard {
    /// Stop the service; with `disable`, also set its start type to Disabled. Hold
    /// `machine::exclusive()` for as long as the guard lives: no other logon may run meanwhile.
    pub fn engage(disable: bool) -> SeclogonGuard {
        let state = powershell("$s = Get-Service -Name seclogon; \"$($s.StartType) $($s.Status)\"");
        let (start_type, status) = state.split_once(' ').expect("StartType and Status");
        let guard = SeclogonGuard {
            start_type: start_type.to_owned(),
            was_running: status == "Running",
        };
        // Stop-Service returns when the service has stopped.
        powershell("Stop-Service -Name seclogon -Force");
        if disable {
            powershell("Set-Service -Name seclogon -StartupType Disabled");
        }
        guard
    }
}

impl Drop for SeclogonGuard {
    fn drop(&mut self) {
        powershell(&format!("Set-Service -Name seclogon -StartupType {}", self.start_type));
        if self.was_running {
            powershell("Start-Service -Name seclogon");
        }
    }
}

/// The real `ssh-broker agent --background`, started as an account's network token and ended when
/// this is dropped.
pub struct RealAgent {
    pub process: Spawned,
}

impl RealAgent {
    pub fn start(kit: &Kit, account: &Account) -> RealAgent {
        let command_line = format!(
            "\"{}\" agent --background --expect-user {}",
            kit.exe.display(),
            account.sid_text
        );
        let process = account.spawn_with(
            &kit.exe,
            &command_line,
            kit.dir(),
            &[],
            CREATE_PROCESS_LOGON_FLAGS(0),
            None,
        );
        process.resume();
        RealAgent { process }
    }

    /// Whether the agent process has not ended: a state check, not a wait.
    pub fn is_running(&self) -> bool {
        // SAFETY: a valid process handle.
        let state = unsafe { WaitForSingleObject(self.process.process.0, 0) }; // sleep-ok: zero-timeout state check of a process handle, not a wait
        state == WAIT_TIMEOUT
    }
}

impl Drop for RealAgent {
    fn drop(&mut self) {
        // SAFETY: a valid process handle; ending an agent that already ended is harmless.
        let _ = unsafe { TerminateProcess(self.process.process.0, 1) };
    }
}

/// How long an agent that was started may take to listen. Generous: a first logon creates the profile.
pub const SERVING_BOUND: std::time::Duration = std::time::Duration::from_secs(180);

/// Block until the agent that serves `location` has rewritten its `serving` marker, that is, until
/// it is listening. A directory watch is armed before the marker is looked for, so a write between
/// the look and the wait is not missed. An agent that ends first fails the wait with its exit code;
/// an agent that neither listens nor ends fails it after [`SERVING_BOUND`], an external event that
/// may never come.
pub fn wait_for_serving_marker(location: &SocketLocation, agent: HANDLE) {
    wait_for_marker(location, Some(agent), SERVING_BOUND)
}

/// [`wait_for_serving_marker`] for an agent that no handle is held on (a scheduled task starts it):
/// the start is an external event that may never come, so the wait has a failure bound and its
/// expiry fails the test saying so.
pub fn wait_for_serving_marker_of_a_task(location: &SocketLocation, bound: std::time::Duration) {
    wait_for_marker(location, None, bound)
}

fn wait_for_marker(location: &SocketLocation, agent: Option<HANDLE>, bound: std::time::Duration) {
    // The socket folder, and the profile above it, may not exist yet: the watch follows the path down.
    let mut watch = SocketWatch::for_location(location).unwrap_or_else(|e| panic!("{e:#}"));
    loop {
        if location.serving_marker_path().is_file() {
            return;
        }
        let handles: Vec<HANDLE> = std::iter::once(watch.handle()).chain(agent).collect();
        let millis = u32::try_from(bound.as_millis()).expect("a bound shorter than INFINITE");
        // SAFETY: every handle is valid.
        let woke = unsafe { WaitForMultipleObjects(&handles, false, millis) }; // sleep-ok: failure bound on an agent start that may never come; expiry fails the test
        if woke == WAIT_OBJECT_0 {
            watch.rearm().unwrap_or_else(|e| panic!("{e:#}"));
        } else if woke == WAIT_TIMEOUT {
            panic!(
                "no agent was serving {} after {bound:?}: it neither wrote its serving marker nor ended,                  or the scheduled task did not start one",
                location.dir.display()
            );
        } else if let Some(agent) = agent {
            // The agent may have written the marker as its last act.
            if location.serving_marker_path().is_file() {
                return;
            }
            let mut code = 0u32;
            // SAFETY: a valid process handle and out-pointer.
            let _ = unsafe { windows::Win32::System::Threading::GetExitCodeProcess(agent, &mut code) };
            panic!("the agent ended with {code:#x} before it was listening");
        } else {
            panic!("waiting for the serving marker failed: {woke:?}");
        }
    }
}

/// Everything the agent logged in `location`'s logs folder.
pub fn read_logs(location: &SocketLocation) -> String {
    let mut text = String::new();
    if let Ok(entries) = std::fs::read_dir(location.logs_dir()) {
        for entry in entries.flatten() {
            text.push_str(&std::fs::read_to_string(entry.path()).unwrap_or_default());
        }
    }
    text
}
