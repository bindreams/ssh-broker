//! Helpers around `examples/session_stand_in.rs`: a directory every account can run from, the stand-in
//! shim started as an account's network token, and a guard that stops or disables `seclogon`.
//!
//! The including crate declares `account_fixture` (the account fixture), `desktop` and `machine`.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

use ssh_broker::ready::{ReadyEvent, Waited, generate_name};
use windows::Win32::System::Threading::CREATE_PROCESS_LOGON_FLAGS;

use crate::account_fixture::{Account, SharedDir, Spawned};

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
}

impl Kit {
    pub fn new(tag: &str) -> Kit {
        let dir = SharedDir::new(tag);
        let exe = dir.0.join("stand_in.exe");
        std::fs::copy(example_exe(), &exe).unwrap();
        Kit { dir, exe }
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
/// wait is on the "reported" event and on the shim's own exit, so a shim that dies is a failure and
/// not a hang. With `hold` the shim then stays alive until it is killed.
pub fn start_shim(kit: &Kit, account: &Account, hold: bool, before_resume: impl FnOnce(&Spawned)) -> ShimRun {
    let reported_name = generate_name().unwrap();
    let reported = ReadyEvent::create_named(&reported_name, &account.sid_text).unwrap();
    std::fs::write(
        kit.path("shim.input"),
        format!("{}\n{}\n{reported_name}\n", account.password, kit.exe.display()),
    )
    .unwrap();
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
    match reported.wait_with(process.process.0).unwrap() {
        Waited::Ready => {}
        Waited::AgentExited(code) => panic!(
            "the stand-in shim ended with {code:#x} before it reported; shim.result: {}",
            kit.read("shim.result")
        ),
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
