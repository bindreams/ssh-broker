//! Helpers around `examples/session_stand_in.rs`: a directory every account can run from, the stand-in
//! shim started as an account's network token, and a guard that stops or disables `seclogon`.
//!
//! The including crate declares `account_fixture` (the account fixture), `desktop` and `machine`.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

use ssh_broker::ready::{ReadyEvent, Waited, generate_name};
use ssh_broker::socket_loc::SocketLocation;
use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::Storage::FileSystem::{
    FILE_NOTIFY_CHANGE_FILE_NAME, FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_CHANGE_SIZE, FindCloseChangeNotification,
    FindFirstChangeNotificationW, FindNextChangeNotification,
};
use windows::Win32::System::Threading::{
    CREATE_PROCESS_LOGON_FLAGS, INFINITE, TerminateProcess, WaitForMultipleObjects, WaitForSingleObject,
};
use windows::core::PCWSTR;

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

/// Block until the agent that serves `location` has rewritten its `serving` marker, that is, until
/// it is listening. A directory watch is armed before the marker is looked for, so a write between
/// the look and the wait is not missed. An agent that ends first fails the wait with its exit code.
pub fn wait_for_serving_marker(location: &SocketLocation, agent: HANDLE) {
    use std::os::windows::ffi::OsStrExt;
    // The socket folder may not exist yet, so the watch is on its parent and covers the subtree.
    let watched = location.dir.parent().expect("the socket folder has a parent");
    let watched_w: Vec<u16> = watched.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    // SAFETY: a NUL-terminated path; the handle is closed below.
    let watch = unsafe {
        FindFirstChangeNotificationW(
            PCWSTR(watched_w.as_ptr()),
            true,
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE,
        )
    }
    .unwrap();
    loop {
        if location.serving_marker_path().is_file() {
            break;
        }
        // SAFETY: both handles are valid.
        let woke = unsafe { WaitForMultipleObjects(&[watch, agent], false, INFINITE) };
        if woke == WAIT_OBJECT_0 {
            // SAFETY: a valid watch handle.
            unsafe { FindNextChangeNotification(watch) }.unwrap();
        } else {
            let mut code = 0u32;
            // SAFETY: a valid process handle and out-pointer.
            let _ = unsafe { windows::Win32::System::Threading::GetExitCodeProcess(agent, &mut code) };
            panic!("the agent ended with {code:#x} before it was listening");
        }
    }
    // SAFETY: the handle from above.
    let _ = unsafe { FindCloseChangeNotification(watch) };
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
