//! What a test that runs `apply` over the machine's real install puts back: the install directory, the tasks, sshd's
//! `DefaultShell` values, and sshd's configuration files (`sshd_config` and `sshd_config.d`), which `apply` now
//! changes too. **Elevated (CI only).** One guard for every test binary that runs `apply`, so that the install
//! directory is absent again when the test ends, whichever binary runs first.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use ssh_broker::provision::sshd_config::{ACCEPT_LINE, DROP_IN_DIR_NAME, DROP_IN_NAME, INCLUDE_LINE};
use ssh_broker::provision::{self, procwait, schtasks, taskscheduler};

use crate::desktop;

pub const OPENSSH_KEY: &str = r"HKLM\SOFTWARE\OpenSSH";
const SHELL_VALUES: [&str; 4] = [
    "DefaultShell",
    "DefaultShellCommandOption",
    "DefaultShellArguments",
    "DefaultShellEscapeArguments",
];

pub fn reg(args: &[&str]) -> std::process::Output {
    desktop::output(Command::new("reg").args(args)).expect("run reg.exe")
}

// sshd's files =====

pub fn ssh_dir() -> PathBuf {
    Path::new(&std::env::var("ProgramData").expect("ProgramData is set")).join("ssh")
}

pub fn config_path() -> PathBuf {
    ssh_dir().join("sshd_config")
}

pub fn drop_in_dir() -> PathBuf {
    ssh_dir().join(DROP_IN_DIR_NAME)
}

pub fn drop_in_path() -> PathBuf {
    drop_in_dir().join(DROP_IN_NAME)
}

/// The candidate file `apply` makes beside the original.
pub fn candidate_path() -> PathBuf {
    ssh_dir().join("sshd_config.ssh-broker-new")
}

/// The runner's `sshd_config` as it was before any test changed it, read once per test process.
static STOCK: OnceLock<Vec<u8>> = OnceLock::new();

/// `text` without the lines `apply` adds to `sshd_config`. A test process does not know whether a test that ran
/// before it left them in the file (nextest starts one process per test, and the tests that run in parallel
/// change sshd's configuration for good), and a file with the lines is not stock.
fn without_the_lines_apply_adds(text: &[u8]) -> Vec<u8> {
    text.split_inclusive(|&byte| byte == b'\n')
        .filter(|line| {
            let line = String::from_utf8_lossy(line);
            let line = line.trim();
            line != INCLUDE_LINE && line != ACCEPT_LINE
        })
        .flatten()
        .copied()
        .collect()
}

/// The stock `sshd_config`, saved the first time it is asked for.
pub fn stock() -> &'static [u8] {
    STOCK.get_or_init(|| {
        without_the_lines_apply_adds(&std::fs::read(config_path()).expect("read the stock sshd_config"))
    })
}

/// Put sshd's files as the runner has them: the stock `sshd_config`, no drop-in and no folder for one. The
/// running service is not restarted: `apply` decides from what `sshd -T` reads from the files, and says whether the
/// service started before they were written.
pub fn reset() -> &'static [u8] {
    let stock = stock();
    put_back(stock).expect("put the stock sshd_config back");
    stock
}

pub fn put_back(stock: &[u8]) -> std::io::Result<()> {
    let written = std::fs::write(config_path(), stock);
    let _ = std::fs::remove_dir_all(drop_in_dir());
    let _ = std::fs::remove_file(candidate_path());
    written
}

/// Puts sshd's files as [`reset`] makes them when the test ends, also when it fails: what a test leaves in
/// `sshd_config.d` is read by the other test binaries that share the machine, and a drop-in sshd rejects keeps
/// them from configuring it. Made after `reset()`, so the stock file is known.
pub struct ResetAtTheEnd;

impl Drop for ResetAtTheEnd {
    fn drop(&mut self) {
        if let Some(stock) = STOCK.get() {
            let _ = put_back(stock);
        }
    }
}

// the install =====

/// Puts the machine back as `capture` found it: the real tasks, the install directory, sshd's DefaultShell values
/// and sshd's configuration files.
pub struct Install {
    exported: Option<PathBuf>,
}

impl Install {
    pub fn capture() -> Install {
        assert!(
            !Path::new(provision::BASE_DIR).exists(),
            "{} exists: this test installs there and would remove it",
            provision::BASE_DIR
        );
        stock();
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
        let _ = desktop::output(Command::new("schtasks").args(["/Delete", "/TN", schtasks::AGENT_TASK, "/F"]));
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
        if let Some(stock) = STOCK.get() {
            let _ = put_back(stock);
        }
        // `Ok` with a pending delete and `NotFound` from an entry inside a surviving tree both leave the
        // directory; check that it is gone.
        let left = match std::fs::remove_dir_all(provision::BASE_DIR) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Some(e.to_string()),
            removed => match Path::new(provision::BASE_DIR).try_exists() {
                Ok(false) => None,
                Ok(true) => Some(match removed {
                    Ok(()) => "it still exists after the removal returned".to_owned(),
                    Err(e) => format!("it still exists after the removal failed: {e}"),
                }),
                Err(e) => Some(format!("cannot tell whether it is gone: {e}")),
            },
        };
        if let Some(cause) = left {
            let message = format!(
                "cannot remove {}: {cause}\nprocesses whose image or command line contains it:\n{}",
                provision::BASE_DIR,
                install_holders()
            );
            // A panic during an unwind aborts the test binary, and so does `eprintln!` on a closed stderr.
            if std::thread::panicking() {
                use std::io::Write as _;
                let _ = writeln!(std::io::stderr(), "{message}");
            } else {
                panic!("{message}");
            }
        }
    }
}

/// The processes whose image path or command line contains the install directory, one per line as
/// `pid image: path` or `pid command line: text`. Says so when there are none, and when the listing
/// itself failed.
fn install_holders() -> String {
    let dir = provision::BASE_DIR;
    let script = format!(
        "$ErrorActionPreference = 'Stop'; \
         Get-CimInstance Win32_Process | Where-Object {{ $_.ProcessId -ne $PID }} | ForEach-Object {{ \
         if ($_.ExecutablePath -like '{dir}*') {{ \"$($_.ProcessId) image: $($_.ExecutablePath)\" }}; \
         if ($_.CommandLine -like '*{dir}*') {{ \"$($_.ProcessId) command line: $($_.CommandLine)\" }} }}"
    );
    match desktop::output(Command::new("powershell").args(["-NoProfile", "-NonInteractive", "-Command", &script])) {
        Ok(out) if !out.status.success() => format!(
            "the listing failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ),
        Ok(out) if out.stdout.iter().all(u8::is_ascii_whitespace) => {
            "no process with that image or command line".to_owned()
        }
        Ok(out) => String::from_utf8_lossy(&out.stdout).into_owned(),
        Err(e) => format!("the listing failed: cannot start powershell: {e}"),
    }
}
