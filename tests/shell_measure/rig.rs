//! What every measurement needs: facts output, a throwaway account stock sshd admits, the DefaultShell
//! registry values, and a bounded run of ssh, scp and sftp. The account and key code is copied from
//! `tests/real_sshd_windows.rs`, where it is private (this branch is never merged).
#![allow(dead_code)]

use std::ffi::OsString;
use std::io::Write as _;
use std::os::windows::io::AsRawHandle as _;
use std::os::windows::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

use windows::Win32::Foundation::HANDLE;

use crate::account_fixture::{self, Account, ServiceLogon};
use crate::bounded_wait;

pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;
pub const SSH_GROUP: &str = "OpenSSH Users";
pub const OPENSSH_REG: &str = r"HKLM\SOFTWARE\OpenSSH";

/// The measurements' scratch directory: Users may write it, because the probe runs as the account.
pub fn work_dir() -> PathBuf {
    let dir = Path::new(&std::env::var("ProgramData").expect("ProgramData")).join("sb-measure");
    std::fs::create_dir_all(&dir).expect("create the work directory");
    let (ok, text) = run("icacls", &[dir.to_str().unwrap(), "/grant", "*S-1-5-32-545:(OI)(CI)M"]);
    assert!(ok, "icacls {dir:?}: {text}");
    dir
}

/// One fact: printed (the log is the result) and appended to `SPIKE_FACTS_FILE`, which the workflow uploads.
pub fn fact(line: &str) {
    println!("SPIKE {line}");
    if let Some(path) = std::env::var_os("SPIKE_FACTS_FILE") {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("open the facts file");
        writeln!(file, "SPIKE {line}").expect("append a fact");
    }
}

pub fn run(program: &str, args: &[&str]) -> (bool, String) {
    let out = Command::new(program)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .unwrap_or_else(|e| panic!("{program} did not run: {e}"));
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

fn icacls(path: &Path, account_sid: &str) {
    let inherit = if path.is_dir() { "(OI)(CI)" } else { "" };
    let grants = [
        "/inheritance:r".to_owned(),
        "/grant:r".to_owned(),
        format!("*S-1-5-18:{inherit}F"),
        format!("*S-1-5-32-544:{inherit}F"),
        format!("*{account_sid}:{inherit}F"),
    ];
    let mut args: Vec<&str> = vec![path.to_str().unwrap()];
    args.extend(grants.iter().map(String::as_str));
    let (ok, text) = run("icacls", &args);
    assert!(ok, "icacls {path:?}: {text}");
}

struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A key pair for the account, the public half installed where sshd reads it.
pub struct Keys {
    pub private: PathBuf,
    _dir: TempDir,
}

fn install_key(account: &Account) -> Keys {
    let dir = TempDir(std::env::temp_dir().join(format!("sb-sshkey-{}-{}", account.name, std::process::id())));
    let _ = std::fs::remove_dir_all(&dir.0);
    std::fs::create_dir_all(&dir.0).unwrap();
    let private = dir.0.join("id");
    let (ok, text) = run(
        "ssh-keygen",
        &["-q", "-t", "ed25519", "-N", "", "-f", private.to_str().unwrap()],
    );
    assert!(ok, "ssh-keygen: {text}");
    icacls(&dir.0, "S-1-5-18");
    let dot_ssh = account.profile().join(".ssh");
    std::fs::create_dir_all(&dot_ssh).unwrap();
    let authorized_keys = dot_ssh.join("authorized_keys");
    std::fs::copy(dir.0.join("id.pub"), &authorized_keys).unwrap();
    icacls(&dot_ssh, &account.sid_text);
    icacls(&authorized_keys, &account.sid_text);
    Keys { private, _dir: dir }
}

fn admit(account: &Account) {
    if !run("net", &["localgroup", SSH_GROUP]).0 {
        let (ok, text) = run("net", &["localgroup", SSH_GROUP, "/add"]);
        assert!(ok, "create the group {SSH_GROUP}: {text}");
    }
    let (ok, text) = run("net", &["localgroup", SSH_GROUP, &account.name, "/add"]);
    assert!(ok, "add {} to {SSH_GROUP}: {text}", account.name);
    let _ = run("net", &["start", "sshd"]);
    let (_, state) = run("sc", &["query", "sshd"]);
    assert!(state.contains("RUNNING"), "the sshd service is not running:\n{state}");
}

/// A throwaway standard account that stock sshd lets in by key.
pub struct Rig {
    pub account: Account,
    pub keys: Keys,
    pub work: PathBuf,
}

impl Rig {
    pub fn new(tag: &str) -> Rig {
        account_fixture::assert_elevated();
        let work = work_dir();
        let account = Account::create(tag, true);
        // sshd is a service: its logon keeps the profile's hive loaded, which `Account`'s teardown must know.
        account.started_by(ServiceLogon::Sshd);
        admit(&account);
        let keys = install_key(&account);
        let initial = run("reg", &["query", OPENSSH_REG]).1;
        fact(&format!("{tag}.registry-at-start={initial:?}"));
        Rig { account, keys, work }
    }

    pub fn target(&self) -> String {
        format!("{}@localhost", self.account.name)
    }

    /// `-i key -o ...`: accepted by ssh, scp and sftp alike.
    pub fn options(&self) -> Vec<OsString> {
        let mut args: Vec<OsString> = vec!["-i".into(), self.keys.private.clone().into()];
        for option in [
            "StrictHostKeyChecking=no",
            "UserKnownHostsFile=NUL",
            "BatchMode=yes",
            "IdentitiesOnly=yes",
            "PasswordAuthentication=no",
        ] {
            args.push("-o".into());
            args.push(option.into());
        }
        args
    }
}

/// Make `shell` sshd's `DefaultShell`; the escape flag is set to `escape` or removed, and the option and
/// arguments values are removed, which is stock sshd's default state.
pub fn set_shell(shell: &Path, escape: Option<u32>) {
    let reg = |args: &[&str]| run("reg", args);
    let (ok, text) = reg(&[
        "add",
        OPENSSH_REG,
        "/v",
        "DefaultShell",
        "/t",
        "REG_SZ",
        "/d",
        shell.to_str().unwrap(),
        "/f",
    ]);
    assert!(ok, "reg add DefaultShell: {text}");
    for name in ["DefaultShellCommandOption", "DefaultShellArguments"] {
        let _ = reg(&["delete", OPENSSH_REG, "/v", name, "/f"]);
    }
    match escape {
        Some(flag) => {
            let flag = flag.to_string();
            let (ok, text) = reg(&[
                "add",
                OPENSSH_REG,
                "/v",
                "DefaultShellEscapeArguments",
                "/t",
                "REG_DWORD",
                "/d",
                &flag,
                "/f",
            ]);
            assert!(ok, "reg add DefaultShellEscapeArguments: {text}");
        }
        None => {
            let _ = reg(&["delete", OPENSSH_REG, "/v", "DefaultShellEscapeArguments", "/f"]);
        }
    }
}

pub struct Outcome {
    /// `None`: the tool did not end within the bound and was ended.
    pub code: Option<u32>,
    pub stdout: Vec<u8>,
    pub stderr: String,
}

static RUNS: AtomicU32 = AtomicU32::new(0);

/// Run `tool args` in `cwd` with its output in files; stdin is null, or an open pipe that is dropped when
/// the tool has ended (a PTY session). The wait is bounded by `CHILD_EXIT_BOUND`: the tool is an external
/// process that may never end, and expiry is recorded as a hang, not read as state.
pub fn run_tool(tool: &str, args: &[OsString], cwd: &Path, hold_stdin: bool, scratch: &Path) -> Outcome {
    let n = RUNS.fetch_add(1, Ordering::Relaxed);
    let out_path = scratch.join(format!("run-{n}.out"));
    let err_path = scratch.join(format!("run-{n}.err"));
    let mut command = Command::new(tool);
    command
        .args(args)
        .current_dir(cwd)
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(std::fs::File::create(&out_path).unwrap())
        .stderr(std::fs::File::create(&err_path).unwrap())
        .stdin(if hold_stdin { Stdio::piped() } else { Stdio::null() });
    let mut child = command.spawn().unwrap_or_else(|e| panic!("{tool} did not start: {e}"));
    let handle = HANDLE(child.as_raw_handle());
    let pid = child.id();
    let ended = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        bounded_wait::wait_for_exit(handle, pid, tool, bounded_wait::CHILD_EXIT_BOUND, &[])
    }));
    let code = ended.ok();
    if code.is_none() {
        let _ = child.kill();
    }
    let _ = child.wait();
    drop(child.stdin.take());
    let stdout = std::fs::read(&out_path).unwrap_or_default();
    let stderr = String::from_utf8_lossy(&std::fs::read(&err_path).unwrap_or_default()).into_owned();
    let _ = std::fs::remove_file(&out_path);
    let _ = std::fs::remove_file(&err_path);
    Outcome { code, stdout, stderr }
}

/// `.../target/debug/examples/<name>.exe`, relative to the running test binary.
pub fn example(name: &str) -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let path = exe
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("examples")
        .join(format!("{name}.exe"));
    assert!(
        path.is_file(),
        "the example {path:?} is not built: run `cargo build --examples`"
    );
    path
}

pub fn os(args: &[&str]) -> Vec<OsString> {
    args.iter().map(OsString::from).collect()
}
