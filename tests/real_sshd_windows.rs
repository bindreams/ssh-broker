//! The prompt path through the runner's real `sshd`: the product's actual path (M8). Windows only;
//! **Elevated (CI only)**.
//!
//! sshd starts the shim as the `DefaultShell` of a throwaway standard account that has no session; the
//! shim prompts, the password logs the account on, and the login relays into the new background
//! session. Before that, the same account logs in once with a probe as the `DefaultShell`, which
//! records the session, the logon type and the job the shim runs in under sshd.
//!
//! This machine is the runner's: the test changes sshd's `DefaultShell` and adds the account to the
//! group `sshd_config` allows. The runner is discarded after the job, so neither is put back.
#![cfg(windows)]

use std::io::Write as _;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::time::Duration;

use ssh_broker::provision::registry::{OPENSSH_KEY, set_default_shell_under};

#[path = "common/account.rs"]
mod account_fixture;
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
use stand_in::Kit;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// The group `sshd_config` of the runner image allows besides Administrators (`AllowGroups
/// administrators "openssh users"`).
const SSH_GROUP: &str = "OpenSSH Users";

/// What the prompt says first, and the start of a PowerShell prompt (both as in `prompt_path_windows`).
const PROMPT: &str = "Enter your Windows password to start one.";
const SHELL_PROMPT: &str = "PS C:\\";

/// How long the session may stay silent while the test waits for it: an external event that may
/// never come. Generous: a first logon makes the profile's session.
const SILENCE_BOUND: Duration = Duration::from_secs(240);

fn run(program: &str, args: &[&str]) -> (bool, String) {
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
    let grants = [
        "/inheritance:r",
        "/grant:r",
        "*S-1-5-18:(OI)(CI)F",
        "*S-1-5-32-544:(OI)(CI)F",
    ];
    let user = format!("*{account_sid}:(OI)(CI)F");
    let mut args: Vec<&str> = vec![path.to_str().unwrap()];
    args.extend(grants);
    args.push(&user);
    let (ok, text) = run("icacls", &args);
    assert!(ok, "icacls {path:?}: {text}");
}

/// Everything that would explain a refused login, for a failure message.
fn diagnostics(ssh_stderr: &Path, authorized_keys: &Path) -> String {
    let mut report = String::new();
    report += &format!(
        "--- ssh -v ---\n{}\n",
        std::fs::read_to_string(ssh_stderr).unwrap_or_default()
    );
    report += &format!("--- sshd -T ---\n{}\n", run("sshd", &["-T"]).1);
    report += &format!(
        "--- net localgroup \"{SSH_GROUP}\" ---\n{}\n",
        run("net", &["localgroup", SSH_GROUP]).1
    );
    report += &format!(
        "--- icacls authorized_keys ---\n{}\n",
        run("icacls", &[authorized_keys.to_str().unwrap()]).1
    );
    report += &format!(
        "--- OpenSSH/Operational ---\n{}\n",
        run(
            "wevtutil",
            &["qe", "OpenSSH/Operational", "/c:60", "/rd:true", "/f:text"]
        )
        .1
    );
    report
}

/// A folder removed on drop.
struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A key pair for the account, the public half installed where sshd reads it.
struct Keys {
    private: PathBuf,
    authorized_keys: PathBuf,
    _dir: TempDir,
}

fn install_key(account: &Account) -> Keys {
    let dir = TempDir(std::env::temp_dir().join(format!("sb-sshkey-{}", std::process::id())));
    let _ = std::fs::remove_dir_all(&dir.0);
    std::fs::create_dir_all(&dir.0).unwrap();
    let private = dir.0.join("id");
    let (ok, text) = run(
        "ssh-keygen",
        &["-q", "-t", "ed25519", "-N", "", "-f", private.to_str().unwrap()],
    );
    assert!(ok, "ssh-keygen: {text}");
    // The ssh client refuses a private key other accounts can read.
    icacls(&dir.0, "S-1-5-18");
    // A standard user's keys are in the profile; only SYSTEM, Administrators and the user may hold them.
    let dot_ssh = account.profile().join(".ssh");
    std::fs::create_dir_all(&dot_ssh).unwrap();
    let authorized_keys = dot_ssh.join("authorized_keys");
    std::fs::copy(dir.0.join("id.pub"), &authorized_keys).unwrap();
    icacls(&dot_ssh, &account.sid_text);
    icacls(&authorized_keys, &account.sid_text);
    Keys {
        private,
        authorized_keys,
        _dir: dir,
    }
}

/// Let sshd's `AllowGroups` admit the account, and make sure sshd runs.
fn admit(account: &Account) {
    if !run("net", &["localgroup", SSH_GROUP]).0 {
        let (ok, text) = run("net", &["localgroup", SSH_GROUP, "/add"]);
        assert!(ok, "create the group {SSH_GROUP}: {text}");
    }
    let (ok, text) = run("net", &["localgroup", SSH_GROUP, &account.name, "/add"]);
    assert!(ok, "add {} to {SSH_GROUP}: {text}", account.name);
    // "already been started" (2182) is fine; whether it runs is what `sc query` says.
    let _ = run("net", &["start", "sshd"]);
    let (_, state) = run("sc", &["query", "sshd"]);
    assert!(state.contains("RUNNING"), "the sshd service is not running:\n{state}");
}

fn ssh_command(keys: &Keys, account: &Account, stderr: std::fs::File) -> Command {
    let mut command = Command::new("ssh");
    command
        .args(["-v", "-i"])
        .arg(&keys.private)
        .args([
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=NUL",
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "PasswordAuthentication=no",
        ])
        .arg(format!("{}@localhost", account.name))
        .creation_flags(CREATE_NO_WINDOW)
        .stderr(stderr);
    command
}

/// An interactive login through sshd, driven by typed lines and read as text.
struct SshSession {
    child: Child,
    stdin: ChildStdin,
    output: Receiver<Vec<u8>>,
    transcript: Vec<u8>,
    diagnostics: Box<dyn Fn() -> String>,
}

impl SshSession {
    fn start(mut command: Command, diagnostics: impl Fn() -> String + 'static) -> SshSession {
        command.arg("-tt").stdin(Stdio::piped()).stdout(Stdio::piped());
        let mut child = command.spawn().expect("run ssh");
        let stdin = child.stdin.take().unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let (chunks, output) = channel();
        std::thread::Builder::new()
            .name("ssh-reader".into())
            .spawn(move || {
                use std::io::Read as _;
                let mut buf = [0u8; 4096];
                loop {
                    match stdout.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if chunks.send(buf[..n].to_vec()).is_err() {
                                return;
                            }
                        }
                    }
                }
            })
            .expect("start the reader");
        SshSession {
            child,
            stdin,
            output,
            transcript: Vec::new(),
            diagnostics: Box::new(diagnostics),
        }
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.transcript).into_owned()
    }

    fn fail(&self, what: &str) -> ! {
        panic!("{what}; the session showed:\n{}\n{}", self.text(), (self.diagnostics)())
    }

    fn type_line(&mut self, line: &str) {
        if self
            .stdin
            .write_all(format!("{line}\r").as_bytes())
            .and_then(|()| self.stdin.flush())
            .is_err()
        {
            self.fail("could not write to ssh");
        }
    }

    fn read_until(&mut self, needle: &str) {
        loop {
            if self.text().contains(needle) {
                return;
            }
            let received = self.output.recv_timeout(SILENCE_BOUND); // sleep-ok: failure bound on the session's output, an external event that may never come; expiry fails the test and is not read as state
            match received {
                Ok(chunk) => self.transcript.extend_from_slice(&chunk),
                Err(RecvTimeoutError::Disconnected) => {
                    self.fail(&format!("ssh ended before the session showed {needle:?}"))
                }
                Err(RecvTimeoutError::Timeout) => self.fail(&format!(
                    "the session was silent for {SILENCE_BOUND:?} while the test waited for {needle:?}"
                )),
            }
        }
    }

    /// Read until ssh closes its output, then wait for it to end.
    fn finish(mut self) -> i32 {
        loop {
            match self.output.recv_timeout(SILENCE_BOUND) {
                // sleep-ok: failure bound on the session's end, an external event that may never come
                Ok(chunk) => self.transcript.extend_from_slice(&chunk),
                Err(RecvTimeoutError::Disconnected) => break,
                Err(RecvTimeoutError::Timeout) => {
                    self.fail(&format!("the session did not end within {SILENCE_BOUND:?}"))
                }
            }
        }
        self.child.wait().expect("wait for ssh").code().unwrap_or(-1)
    }
}

impl Drop for SshSession {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

/// Elevated (CI only). M8: the shim as sshd's `DefaultShell`, for an account with no session.
#[test]
fn prompt_path_through_real_sshd() {
    let _machine = machine::shared();
    account_fixture::assert_elevated();
    let kit = Kit::broker_with_helper("sshd");
    let account = Account::create("sshd", true);
    admit(&account);
    let keys = install_key(&account);
    let stderr_path = kit.path("ssh-stderr.txt");
    let diag = {
        let (stderr_path, authorized_keys) = (stderr_path.clone(), keys.authorized_keys.clone());
        move || diagnostics(&stderr_path, &authorized_keys)
    };
    let open_stderr = || std::fs::File::create(&stderr_path).unwrap();

    // 1. What the shim runs in under sshd: the probe is the DefaultShell for one command.
    set_default_shell_under(OPENSSH_KEY, &kit.helper.to_string_lossy()).expect("set the probe as DefaultShell");
    let mut probe = ssh_command(&keys, &account, open_stderr());
    let out = probe.arg("probe").stdin(Stdio::null()).output().expect("run ssh");
    let facts = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success() && facts.contains("session="),
        "the probe did not run through sshd (exit {:?}); stdout:\n{facts}\n{}",
        out.status.code(),
        diag()
    );
    eprintln!("M8 the shim's environment under sshd (session, logon type, job):\n{facts}");

    // 2. The product's path: the shim is the DefaultShell, the account has no session.
    set_default_shell_under(OPENSSH_KEY, &kit.exe.to_string_lossy()).expect("set the shim as DefaultShell");
    let mut session = SshSession::start(ssh_command(&keys, &account, open_stderr()), diag);
    session.read_until(PROMPT);
    session.type_line(&account.password);
    session.read_until(SHELL_PROMPT);

    session.type_line("Write-Output ('profile=' + $env:USERPROFILE + '.')");
    session.read_until(&format!("profile={}.", account.profile().display()));
    session.type_line("Write-Output ('session-id=' + (Get-Process -Id $PID).SessionId + '.')");
    session.read_until("session-id=");
    session.type_line(
        "try { [void][Security.Cryptography.ProtectedData]::Protect([byte[]](1,2,3), $null, 'CurrentUser'); \
         Write-Output ('dpapi' + '-ok') } catch { Write-Output ('dpapi' + '-failed ' + $_) }",
    );
    session.read_until("dpapi-ok");
    eprintln!("M8 the relayed session showed:\n{}", session.text());
    session.type_line("exit");
    let code = session.finish();
    assert_eq!(code, 0, "ssh exited with {code}");
}
