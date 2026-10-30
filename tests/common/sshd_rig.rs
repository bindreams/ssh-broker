//! What a test through the runner's real `sshd` needs: a throwaway account sshd admits, its key, an
//! interactive `ssh` driven by typed lines, and the DefaultShell registry values. **CI only.**
//!
//! Shared by `real_sshd_windows` (the prompt path) and `shell_sshd_windows` (what the shell does with a
//! command), so there is one copy of the account and key code.
#![allow(dead_code)]

use std::io::Write as _;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::time::Duration;

use crate::account_fixture::Account;
use crate::stand_in::Kit;

pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// The group `sshd_config` of the runner image allows besides Administrators (`AllowGroups
/// administrators "openssh users"`).
pub const SSH_GROUP: &str = "OpenSSH Users";

/// What the prompt says first, and the start of a PowerShell prompt (both as in `prompt_path_windows`).
pub const PROMPT: &str = "Enter your Windows password to start one.";
pub const SHELL_PROMPT: &str = "PS C:\\";

/// How long the session may stay silent while the test waits for it: an external event that may
/// never come. Generous: a first logon makes the profile's session.
pub const SILENCE_BOUND: Duration = Duration::from_secs(240);

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

/// Make `path` readable by SYSTEM, Administrators and the account only. A file takes plain `F`:
/// `(OI)(CI)` on a file leaves it with an empty DACL, which sshd's `authorized_keys` check refuses.
pub fn icacls(path: &Path, account_sid: &str) {
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

/// Everything that would explain a refused login, for a failure message.
pub fn diagnostics(ssh_stderr: &Path, authorized_keys: &Path) -> String {
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
    // Why sshd refused a key (bad ownership or modes, an AllowGroups miss) is in its own log, not in the event log.
    let sshd_log = Path::new(&std::env::var("ProgramData").unwrap_or_default())
        .join("ssh")
        .join("logs")
        .join("sshd.log");
    let sshd_log_text =
        std::fs::read_to_string(&sshd_log).unwrap_or_else(|e| format!("(no {}: {e})", sshd_log.display()));
    let tail: Vec<&str> = sshd_log_text.lines().rev().take(80).collect();
    report += &format!(
        "--- {} (last {} lines) ---\n{}\n",
        sshd_log.display(),
        tail.len(),
        tail.into_iter().rev().collect::<Vec<_>>().join("\n")
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
pub struct TempDir(pub PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A key pair for the account, the public half installed where sshd reads it.
pub struct Keys {
    pub private: PathBuf,
    pub authorized_keys: PathBuf,
    pub _dir: TempDir,
}

pub fn install_key(account: &Account) -> Keys {
    let dir = TempDir(std::env::temp_dir().join(format!("sb-sshkey-{}-{}", account.name, std::process::id())));
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
pub fn admit(account: &Account) {
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

pub fn ssh_command(keys: &Keys, account: &Account, stderr: std::fs::File) -> Command {
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
pub struct SshSession {
    pub child: Child,
    pub stdin: ChildStdin,
    pub output: Receiver<Vec<u8>>,
    pub transcript: Vec<u8>,
    pub diagnostics: Box<dyn Fn() -> String>,
}

impl SshSession {
    pub fn start(mut command: Command, diagnostics: impl Fn() -> String + 'static) -> SshSession {
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

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.transcript).into_owned()
    }

    pub fn fail(&self, what: &str) -> ! {
        panic!("{what}; the session showed:\n{}\n{}", self.text(), (self.diagnostics)())
    }

    pub fn type_line(&mut self, line: &str) {
        if self
            .stdin
            .write_all(format!("{line}\r").as_bytes())
            .and_then(|()| self.stdin.flush())
            .is_err()
        {
            self.fail("could not write to ssh");
        }
    }

    pub fn read_until(&mut self, needle: &str) {
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

    /// Read until the session has shown one of `needles`; the index of the first one found.
    pub fn read_until_any(&mut self, needles: &[&str]) -> usize {
        loop {
            let text = self.text();
            if let Some(found) = needles.iter().position(|needle| text.contains(needle)) {
                return found;
            }
            let received = self.output.recv_timeout(SILENCE_BOUND); // sleep-ok: failure bound on the session's output, an external event that may never come; expiry fails the test and is not read as state
            match received {
                Ok(chunk) => self.transcript.extend_from_slice(&chunk),
                Err(RecvTimeoutError::Disconnected) => {
                    self.fail(&format!("ssh ended before the session showed one of {needles:?}"))
                }
                Err(RecvTimeoutError::Timeout) => self.fail(&format!(
                    "the session was silent for {SILENCE_BOUND:?} while the test waited for one of {needles:?}"
                )),
            }
        }
    }

    /// Read until ssh closes its output, then wait for it to end.
    pub fn finish(mut self) -> i32 {
        loop {
            let received = self.output.recv_timeout(SILENCE_BOUND); // sleep-ok: failure bound on the session's end, an external event that may never come; expiry fails the test and is not read as state
            match received {
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

/// A throwaway account sshd admits, with its key and the diagnostics a failed login needs.
pub struct Login<'a> {
    pub account: &'a Account,
    pub keys: Keys,
    pub stderr_path: PathBuf,
}

impl<'a> Login<'a> {
    pub fn new(kit: &Kit, account: &'a Account) -> Login<'a> {
        admit(account);
        Login {
            account,
            keys: install_key(account),
            stderr_path: kit.path(&format!("ssh-stderr-{}.txt", account.name)),
        }
    }

    pub fn command(&self) -> Command {
        ssh_command(
            &self.keys,
            self.account,
            std::fs::File::create(&self.stderr_path).unwrap(),
        )
    }

    pub fn diagnostics(&self) -> impl Fn() -> String + 'static {
        let (stderr_path, authorized_keys) = (self.stderr_path.clone(), self.keys.authorized_keys.clone());
        move || diagnostics(&stderr_path, &authorized_keys)
    }

    /// An interactive login through sshd.
    pub fn start(&self) -> SshSession {
        SshSession::start(self.command(), self.diagnostics())
    }

    /// A login that ends in a shell without a prompt: the account's session was already running.
    pub fn start_into_running_session(&self) -> SshSession {
        let mut session = self.start();
        if session.read_until_any(&[PROMPT, SHELL_PROMPT]) == 0 {
            session.fail("the login asked for the password: no session was running")
        }
        session
    }
}

impl SshSession {
    /// Type the password at the prompt and wait for the shell.
    pub fn log_in(&mut self, password: &str) {
        self.read_until(PROMPT);
        self.type_line(password);
        self.read_until(SHELL_PROMPT);
    }

    /// The shell is the background session's and can make a named kernel object, which PSReadLine's
    /// history needs: DPAPI and a mutex work. Returns the pid of the shell's parent, the agent.
    pub fn check_relayed_shell(&mut self) -> u32 {
        self.type_line(
            "try { [void][Security.Cryptography.ProtectedData]::Protect([byte[]](1,2,3), $null, 'CurrentUser'); \
             Write-Output ('dpapi' + '-ok') } catch { Write-Output ('dpapi' + '-failed ' + $_) }",
        );
        if self.read_until_any(&["dpapi-ok", "dpapi-failed"]) != 0 {
            self.fail("the shell is not the session's (DPAPI failed)");
        }
        self.type_line(
            "try { [void][Threading.Mutex]::new($false, 'sbprobe' + $PID); Write-Output ('mutex' + '-ok') } \
             catch { Write-Output ('mutex' + '-failed ' + $_.Exception.GetType().Name) }",
        );
        if self.read_until_any(&["mutex-ok", "mutex-failed"]) != 0 {
            self.fail("a named mutex cannot be made in the relayed shell");
        }
        self.type_line("Write-Output ('parent-' + 'pid=' + (Get-Process -Id $PID).Parent.Id + ';do' + 'ne')");
        self.read_until(";done");
        let text = self.text();
        let after = text.rsplit("parent-pid=").next().unwrap_or_default();
        let digits: String = after.chars().take_while(char::is_ascii_digit).collect();
        digits
            .parse()
            .unwrap_or_else(|_| self.fail("the shell did not report its parent"))
    }

    /// PSReadLine crashes at every prompt when it cannot make its named mutex, and prints it on the
    /// console. Call after the last command, so every prompt of the session has been shown.
    pub fn assert_no_psreadline_crash(&self) {
        let text = self.text();
        if text.contains("Oops, something went wrong") || text.contains("PSReadLine") {
            self.fail("PSReadLine crashed in the relayed shell");
        }
    }

    /// A marker the shell prints but does not echo back as typed.
    pub fn say(&mut self, marker: &str) {
        let (head, tail) = marker.split_at(marker.len() / 2);
        self.type_line(&format!("Write-Output ('{head}' + '{tail}')"));
        self.read_until(marker);
    }

    pub fn leave(mut self) {
        self.assert_no_psreadline_crash();
        self.type_line("exit");
        let code = self.finish();
        assert_eq!(code, 0, "ssh exited with {code}");
    }
}
