//! What `tests/elevate_windows.rs` and `tests/consent_windows.rs` share: an administrator whose agent a login at the
//! password prompt has started (at High), and the ways to run `ssh-broker elevate` in its sessions through the
//! runner's sshd. **Elevated (CI only).**
//!
//! The including test crate declares the modules this one uses, at its root: `account_fixture`, `session_end`,
//! `sshd_rig` and `stand_in`.
#![allow(dead_code)]

use ssh_broker::provision::canonical_exe;
use ssh_broker::provision::registry::{OPENSSH_KEY, set_default_shell_under};
use ssh_broker::socket_loc::{self, Integrity, SocketLocation};

use crate::account_fixture::{self, Account, ServiceLogon};
use crate::session_end;
use crate::sshd_rig::{self, Login, SHELL_PROMPT, SshSession, no_shell_to_carry, run_client};
use crate::stand_in::{self, Kit};

/// What `whoami /groups` prints for a process at High.
pub const HIGH: &str = r"Mandatory Label\High Mandatory Level";

/// Rows of history a rendering keeps.
pub const SCROLLBACK: usize = 2000;

/// `elevate` refuses with 126.
pub const REFUSED: u32 = 126;

/// The exe the agent of a session started at the password prompt runs: the shim starts it from the installed exe,
/// not from its own copy in the kit (`shim_offer::run_offer`), so that is the image to look for.
pub fn agent_exe() -> std::path::PathBuf {
    canonical_exe()
}

/// An account whose agent a login at the password prompt has started (at High for an administrator), and the kit that
/// holds the shim sshd runs. The first login stays open: it is what keeps the account's session.
pub struct Started<'a> {
    pub kit: &'a Kit,
    pub account: &'a Account,
    pub login: Login<'a>,
    _first: SshSession,
}

impl<'a> Started<'a> {
    pub fn start(kit: &'a Kit, account: &'a Account) -> Started<'a> {
        let login = Login::new(kit, account);
        set_default_shell_under(OPENSSH_KEY, &kit.exe.to_string_lossy(), &no_shell_to_carry())
            .expect("set the shim as DefaultShell");
        let mut first = login.start();
        first.log_in(&account.password);
        Started {
            kit,
            account,
            login,
            _first: first,
        }
    }

    /// `ssh -T host -- "& '<exe>' elevate <tail>; exit $LASTEXITCODE"`, a login that asked for `asking` (`None`: it
    /// set nothing): a session without a terminal. The account's shell is PowerShell, which runs a quoted path only
    /// through its call operator; the exit is the elevated command's code, which PowerShell would otherwise make 0
    /// or 1.
    pub fn elevate_over_ssh(&self, asking: Option<&str>, tail: &str) -> sshd_rig::Outcome {
        self.elevate_over_ssh_after(asking, "", tail)
    }

    /// [`Started::elevate_over_ssh`] after the PowerShell statements `before` (each ending in `;`) have run in the
    /// session.
    pub fn elevate_over_ssh_after(&self, asking: Option<&str>, before: &str, tail: &str) -> sshd_rig::Outcome {
        let mut ssh = self.login.command_with(asking);
        ssh.arg("-T").arg("--").arg(format!(
            "{before}& '{}' elevate {tail}; exit $LASTEXITCODE",
            self.kit.exe.display()
        ));
        run_client(ssh, false, self.kit.dir())
    }

    /// What explains a failure: what the account's agent and shim logged, in both of its folders, first (the
    /// login's own evidence is long), then the login's.
    pub fn diagnostics(&self) -> impl Fn() -> String + 'static {
        let logs: Vec<SocketLocation> = [Integrity::High, Integrity::Medium]
            .into_iter()
            .filter_map(|integrity| socket_loc::for_profile(self.account.try_profile()?, integrity).ok())
            .collect();
        let login = self.login.diagnostics();
        move || {
            let mut report = String::new();
            for location in &logs {
                report += &format!(
                    "--- the logs in {} ---\n{}\n",
                    location.logs_dir().display(),
                    stand_in::read_logs(location)
                );
            }
            report + &login()
        }
    }

    /// `outcome`, with its stdout a second time as bytes (a terminal's escape codes do not show otherwise), and
    /// [`Started::diagnostics`].
    pub fn failure(&self, outcome: &sshd_rig::Outcome) -> String {
        let stdout = String::from_utf8_lossy(&outcome.stdout);
        format!(
            "exit {:?}\nstdout: {stdout}\nstdout, escaped: {stdout:?}\nstderr: {}\n{}",
            outcome.code,
            outcome.stderr,
            (self.diagnostics())()
        )
    }

    /// A session with a terminal whose login asked for `auto-approve`, past its first prompt. `sbk` is an alias of
    /// the broker's exe in it, so that a typed `elevate` line is short enough not to wrap on the screen.
    pub fn terminal_session(&self) -> SshSession {
        self.terminal_session_asking(Some("auto-approve"))
    }

    /// [`Started::terminal_session`] for a login that asked for `asking` (`None`: it set nothing, which is the level
    /// that asks the person at the terminal).
    pub fn terminal_session_asking(&self, asking: Option<&str>) -> SshSession {
        let mut session = SshSession::start(self.login.command_with(asking), self.diagnostics());
        session.read_until(SHELL_PROMPT);
        session.type_line(&format!("Set-Alias sbk '{}'", self.kit.exe.display()));
        session.say("ALIAS-IS-SET");
        session
    }
}

pub fn an_administrator(tag: &str) -> (Kit, Account, session_end::LogOutOnDrop) {
    account_fixture::assert_elevated();
    let kit = Kit::broker_with_helper(tag);
    let account = Account::create(tag, true);
    account.make_administrator();
    let end = session_end::LogOutOnDrop::new(&agent_exe(), &account, ServiceLogon::Sshd);
    (kit, account, end)
}
