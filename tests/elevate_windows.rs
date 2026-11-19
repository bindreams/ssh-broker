//! `ssh-broker elevate` through a real sshd. Windows only; **Elevated (CI only)**: each test makes a local account,
//! logs it in through the runner's sshd and starts its agent.
//!
//! An administrator's default session is unelevated, and its agent runs at High. `elevate <command>` typed in it
//! asks that agent, on `request.sock`, to run the command, which the session's login (`SSH_BROKER_ELEVATION`)
//! allows or not:
//!
//! - `never` refuses, and nothing runs;
//! - `auto-approve` runs the command with the agent's own token, elevated, whose output is the session's, with a
//!   terminal and without one;
//! - the default (`prompt`) asks the person at the terminal, which a later unit builds: until then it is refused
//!   with a sentence that says so;
//! - `always` runs it in place, in a session that is elevated already.
//!
//! What the person sees of the terminal while the command runs is the screen tests', not these.
#![cfg(windows)]

use ssh_broker::offer::text;
use ssh_broker::provision::canonical_exe;
use ssh_broker::provision::registry::{OPENSSH_KEY, set_default_shell_under};

#[path = "common/account.rs"]
mod account_fixture;
#[path = "common/agent_conn.rs"]
mod agent_conn;
#[path = "common/bounded_wait.rs"]
mod bounded_wait;
#[path = "common/child_entry.rs"]
mod child_entry;
#[path = "common/desktop.rs"]
mod desktop;
#[path = "common/drain.rs"]
mod drain;
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
#[path = "common/sshd_rig.rs"]
mod sshd_rig;
#[path = "common/stand_in.rs"]
mod stand_in;

use account_fixture::{Account, ServiceLogon};
use sshd_rig::{Login, SHELL_PROMPT, SshSession, no_shell_to_carry, run_client};
use stand_in::Kit;

/// What `whoami /groups` prints for a process at High, and for one that is not.
const HIGH: &str = r"Mandatory Label\High Mandatory Level";
const MEDIUM: &str = r"Mandatory Label\Medium Mandatory Level";

/// `elevate` refuses with 126.
const REFUSED: u32 = 126;

/// The exe the agent of a session started at the password prompt runs: the shim starts it from the installed exe,
/// not from its own copy in the kit (`shim_offer::run_offer`), so that is the image to look for.
fn agent_exe() -> std::path::PathBuf {
    canonical_exe()
}

/// An account whose agent a login at the password prompt has started (at High for an administrator), and the kit that
/// holds the shim sshd runs. The first login stays open: it is what keeps the account's session.
struct Started<'a> {
    kit: &'a Kit,
    login: Login<'a>,
    _first: SshSession,
}

impl<'a> Started<'a> {
    fn start(kit: &'a Kit, account: &'a Account) -> Started<'a> {
        let login = Login::new(kit, account);
        set_default_shell_under(OPENSSH_KEY, &kit.exe.to_string_lossy(), &no_shell_to_carry())
            .expect("set the shim as DefaultShell");
        let mut first = login.start();
        first.log_in(&account.password);
        Started {
            kit,
            login,
            _first: first,
        }
    }

    /// `ssh -T host -- "& '<exe>' elevate <tail>; exit $LASTEXITCODE"`, a login that asked for `asking` (`None`: it
    /// set nothing): a session without a terminal. The account's shell is PowerShell, which runs a quoted path only
    /// through its call operator; the exit is the elevated command's code, which PowerShell would otherwise make 0
    /// or 1.
    fn elevate_over_ssh(&self, asking: Option<&str>, tail: &str) -> sshd_rig::Outcome {
        let mut ssh = self.login.command_with(asking);
        ssh.arg("-T").arg("--").arg(format!(
            "& '{}' elevate {tail}; exit $LASTEXITCODE",
            self.kit.exe.display()
        ));
        run_client(ssh, false, self.kit.dir())
    }

    fn failure(&self, outcome: &sshd_rig::Outcome) -> String {
        format!(
            "exit {:?}\nstdout: {}\nstderr: {}\n{}",
            outcome.code,
            String::from_utf8_lossy(&outcome.stdout),
            outcome.stderr,
            (self.login.diagnostics())()
        )
    }
}

fn an_administrator(tag: &str) -> (Kit, Account, session_end::LogOutOnDrop) {
    account_fixture::assert_elevated();
    let kit = Kit::broker_with_helper(tag);
    let account = Account::create(tag, true);
    account.make_administrator();
    let end = session_end::LogOutOnDrop::new(&agent_exe(), &account, ServiceLogon::Sshd);
    (kit, account, end)
}

// What the login allows -----

/// Elevated (CI only). A login that asked for `never` is refused, with the sentence, exit 126, and the command
/// is not run: it would have made a file.
#[test]
fn never_refuses_elevate_and_nothing_runs() {
    let _machine = machine::exclusive();
    let (kit, account, _end) = an_administrator("elnv");
    let admin = Started::start(&kit, &account);

    let marker = kit.path("never-ran");
    let outcome = admin.elevate_over_ssh(Some("never"), &format!("cmd.exe /c copy NUL {}", marker.display()));
    assert_eq!(outcome.code, Some(REFUSED), "{}", admin.failure(&outcome));
    assert!(
        outcome.stderr.contains(text::elevation_never().trim_end()),
        "{}",
        admin.failure(&outcome)
    );
    assert!(!marker.exists(), "the command ran: {}", admin.failure(&outcome));
}

/// Elevated (CI only). `ssh host cmd` with `auto-approve`: the command runs elevated, with the agent's token, and
/// its output is on the channel, while the session that asked is not elevated.
#[test]
fn auto_approve_in_ssh_host_cmd_runs_whoami_elevated_with_its_output_on_the_channel() {
    let _machine = machine::exclusive();
    let (kit, account, _end) = an_administrator("elau");
    let admin = Started::start(&kit, &account);

    let elevated = admin.elevate_over_ssh(Some("auto-approve"), "whoami /groups");
    let shown = String::from_utf8_lossy(&elevated.stdout).into_owned();
    assert!(shown.contains(HIGH), "{}", admin.failure(&elevated));
    assert_eq!(elevated.code, Some(0), "{}", admin.failure(&elevated));

    // The same program in the session itself is the session's: unelevated.
    let mut ssh = admin.login.command_asking("auto-approve");
    ssh.arg("-T").arg("--").arg("whoami /groups");
    let plain = run_client(ssh, false, kit.dir());
    let plain_shown = String::from_utf8_lossy(&plain.stdout).into_owned();
    assert!(
        plain_shown.contains(MEDIUM) && !plain_shown.contains(HIGH),
        "{}",
        admin.failure(&plain)
    );
}

/// Elevated (CI only). With a terminal: the command runs elevated, its output reaches the person, and the session
/// answers the next line.
#[test]
fn auto_approve_with_a_terminal_runs_the_command_elevated_and_the_session_continues_after_it() {
    let _machine = machine::exclusive();
    let (kit, account, _end) = an_administrator("elwt");
    let admin = Started::start(&kit, &account);

    let mut session = SshSession::start(admin.login.command_asking("auto-approve"), admin.login.diagnostics());
    session.read_until(SHELL_PROMPT);
    session.type_line(&format!("& '{}' elevate cmd.exe /c whoami /groups", kit.exe.display()));
    session.read_until(HIGH);
    session.say("the-session-went-on");
    session.leave();
}

/// Elevated (CI only). The default login asks the person at the terminal, which a later unit builds: until then
/// `elevate` is refused with a sentence that says so, and the command does not run.
#[test]
fn elevate_with_prompt_is_refused_until_the_next_unit() {
    let _machine = machine::exclusive();
    let (kit, account, _end) = an_administrator("elpr");
    let admin = Started::start(&kit, &account);

    let marker = kit.path("prompt-ran");
    let outcome = admin.elevate_over_ssh(None, &format!("cmd.exe /c copy NUL {}", marker.display()));
    assert_eq!(outcome.code, Some(REFUSED), "{}", admin.failure(&outcome));
    assert!(
        outcome.stderr.contains(text::elevation_consent_not_built().trim_end()),
        "{}",
        admin.failure(&outcome)
    );
    assert!(!marker.exists(), "the command ran: {}", admin.failure(&outcome));
}

/// Elevated (CI only). The code `elevate` exits with is the command's.
#[test]
fn the_exit_code_of_the_elevated_command_is_the_codes_of_elevate() {
    let _machine = machine::exclusive();
    let (kit, account, _end) = an_administrator("elex");
    let admin = Started::start(&kit, &account);

    let outcome = admin.elevate_over_ssh(Some("auto-approve"), "cmd.exe /c exit 7");
    assert_eq!(outcome.code, Some(7), "{}", admin.failure(&outcome));
}

/// Elevated (CI only). A login that asked for `always` is at High already: `elevate` runs the command in place and
/// asks nobody (a request to the agent would be refused: that session is elevated).
#[test]
fn always_runs_elevate_in_place_and_asks_nothing() {
    let _machine = machine::exclusive();
    let (kit, account, _end) = an_administrator("elal");
    let admin = Started::start(&kit, &account);

    let outcome = admin.elevate_over_ssh(Some("always"), "whoami /groups");
    let shown = String::from_utf8_lossy(&outcome.stdout).into_owned();
    assert!(shown.contains(HIGH), "{}", admin.failure(&outcome));
    assert_eq!(outcome.code, Some(0), "{}", admin.failure(&outcome));
    assert!(
        !outcome.stderr.contains(text::elevation_already_elevated().trim_end()),
        "the agent was asked: {}",
        admin.failure(&outcome)
    );
}

// Where it is refused -----

/// Elevated (CI only). A shell that is not under ssh-broker (no agent: the shim runs the command itself) has no
/// session id: `elevate` says it is not hosted.
#[test]
fn elevate_in_the_failopen_shell_is_refused_not_hosted() {
    let _machine = machine::exclusive();
    account_fixture::assert_elevated();
    let kit = Kit::broker_with_helper("elfo");
    let account = Account::create("elfo", true);
    let _end = session_end::LogOutOnDrop::new(&agent_exe(), &account, ServiceLogon::Sshd);
    let login = Login::new(&kit, &account);
    set_default_shell_under(OPENSSH_KEY, &kit.exe.to_string_lossy(), &no_shell_to_carry())
        .expect("set the shim as DefaultShell");

    // No login has started this account's agent, and a command is never offered a password prompt.
    let mut ssh = login.command();
    ssh.arg("-T")
        .arg("--")
        .arg(format!("& '{}' elevate whoami; exit $LASTEXITCODE", kit.exe.display()));
    let outcome = run_client(ssh, false, kit.dir());
    assert_eq!(outcome.code, Some(REFUSED), "{:?}\n{}", outcome.code, outcome.stderr);
    assert!(
        outcome.stderr.contains(text::elevation_not_hosted().trim_end()),
        "{}",
        outcome.stderr
    );
}

/// Elevated (CI only). A standard account's agent runs below High and keeps no request socket: `elevate` says
/// that, with exit 126.
#[test]
fn a_standard_accounts_elevate_is_refused_naming_why() {
    let _machine = machine::exclusive();
    account_fixture::assert_elevated();
    let kit = Kit::broker_with_helper("elst");
    let account = Account::create("elst", true);
    let _end = session_end::LogOutOnDrop::new(&agent_exe(), &account, ServiceLogon::Sshd);
    let admin = Started::start(&kit, &account);

    let outcome = admin.elevate_over_ssh(Some("auto-approve"), "whoami");
    assert_eq!(outcome.code, Some(REFUSED), "{}", admin.failure(&outcome));
    assert!(
        outcome.stderr.contains(text::elevation_needs_high_agent().trim_end()),
        "{}",
        admin.failure(&outcome)
    );
}
