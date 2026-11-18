//! The prompt path through the runner's real `sshd`: the product's actual path (M8). Windows only;
//! **Elevated (CI only)**.
//!
//! sshd starts the shim as the `DefaultShell` of a throwaway standard account that has no session; the
//! shim prompts, the password logs the account on, and the login relays into the new background
//! session. Before that, the same account logs in once with a probe as the `DefaultShell`, which
//! records the session, the logon type and the job the shim runs in under sshd.
//!
//! The level a login asks for (`SSH_BROKER_ELEVATION`) is tried here too, as a standard account (the first test), an
//! administrator and a Backup Operators account, over the same sshd (the tests at the end).
//!
//! This machine is the runner's: the test changes sshd's `DefaultShell` and adds the account to the
//! group `sshd_config` allows. The runner is discarded after the job, so neither is put back.
#![cfg(windows)]

use std::process::Stdio;

use ssh_broker::autologin;
use ssh_broker::provision::procwait;
use ssh_broker::provision::registry::{OPENSSH_KEY, set_default_shell_under};
use ssh_broker::socket_loc::{self, Integrity};

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
#[path = "common/whoami_groups.rs"]
mod whoami_groups;

use account_fixture::{Account, ServiceLogon};
use agent_conn::local_account;
use sshd_rig::{
    Login, Outcome, PROMPT, SHELL_PROMPT, SshSession, no_shell_to_carry, run_client, screen_text, set_stock_shell,
};
use stand_in::Kit;
use whoami_groups::{TokenShown, token_shown};

/// Elevated (CI only). M8: the shim as sshd's `DefaultShell`, for an account with no session. Beyond
/// the login: the relayed shell can make a named mutex and PSReadLine does not crash in it (the
/// prompt-path tests run their shims in the runner's session, where another user's token can make
/// none); a second connection while the first is open uses the same agent; and the session is still
/// there for a third after every connection has gone (the agent is not in sshd's job). A login that sets no
/// variable gets this standard account the token its own command has, `always` is refused naming the variable
/// (the account's agent is below High), also with a blank command, and `internal-unelevated` is an ordinary command. Last, two first
/// connections of another new account at once.
#[test]
fn prompt_path_through_real_sshd() {
    // Exclusive: `Login::new` rewrites sshd's configuration and restarts it ([`accept_elevation_variable`]).
    let _machine = machine::exclusive();
    account_fixture::assert_elevated();
    let kit = Kit::broker_with_helper("sshd");
    let account = Account::create("sshd", true);
    // The session is ended with `logout` before the account goes, passing or failing; a logout that
    // fails fails a passing test (see `session_end`).
    let _end = session_end::LogOutOnDrop::new(&kit.exe, &account, ServiceLogon::Sshd);
    let login = Login::new(&kit, &account);

    // 1. What the shim runs in under sshd: the probe is the DefaultShell for one command.
    set_default_shell_under(OPENSSH_KEY, &kit.helper.to_string_lossy(), &no_shell_to_carry())
        .expect("set the probe as DefaultShell");
    let mut probe = login.command();
    let out = probe.arg("probe").stdin(Stdio::null()).output().expect("run ssh");
    let facts = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success() && facts.contains("session="),
        "the probe did not run through sshd (exit {:?}); stdout:\n{facts}\n{}",
        out.status.code(),
        (login.diagnostics())()
    );
    eprintln!("M8 the shim's environment under sshd (session, logon type, job):\n{facts}");

    // 2. The product's path: the shim is the DefaultShell, the account has no session.
    set_default_shell_under(OPENSSH_KEY, &kit.exe.to_string_lossy(), &no_shell_to_carry())
        .expect("set the shim as DefaultShell");
    let mut first = login.start();
    first.log_in(&account.password);
    first.type_line("Write-Output ('profile=' + $env:USERPROFILE + '.')");
    first.read_until(&format!("profile={}.", account.profile().display()));
    first.type_line("Write-Output ('session-id=' + (Get-Process -Id $PID).SessionId + '.')");
    first.read_until("session-id=");
    let agent = first.check_relayed_shell();
    eprintln!("M8 the relayed session showed:\n{}", first.text());

    // A login that sets no variable, for an account below High: the agent serves it, at the token the account's
    // own command has. `always` cannot be given there and is refused, naming the variable. The word is a
    // program like any other.
    assert_eq!(
        token_of_command(&kit, &login, None, "whoami /groups", Server::Agent),
        TokenShown::new("Medium", "absent"),
        "the ordinary account's own command"
    );
    // A blank command (one space, as `fail_open_windows` sends it) is refused too, not ended with exit 0.
    for remote in ["whoami /groups", " "] {
        assert_refused_naming_the_variable(
            &kit,
            &login,
            "always",
            remote,
            ssh_broker::offer::text::ALWAYS_BELOW_HIGH_WHAT,
        );
    }
    assert_the_old_word_is_an_ordinary_command(&kit, &login);

    // 3. A second connection while the first is open: no prompt, the same agent.
    let mut second = login.start_into_running_session();
    assert_eq!(
        second.check_relayed_shell(),
        agent,
        "the second connection's shell is not a child of the first one's agent"
    );

    // 4. The first one leaves; the second still has its session.
    first.leave();
    second.say("second-still-up");
    second.leave();

    // 5. Every connection has gone and the session is still running: a new login gets no password prompt.
    let mut third = login.start_into_running_session();
    assert_eq!(
        third.check_relayed_shell(),
        agent,
        "the third connection found another agent"
    );
    third.leave();

    // 6. Two first connections of another new account at once.
    two_simultaneous_first_connections(&kit);
}

/// Two first connections of one new account through sshd at once, with the shim as `DefaultShell`: each
/// prompts and logs on, both end in the same session's shell, neither hangs, and the session outlives both.
fn two_simultaneous_first_connections(kit: &Kit) {
    let account = Account::create("sshd2", true);
    let _end = session_end::LogOutOnDrop::new(&kit.exe, &account, ServiceLogon::Sshd);
    let login = Login::new(kit, &account);

    let mut sessions = [login.start(), login.start()];
    for session in &mut sessions {
        session.read_until(PROMPT);
    }
    for session in &mut sessions {
        session.type_line(&account.password);
    }
    let mut agents = Vec::new();
    for session in &mut sessions {
        session.read_until(SHELL_PROMPT);
        agents.push(session.check_relayed_shell());
    }
    assert_eq!(agents[0], agents[1], "the two shells have different agents");
    let [first, second] = sessions;
    first.leave();
    second.leave();

    let mut third = login.start_into_running_session();
    assert_eq!(
        third.check_relayed_shell(),
        agents[0],
        "the third connection found another agent"
    );
    third.leave();
}

// What the level a login asks for gives, through the real sshd =====

/// Who ran a login's session. A token shown is no proof of it: the shim's fail-open shell steps down to the same
/// tokens the agent does.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Server {
    /// The agent served it: the shim relayed the session.
    Agent,
    /// The shim ran it itself, having failed open.
    Shim,
    /// sshd ran the shell: the broker is not the `DefaultShell`.
    Sshd,
}

/// The sessions the shim has run itself so far, by the log in the account's folder (flushed when the shim exits).
/// A session with a terminal has no stderr to say it on.
fn ran_by_shim(account: &Account) -> usize {
    let location = account.socket_location();
    stand_in::read_logs(&location)
        .matches(&ssh_broker::shim_pty::unavailable_message(None))
        .count()
}

/// Fail unless `said_unavailable` (the shim's line "agent unavailable", read from the client's stderr or, with a
/// terminal, from the log) is true exactly when `server` is the shim.
fn assert_served_by(server: Server, remote: &str, said_unavailable: bool, outcome: &Outcome, login: &Login<'_>) {
    assert_eq!(
        said_unavailable,
        server == Server::Shim,
        "`{remote}`: {}\nstderr:\n{}\n{}",
        match server {
            Server::Agent => "the shim ran the session itself, not through the agent",
            Server::Shim => "the agent served a session that was to fail open",
            Server::Sshd => "the shim ran a session that sshd was to run alone",
        },
        outcome.stderr,
        (login.diagnostics())()
    );
}

/// `ssh -T host -- remote` with the level `asking` names (none: the client sets no variable), run to its end: the
/// outcome and its stdout, once `server` is shown to be what served it. The exit code is the caller's to judge.
fn run_command_through_sshd(
    kit: &Kit,
    login: &Login<'_>,
    asking: Option<&str>,
    remote: &str,
    server: Server,
) -> (Outcome, String) {
    let mut ssh = login.command_with(asking);
    ssh.arg("-T").arg("--").arg(remote);
    let outcome = run_client(ssh, false, kit.dir());
    let shown = String::from_utf8_lossy(&outcome.stdout).into_owned();
    // Kept in the log of a test that fails on what it showed: the raw output and the shim's own words.
    eprintln!("`{remote}` showed:\n{shown}\nstderr of the client:\n{}", outcome.stderr);
    let said = outcome
        .stderr
        .contains(&ssh_broker::shim_pty::unavailable_message(None));
    assert_served_by(server, remote, said, &outcome, login);
    (outcome, shown)
}

/// `ssh -T host -- remote` asking `asking`, run to its end: the token `remote` (a `whoami /groups`) was started
/// with, by `server`.
fn token_of_command(kit: &Kit, login: &Login<'_>, asking: Option<&str>, remote: &str, server: Server) -> TokenShown {
    let (outcome, shown) = run_command_through_sshd(kit, login, asking, remote, server);
    assert!(
        outcome.code == Some(0),
        "`{remote}` did not run through sshd (exit {:?}); stdout:\n{shown}\nstderr:\n{}\n{}",
        outcome.code,
        outcome.stderr,
        (login.diagnostics())()
    );
    token_shown(&shown)
}

/// `ssh -tt host -- remote` asking `asking`, run to its end: the token `remote` (a `whoami /groups`) was started
/// with, by `server`, read from what the terminal showed.
fn token_of_command_with_terminal(
    kit: &Kit,
    login: &Login<'_>,
    asking: Option<&str>,
    remote: &str,
    server: Server,
) -> TokenShown {
    let mut ssh = login.command_with(asking);
    ssh.arg("-tt").arg("--").arg(remote);
    let before = ran_by_shim(login.account);
    let outcome = run_client(ssh, true, kit.dir());
    let shown = screen_text(&outcome.stdout);
    assert!(
        outcome.code == Some(0),
        "`{remote}` with a terminal did not run through sshd (exit {:?}); the terminal showed:\n{shown}\nstderr:\n{}\n{}",
        outcome.code,
        outcome.stderr,
        (login.diagnostics())()
    );
    eprintln!(
        "`{remote}` with a terminal showed:\n{shown}\nstderr of the client:\n{}",
        outcome.stderr
    );
    let said = ran_by_shim(login.account) > before;
    assert_served_by(server, remote, said, &outcome, login);
    token_shown(&shown)
}

/// What a PowerShell session of the agent says of its own token, typed as a line: `wg-label=<label>
/// wg-admin=<state>;`. The markers are joined by the shell so that the echo of the typed line does not hold them.
/// The shell is first shown to be the agent's ([`SshSession::check_relayed_shell`]): a session of the shim's own
/// has no DPAPI.
fn token_of_shell(session: &mut SshSession) -> TokenShown {
    session.check_relayed_shell();
    session.type_line(
        r#"$g = (whoami /groups | Out-String); $a = if ($g -match 'S-1-5-32-544\s+(Mandatory group, Enabled by default, Enabled group|Group used for deny only)') { if ($Matches[1] -like 'Group*') { 'deny-only' } else { 'enabled' } } else { 'absent' }; Write-Output ('wg' + '-label=' + [regex]::Match($g, 'Mandatory Label\\(\w+) Mandatory Level').Groups[1].Value + ' wg' + '-admin=' + $a + ';')"#,
    );
    session.read_until_any(&["wg-admin=enabled;", "wg-admin=deny-only;", "wg-admin=absent;"]);
    let text = session.text();
    eprintln!("the shell said of its token:\n{text}");
    let at = text.rfind("wg-label=").expect("the label was printed");
    let line = text[at..].split(';').next().unwrap();
    let (label, administrators) = line.split_once(" wg-admin=").expect("the line has both parts");
    TokenShown {
        label: label.trim_start_matches("wg-label=").to_owned(),
        administrators: match administrators {
            "enabled" => "enabled",
            "deny-only" => "deny-only",
            _ => "absent",
        },
    }
}

/// `ssh -T host -- remote` asking `asking` where the login is refused before anything runs: exit 255 and nothing
/// on stdout, and a sentence on stderr that names the variable.
fn assert_refused_naming_the_variable(kit: &Kit, login: &Login<'_>, asking: &str, remote: &str, said: &str) {
    let (outcome, shown) = run_command_through_sshd(kit, login, Some(asking), remote, Server::Agent);
    assert_eq!(
        outcome.code,
        Some(255),
        "`{remote}` asking {asking:?}: stdout:\n{shown}\nstderr:\n{}",
        outcome.stderr
    );
    assert!(shown.trim().is_empty(), "`{remote}` asking {asking:?} ran: {shown}");
    assert!(
        outcome.stderr.contains(said) && outcome.stderr.contains("SSH_BROKER_ELEVATION"),
        "`{remote}` asking {asking:?}: the sentence is missing from stderr:\n{}",
        outcome.stderr
    );
}

/// `ssh host internal-unelevated whoami /groups`: the word is a program like any other. The shell runs a
/// program of that name and fails as it does for one that is not there, and no token is shown.
fn assert_the_old_word_is_an_ordinary_command(kit: &Kit, login: &Login<'_>) {
    let (outcome, shown) =
        run_command_through_sshd(kit, login, None, "internal-unelevated whoami /groups", Server::Agent);
    let said = format!("{shown}{}", outcome.stderr);
    assert_ne!(
        outcome.code,
        Some(0),
        "the old word ran as a command that succeeds:\n{said}"
    );
    assert!(
        !shown.contains("Mandatory Label"),
        "the old word was read and `whoami /groups` ran:\n{shown}"
    );
    assert!(
        said.contains("internal-unelevated"),
        "the shell did not name the program it could not run:\n{said}"
    );
}

/// A value that is not one of the four words fails the login with the sentence that names it, exit 255, and the
/// command does not run: its side effect (a file in the kit's folder) is absent, and is there for the control, a
/// login that sets no variable.
fn assert_unknown_value_runs_nothing(kit: &Kit, login: &Login<'_>, value: &str) {
    let marker = kit.path(&format!("ran-{}.txt", value.to_ascii_lowercase()));
    let remote = format!("Set-Content -Path '{}' -Value ran", marker.display());
    let _ = std::fs::remove_file(&marker);

    let (outcome, shown) = run_command_through_sshd(kit, login, Some(value), &remote, Server::Agent);
    assert_eq!(
        outcome.code,
        Some(255),
        "asking {value:?}: stdout:\n{shown}\nstderr:\n{}",
        outcome.stderr
    );
    assert!(
        outcome
            .stderr
            .contains(&ssh_broker::offer::text::unknown_elevation(value)),
        "asking {value:?}: the sentence is missing from stderr:\n{}",
        outcome.stderr
    );
    assert!(!marker.exists(), "asking {value:?}: the command ran");

    let (control, _) = run_command_through_sshd(kit, login, None, &remote, Server::Agent);
    assert_eq!(control.code, Some(0), "control: {}", control.stderr);
    assert!(marker.exists(), "control: the command did not run");
    let _ = std::fs::remove_file(&marker);
}

/// Elevated (CI only). An administrator's SSH session through the brokered agent is unelevated unless the login
/// asks for `always`: with no variable, and with `never`, `prompt` and `auto-approve`, for a command, with and
/// without a terminal, and for a shell; `always` gives the elevated session in each of those. A value that is not
/// one of the four words fails the login and runs nothing. The administrator's key is in the administrators'
/// file (see `sshd_rig::install_key`).
#[test]
fn an_administrators_session_through_real_sshd_is_unelevated_unless_the_login_asks_for_always() {
    let _machine = machine::exclusive();
    account_fixture::assert_elevated();
    let kit = Kit::broker_with_helper("sshw");
    let account = Account::create("sshw", true);
    account.make_administrator();
    // The session started at the password prompt is ended with `logout` before the account goes.
    let _end = session_end::LogOutOnDrop::new(&kit.exe, &account, ServiceLogon::Sshd);
    let login = Login::new(&kit, &account);

    set_default_shell_under(OPENSSH_KEY, &kit.exe.to_string_lossy(), &no_shell_to_carry())
        .expect("set the shim as DefaultShell");
    let elevated = TokenShown::new("High", "enabled");
    let unelevated = TokenShown::new("Medium", "deny-only");
    // The account's session, started at the password prompt; it stays up for the sessions below. A login that sets
    // no variable gets an unelevated shell, as a desktop's ordinary PowerShell is.
    let mut first = login.start();
    first.log_in(&account.password);
    assert_eq!(
        token_of_shell(&mut first),
        unelevated,
        "the login's own shell is not unelevated"
    );
    for asking in [None, Some("never"), Some("prompt"), Some("auto-approve")] {
        assert_eq!(
            token_of_command(&kit, &login, asking, "whoami /groups", Server::Agent),
            unelevated,
            "asking {asking:?}"
        );
    }
    assert_eq!(
        token_of_command_with_terminal(&kit, &login, None, "whoami /groups", Server::Agent),
        unelevated,
        "no variable, with a terminal"
    );
    assert_eq!(
        token_of_command(&kit, &login, Some("always"), "whoami /groups", Server::Agent),
        elevated,
        "always"
    );
    assert_eq!(
        token_of_command_with_terminal(&kit, &login, Some("always"), "whoami /groups", Server::Agent),
        elevated,
        "always, with a terminal"
    );
    let mut shell = SshSession::start(login.command_asking("always"), login.diagnostics());
    shell.read_until(SHELL_PROMPT);
    assert_eq!(
        token_of_shell(&mut shell),
        elevated,
        "ssh -tt -o SetEnv=SSH_BROKER_ELEVATION=always host"
    );
    shell.leave();

    for value in ["Always", "sometimes"] {
        assert_unknown_value_runs_nothing(&kit, &login, value);
    }
    assert_the_old_word_is_an_ordinary_command(&kit, &login);

    // A terminal session whose configured shell cannot start gets the `console-fallback` verb's shell, which is
    // started with the same token.
    let broken = kit.path("not-a-program.exe");
    std::fs::write(&broken, "this is not a program").unwrap();
    account.write_user_config(&format!("shell: '{}'\n", broken.display()));
    assert_eq!(
        token_of_command_with_terminal(&kit, &login, None, "whoami /groups", Server::Agent),
        unelevated,
        "through the console-fallback verb"
    );
    assert_eq!(
        token_of_command_with_terminal(&kit, &login, Some("always"), "whoami /groups", Server::Agent),
        elevated,
        "control: the verb's shell is elevated when the login asks for always"
    );

    first.leave();
}

/// Elevated (CI only). With no agent running, the fail-open shell of a login that sets no variable is the
/// unelevated one, and one that asks for `always` is the elevated one sshd gave the shim.
#[test]
fn an_administrators_fail_open_shell_follows_the_same_rule() {
    let _machine = machine::exclusive();
    account_fixture::assert_elevated();
    let kit = Kit::broker_with_helper("sshf");
    let account = Account::create("sshf", true);
    account.make_administrator();
    // A shell that is there and not the broker's: with no agent, a command session is not offered one.
    account.write_user_config("shell: cmd.exe\n");
    // sshd's logon keeps the account's hive loaded, so the account is declared as logged on by sshd, which is how
    // `Account::drop` deletes the profile; there is no agent to end (see `session_end`).
    account.started_by(ServiceLogon::Sshd);
    let login = Login::new(&kit, &account);
    set_default_shell_under(OPENSSH_KEY, &kit.exe.to_string_lossy(), &no_shell_to_carry())
        .expect("set the shim as DefaultShell");

    assert_eq!(
        token_of_command(&kit, &login, None, "whoami /groups", Server::Shim),
        TokenShown::new("Medium", "deny-only"),
        "no variable, no agent"
    );
    assert_eq!(
        token_of_command(&kit, &login, Some("always"), "whoami /groups", Server::Shim),
        TokenShown::new("High", "enabled"),
        "always, no agent"
    );
}

/// The levels of the folders the broker keeps, High first: where an agent of an account may be looked for.
const LEVELS: [Integrity; 2] = [Integrity::High, Integrity::Medium];

/// The ids of the agents `account` has running from `kit`'s exe at `level`.
fn agents_at(kit: &Kit, account: &Account, level: Integrity) -> Vec<u32> {
    procwait::user_agents(&kit.exe, &account.sid, level)
        .unwrap_or_else(|e| panic!("look for the agents of {}: {e:#}", account.name))
        .into_iter()
        .map(|agent| agent.pid)
        .collect()
}

/// The ids of the agents `account` has running from `kit`'s exe, at either level.
fn agents_of(kit: &Kit, account: &Account) -> Vec<u32> {
    LEVELS
        .into_iter()
        .flat_map(|level| agents_at(kit, account, level))
        .collect()
}

/// What the agent of `account` logged in the folder of each level: for a failure message.
fn logs_of_both_levels(account: &Account) -> String {
    LEVELS
        .into_iter()
        .map(|level| {
            let location =
                socket_loc::for_profile(account.profile(), level).expect("the account's profile path is short enough");
            format!(
                "{level:?} folder {}:\n{}",
                location.dir().display(),
                stand_in::read_logs(&location)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// `text` without its whitespace: a sentence the console wrapped, or one that has runs of blanks in it, is found whole.
fn squeezed(text: &str) -> String {
    text.split_whitespace().collect()
}

/// Elevated (CI only). An account in Backup Operators and not in Administrators gets a High logon from sshd,
/// so the level, not the group, decides what the broker gives it: the shell is High (a); the password prompt
/// states the `SeImpersonatePrivilege` limit and starts no agent (b); the account's agent started by
/// `auto-login` serves an SSH login at High when it asks for `always`, and gives Medium when it asks nothing (c).
///
/// Every wait is on an event of the session. Where the outcome could be "never" the test asserts first: the
/// started agent's level against the folder the shim looks in, before the wait for it to serve at that level.
#[test]
fn a_backup_operators_account_gets_the_stated_limit_at_the_prompt_and_is_served_by_its_agent() {
    let _machine = machine::exclusive();
    account_fixture::assert_elevated();
    let kit = Kit::broker_with_helper("sshb");
    let account = Account::create("sshb", true);
    // Not an administrator, and not granted the batch-logon right or anything else: what sshd and the prompt
    // do with it is what Windows gives its group. Its sessions are at High (see `Account::integrity`).
    account.make_backup_operator();
    // The session (c) starts, a Task Scheduler logon, is ended with `logout` before the account goes, passing or
    // failing.
    let _end = session_end::LogOutOnDrop::new(&kit.exe, &account, ServiceLogon::TaskScheduler);
    let login = Login::new(&kit, &account);

    // (a) What the plain shell gets: stock sshd with cmd.exe as the shell.
    let system_root = std::env::var("SystemRoot").expect("SystemRoot is set");
    set_stock_shell(&std::path::Path::new(&system_root).join(r"System32\cmd.exe"));
    let plain = token_of_command(&kit, &login, None, "whoami /groups", Server::Sshd);
    eprintln!("what sshd gives the plain shell of a Backup Operators account that is not an administrator: {plain:?}");
    assert_eq!(
        plain,
        TokenShown::new("High", "absent"),
        "sshd gave this account a token that is not High without Administrators: the plan's premise does not hold on this machine, which is a finding to report, not a failure of the broker"
    );

    // (b) The prompt, through the broker as the DefaultShell. The wait for the plain shell ends the same way
    // whether or not an agent started: a started agent serves a shell with the same prompt, and the sentence
    // is what tells them apart.
    set_default_shell_under(OPENSSH_KEY, &kit.exe.to_string_lossy(), &no_shell_to_carry())
        .expect("set the shim as DefaultShell");
    let mut prompted = login.start();
    prompted.log_in(&account.password);
    let shown = squeezed(&screen_text(&prompted.transcript));
    let sentence = squeezed(&ssh_broker::offer::text::impersonate_right_missing(&account.name));
    assert!(
        shown.contains(&sentence),
        "the shim did not say that this login cannot start an elevated session from a password: the stated limit does not hold (an agent was started, or the logon failed for another reason). The session showed:
{}",
        prompted.text()
    );
    prompted.type_line("exit");
    prompted.finish();
    let running = agents_of(&kit, &account);
    assert!(
        running.is_empty(),
        "agents of the account run after the prompt said it could start none (pids {running:?}): the stated limit does not hold"
    );

    // (c) The account's agent, started the way the product starts one for an account with a stored password:
    // the boot task of `auto-login` (a start by this test process, as another account, is one the product never
    // makes). Backup Operators hold "Log on as a batch job" by default, so the account is granted nothing.
    autologin::on(&mut kit.autologin_env(&account.password), &local_account(&account)).unwrap_or_else(|e| {
        panic!(
            "`auto-login on` for the Backup Operators account failed: {e:#}\nBackup Operators hold \"Log on as a batch \
             job\" by default: if this says the right is missing, that is a finding to report"
        )
    });
    // The agent's level is read before anything waits for it to serve at the level the shim looks in: an agent
    // at the other level never serves the login. The wait for the first marker, in either folder, fails after its
    // bound both when the agent never listens and when it ends before it listens (no handle is held on a task's
    // agent, so its exit does not end the wait); the message then carries what the agent logged, in both folders.
    let expected = account.integrity();
    let locations = LEVELS.map(|level| {
        socket_loc::for_profile(account.profile(), level).expect("the account's profile path is short enough")
    });
    if let Err(failed) = session_end::attempt("wait for the account's agent to serve", || {
        stand_in::wait_for_serving_marker_in_any_of(&[&locations[0], &locations[1]], stand_in::SERVING_BOUND)
    }) {
        panic!("{failed}\n{}", logs_of_both_levels(&account));
    }
    if agents_at(&kit, &account, expected).is_empty() {
        let other = LEVELS.into_iter().find(|level| *level != expected).unwrap();
        let why = if agents_at(&kit, &account, other).is_empty() {
            "the account's agent wrote its serving marker and is not running at either level".to_owned()
        } else {
            format!(
                "the boot task's agent of such an account is not at the level sshd gives its logins ({expected:?}; \
                 it runs at {other:?}), so `auto-login` does not serve them: a finding to report"
            )
        };
        panic!("{why}\n{}", logs_of_both_levels(&account));
    }

    assert_eq!(
        token_of_command(&kit, &login, Some("always"), "whoami /groups", Server::Agent).label,
        "High",
        "the login served by the agent is not at the level sshd gave"
    );
    assert_eq!(
        token_of_command(&kit, &login, None, "whoami /groups", Server::Agent),
        TokenShown::new("Medium", "absent"),
        "a login that sets no variable"
    );

    session_end::log_out_running(&kit.exe, &account, ServiceLogon::TaskScheduler);
    autologin::off(&mut kit.autologin_env(&account.password), &local_account(&account)).unwrap();
}
