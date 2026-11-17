//! The prompt path through the runner's real `sshd`: the product's actual path (M8). Windows only;
//! **Elevated (CI only)**.
//!
//! sshd starts the shim as the `DefaultShell` of a throwaway standard account that has no session; the
//! shim prompts, the password logs the account on, and the login relays into the new background
//! session. Before that, the same account logs in once with a probe as the `DefaultShell`, which
//! records the session, the logon type and the job the shim runs in under sshd.
//!
//! The word `internal-unelevated` is tried here too, as an administrator and as a Backup Operators account, over the
//! same sshd (the tests at the end).
//!
//! This machine is the runner's: the test changes sshd's `DefaultShell` and adds the account to the
//! group `sshd_config` allows. The runner is discarded after the job, so neither is put back.
#![cfg(windows)]

use std::process::Stdio;

use ssh_broker::provision::registry::{OPENSSH_KEY, set_default_shell_under};

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
use sshd_rig::{Login, PROMPT, SHELL_PROMPT, SshSession, no_shell_to_carry, run_client, screen_text, set_stock_shell};
use stand_in::Kit;
use whoami_groups::{TokenShown, token_shown};

/// Elevated (CI only). M8: the shim as sshd's `DefaultShell`, for an account with no session. Beyond
/// the login: the relayed shell can make a named mutex and PSReadLine does not crash in it (the
/// prompt-path tests run their shims in the runner's session, where another user's token can make
/// none); a second connection while the first is open uses the same agent; and the session is still
/// there for a third after every connection has gone (the agent is not in sshd's job). Last, two first
/// connections of another new account at once.
#[test]
fn prompt_path_through_real_sshd() {
    let _machine = machine::shared();
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

// What the word gives, through the real sshd =====

/// `ssh -T host -- remote`, run to its end: the token `remote` (a `whoami /groups`) was started with.
fn token_of_command(kit: &Kit, login: &Login<'_>, remote: &str) -> TokenShown {
    let mut ssh = login.command();
    ssh.arg("-T").arg("--").arg(remote);
    let outcome = run_client(ssh, false, kit.dir());
    let shown = String::from_utf8_lossy(&outcome.stdout).into_owned();
    assert!(
        outcome.code == Some(0),
        "`{remote}` did not run through sshd (exit {:?}); stdout:\n{shown}\nstderr:\n{}\n{}",
        outcome.code,
        outcome.stderr,
        (login.diagnostics())()
    );
    token_shown(&shown)
}

/// `ssh -tt host -- remote`, run to its end: the token `remote` (a `whoami /groups`) was started with, read
/// from what the terminal showed.
fn token_of_command_with_terminal(kit: &Kit, login: &Login<'_>, remote: &str) -> TokenShown {
    let mut ssh = login.command();
    ssh.arg("-tt").arg("--").arg(remote);
    let outcome = run_client(ssh, true, kit.dir());
    let shown = screen_text(&outcome.stdout);
    assert!(
        outcome.code == Some(0),
        "`{remote}` with a terminal did not run through sshd (exit {:?}); the terminal showed:\n{shown}\nstderr:\n{}\n{}",
        outcome.code,
        outcome.stderr,
        (login.diagnostics())()
    );
    token_shown(&shown)
}

/// What a PowerShell session says of its own token, typed as a line: `wg-label=<label> wg-admin=<state>;`. The
/// markers are joined by the shell so that the echo of the typed line does not hold them.
fn token_of_shell(session: &mut SshSession) -> TokenShown {
    session.type_line(
        r#"$g = (whoami /groups | Out-String); $a = if ($g -match 'S-1-5-32-544\s+(Mandatory group, Enabled by default, Enabled group|Group used for deny only)') { if ($Matches[1] -like 'Group*') { 'deny-only' } else { 'enabled' } } else { 'absent' }; Write-Output ('wg' + '-label=' + [regex]::Match($g, 'Mandatory Label\\(\w+) Mandatory Level').Groups[1].Value + ' wg' + '-admin=' + $a + ';')"#,
    );
    session.read_until_any(&["wg-admin=enabled;", "wg-admin=deny-only;", "wg-admin=absent;"]);
    let text = session.text();
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

/// Elevated (CI only). An administrator's SSH session through the brokered agent is elevated, and the word
/// `internal-unelevated` gives an unelevated one: in the three places it can be written (the client's command,
/// a key that forces it with the client's command after it, a key that forces it with none), on pipes and with
/// a terminal, and through the `console-fallback` verb. The administrator's key is in the administrators' file
/// (see `sshd_rig::install_key`).
#[test]
fn an_administrators_session_through_real_sshd_is_elevated_and_the_word_gives_an_unelevated_one() {
    let _machine = machine::exclusive();
    account_fixture::assert_elevated();
    let kit = Kit::broker_with_helper("sshw");
    let account = Account::create("sshw", true);
    account.make_administrator();
    let login = Login::new(&kit, &account);
    let forcing = Login::forcing(&kit, &account, "internal-unelevated");

    set_default_shell_under(OPENSSH_KEY, &kit.exe.to_string_lossy(), &no_shell_to_carry())
        .expect("set the shim as DefaultShell");
    // The account's session, started at the password prompt; it stays up for the sessions below.
    let mut first = login.start();
    first.log_in(&account.password);
    first.check_relayed_shell();
    assert_eq!(
        token_of_shell(&mut first),
        TokenShown::new("High", "enabled"),
        "the login's own shell is not elevated"
    );

    let elevated = TokenShown::new("High", "enabled");
    let unelevated = TokenShown::new("Medium", "deny-only");
    // 1. The client's command: no word, the word, and a word that is only the start of another command.
    assert_eq!(token_of_command(&kit, &login, "whoami /groups"), elevated, "no word");
    assert_eq!(
        token_of_command(&kit, &login, "internal-unelevated whoami /groups"),
        unelevated,
        "the word, then the command"
    );
    // 2. A key that forces the word: the client's command arrives in SSH_ORIGINAL_COMMAND.
    assert_eq!(
        token_of_command(&kit, &forcing, "whoami /groups"),
        unelevated,
        "the word forced on the key, the client's command after it"
    );
    // 3. With a terminal: a command, and the bare word (a login).
    assert_eq!(
        token_of_command_with_terminal(&kit, &login, "internal-unelevated whoami /groups"),
        unelevated,
        "the word and a command, with a terminal"
    );
    let mut shell = SshSession::start_as_given(
        {
            let mut ssh = login.command();
            ssh.arg("-tt").arg("--").arg("internal-unelevated");
            ssh
        },
        login.diagnostics(),
    );
    shell.read_until(SHELL_PROMPT);
    assert_eq!(
        token_of_shell(&mut shell),
        unelevated,
        "ssh -tt host internal-unelevated"
    );
    shell.leave();
    // 4. The word forced on the key and no client command: a login.
    let mut forced_login = forcing.start();
    forced_login.read_until(SHELL_PROMPT);
    assert_eq!(
        token_of_shell(&mut forced_login),
        unelevated,
        "the word forced, no command"
    );
    forced_login.leave();

    // 5. A terminal session whose configured shell cannot start is replaced by the `console-fallback` verb, and
    // that shell is unelevated too.
    let broken = kit.path("not-a-program.exe");
    std::fs::write(&broken, "this is not a program").unwrap();
    account.write_user_config(&format!("shell: '{}'\n", broken.display()));
    assert_eq!(
        token_of_command_with_terminal(&kit, &login, "internal-unelevated whoami /groups"),
        unelevated,
        "through the console-fallback verb"
    );
    assert_eq!(
        token_of_command_with_terminal(&kit, &login, "whoami /groups"),
        elevated,
        "control: the verb's shell is elevated without the word"
    );

    first.leave();
}

/// Elevated (CI only). With no agent running, the fail-open shell of a login that said the word is
/// unelevated, and the same login without the word is the elevated one sshd gave the shim.
#[test]
fn an_administrators_fail_open_shell_is_unelevated_when_the_login_said_the_word() {
    let _machine = machine::exclusive();
    account_fixture::assert_elevated();
    let kit = Kit::broker_with_helper("sshf");
    let account = Account::create("sshf", true);
    account.make_administrator();
    // A shell that is there and not the broker's: with no agent, a command session is not offered one.
    account.write_user_config("shell: cmd.exe\n");
    let login = Login::new(&kit, &account);
    set_default_shell_under(OPENSSH_KEY, &kit.exe.to_string_lossy(), &no_shell_to_carry())
        .expect("set the shim as DefaultShell");

    assert_eq!(
        token_of_command(&kit, &login, "whoami /groups"),
        TokenShown::new("High", "enabled"),
        "control: no word, no agent"
    );
    assert_eq!(
        token_of_command(&kit, &login, "internal-unelevated whoami /groups"),
        TokenShown::new("Medium", "deny-only"),
        "the word, no agent"
    );
}

/// Elevated (CI only). One test, for an account that is in Backup Operators and not in Administrators.
/// Windows treats such an account's full token as one it filters, so sshd may hand the shim a token above
/// Medium that has no Administrators in it: the level, not the group, decides what the broker gives it. The
/// test records what sshd gives the plain shell; then the brokered exec session of the account must be at that
/// level and served, and `internal-unelevated` must give it Medium.
///
/// It fails by assertion, before any wait: the premises (sshd's token is High, a batch logon of the account is
/// High) are read first, so that a shim and an agent at different levels, which would wait on each other,
/// are never started.
#[test]
fn a_backup_operators_account_is_served_at_the_level_sshd_gives_it_and_the_word_steps_it_down() {
    let _machine = machine::exclusive();
    account_fixture::assert_elevated();
    let kit = Kit::broker_with_helper("sshb");
    let account = Account::create("sshb", true);
    account.make_backup_operator();
    // The prompt starts an agent at High with a batch logon, which a standard account does not have the right to.
    account.grant_batch_logon_right();
    let login = Login::new(&kit, &account);

    // 1. What the plain shell gets: stock sshd with cmd.exe as the shell.
    let system_root = std::env::var("SystemRoot").expect("SystemRoot is set");
    set_stock_shell(&std::path::Path::new(&system_root).join(r"System32\cmd.exe"));
    let plain = token_of_command(&kit, &login, "whoami /groups");
    eprintln!("what sshd gives the plain shell of a Backup Operators account that is not an administrator: {plain:?}");
    assert_eq!(
        plain,
        TokenShown::new("High", "absent"),
        "sshd gave this account a token that is not High without Administrators: the plan's premise does not hold \
         on this machine, which is a finding to report, not a failure of the broker"
    );

    // 2. What the agent the prompt starts would run at: read from a batch logon of the account, before
    // anything waits for it.
    let local = ssh_broker::account::account_named(&account.name).expect("look up the account");
    let batch = ssh_broker::logon::batch_logon(&local, &password::password(&account.password))
        .unwrap_or_else(|e| panic!("a batch logon of the account: {e:?}"));
    let rid = ssh_broker::account::integrity_of(batch.0).expect("read the integrity of the batch token");
    assert_eq!(
        ssh_broker::account::integrity_class(rid),
        ssh_broker::socket_loc::Integrity::High,
        "a batch logon of this account is at {rid:#x}, below High: the shim looks in the elevated folder and the \
         agent the prompt starts would serve the other one"
    );
    drop(batch);

    // 3. Through the broker: the account's session, then exec sessions served by it.
    set_default_shell_under(OPENSSH_KEY, &kit.exe.to_string_lossy(), &no_shell_to_carry())
        .expect("set the shim as DefaultShell");
    let mut first = login.start();
    first.log_in(&account.password);
    first.check_relayed_shell();
    let served = token_of_command(&kit, &login, "whoami /groups");
    assert_eq!(
        served.label, "High",
        "the brokered exec session is not at the level sshd gave"
    );
    assert_eq!(
        token_of_command(&kit, &login, "internal-unelevated whoami /groups"),
        TokenShown::new("Medium", "absent"),
        "the word"
    );
    first.leave();
}
