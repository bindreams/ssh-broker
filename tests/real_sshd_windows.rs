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

use account_fixture::{Account, ServiceLogon};
use sshd_rig::{Login, PROMPT, SHELL_PROMPT};
use stand_in::Kit;

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
    set_default_shell_under(OPENSSH_KEY, &kit.helper.to_string_lossy()).expect("set the probe as DefaultShell");
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
    set_default_shell_under(OPENSSH_KEY, &kit.exe.to_string_lossy()).expect("set the shim as DefaultShell");
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
