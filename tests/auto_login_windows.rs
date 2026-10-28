//! `auto-login on|off`: a stored-password boot task per account. Windows only; **Elevated (CI only)**.
//!
//! These tests create throwaway accounts, store their passwords with Task Scheduler and let it log
//! them on as a batch job. They need an elevated administrator and refuse to run anywhere else:
//! run them in CI, never on a workstation. Each uses its own account and asserts only on what it
//! made. The task runs a copy of the real exe in a directory every account can read, because the
//! installed directory of a real machine does not exist in CI (the install check is skipped by
//! `WindowsEnv::with_exe_unchecked`).
#![cfg(windows)]

use std::collections::BTreeSet;

use ssh_broker::account::LocalAccount;
use ssh_broker::autologin::{self, PasswordSource, WindowsEnv};
use ssh_broker::provision::session_task::{task_name, task_problem};
use ssh_broker::provision::taskscheduler;
use ssh_broker::socket_loc;

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
#[path = "common/stand_in.rs"]
mod stand_in;
#[path = "common/system_task.rs"]
mod system_task;
#[path = "common/task_instances.rs"]
mod task_instances;

use account_fixture::{Account, ServiceLogon, holders};
use agent_conn::{AgentConn, local_account};
use stand_in::Kit;

/// How long a scheduled start may take before the test calls it failed. The start is an external
/// event; expiry fails the test and says the task did not start an agent.
const TASK_START_BOUND: std::time::Duration = std::time::Duration::from_secs(180);

fn kit(tag: &str) -> Kit {
    Kit::copy_of_broker(tag)
}

fn env(kit: &Kit, password: &str) -> WindowsEnv {
    WindowsEnv::with_exe_unchecked(
        PasswordSource::Given(Some(password::password(password))),
        kit.exe.clone(),
    )
}

fn location(account: &Account) -> socket_loc::SocketLocation {
    socket_loc::for_profile(account.profile()).unwrap()
}

/// Wait for the agent the task started, then run `check` with a way to connect to it, then end the
/// session, so that no agent outlives the test.
fn with_session(kit: &Kit, account: &Account, check: impl FnOnce(&mut dyn FnMut() -> AgentConn)) {
    let location = location(account);
    stand_in::wait_for_serving_marker_of_a_task(&location, TASK_START_BOUND);
    let connect = &mut || AgentConn::connect(&location);
    check(connect);
    logout_with(kit, account);
}

/// End the session a task started with the product's `logout` (the kit's copy of the exe, run inside the
/// agent) and wait for its logoff. It checks what ssh-broker controls (see `session_end`), not that Windows
/// unloads the hive of a Task Scheduler logon.
fn logout_with(kit: &Kit, account: &Account) -> session_end::Ended {
    session_end::log_out(&kit.exe, account, ServiceLogon::TaskScheduler)
        .unwrap_or_else(|why| panic!("logout of {}: {why}", account.name))
        .unwrap_or_else(|| panic!("no agent of {} was running to log out", account.name))
}

fn state_of(account: &Account) -> Option<ssh_broker::provision::session_task::TaskState> {
    taskscheduler::task_state(&task_name(&account.sid_text)).unwrap()
}

/// A standard account that holds the batch right, so its task can run.
fn account_with_batch_right(tag: &str) -> Account {
    let account = Account::create(tag, true);
    account.grant_batch_logon_right();
    account
}

/// Elevated (CI only).
#[test]
fn on_registers_a_verified_task_and_off_deletes_it() {
    let _machine = machine::shared();
    let kit = kit("al1");
    let account = account_with_batch_right("al1");
    let _end = session_end::LogOutOnDrop::new(&kit.exe, &account, ServiceLogon::TaskScheduler);
    let local = local_account(&account);

    autologin::on(&mut env(&kit, &account.password), &local).unwrap();
    let state = state_of(&account).expect("the task is registered");
    let exe = kit.exe.to_string_lossy().into_owned();
    assert_eq!(task_problem(&state, &exe, &account.sid_text), None);
    stand_in::wait_for_serving_marker_of_a_task(&location(&account), TASK_START_BOUND);
    logout_with(&kit, &account);

    autologin::off(&mut env(&kit, &account.password), &local).unwrap();
    assert!(state_of(&account).is_none(), "off deletes the task");
}

/// Elevated (CI only).
#[test]
fn off_twice_is_ok() {
    let _machine = machine::shared();
    let kit = kit("al2");
    let account = account_with_batch_right("al2");
    let _end = session_end::LogOutOnDrop::new(&kit.exe, &account, ServiceLogon::TaskScheduler);
    let local = local_account(&account);

    autologin::on(&mut env(&kit, &account.password), &local).unwrap();
    stand_in::wait_for_serving_marker_of_a_task(&location(&account), TASK_START_BOUND);
    logout_with(&kit, &account);
    autologin::off(&mut env(&kit, &account.password), &local).unwrap();
    autologin::off(&mut env(&kit, &account.password), &local).unwrap();
}

/// Elevated (CI only).
#[test]
fn on_with_a_wrong_password_leaves_no_task() {
    let _machine = machine::shared();
    let kit = kit("al3");
    let account = account_with_batch_right("al3");

    let err = autologin::on(&mut env(&kit, "not-the-password"), &local_account(&account)).unwrap_err();
    assert!(format!("{err:#}").contains("password"), "{err:#}");
    assert!(state_of(&account).is_none(), "a refused password leaves no task");
}

/// Elevated (CI only). M5(d): a standard account that holds the right gets a session in session 0
/// with its profile and DPAPI, and the agent hosts PTY and exec shells there.
#[test]
fn stored_task_starts_a_working_session_with_dpapi() {
    let _machine = machine::shared();
    let kit = kit("al4");
    let account = account_with_batch_right("al4");
    let _end = session_end::LogOutOnDrop::new(&kit.exe, &account, ServiceLogon::TaskScheduler);
    let local = local_account(&account);

    autologin::on(&mut env(&kit, &account.password), &local).unwrap();
    with_session(&kit, &account, |connect| {
        // An exec session through the agent.
        let mut exec = connect();
        exec.start_exec("cmd.exe /c echo exec-in-session-zero");
        exec.end_stdin();
        let done = exec.read_to_end();
        assert!(
            done.stdout.contains("exec-in-session-zero"),
            "stdout: {:?}",
            done.stdout
        );

        // A PTY session through the agent.
        let mut pty = connect();
        pty.start_pty("cmd.exe");
        pty.type_line("echo pty-in-session-zero");
        pty.read_until_pty_shows("pty-in-session-zero");
        pty.type_line("exit");
        pty.read_to_end();

        // The parity probe passes for a session-0 batch agent: `is_genuine_session`.
        let mut probe = connect();
        probe.start_exec(&format!("\"{}\" verify-probe", kit.exe.display()));
        probe.end_stdin();
        let done = probe.read_to_end();
        assert_eq!(done.exit, Some(0), "verify-probe: {:?} {:?}", done.stdout, done.stderr);
        assert!(done.stdout.contains("session_id=0"), "{}", done.stdout);
        assert!(done.stdout.contains("logon=4"), "a batch logon: {}", done.stdout);
        assert!(done.stdout.contains("dpapi=ok"), "{}", done.stdout);
    });
    autologin::off(&mut env(&kit, &account.password), &local).unwrap();
}

/// Elevated (CI only). Not measured by the spike: an administrator's task. Administrators hold the
/// batch right by default.
#[test]
fn stored_task_for_an_administrator_starts_a_session() {
    let _machine = machine::shared();
    let kit = kit("al5");
    let account = Account::create("al5", true);
    let _end = session_end::LogOutOnDrop::new(&kit.exe, &account, ServiceLogon::TaskScheduler);
    account.make_administrator();
    let local = local_account(&account);

    autologin::on(&mut env(&kit, &account.password), &local).unwrap();
    stand_in::wait_for_serving_marker_of_a_task(&location(&account), TASK_START_BOUND);
    let mut exec = AgentConn::connect(&location(&account));
    exec.start_exec("cmd.exe /c echo admin-session-up");
    exec.end_stdin();
    assert!(exec.read_to_end().stdout.contains("admin-session-up"));
    logout_with(&kit, &account);
    autologin::off(&mut env(&kit, &account.password), &local).unwrap();
}

/// Elevated (CI only). M5(d), the OQ1 recommendation: without the batch right `on` refuses, naming it,
/// before registering anything.
#[test]
fn standard_account_without_the_batch_right_is_refused_before_registering() {
    let _machine = machine::shared();
    let kit = kit("al6");
    let account = Account::create("al6", true);

    let err = autologin::on(&mut env(&kit, &account.password), &local_account(&account)).unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("Log on as a batch job"), "{text}");
    assert!(state_of(&account).is_none(), "nothing is registered without the right");
}

/// The `cmdkey` entries of Task Scheduler held for this account.
fn stored_entries(account: &Account) -> usize {
    let listing = system_task::cmdkey_list_as_system(&account.name);
    system_task::task_entries_for(&listing, &account.name)
}

/// Elevated (CI only). M5(e): the stored credential is in the SYSTEM store after `on` and gone after
/// `off`. The first half is what lets the second half fail.
#[test]
fn credential_is_gone_after_off() {
    let _machine = machine::shared();
    let kit = kit("al7");
    let account = account_with_batch_right("al7");
    let _end = session_end::LogOutOnDrop::new(&kit.exe, &account, ServiceLogon::TaskScheduler);
    let local = local_account(&account);

    autologin::on(&mut env(&kit, &account.password), &local).unwrap();
    stand_in::wait_for_serving_marker_of_a_task(&location(&account), TASK_START_BOUND);
    logout_with(&kit, &account);
    assert_eq!(
        stored_entries(&account),
        1,
        "after on, the store holds the account's credential"
    );

    autologin::off(&mut env(&kit, &account.password), &local).unwrap();
    assert_eq!(
        stored_entries(&account),
        0,
        "after off, the credential is gone with the task"
    );
}

/// Elevated (CI only). M5(e): two registrations of one account leave one entry, and `off` leaves none.
#[test]
fn on_twice_then_off_leaves_no_credential() {
    let _machine = machine::shared();
    let kit = kit("al8");
    let account = account_with_batch_right("al8");
    let _end = session_end::LogOutOnDrop::new(&kit.exe, &account, ServiceLogon::TaskScheduler);
    let local = local_account(&account);

    autologin::on(&mut env(&kit, &account.password), &local).unwrap();
    stand_in::wait_for_serving_marker_of_a_task(&location(&account), TASK_START_BOUND);
    autologin::on(&mut env(&kit, &account.password), &local).unwrap();
    assert_eq!(stored_entries(&account), 1, "registering twice stores one credential");
    logout_with(&kit, &account);

    autologin::off(&mut env(&kit, &account.password), &local).unwrap();
    assert_eq!(stored_entries(&account), 0);
}

/// Elevated (CI only). M5(g): a stale stored password is invisible in the task's last result, and the
/// `verify` row says so instead of claiming to have checked.
#[test]
fn a_stale_password_is_not_visible_in_the_last_result() {
    use ssh_broker::provision::session_task::task_row;

    let _machine = machine::shared();
    logon_session::assert_auditing("Logon", "Failure");
    let kit = kit("al9");
    let mut account = account_with_batch_right("al9");
    let _end = session_end::LogOutOnDrop::new(&kit.exe, &account, ServiceLogon::TaskScheduler);
    let local: LocalAccount = local_account(&account);
    let exe = kit.exe.to_string_lossy().into_owned();

    autologin::on(&mut env(&kit, &account.password), &local).unwrap();
    stand_in::wait_for_serving_marker_of_a_task(&location(&account), TASK_START_BOUND);
    logout_with(&kit, &account);

    // The stored password goes stale; the next run cannot log on. The task ignores a start while an
    // instance is listed, so the run after the logout must find none.
    task_instances::wait_until_none(&task_name(&account.sid_text), TASK_START_BOUND);
    let failed_logon = logon_session::failed_logon_watch(&account.name);
    account.set_password("Changed-Pw-9z!Aa");
    taskscheduler::run_task(&task_name(&account.sid_text)).unwrap();
    assert!(
        failed_logon.wait(TASK_START_BOUND),
        "no failed logon (4625) of {} was recorded: the run did not try to log on",
        account.name
    );

    let state = taskscheduler::task_state(&task_name(&account.sid_text));
    let row = task_row(&state, &exe, &account.sid_text);
    assert!(row.pass, "the definition is still right: {}", row.detail);
    assert!(
        row.detail.contains("a failed logon is not recorded"),
        "the row must say it cannot see this: {}",
        row.detail
    );
    autologin::off(&mut env(&kit, &account.password), &local).unwrap();
}

/// How many times the session is started and ended in `logon_sessions_with_no_process_do_not_pile_up`.
const CYCLES: usize = 3;

/// The logon sessions of `account` that LSA lists and that have no process left, other than those Windows
/// has logged off (`logged_off`: the logoff event was seen, so LSA may still list them for a moment while it
/// tears them down).
fn sessions_without_a_process(account: &Account, logged_off: &BTreeSet<u64>) -> Vec<holders::LogonSession> {
    let own = std::process::id();
    holders::sessions_of(&account.sid_text)
        .unwrap_or_else(|why| panic!("list the logon sessions of {}: {why}", account.name))
        .into_iter()
        .filter(|session| !logged_off.contains(&session.id))
        .filter(|session| {
            logon_session::processes_of(session.id)
                .iter()
                .all(|(pid, _)| *pid == own)
        })
        .collect()
}

/// Elevated (CI only). A measurement of a possible defect (Windows can keep the Batch logon session
/// of a Task Scheduler start although no process of it is left). One account, auto-login on, the
/// session started by the task and ended with the product's `logout`, [`CYCLES`] times. After each cycle
/// the account's logon sessions that LSA lists and that have no process left are counted; the count must not
/// grow from the first cycle to the last, or sessions pile up.
#[test]
fn logon_sessions_with_no_process_do_not_pile_up() {
    let _machine = machine::shared();
    let kit = kit("alcyc");
    let account = account_with_batch_right("alcyc");
    let _end = session_end::LogOutOnDrop::new(&kit.exe, &account, ServiceLogon::TaskScheduler);
    let local = local_account(&account);
    let location = location(&account);
    let task = task_name(&account.sid_text);

    let mut left_after: Vec<Vec<holders::LogonSession>> = Vec::new();
    let mut previous_marker: Option<String> = None;
    for cycle in 1..=CYCLES {
        if cycle == 1 {
            autologin::on(&mut env(&kit, &account.password), &local).unwrap();
        } else {
            // The task ignores a start while an instance is listed.
            task_instances::wait_until_none(&task, TASK_START_BOUND);
            taskscheduler::run_task(&task).unwrap();
        }
        // The marker of the agent before stays in the folder: wait for the new agent's.
        stand_in::wait_for_new_serving_marker_of_a_task(&location, previous_marker.as_deref(), TASK_START_BOUND);
        let ended = logout_with(&kit, &account);
        previous_marker = stand_in::serving_marker_text(&location);
        left_after.push(sessions_without_a_process(&account, &ended.logged_off));
    }
    autologin::off(&mut env(&kit, &account.password), &local).unwrap();

    let first = left_after.first().map_or(0, Vec::len);
    let last = left_after.last().map_or(0, Vec::len);
    assert!(
        last <= first,
        "logon sessions of {} with no process left grew from {first} after cycle 1 to {last} after cycle \
         {CYCLES}. Sessions listed by LSA after each cycle:\n{}",
        account.name,
        left_after
            .iter()
            .enumerate()
            .map(|(index, sessions)| format!(
                "after cycle {}: {}{}",
                index + 1,
                sessions.len(),
                sessions
                    .iter()
                    .map(|session| format!("\n  {session}"))
                    .collect::<String>()
            ))
            .collect::<Vec<_>>()
            .join("\n")
    );
    // The count is printed when it passes too: it is the measurement.
    account_fixture::hive::record(&format!(
        "logon sessions of {} with no process left, after each of {CYCLES} cycles: {:?}",
        account.name,
        left_after.iter().map(Vec::len).collect::<Vec<_>>()
    ));
}
