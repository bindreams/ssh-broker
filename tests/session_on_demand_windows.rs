//! Session on demand: the prompt path, the background agent and `logout`. Windows only;
//! **Elevated (CI only)**.
//!
//! These tests create throwaway local accounts, log them on and start processes under them. They
//! need an elevated administrator and refuse to run anywhere else, before they touch anything: run
//! them in CI, never on a workstation. Every test holds `machine::shared()` or
//! `machine::exclusive()` for as long as it touches machine-wide state.
#![cfg(windows)]

use ssh_broker::account::{self, AccountKind, LocalAccount};
use ssh_broker::logon;
use ssh_broker::ready::{self, ReadyEvent, Waited};
use ssh_broker::userdir::{self, NoProfile};
use ssh_broker::winutil::OwnedHandle;
use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::NetworkManagement::NetManagement::UF_ACCOUNTDISABLE;
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo, SE_KERNEL_OBJECT,
};
use windows::Win32::Security::{DACL_SECURITY_INFORMATION, LABEL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE};
use windows::core::PWSTR;

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
#[path = "common/job.rs"]
mod job;
#[path = "common/logon_session.rs"]
mod logon_session;
#[path = "common/machine.rs"]
mod machine;
#[path = "common/password.rs"]
mod password;
#[path = "common/process_list.rs"]
mod process_list;
#[path = "common/stand_in.rs"]
mod stand_in;

use account_fixture::Account;
use agent_conn::{AgentConn, BackgroundAgent};
use job::KillOnCloseJob;
use stand_in::{Kit, RealAgent, SeclogonGuard, start_shim};

/// The product's view of a fixture account.
fn account_of(account: &Account) -> LocalAccount {
    LocalAccount {
        name: account.name.clone(),
        sid: account.sid_text.clone(),
        kind: AccountKind::Local,
    }
}

// Account identity ---------------------------------------------------------------------------

/// Elevated (CI only).
#[test]
fn profile_dir_of_token_reports_no_profile_for_an_account_that_never_logged_on() {
    let _machine = machine::shared();
    let never = Account::create("nopro", false);
    let token = never.network_token();
    let err = userdir::profile_dir_of_token(token.0).unwrap_err();
    assert!(
        err.downcast_ref::<NoProfile>().is_some(),
        "an account without a profile must fail with NoProfile, got: {err:#}"
    );
}

/// Elevated (CI only).
#[test]
fn account_named_resolves_a_fixture_account_with_a_space_in_its_name() {
    let _machine = machine::shared();
    let name = format!("sb sp{:x}", std::process::id());
    let fixture = Account::create_named(&name, "Pw-Sp-Aa1!-x", false);
    let resolved = account::account_named(&name).unwrap();
    assert!(resolved.name.eq_ignore_ascii_case(&name), "{} != {name}", resolved.name);
    assert_eq!(resolved.sid, fixture.sid_text);
    assert_eq!(resolved.kind, AccountKind::Local);
}

/// Elevated (CI only).
#[test]
fn is_elevated_is_true_for_the_ci_token() {
    let _machine = machine::shared();
    account_fixture::assert_elevated();
    assert!(account::is_elevated().unwrap());
}

// The ready event and the logon call ------------------------------------------------------------

/// The DACL and mandatory label the kernel holds for `event`, as SDDL.
fn event_sddl(event: &ReadyEvent) -> String {
    let info = DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION;
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: a valid handle and out-pointer; the descriptor and the text are freed below.
    unsafe {
        let rc = GetSecurityInfo(
            event.as_handle(),
            SE_KERNEL_OBJECT,
            info,
            None,
            None,
            None,
            None,
            Some(&mut descriptor),
        );
        assert_eq!(rc.0, 0, "GetSecurityInfo failed with {}", rc.0);
        let mut text = PWSTR::null();
        ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor, 1, info, &mut text, None).unwrap();
        let sddl = text.to_string().unwrap();
        let _ = LocalFree(Some(HLOCAL(text.0.cast())));
        let _ = LocalFree(Some(HLOCAL(descriptor.0)));
        sddl
    }
}

/// Elevated (CI only). The measured form (spike M3, run 3): the generic rights are mapped to the
/// event's specific ones, and the label carries the inherited-auto flag.
#[test]
fn ready_event_dacl_is_exact() {
    let _machine = machine::shared();
    let account = Account::create("rdacl", false);
    let (name, sid) = (ready::generate_name().unwrap(), account.sid_text.clone());
    let event = ReadyEvent::create_named(&name, &sid).unwrap();
    assert_eq!(
        event_sddl(&event),
        format!("D:(A;;0x1f0003;;;SY)(A;;0x1f0003;;;BA)(A;;0x100002;;;{sid})S:AI(ML;;NW;;;ME)")
    );
}

/// Elevated (CI only). The sshd shape: the shim is a network-logon token of a standard account in a
/// kill-on-close job and creates the event in `Global\`, which the spike never did; the agent is
/// the child the logon starts.
#[test]
fn ready_event_made_by_a_network_token_shim_is_signalled_by_the_agent() {
    let _machine = machine::shared();
    let kit = Kit::new("rnet");
    let account = Account::create("rnet", true);
    let mut job = KillOnCloseJob::create();
    let shim = start_shim(&kit, &account, false, |shim| job.assign(shim.process.0));
    assert!(shim.result.starts_with("Ready"), "shim.result: {}", shim.result);
    assert_eq!(kit.agent_info("sid"), account.sid_text);
    assert_eq!(kit.agent_info("expect_user_matches"), "true");
    shim.process.wait();
    job.close();
}

/// Elevated (CI only). An administrator's shim runs at High integrity and the agent at Medium: the
/// spike saw a Medium process open such an event with the explicit DACL and label, and a
/// network-token stand-in denied for an event it did not create. This test comes first: the label is
/// kept only if it is what makes it pass.
#[test]
fn ready_event_made_by_an_administrators_shim_is_signalled_by_the_agent() {
    let _machine = machine::shared();
    account_fixture::assert_elevated();
    let kit = Kit::new("radm");
    let account = Account::create("radm", true);
    let name = ready::generate_name().unwrap();
    let event = ReadyEvent::create_named(&name, &account.sid_text).unwrap();
    let password = password::password(&account.password);
    let started = logon::start_background_agent(&account_of(&account), &password, &kit.exe, &name)
        .unwrap_or_else(|e| panic!("logon failed: {e:?}"));
    let waited = event.wait_with(started.process.0).unwrap();
    assert_eq!(waited, Waited::Ready, "agent.error: {}", kit.read("agent.error"));
    assert_eq!(kit.agent_info("sid"), account.sid_text);
}

/// Elevated (CI only). M3: the logon child is started by the Secondary Logon service, and whether it
/// shares its caller's kill-on-close job is the open question. The caller is a network-token process
/// in such a job; the child signals ready; the job is closed; then the child is told to acknowledge.
/// It acknowledges (it survived) or it is gone (it died with the job). The wait is on the
/// acknowledgement and on the child's exit, so neither outcome hangs.
#[test]
fn logon_child_survives_the_callers_job_closing() {
    let _machine = machine::shared();
    let kit = Kit::new("m3");
    let account = Account::create("m3", true);
    let sid = account.sid_text.clone();
    let (go_name, ack_name) = (ready::generate_name().unwrap(), ready::generate_name().unwrap());
    let go = ReadyEvent::create_named(&go_name, &sid).unwrap();
    let ack = ReadyEvent::create_named(&ack_name, &sid).unwrap();
    std::fs::write(kit.path("agent.plan"), format!("go={go_name}\nack={ack_name}\n")).unwrap();

    let mut job = KillOnCloseJob::create();
    let shim = start_shim(&kit, &account, true, |shim| job.assign(shim.process.0));
    assert!(shim.result.starts_with("Ready"), "shim.result: {}", shim.result);
    let agent_pid: u32 = kit.agent_info("pid").parse().unwrap();
    // SAFETY: a plain open by id; the handle is closed by `OwnedHandle`.
    let agent = OwnedHandle(
        unsafe {
            OpenProcess(
                PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                agent_pid,
            )
        }
        .unwrap_or_else(|e| panic!("open the logon child (pid {agent_pid}): {e}")),
    );

    job.close();
    // The job's close is what ends the shim; wait for that before the child is asked anything.
    shim.process.wait();

    go.signal().unwrap();
    match ack.wait_with(agent.0).unwrap() {
        Waited::Ready => {}
        Waited::AgentExited(code) => panic!(
            "M3: the logon child (pid {agent_pid}) did not survive its caller's job closing: it exited with {code:#x} \
             before acknowledging. CREATE_BREAKAWAY_FROM_JOB is the next thing to try, and an owner question where the \
             job forbids breakaway"
        ),
    }
}

/// Elevated (CI only). M7: with `seclogon` stopped (demand start) the call either starts the service
/// and succeeds, or fails with Windows' reason; either way the outcome is whole and the service is
/// put back.
#[test]
fn logon_with_seclogon_stopped_returns_windows_reason() {
    let _machine = machine::exclusive();
    let kit = Kit::new("m7s");
    let account = Account::create("m7s", true);
    let _seclogon = SeclogonGuard::engage(false);
    let (event, name) = ReadyEvent::create().unwrap();
    let password = password::password(&account.password);
    match logon::start_background_agent(&account_of(&account), &password, &kit.exe, &name) {
        Ok(started) => {
            let waited = event.wait_with(started.process.0).unwrap();
            assert_eq!(waited, Waited::Ready, "agent.error: {}", kit.read("agent.error"));
        }
        Err(failure) => assert!(!failure.reason.is_empty(), "no reason for code {}", failure.code),
    }
}

/// Elevated (CI only). M7: with `seclogon` disabled nothing can start it, so the call fails, and
/// the failure carries Windows' sentence.
#[test]
fn logon_with_seclogon_disabled_returns_windows_reason() {
    let _machine = machine::exclusive();
    let kit = Kit::new("m7d");
    let account = Account::create("m7d", true);
    let _seclogon = SeclogonGuard::engage(true);
    let (_event, name) = ReadyEvent::create().unwrap();
    let password = password::password(&account.password);
    let failure = logon::start_background_agent(&account_of(&account), &password, &kit.exe, &name)
        .err()
        .expect("the logon must fail while seclogon is disabled");
    assert!(!failure.reason.is_empty(), "no reason for code {}", failure.code);
}

/// Elevated (CI only).
#[test]
fn wrong_password_returns_windows_reason() {
    let _machine = machine::shared();
    let kit = Kit::new("wrong");
    let account = Account::create("wrong", true);
    let (_event, name) = ReadyEvent::create().unwrap();
    let password = password::password("not-the-password");
    let failure = logon::start_background_agent(&account_of(&account), &password, &kit.exe, &name)
        .err()
        .expect("a wrong password must fail");
    assert_eq!(failure.code, 1326, "{failure:?}");
    assert!(failure.reason.to_lowercase().contains("password"), "{failure:?}");
}

/// Elevated (CI only).
#[test]
fn disabled_account_returns_reason() {
    let _machine = machine::shared();
    let kit = Kit::new("dis");
    let account = Account::create_with("dis", true, UF_ACCOUNTDISABLE);
    let (_event, name) = ReadyEvent::create().unwrap();
    let password = password::password(&account.password);
    let failure = logon::start_background_agent(&account_of(&account), &password, &kit.exe, &name)
        .err()
        .expect("a disabled account must fail");
    assert!(matches!(failure.code, 1327 | 1331), "{failure:?}");
    assert!(!failure.reason.is_empty());
}

/// Elevated (CI only). The stand-in child needs no console; the account name holds a space.
#[test]
fn logon_as_account_with_space_in_name() {
    let _machine = machine::shared();
    let kit = Kit::new("sp");
    let name = format!("sb lg{:x}", std::process::id());
    let account = Account::create_named(&name, "Pw-Sp-Aa1!-lg", true);
    let ready_name = ready::generate_name().unwrap();
    let event = ReadyEvent::create_named(&ready_name, &account.sid_text).unwrap();
    let password = password::password(&account.password);
    let started = logon::start_background_agent(&account_of(&account), &password, &kit.exe, &ready_name)
        .unwrap_or_else(|e| panic!("logon as {name:?} failed: {e:?}"));
    let waited = event.wait_with(started.process.0).unwrap();
    assert_eq!(waited, Waited::Ready, "agent.error: {}", kit.read("agent.error"));
    assert_eq!(kit.agent_info("sid"), account.sid_text);
}

// The background agent -----------------------------------------------------------------------

/// Elevated (CI only). Spike M4: a second agent of the same user in the same session never binds and
/// leaves (the `SessionSlot`), so no competing agent serves. Both are the real agent, started as one
/// account's network token; the wait for the second is on its exit.
#[test]
fn second_agent_in_the_same_session_leaves_without_binding() {
    let _machine = machine::shared();
    let kit = Kit::copy_of_broker("m4");
    let account = Account::create("m4", true);
    let location = ssh_broker::socket_loc::for_profile(account.profile()).unwrap();

    let first = RealAgent::start(&kit, &account);
    stand_in::wait_for_serving_marker(&location, first.process.process.0);
    assert!(first.is_running(), "the first agent must be serving");

    let second = RealAgent::start(&kit, &account);
    assert_eq!(second.process.wait(), 0, "the second agent must leave without an error");
    let log = stand_in::read_logs(&location);
    assert!(
        log.contains("another agent already runs in this session"),
        "the second agent must say why it left:\n{log}"
    );
    assert!(first.is_running(), "the first agent must still be serving");
}

// logout -----

/// The longest the logoff event of an ended logon session is awaited. The event is one the OS may
/// never deliver, so this bounds a wait on the outside world; expiry is a failure that reports the
/// measurement, never a pass.
const LOGOFF_EVENT_BOUND: std::time::Duration = std::time::Duration::from_secs(180);

/// The command that asks the agent to end, run inside it.
fn logout_command(kit: &Kit) -> String {
    format!("\"{}\" logout", kit.exe.display())
}

/// Elevated (CI only). The client of `logout` is a child of the shell the agent hosts: the agent
/// must not end that tree before the client has shown the reply.
#[test]
fn logout_message_reaches_a_pty_client_running_inside_the_agent() {
    let _machine = machine::shared();
    let kit = Kit::copy_of_broker("lopty");
    let account = Account::create("lopty", true);
    let agent = BackgroundAgent::start(&kit, &account);

    let mut session = AgentConn::connect(&agent.location);
    session.start_pty("cmd.exe");
    session.type_line(&logout_command(&kit));
    let done = session.read_to_end();
    assert!(
        done.pty.contains("ending your background session."),
        "the PTY transcript lacks the reply:
{}",
        done.pty
    );
}

/// Elevated (CI only). The exec relay runs `logout` in the agent: its stderr and its exit code (0)
/// come back to the shim.
#[test]
fn logout_exit_code_reaches_an_exec_client_inside_the_agent() {
    let _machine = machine::shared();
    let kit = Kit::copy_of_broker("loexec");
    let account = Account::create("loexec", true);
    let agent = BackgroundAgent::start(&kit, &account);

    let mut session = AgentConn::connect(&agent.location);
    session.start_exec(&logout_command(&kit));
    session.end_stdin();
    let done = session.read_to_end();
    assert!(
        done.stderr.contains("ending your background session."),
        "stderr: {:?}, stdout: {:?}",
        done.stderr,
        done.stdout
    );
    assert_eq!(done.exit, Some(0), "the shim exits with logout's code");
}

/// Ask the agent to end from inside it, over a second connection.
fn logout_from_inside(kit: &Kit, agent: &BackgroundAgent) -> agent_conn::Finished {
    let mut asker = AgentConn::connect(&agent.location);
    asker.start_exec(&logout_command(kit));
    asker.end_stdin();
    asker.read_to_end()
}

/// Elevated (CI only). Every process holding the account's logon session ends because of `logout`:
/// the test lists them first and then waits on their handles, so a `logout` that ends fewer is a
/// failure of the job, not a pass by timing.
#[test]
fn logout_ends_every_process_of_the_logon_session() {
    let _machine = machine::shared();
    let kit = Kit::copy_of_broker("loall");
    let account = Account::create("loall", true);
    let agent = BackgroundAgent::start(&kit, &account);
    let id = logon_session::logon_id(agent.process.0);

    // A shell is running in the session when the end comes.
    let mut shell = AgentConn::connect(&agent.location);
    shell.start_pty("cmd.exe");
    shell.type_line("echo shell-is-up");
    shell.read_until_pty_shows("shell-is-up");

    let own = std::process::id();
    let held: Vec<_> = logon_session::processes_of(id)
        .into_iter()
        .filter(|(pid, _)| *pid != own)
        .collect();
    assert!(
        held.len() >= 2,
        "expected the agent and its shell in logon session {id:#x}, found {:?}",
        held.iter().map(|(pid, _)| pid).collect::<Vec<_>>()
    );

    let reply = logout_from_inside(&kit, &agent);
    assert_eq!(reply.exit, Some(0), "stderr: {}", reply.stderr);
    for (pid, process) in &held {
        bounded_wait::wait_for_exit(
            process.0,
            *pid,
            "a process of the logon session after logout",
            bounded_wait::CHILD_EXIT_BOUND,
            &[],
        );
    }
}

/// Elevated (CI only). Spike M6, not settled in three runs: does the logon session itself go away
/// once its last process has ended? There is no primitive that says a session is gone, and looking
/// at `LsaEnumerateLogonSessions` right after the last exit races LSA's teardown, which starts when
/// the last token handle closes. So this waits for the event Windows writes when it destroys a
/// session, Security 4634 for this logon id, subscribed before `logout` runs. If it does not come
/// within the bound, that is M6's measured result, reported as such.
#[test]
fn logon_session_is_logged_off_after_logout() {
    let _machine = machine::shared();
    logon_session::assert_logoff_auditing();
    let kit = Kit::copy_of_broker("lolog");
    let account = Account::create("lolog", true);
    let agent = BackgroundAgent::start(&kit, &account);
    let id = logon_session::logon_id(agent.process.0);
    let watch = logon_session::LogoffWatch::new(id);

    let own = std::process::id();
    let held: Vec<_> = logon_session::processes_of(id)
        .into_iter()
        .filter(|(pid, _)| *pid != own)
        .collect();
    let reply = logout_from_inside(&kit, &agent);
    assert_eq!(reply.exit, Some(0), "stderr: {}", reply.stderr);
    for (pid, process) in &held {
        bounded_wait::wait_for_exit(
            process.0,
            *pid,
            "a process of the logon session after logout",
            bounded_wait::CHILD_EXIT_BOUND,
            &[],
        );
    }
    // Every handle this test holds on the session's processes keeps their tokens, and so the session, alive.
    drop(held);
    drop(agent);

    assert!(
        watch.wait(LOGOFF_EVENT_BOUND),
        "M6: logon session {id:#x} still present: no 4634 although every process of it has ended"
    );
}
