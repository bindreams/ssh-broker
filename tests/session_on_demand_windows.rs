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
#[path = "common/bounded_wait.rs"]
mod bounded_wait;
#[path = "common/desktop.rs"]
mod desktop;
#[path = "common/hard_errors.rs"]
mod hard_errors;
#[path = "common/job.rs"]
mod job;
#[path = "common/machine.rs"]
mod machine;
#[path = "common/password.rs"]
mod password;
#[path = "common/process_list.rs"]
mod process_list;
#[path = "common/stand_in.rs"]
mod stand_in;

use account_fixture::Account;
use job::KillOnCloseJob;
use stand_in::{Kit, SeclogonGuard, start_shim};

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
