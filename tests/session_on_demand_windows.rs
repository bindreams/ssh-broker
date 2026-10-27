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
use ssh_broker::userdir::{self, NoProfile};
use ssh_broker::winutil::OwnedHandle;
use windows::Win32::NetworkManagement::NetManagement::UF_ACCOUNTDISABLE;
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE};

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
use stand_in::file_signal::FileWaited;
use stand_in::{Kit, RealAgent, SeclogonGuard, start_shim, start_shim_typing};

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

// The logon call and what the shim sees of the agent it starts ---------------------------------

/// Elevated (CI only). The sshd shape: the shim is a network-logon token of a standard account in a
/// kill-on-close job. It starts the agent through the logon and learns that the agent serves from
/// the files it writes (the product's own `SocketWatch`), under that token; no named kernel object
/// is involved, because that token is refused every one (CI round 4).
#[test]
fn a_network_token_shim_sees_the_agent_it_starts() {
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

/// Elevated (CI only). An administrator's shim runs at High integrity and the agent at Medium; the
/// shim still learns that the agent serves from the files it writes.
#[test]
fn an_administrators_shim_sees_the_agent_it_starts() {
    let _machine = machine::shared();
    account_fixture::assert_elevated();
    let kit = Kit::new("radm");
    let account = Account::create("radm", true);
    let password = password::password(&account.password);
    let started = logon::start_background_agent(&account_of(&account), &password, &kit.exe)
        .unwrap_or_else(|e| panic!("logon failed: {e:?}"));
    let location = ssh_broker::socket_loc::for_profile(account.profile()).unwrap();
    stand_in::wait_for_serving_marker(&location, started.process.0);
    assert_eq!(
        kit.agent_info("sid"),
        account.sid_text,
        "agent.error: {}",
        kit.read("agent.error")
    );
}

/// What became of the logon child when its caller's job was closed.
enum M3Outcome {
    /// It acknowledged after the close.
    Survived,
    /// It was gone. `child` and `shim` are the exit codes of the logon child and of the caller (which
    /// the close certainly ended); `had_waited` says whether the child had recorded that it was
    /// waiting, which a process that ended by itself while waiting could not have skipped.
    Ended { child: u32, shim: u32, had_waited: bool },
}

/// M3: the caller is a network-token process in `jobs`, outermost first (a chain of nested jobs when
/// there are several); it starts the logon child through the product's `start_background_agent`. The
/// child records that it is waiting; the jobs are closed, innermost first; then the child is told to
/// acknowledge. Both outcomes end the wait: it waits on the acknowledgement and on the child's exit.
///
/// Returns what became of the child, what the logon reported about its survival (`survival=...` in the
/// shim's report, the value the prompt path turns into a line for the user), and the child's job
/// membership as this test reads it from outside, before the jobs close.
fn logon_child_after_the_callers_jobs_close(tag: &str, mut jobs: Vec<KillOnCloseJob>) -> M3Run {
    let _machine = machine::shared();
    let kit = Kit::new(tag);
    let account = Account::create(tag, true);
    // The stand-in agent, once it is up, waits for the file `agent.go` and then writes `agent.ack`.
    std::fs::write(kit.path("agent.plan"), "").unwrap();

    let shim = start_shim(&kit, &account, true, |shim| {
        for job in &jobs {
            job.assign(shim.process.0);
        }
    });
    assert!(shim.result.starts_with("Ready"), "shim.result: {}", shim.result);
    let reported = shim.result.clone();
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
    // Close the job only once the child is waiting, so that nothing it does after the close is in doubt.
    match stand_in::file_signal::wait_for_file(
        &kit.path("agent.waiting"),
        Some(agent.0),
        Some(stand_in::SERVING_BOUND),
        "the logon child's record that it is waiting",
    ) {
        FileWaited::Appeared => {}
        FileWaited::ProcessEnded(code) => {
            panic!("the logon child (pid {agent_pid}) ended with {code:#x} before the job was closed")
        }
    }

    let membership = logon::ChildJob::of_process(agent.0);

    for job in jobs.iter_mut().rev() {
        job.close();
    }
    // The close is what ends the shim; wait for that before the child is asked anything.
    let shim_code = shim.process.wait();

    stand_in::file_signal::publish(&kit.path("agent.go"), "go");
    match stand_in::file_signal::wait_for_file(
        &kit.path("agent.ack"),
        Some(agent.0),
        Some(stand_in::SERVING_BOUND),
        "the logon child's acknowledgement",
    ) {
        FileWaited::Appeared => M3Run {
            outcome: M3Outcome::Survived,
            reported,
            membership,
        },
        FileWaited::ProcessEnded(child) => M3Run {
            outcome: M3Outcome::Ended {
                child,
                shim: shim_code,
                had_waited: kit.path("agent.waiting").is_file(),
            },
            reported,
            membership,
        },
    }
}

/// What one M3 run measured.
struct M3Run {
    outcome: M3Outcome,
    /// The shim's report, which carries the logon's claim (`survival=...`).
    reported: String,
    /// Whether the child was in a job when the test looked, before any job closed.
    membership: logon::ChildJob,
}

impl M3Run {
    /// Whether the child outlived its caller's jobs. A child that ended without having recorded that it
    /// was waiting ended by itself, which says nothing about the jobs: that is a failure of the run.
    fn survived(&self, chain: &str) -> bool {
        match &self.outcome {
            M3Outcome::Survived => true,
            M3Outcome::Ended { had_waited: true, .. } => false,
            M3Outcome::Ended {
                child,
                shim,
                had_waited: false,
            } => panic!(
                "{chain}: the logon child ended ({child:#x}; the caller's: {shim:#x}) without having recorded that it was waiting: {}",
                self.measured()
            ),
        }
    }

    /// Everything the run measured, for a failure message.
    fn measured(&self) -> String {
        let fate = match &self.outcome {
            M3Outcome::Survived => "the child survived its caller's jobs closing".to_string(),
            M3Outcome::Ended {
                child,
                shim,
                had_waited,
            } => format!(
                "the child ended with its caller's jobs: exit code {child:#x} (the caller's: {shim:#x}), it had recorded that it was waiting: {had_waited}"
            ),
        };
        format!(
            "measured: {fate}; the child's job membership before the close: {:?}; the logon reported: {}",
            self.membership, self.reported
        )
    }

    /// The logon's claim, which the prompt path turns into a line for the user, is the survival that
    /// was measured. Prints the measurement on a mismatch so that the rule can be revisited from it.
    fn assert_claim_matches_measurement(&self, chain: &str) {
        let survived = self.survived(chain);
        let claim = if self.reported.contains("survival=OutlivesConnection") {
            true
        } else if self.reported.contains("survival=EndsWithConnection") {
            false
        } else {
            panic!("{chain}: the logon reported no survival: {}", self.measured())
        };
        assert_eq!(
            claim,
            survived,
            "{chain}: the logon's claim (outlives: {claim}) is not what happened (outlived: {survived}); {}",
            self.measured()
        );
    }
}

/// Elevated (CI only). M3: the caller's job allows no breakaway, so the product asks for none, the
/// child stays in the job and ends with it, and the logon reports that the session does not outlive
/// the connection (the prompt path says so to the user).
#[test]
fn logon_child_in_a_job_that_forbids_breakaway_ends_with_the_job_and_the_logon_says_so() {
    let run = logon_child_after_the_callers_jobs_close("m3a", vec![KillOnCloseJob::create()]);
    assert!(!run.survived("job without BREAKAWAY_OK"), "{}", run.measured());
    run.assert_claim_matches_measurement("job without BREAKAWAY_OK");
}

/// Elevated (CI only). M3: where the caller's job allows breakaway the product asks for it, and the
/// logon child outlives the job.
#[test]
fn logon_child_survives_the_callers_job_closing_where_breakaway_is_allowed() {
    let run = logon_child_after_the_callers_jobs_close("m3b", vec![KillOnCloseJob::create_allowing_breakaway()]);
    assert!(
        run.survived("job with BREAKAWAY_OK"),
        "the logon child ended with its caller's job although the job allows breakaway and the logon asked for it; {}",
        run.measured()
    );
    run.assert_claim_matches_measurement("job with BREAKAWAY_OK");
}

/// A chain of two nested jobs, outermost first, each allowing breakaway or not. Windows shows a process
/// only the innermost, which is what the product reads of its caller.
fn nested_jobs(outer_allows: bool, inner_allows: bool) -> Vec<KillOnCloseJob> {
    let job = |allows| {
        if allows {
            KillOnCloseJob::create_allowing_breakaway()
        } else {
            KillOnCloseJob::create()
        }
    };
    vec![job(outer_allows), job(inner_allows)]
}

/// Elevated (CI only). Every job of the chain allows breakaway: the product asks for it and the logon
/// child outlives the chain.
#[test]
fn logon_child_survives_nested_jobs_that_all_allow_breakaway() {
    let run = logon_child_after_the_callers_jobs_close("m3n1", nested_jobs(true, true));
    assert!(
        run.survived("all nested jobs allow"),
        "the logon child ended with a chain of jobs that all allow breakaway; {}",
        run.measured()
    );
    run.assert_claim_matches_measurement("all nested jobs allow");
}

/// Elevated (CI only). The innermost job allows breakaway and an outer one does not. Whether Windows
/// refuses the flagged call, and where the child ends up, is what this measures (CI round 8: it does not
/// refuse). The logon must succeed, and what it tells the user must be what happened.
#[test]
fn logon_succeeds_when_an_outer_job_forbids_the_breakaway_the_inner_one_allows() {
    let run = logon_child_after_the_callers_jobs_close("m3n2", nested_jobs(false, true));
    run.assert_claim_matches_measurement("outer forbids, inner allows");
}

/// Elevated (CI only). The innermost job forbids breakaway and an outer one allows it: the product
/// asks for none, the logon succeeds, and the child ends with the chain.
#[test]
fn logon_succeeds_when_the_inner_job_forbids_breakaway_and_an_outer_one_allows_it() {
    let run = logon_child_after_the_callers_jobs_close("m3n3", nested_jobs(true, false));
    assert!(!run.survived("outer allows, inner forbids"), "{}", run.measured());
    run.assert_claim_matches_measurement("outer allows, inner forbids");
}

/// Elevated (CI only). A wrong password in a chain that refuses breakaway is answered `1326` and not
/// access denied: the refusal comes after Windows has checked the password, so the product's one
/// fallback on access denied never tries a wrong password twice.
#[test]
fn a_wrong_password_in_a_job_chain_is_answered_with_a_logon_failure() {
    let _machine = machine::shared();
    let kit = Kit::new("m3n4");
    let account = Account::create("m3n4", true);
    let mut jobs = nested_jobs(false, true);
    let shim = start_shim_typing(&kit, &account, "not-the-password", false, |shim| {
        for job in &jobs {
            job.assign(shim.process.0);
        }
    });
    assert!(
        shim.result.starts_with("logon failed: 1326 "),
        "a wrong password must be a logon failure, not a refused breakaway: {}",
        shim.result
    );
    shim.process.wait();
    for job in jobs.iter_mut().rev() {
        job.close();
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
    let password = password::password(&account.password);
    match logon::start_background_agent(&account_of(&account), &password, &kit.exe) {
        Ok(started) => {
            let location = ssh_broker::socket_loc::for_profile(account.profile()).unwrap();
            stand_in::wait_for_serving_marker(&location, started.process.0);
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
    let password = password::password(&account.password);
    let failure = logon::start_background_agent(&account_of(&account), &password, &kit.exe)
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
    let password = password::password("not-the-password");
    let failure = logon::start_background_agent(&account_of(&account), &password, &kit.exe)
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
    let password = password::password(&account.password);
    let failure = logon::start_background_agent(&account_of(&account), &password, &kit.exe)
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
    let password = password::password(&account.password);
    let started = logon::start_background_agent(&account_of(&account), &password, &kit.exe)
        .unwrap_or_else(|e| panic!("logon as {name:?} failed: {e:?}"));
    let location = ssh_broker::socket_loc::for_profile(account.profile()).unwrap();
    stand_in::wait_for_serving_marker(&location, started.process.0);
    assert_eq!(
        kit.agent_info("sid"),
        account.sid_text,
        "agent.error: {}",
        kit.read("agent.error")
    );
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
    // The agent ends after every connection has finished, and a connection finishes when its client
    // closes it. The shim does that on the exit code; this client must too.
    shell.read_to_end();
    drop(shell);
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
