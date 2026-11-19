//! The request socket: what an agent at High keeps in the plain folder for the processes of its account below
//! High, and `logout` over it. Windows only; **Elevated (CI only)**.
//!
//! - A process of the account below High connects to a socket that a process at High made in the plain folder
//!   with the product's own calls (the premise the request socket rests on, measured by spike 5).
//! - In a real sshd session of an administrator, which is unelevated by default, `logout` reaches the agent at
//!   High and ends the session; for a standard account `logout` still asks `agent.sock`.
//! - An agent whose plain folder is refused serves its sessions, and `logout` from them says why.
//!
//! That a process below High cannot connect to `agent.sock` of the elevated folder is
//! `user_isolation_windows.rs`'s `an_unelevated_process_of_the_account_is_refused_the_elevated_folder`, which
//! stays as it is.
#![cfg(windows)]

use std::path::PathBuf;

use ssh_broker::acl::Sid;
use ssh_broker::afunix::Listener;
use ssh_broker::autologin;
use ssh_broker::pipes::ExecChild;
use ssh_broker::provision::registry::{OPENSSH_KEY, set_default_shell_under};
use ssh_broker::provision::{canonical_exe, procwait};
use ssh_broker::request::UNREACHABLE_CODE;
use ssh_broker::socket_loc::{self, Integrity};
use ssh_broker::userdir;
use ssh_broker::winutil::{UnelevatedToken, own_token};

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
use agent_conn::{AgentConn, local_account};
use sshd_rig::{Login, TempDir, no_shell_to_carry, run_client};
use stand_in::Kit;

const CHILD: &str = "the_unelevated_child_connects_to_request_sock";

// A socket a process at High made, and a process below High =====

/// Elevated (CI only). A process of the account below High connects to `request.sock`, which a process at High
/// made in the plain folder with the calls the agent makes it with (`open_socket_dir` at Medium, `Listener::bind`
/// at Medium): the file a High process makes there carries no High label, so the connect is not refused. The
/// child is started with [`UnelevatedToken::of_this_process`] and connects with the product's own
/// [`userdir::SocketDir::connect_request`]; the parent sees the connection arrive.
#[test]
fn an_unelevated_process_of_the_account_connects_to_request_sock_bound_by_a_high_process() {
    account_fixture::assert_elevated();
    let me = Sid::current_user().unwrap();
    let profile = TempDir::new("request-profile");
    std::fs::create_dir_all(profile.0.join(r"AppData\Local")).unwrap();
    let location = socket_loc::for_profile(&profile.0, Integrity::Medium).expect("the stand-in profile path is short");
    let _folder = userdir::open_socket_dir(&location, &me).expect("make the plain folder at High");
    let listener = Listener::bind(&location.request_path(), Integrity::Medium).expect("bind request.sock at High");

    let pair = TempDir::new("request-pair");
    child_entry::write_input(&pair.0, &format!("profile={}\n", profile.0.display()));
    let token = UnelevatedToken::of_this_process().expect("make the unelevated token");
    let line = child_entry::command_line(&std::env::current_exe().unwrap(), CHILD, &pair.0);
    let child = ExecChild::spawn(&line, None, Some(&token), &[]).expect("start the child on pipes");
    let (out, err) = (
        drain::drain(child.stdout_read_raw()),
        drain::drain(child.stderr_read_raw()),
    );
    let waited = child.wait();
    // Join before any assert: the readers use handles `child` closes.
    let said = format!("{}{}", drain::text_of(out), drain::text_of(err));
    waited.unwrap_or_else(|e| panic!("wait for the child: {e}\nit said:\n{said}"));
    let got = std::fs::read_to_string(child_entry::result_path(&pair.0))
        .unwrap_or_else(|e| panic!("the child wrote no result ({e}); it said:\n{said}"));
    assert_eq!(got, "elevation=Filtered\nconnect=ok\n", "the child said:\n{said}");
    listener.accept().expect("the child's connection came to request.sock");
}

/// The child half. Run by the test above with `--ignored`, never on its own.
#[test]
#[ignore = "the child half of a parent/child pair; its parent starts it with the pair's directory"]
fn the_unelevated_child_connects_to_request_sock() {
    let dir = child_entry::dir();
    let text = child_entry::input(&dir);
    let profile = PathBuf::from(
        text.lines()
            .find_map(|line| line.strip_prefix("profile="))
            .expect("the input names the profile"),
    );
    let token = own_token().expect("open the child's own token");
    let elevation = ssh_broker::account::elevation_of(token.0).unwrap();
    let location = socket_loc::for_profile(&profile, Integrity::Medium).unwrap();
    let folder = userdir::inspect_socket_dir(&location, &Sid::current_user().unwrap())
        .unwrap_or_else(|e| panic!("look at the plain folder: {e:#}"));
    let connect = match folder.connect_request() {
        Ok(_) => "ok".to_owned(),
        Err(e) => format!("failed: {e:#}"),
    };
    child_entry::write_result(&dir, &format!("elevation={elevation:?}\nconnect={connect}\n"));
}

// logout in an unelevated session =====

/// The reply the agent gives `logout`.
const ENDING: &str = "ending your background session.";

/// `ssh -T host -- "& '<exe>' logout"`, in the session the account's default login gets: unelevated. The
/// account's shell is PowerShell, which runs a quoted path only through its call operator.
fn logout_over_ssh(kit: &Kit, login: &Login<'_>) -> sshd_rig::Outcome {
    let mut ssh = login.command();
    ssh.arg("-T").arg("--").arg(format!("& '{}' logout", kit.exe.display()));
    run_client(ssh, false, kit.dir())
}

/// The exe the agent of a session started at the password prompt runs: the shim starts it from the installed
/// exe, not from its own copy in the kit (`shim_offer::run_offer`), so that is the image to look for.
fn prompt_agent_exe() -> PathBuf {
    canonical_exe()
}

/// Start the account's session at the password prompt, run `logout` by its full path in a default (unelevated)
/// session, and check that it ended the session: the client's exit code is 0 with the agent's reply, and every
/// agent of the account at `level` has exited.
fn logout_ends_the_session_from_the_default_session(account: &Account, kit: &Kit, level: Integrity) {
    let login = Login::new(kit, account);
    set_default_shell_under(OPENSSH_KEY, &kit.exe.to_string_lossy(), &no_shell_to_carry())
        .expect("set the shim as DefaultShell");
    let mut first = login.start();
    first.log_in(&account.password);

    let agents =
        procwait::user_agents(&prompt_agent_exe(), &account.sid, level).expect("list the agents of the account");
    assert!(!agents.is_empty(), "the login started no agent at {level:?}");
    let outcome = logout_over_ssh(kit, &login);
    assert_eq!(
        outcome.code,
        Some(0),
        "logout in the default session; stderr:\n{}\n{}",
        outcome.stderr,
        (login.diagnostics())()
    );
    assert!(
        outcome.stderr.contains(ENDING),
        "the agent's reply is missing from stderr:\n{}",
        outcome.stderr
    );
    for agent in &agents {
        bounded_wait::wait_for_exit(
            agent.handle(),
            agent.pid,
            "the agent after logout",
            bounded_wait::CHILD_EXIT_BOUND,
            &[],
        );
    }
    drop(first);
}

/// Elevated (CI only). An administrator's default session through the real sshd is unelevated and cannot
/// connect to its elevated agent's `agent.sock`; `ssh-broker.exe logout`, typed there by its full path, reaches the
/// agent on `request.sock`, which ends the session: the client exits 0 with the agent's reply, and the agent is
/// gone.
#[test]
fn logout_typed_in_an_unelevated_session_ends_the_session() {
    let _machine = machine::exclusive();
    account_fixture::assert_elevated();
    let kit = Kit::broker_with_helper("rqlo");
    let account = Account::create("rqlo", true);
    account.make_administrator();
    let _end = session_end::LogOutOnDrop::new(&prompt_agent_exe(), &account, ServiceLogon::Sshd);
    logout_ends_the_session_from_the_default_session(&account, &kit, Integrity::High);
}

/// Elevated (CI only). A standard account's agent runs below High and its sessions reach `agent.sock` in the
/// plain folder: `logout` there asks it, and there is no request socket to ask.
#[test]
fn a_standard_accounts_logout_still_uses_agent_sock() {
    let _machine = machine::exclusive();
    account_fixture::assert_elevated();
    let kit = Kit::broker_with_helper("rqst");
    let account = Account::create("rqst", true);
    let _end = session_end::LogOutOnDrop::new(&prompt_agent_exe(), &account, ServiceLogon::Sshd);
    logout_ends_the_session_from_the_default_session(&account, &kit, Integrity::Medium);
    assert!(
        !account.socket_location().request_path().exists(),
        "an agent below High keeps no request socket"
    );
}

// A plain folder that is refused =====

/// Elevated (CI only). An administrator's agent whose plain folder is not as the agent makes it (here, a folder
/// an administrator made, with the ACL it inherits) does not refuse to start: it serves its sessions, and has no
/// request socket, so `logout` in a default session says it could not reach the session, naming the folder, and
/// exits with `UNREACHABLE_CODE`. The agent is started as the product starts one for an account with no session (the
/// stored-password task of `auto-login on`) and ended by ending its process: its own `logout` is what cannot be
/// reached.
#[test]
fn an_agent_whose_plain_folder_is_wrongly_owned_serves_sessions_and_logout_says_why() {
    let _machine = machine::shared();
    account_fixture::assert_elevated();
    let kit = Kit::copy_of_broker("rqwo");
    let account = Account::create("rqwo", true);
    account.make_administrator();
    account.started_by(ServiceLogon::TaskScheduler);
    let plain = account
        .profile()
        .join(r"AppData\Local")
        .join(socket_loc::SOCKET_DIR_NAME);
    std::fs::create_dir_all(&plain).unwrap();

    let local = local_account(&account);
    autologin::on(&mut kit.autologin_env(&account.password), &local).unwrap();
    let location = account.socket_location();
    stand_in::wait_for_serving_marker_of_a_task(&location, stand_in::SERVING_BOUND);

    // A session that never ends fails after the connection's silence bound; the failure then says which session
    // it was and what the agent had logged.
    let ended = |what: &str, conn: &mut AgentConn| {
        session_end::attempt(what, || conn.read_to_end())
            .unwrap_or_else(|why| panic!("{why}\nthe agent's logs:\n{}", stand_in::read_logs(&location)))
    };
    let mut session = AgentConn::connect(&location, &account.sid);
    session.start_exec("cmd.exe /c echo still-serving");
    session.end_stdin();
    let served = ended("the session that echoes", &mut session);
    assert!(
        served.stdout.contains("still-serving"),
        "the agent did not serve a session: stdout {:?}, stderr {:?}",
        served.stdout,
        served.stderr
    );

    let mut asker = AgentConn::connect(&location, &account.sid);
    asker.start_exec(&format!("\"{}\" logout", kit.exe.display()));
    asker.end_stdin();
    let asked = ended("the session that runs logout", &mut asker);
    assert_eq!(asked.exit, Some(UNREACHABLE_CODE), "stderr: {:?}", asked.stderr);
    assert!(
        asked.stderr.contains("could not reach your session")
            && asked
                .stderr
                .to_lowercase()
                .contains(&plain.display().to_string().to_lowercase()),
        "logout does not name the folder {}: {:?}",
        plain.display(),
        asked.stderr
    );
    assert!(
        !asked.stderr.contains("no session to end"),
        "a refused folder is not the absence of a session: {:?}",
        asked.stderr
    );

    // The agent's own `logout` cannot be reached, so its process is ended; the task is deleted with the credential.
    let agents =
        procwait::user_agents(&kit.exe, &account.sid, Integrity::High).expect("list the agents of the account");
    assert!(!agents.is_empty(), "the task started no agent at High");
    for agent in &agents {
        agent.terminate().expect("end the agent");
    }
    procwait::wait_all_exited(&agents, procwait::EXIT_BOUND).expect("the agent exited");
    autologin::off(&mut kit.autologin_env(&account.password), &local).unwrap();
}
