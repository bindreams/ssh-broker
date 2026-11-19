//! What `apply` does to sshd's configuration and the system `PATH`, over the runner's real `sshd`. Windows only;
//! **Elevated (CI only)**.
//!
//! Each test starts from the runner's stock `sshd_config` (saved the first time any test of this file looks, and
//! put back by `install::reset`), takes the machine alone (`machine::exclusive()`), and changes machine-wide
//! state: sshd's configuration and its service, the `DefaultShell` values, the install directory, the system
//! `PATH`. A test that runs `apply` holds `install::Install`, which puts the install directory, the tasks, the
//! `DefaultShell` values and sshd's files back as `upgrade_windows` does, so that the directory is absent when the
//! test ends whichever binary runs first. The whole binary runs in nextest's `ci-exclusive` profile, where no
//! workflow step has put the exe in the install directory.
#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::Command;

use ssh_broker::acl::{copy_file_security, create_install_dir, install_dir_file_problem, install_dir_problem};
use ssh_broker::provision::path_env::{self, PathPlan};
use ssh_broker::provision::registry;
use ssh_broker::provision::sshd_config::configure::ConfigRead;
use ssh_broker::provision::sshd_config::machine::{configure_this_machine, sshd_reading_this_machine};
use ssh_broker::provision::sshd_config::{
    ACCEPT_LINE, DROP_IN_NAME, INCLUDE_LINE, SshdReading, accepts, accepts_row, drop_in_text, in_force, with_line,
};
use ssh_broker::provision::{BASE_DIR, canonical_exe};
use ssh_broker::socket_loc::Integrity;

#[path = "common/account.rs"]
mod account_fixture;
#[path = "common/agent_conn.rs"]
mod agent_conn;
#[path = "common/bounded_wait.rs"]
mod bounded_wait;
#[path = "common/desktop.rs"]
mod desktop;
#[path = "common/fs_state.rs"]
mod fs_state;
#[path = "common/hard_errors.rs"]
mod hard_errors;
#[path = "common/install.rs"]
mod install;
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
use fs_state::sddl_of;
use install::{Install, ResetAtTheEnd, candidate_path, config_path, drop_in_dir, drop_in_path, reset};
use sshd_rig::{Login, SshSession, restart_sshd, run, run_client, set_stock_shell, sshd_event_logs};
use stand_in::Kit;

/// What `apply`'s sshd step did and said: whether the running sshd takes the variable, and its lines.
fn configure() -> (bool, Vec<String>) {
    let mut said = Vec::new();
    let accepted = configure_this_machine(&mut |line| said.push(line.to_owned()));
    (accepted, said)
}

/// A step that changed a file of sshd's configuration under a running sshd: it says the service has to be
/// restarted, and that the variable is not taken yet.
fn assert_says_to_restart(accepted: bool, said: &[String]) {
    assert!(!accepted, "{said:#?}");
    let last = said.last().expect("the step said nothing");
    assert!(
        last.starts_with("apply: sshd was started before ")
            && last.contains("restart the sshd service for it to accept SSH_BROKER_ELEVATION"),
        "{said:#?}"
    );
}

/// What `sshd -T` and the row read of the machine: the variable is in force and the running sshd has read the
/// files. Asked of the real service, so it is true only after a restart that came after the last write.
fn assert_in_force_and_read() {
    match sshd_reading_this_machine().expect("an elevated administrator can read when sshd's SYSTEM process started") {
        SshdReading::Read { listing, read } => {
            assert!(in_force(&listing), "{listing}");
            assert_eq!(read, ConfigRead::Read, "sshd started after the files were written");
        }
        other => panic!("the sshd service was read as {other:?}"),
    }
    let row = accepts_row(Ok(Integrity::High), sshd_reading_this_machine);
    assert!(row.pass, "{}", row.detail);
}

/// `apply` itself put the variable in force in sshd's configuration, and has not restarted sshd. The rig's
/// `accept_elevation_variable` (run by `Login::new`) would configure sshd itself if `apply` had not, so a test that
/// logs in after `apply` cannot otherwise tell a defect in `apply`'s sshd step.
fn assert_apply_configured_sshd() {
    match sshd_reading_this_machine().expect("an elevated administrator can read sshd's configuration") {
        SshdReading::Read { listing, read } => {
            assert!(
                in_force(&listing),
                "apply did not put the variable in force:\n{listing}"
            );
            assert!(
                matches!(read, ConfigRead::Unread(_)),
                "apply does not restart sshd, so the files are newer than it: {read:?}"
            );
        }
        other => panic!("the sshd service was read as {other:?}"),
    }
}

/// What plain `sshd -T` prints, as the `verify` row reads it.
fn sshd_t() -> String {
    match sshd_reading_this_machine().expect("sshd -T") {
        SshdReading::Read { listing, .. } => listing,
        other => panic!("the sshd service was read as {other:?}"),
    }
}

/// `exe apply`, run by the test process (an elevated administrator): installs the build as the product does.
/// Returns what it printed; fails when it does not end with 0.
fn apply(kit: &Kit) -> String {
    let out = desktop::output(Command::new(&kit.exe).arg("apply")).expect("run apply");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success(), "apply failed ({:?}):\n{text}", out.status.code());
    text
}

fn system_cmd() -> PathBuf {
    Path::new(&std::env::var("SystemRoot").expect("SystemRoot is set")).join(r"System32\cmd.exe")
}

// The drop-in and the Include line =====

/// The step on the runner's stock file: the drop-in, the `Include` line above the first `Match`, the original's
/// security on the replacement, and the sentence that says sshd has to be restarted. After the restart (the
/// rig's, as an administrator would) the `verify` row passes and a second run says nothing.
#[test]
fn apply_s_sshd_step_adds_the_drop_in_and_the_include_above_the_first_match_and_the_row_passes() {
    let _machine = machine::exclusive();
    account_fixture::assert_elevated();
    let stock = reset();
    let _reset = ResetAtTheEnd;
    let security_before = sddl_of(&config_path());

    let (accepted, said) = configure();
    assert_says_to_restart(accepted, &said);
    assert_eq!(
        std::fs::read(config_path()).unwrap(),
        with_line(stock, INCLUDE_LINE).unwrap(),
        "the file is the stock one with the one line above its first Match"
    );
    assert_eq!(std::fs::read(drop_in_path()).unwrap(), drop_in_text().as_bytes());
    assert_eq!(install_dir_problem(&drop_in_dir()).unwrap(), None);
    assert_eq!(install_dir_file_problem(&drop_in_path()).unwrap(), None);
    assert_eq!(
        sddl_of(&config_path()),
        security_before,
        "the replacement has the original's owner and ACL"
    );
    assert!(
        !candidate_path().exists(),
        "the candidate was renamed over the original"
    );
    assert!(
        accepts(&sshd_t(), ssh_broker::protocol::ElevationPolicy::VARIABLE),
        "plain `sshd -T` shows the variable"
    );
    let row = accepts_row(Ok(Integrity::High), sshd_reading_this_machine);
    assert!(!row.pass, "sshd has not read the files yet: {}", row.detail);

    restart_sshd();
    assert_in_force_and_read();

    // A second run changes nothing: sshd started after every file was written, so the step has nothing to say.
    let (again, said) = configure();
    assert!(again && said.is_empty(), "{said:#?}");
}

/// An `Include` that covers the drop-in is already there: the file is not touched and the variable is accepted
/// (the drop-in that the `Include` reads is written).
#[test]
fn a_config_with_an_include_already_present_is_left_alone_and_accepts() {
    let _machine = machine::exclusive();
    account_fixture::assert_elevated();
    let edited = with_line(reset(), INCLUDE_LINE).unwrap();
    let _reset = ResetAtTheEnd;
    std::fs::write(config_path(), &edited).unwrap();

    let (accepted, said) = configure();
    assert_says_to_restart(accepted, &said);
    assert_eq!(std::fs::read(config_path()).unwrap(), edited);
    assert_eq!(std::fs::read(drop_in_path()).unwrap(), drop_in_text().as_bytes());
    assert!(accepts(&sshd_t(), ssh_broker::protocol::ElevationPolicy::VARIABLE));
}

/// A file in `sshd_config.d` that sshd rejects makes the candidate fail `sshd -t` only once the `Include` is in it:
/// the original stays as it was, byte for byte, and `apply` says which line to add.
#[test]
fn an_unparseable_candidate_leaves_the_original_untouched() {
    let _machine = machine::exclusive();
    account_fixture::assert_elevated();
    let stock = reset();
    let _reset = ResetAtTheEnd;
    create_install_dir(&drop_in_dir()).expect("make the drop-in folder");
    std::fs::write(drop_in_dir().join("99-broken.conf"), "ThisIsNotAnSshdOption yes\r\n").unwrap();

    let (accepted, said) = configure();
    assert!(!accepted, "{said:#?}");
    assert_eq!(
        std::fs::read(config_path()).unwrap(),
        stock,
        "the original is untouched"
    );
    assert!(!candidate_path().exists(), "the candidate is removed");
    assert!(
        said.iter()
            .any(|line| line.contains(ACCEPT_LINE) && line.contains("above the first `Match`")),
        "{said:#?}"
    );
}

/// The drop-in is replaced whole or not at all: when the new file beside it cannot be made (the name it would take
/// is a folder here), `apply` leaves the drop-in with the text it had, says the folder is left as it is, and puts the
/// `AcceptEnv` line into `sshd_config` instead.
#[test]
fn a_drop_in_that_cannot_be_replaced_keeps_the_text_it_had() {
    let _machine = machine::exclusive();
    account_fixture::assert_elevated();
    let stock = reset();
    let _reset = ResetAtTheEnd;
    create_install_dir(&drop_in_dir()).expect("make the drop-in folder");
    // Made in the folder `apply` made, the file inherits what the folder gives it, as the step's own does.
    std::fs::write(drop_in_path(), "AcceptEnv OTHER\r\n").unwrap();
    assert_eq!(install_dir_file_problem(&drop_in_path()).unwrap(), None);
    std::fs::create_dir(drop_in_dir().join(format!("{DROP_IN_NAME}.ssh-broker-new")))
        .expect("take the new file's name");

    let (accepted, said) = configure();
    assert_says_to_restart(accepted, &said);
    assert_eq!(
        std::fs::read(drop_in_path()).unwrap(),
        b"AcceptEnv OTHER\r\n",
        "the drop-in is what it was"
    );
    assert_eq!(
        std::fs::read(config_path()).unwrap(),
        with_line(stock, ACCEPT_LINE).unwrap()
    );
    assert!(said.iter().any(|line| line.contains("is left as it is")), "{said:#?}");
}

/// A folder an administrator made by hand inherits `ProgramData\ssh`'s permissions, which are not the ones
/// `apply` makes it with: the premise is measured first. The folder is left as it is, no drop-in is written, and
/// the `AcceptEnv` line goes into `sshd_config` above its first `Match`.
#[test]
fn a_hand_made_sshd_config_d_gets_no_drop_in_and_sshd_config_gets_the_acceptenv_line() {
    let _machine = machine::exclusive();
    account_fixture::assert_elevated();
    let stock = reset();
    let _reset = ResetAtTheEnd;
    std::fs::create_dir(drop_in_dir()).expect("make the folder by hand");
    let problem = install_dir_problem(&drop_in_dir()).expect("judge the folder");
    assert!(
        problem.is_some(),
        "premise: a folder made by hand is not the folder apply makes"
    );

    let (accepted, said) = configure();
    assert_says_to_restart(accepted, &said);
    assert!(!drop_in_path().exists(), "no drop-in was written");
    assert_eq!(
        std::fs::read_dir(drop_in_dir()).unwrap().count(),
        0,
        "the folder is as it was"
    );
    assert_eq!(
        install_dir_problem(&drop_in_dir()).unwrap(),
        problem,
        "its permissions are as they were"
    );
    assert_eq!(
        std::fs::read(config_path()).unwrap(),
        with_line(stock, ACCEPT_LINE).unwrap()
    );
    assert!(
        said.iter()
            .any(|line| line.contains("is left as it is") && line.contains("accepted by a line in sshd_config")),
        "{said:#?}"
    );
    assert!(
        said.iter().all(|line| !line.to_ascii_lowercase().contains("remove")),
        "{said:#?}"
    );
    assert!(accepts(&sshd_t(), ssh_broker::protocol::ElevationPolicy::VARIABLE));
    restart_sshd();
    assert_in_force_and_read();
}

/// sshd reads its configuration when it starts, so a file written after that may not have been read: the `verify`
/// row fails for it until sshd is restarted: for `sshd_config`, for any other file in `sshd_config.d`, and for the
/// folder itself when an entry goes. This also measures that an elevated administrator can read when sshd's
/// process, which runs as SYSTEM, was created.
#[test]
fn a_configuration_written_after_sshd_started_fails_the_row_until_sshd_is_restarted() {
    let _machine = machine::exclusive();
    account_fixture::assert_elevated();
    reset();
    let _reset = ResetAtTheEnd;

    // The step writes both files and says to restart; the restart makes sshd start after both were written.
    let (accepted, said) = configure();
    assert_says_to_restart(accepted, &said);
    restart_sshd();
    assert_in_force_and_read();

    // The file is written again, with the same text: sshd cannot have read this write.
    std::fs::write(config_path(), std::fs::read(config_path()).unwrap()).unwrap();
    let row = accepts_row(Ok(Integrity::High), sshd_reading_this_machine);
    assert!(!row.pass, "{}", row.detail);
    assert!(
        row.detail.contains("started before")
            && row.detail.contains(&config_path().display().to_string())
            && row.detail.contains("restart the sshd service"),
        "{}",
        row.detail
    );

    // The step says the same of a variable already in force, and after a restart the row passes again.
    let (accepted, said) = configure();
    assert_says_to_restart(accepted, &said);
    restart_sshd();
    assert_in_force_and_read();

    // Every file in the folder is judged, whatever its name: another one, written after sshd started, fails the row.
    let other = drop_in_dir().join("50-other.conf");
    std::fs::write(&other, "# nothing\r\n").unwrap();
    let row = accepts_row(Ok(Integrity::High), sshd_reading_this_machine);
    assert!(!row.pass, "{}", row.detail);
    assert!(
        row.detail
            .contains(&format!("before {} was last changed", other.display())),
        "{}",
        row.detail
    );
    restart_sshd();
    assert_in_force_and_read();

    // So is the folder: a file that goes changes it, and the row fails for the folder (this measures that a folder's
    // change time moves when an entry goes).
    std::fs::remove_file(&other).unwrap();
    let row = accepts_row(Ok(Integrity::High), sshd_reading_this_machine);
    assert!(!row.pass, "{}", row.detail);
    assert!(
        row.detail
            .contains(&format!("before {} was last changed", drop_in_dir().display())),
        "{}",
        row.detail
    );
}

/// The copy of a file's security gives the destination the source's owner and DACL, also an owner the caller does
/// not get by default (SYSTEM), which needs `SeRestorePrivilege`; the privilege is enabled for the copy and put
/// back after it: an elevated administrator's token holds it disabled, and the process is left as it was found.
#[test]
fn copying_security_gives_the_owner_and_the_acl_and_leaves_the_restore_privilege_as_it_found_it() {
    account_fixture::assert_elevated();
    let state = || {
        let (ok, text) = run("whoami", &["/priv", "/fo", "csv", "/nh"]);
        assert!(ok, "whoami /priv: {text}");
        text.lines()
            .find(|line| line.contains("SeRestorePrivilege"))
            .unwrap_or_else(|| panic!("the token has no SeRestorePrivilege:\n{text}"))
            .to_owned()
    };
    let dir = std::env::temp_dir().join(format!("sb-copy-security-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (from, to) = (dir.join("from"), dir.join("to"));
    std::fs::write(&from, "a").unwrap();
    std::fs::write(&to, "b").unwrap();
    let (ok, text) = run("icacls", &[from.to_str().unwrap(), "/setowner", r"NT AUTHORITY\SYSTEM"]);
    assert!(ok, "give the source to SYSTEM: {text}");
    let (source_before, destination_before) = (sddl_of(&from), sddl_of(&to));
    assert_ne!(
        source_before, destination_before,
        "premise: the two files differ in their owner"
    );

    let before = state();
    let copied = copy_file_security(&from, &to);
    let after = state();
    let (source_after, destination_after) = (sddl_of(&from), sddl_of(&to));
    let _ = std::fs::remove_dir_all(&dir);
    copied.expect("copy the security");
    assert_eq!(after, before, "the privilege was left as the copy made it");
    assert_eq!(source_after, source_before, "the source is as it was");
    assert_eq!(
        destination_after, source_before,
        "the destination has the source's owner and ACL"
    );
}

/// A login that sets the variable through `SetEnv` gets it in its shell after `apply`, over the real sshd: the
/// stock `cmd.exe` is the shell here, so what it prints is what sshd delivered.
#[test]
fn a_login_with_set_env_always_gets_the_variable_after_apply() {
    let _machine = machine::exclusive();
    account_fixture::assert_elevated();
    let _install = Install::capture();
    reset();
    let kit = Kit::broker_with_helper("sshe");
    apply(&kit);
    assert_apply_configured_sshd();
    let account = Account::create("sshe", true);
    // sshd's logon keeps the account's hive loaded, so the account is declared as logged on by sshd, which is how
    // `Account::drop` deletes the profile; no agent runs for it, so there is none to end (see `session_end`).
    account.started_by(ServiceLogon::Sshd);
    let login = Login::new(&kit, &account);
    set_stock_shell(&system_cmd());

    let mut ssh = login.command_asking("always");
    ssh.arg("-T").arg("--").arg("echo [%SSH_BROKER_ELEVATION%]");
    let outcome = run_client(ssh, false, kit.dir());
    let shown = String::from_utf8_lossy(&outcome.stdout).into_owned();
    assert!(
        shown.contains("[always]"),
        "the shell did not see the variable (exit {:?}):\n{shown}\n{}\n{}",
        outcome.code,
        outcome.stderr,
        (login.diagnostics())()
    );
}

// The PATH =====

/// Take the install directory out of the system `PATH`, as a machine that was never installed has it. The value
/// keeps its registry type.
fn remove_install_dir_from_path() {
    let stored = registry::read_system_path()
        .expect("read the system PATH")
        .expect("the system PATH has a value");
    let (value, expand) = match stored {
        path_env::Stored::Sz(value) => (value, false),
        path_env::Stored::ExpandSz(value) => (value, true),
        path_env::Stored::Other(kind) => panic!("the system PATH is not a string: registry type {kind}"),
    };
    let kept: Vec<&str> = value
        .split(';')
        .filter(|segment| !segment.trim_end_matches('\\').eq_ignore_ascii_case(BASE_DIR))
        .collect();
    registry::write_system_path(&kept.join(";"), expand).expect("write the system PATH");
}

fn install_dir_is_on_path() -> bool {
    matches!(
        path_env::plan(&registry::read_system_path(), BASE_DIR, |text| Ok(text
            .encode_utf16()
            .count())),
        PathPlan::Present
    )
}

/// `apply` puts the install directory on the system `PATH`, and `verify` (an elevated one) says so.
#[test]
fn apply_puts_the_install_directory_on_the_system_path_and_verify_says_so() {
    let _machine = machine::exclusive();
    account_fixture::assert_elevated();
    let _install = Install::capture();
    reset();
    let kit = Kit::broker_with_helper("sshp");
    apply(&kit);
    remove_install_dir_from_path();
    assert!(!install_dir_is_on_path(), "the directory was taken off the PATH");

    let said = apply(&kit);
    assert!(
        install_dir_is_on_path(),
        "apply did not put {BASE_DIR} on the PATH:\n{said}"
    );

    let verify = desktop::output(Command::new(canonical_exe()).arg("verify")).expect("run verify");
    let shown = String::from_utf8_lossy(&verify.stdout).into_owned();
    assert!(
        shown
            .lines()
            .any(|line| line.starts_with("[PASS] install directory on PATH")),
        "verify does not say the directory is on the PATH:\n{shown}"
    );
}

/// What a PowerShell session says of where `ssh-broker` is found, typed as a line whose markers the echo of the
/// typed line does not hold: the answer ends in `;done`, which the shell joins (as in
/// [`SshSession::check_relayed_shell`]).
fn type_where_ssh_broker_is(session: &mut SshSession) -> String {
    session.type_line(
        "Write-Output ('found' + '=' + [string](Get-Command ssh-broker -ErrorAction SilentlyContinue).Source + ';do' + 'ne')",
    );
    session.read_until(";done");
    let text = session.text();
    let at = text.rfind("found=").expect("the session answered");
    text[at + "found=".len()..]
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_owned()
}

/// A session started after `apply` finds `ssh-broker` by name.
#[test]
fn after_apply_a_new_session_runs_ssh_broker_by_name() {
    let _machine = machine::exclusive();
    account_fixture::assert_elevated();
    let _install = Install::capture();
    reset();
    let kit = Kit::broker_with_helper("sshn");
    apply(&kit);
    remove_install_dir_from_path();
    apply(&kit);
    assert_apply_configured_sshd();
    let account = Account::create("sshn", true);
    let _end = session_end::LogOutOnDrop::new(&canonical_exe(), &account, ServiceLogon::Sshd);
    let login = Login::new(&kit, &account);

    // No agent runs for the account: the prompt starts one, after the PATH was written, so its sessions have it.
    let mut session = login.start();
    session.log_in(&account.password);
    let found = type_where_ssh_broker_is(&mut session);
    assert!(
        found.eq_ignore_ascii_case(&canonical_exe().to_string_lossy()),
        "a session started after apply does not find ssh-broker by name: {found:?}\n{}",
        session.text()
    );
    session.leave();
}

/// An agent's environment is fixed when it starts, so the sessions of an agent that `apply` did not restart lack
/// the install directory until it restarts.
#[test]
fn an_agent_that_apply_did_not_restart_keeps_its_old_path_until_it_restarts() {
    let _machine = machine::exclusive();
    account_fixture::assert_elevated();
    let _install = Install::capture();
    reset();
    let kit = Kit::broker_with_helper("sshk");
    apply(&kit);
    assert_apply_configured_sshd();
    remove_install_dir_from_path();
    let account = Account::create("sshk", true);
    let _end = session_end::LogOutOnDrop::new(&canonical_exe(), &account, ServiceLogon::Sshd);
    let login = Login::new(&kit, &account);

    // The agent starts with a PATH that lacks the directory.
    let mut first = login.start();
    first.log_in(&account.password);
    assert_eq!(
        type_where_ssh_broker_is(&mut first),
        "",
        "the agent started with the old PATH"
    );

    // `apply` of the installed build puts the directory on the PATH and restarts no agent.
    apply(&kit);
    assert!(install_dir_is_on_path());
    let mut second = login.start_into_running_session();
    assert_eq!(
        type_where_ssh_broker_is(&mut second),
        "",
        "the running agent's new session has the directory: its environment was not fixed at its start"
    );
    second.leave();
    first.leave();

    // Once the agent has ended, the next one starts with the PATH as it is.
    session_end::log_out_running(&canonical_exe(), &account, ServiceLogon::Sshd);
    let mut third = login.start();
    third.log_in(&account.password);
    let found = type_where_ssh_broker_is(&mut third);
    assert!(
        found.eq_ignore_ascii_case(&canonical_exe().to_string_lossy()),
        "a restarted agent's session does not find ssh-broker by name: {found:?}\n{}",
        third.text()
    );
    third.leave();
}

// verify through a session the prompt started =====

/// The `verify` of an installed build, through a session that the password prompt started: an administrator with no
/// agent logs in with a terminal and types the password at the product's own prompt, so the installed shim starts
/// the installed agent by its batch logon. A login asking `always` then runs the installed exe's `verify`, whose
/// parity probes go through that agent. A junction row that is not "followed" is the RedirectionGuard signal for the
/// password-prompt start path on the runner: stop and report it.
#[test]
fn after_apply_verify_passes_through_a_session_the_password_prompt_started() {
    let _machine = machine::exclusive();
    account_fixture::assert_elevated();
    let _install = Install::capture();
    reset();
    let kit = Kit::broker_with_helper("sshv");
    apply(&kit);
    assert_apply_configured_sshd();
    let installed = canonical_exe();
    let account = Account::create("sshv", true);
    account.make_administrator();
    let _end = session_end::LogOutOnDrop::new(&installed, &account, ServiceLogon::Sshd);
    let login = Login::new(&kit, &account);

    let mut prompted = login.start();
    prompted.log_in(&account.password);

    let mut verify = login.command_asking("always");
    verify
        .arg("-T")
        .arg("--")
        .arg(format!("& '{}' verify", installed.display()));
    let outcome = run_client(verify, false, kit.dir());
    let shown = String::from_utf8_lossy(&outcome.stdout).into_owned();
    assert_eq!(
        outcome.code,
        Some(0),
        "verify did not pass (exit {:?}):\n{shown}\n{}\n{}",
        outcome.code,
        outcome.stderr,
        (login.diagnostics())()
    );
    agent_conn::assert_verify_session_rows(&shown);
    prompted.leave();
}

// A connection after the step =====

/// After the step and a restart, sshd answers a connection: a login for a user that does not exist does the key
/// exchange and ends with "Permission denied". An sshd that cannot read what its configuration includes resets
/// the connection right after the client's version line instead.
#[test]
fn sshd_answers_a_connection_after_the_step_and_a_restart() {
    let _machine = machine::exclusive();
    account_fixture::assert_elevated();
    reset();
    let _reset = ResetAtTheEnd;

    let (accepted, said) = configure();
    assert_says_to_restart(accepted, &said);
    restart_sshd();

    let mut ssh = Command::new("ssh");
    ssh.args([
        "-v",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=NUL",
        "-o",
        "ConnectTimeout=20",
        "nobody-such-user@localhost",
        "true",
    ]);
    let outcome = run_client(ssh, false, &std::env::temp_dir());
    let text = format!("{}{}", String::from_utf8_lossy(&outcome.stdout), outcome.stderr);
    let mut last: Vec<&str> = text.lines().rev().take(10).collect();
    last.reverse();
    assert!(
        text.contains("Permission denied") && !text.contains("Connection reset"),
        "sshd did not answer the connection (ssh exit {:?}); the client's last lines:\n{}\n{}",
        outcome.code,
        last.join("\n"),
        sshd_event_logs(25)
    );
}
