//! What `install` does to sshd's configuration and the system `PATH`, over the runner's real `sshd`. Windows only;
//! **Elevated (CI only)**.
//!
//! Each test starts from the runner's stock `sshd_config` (saved the first time any test of this file looks, and
//! put back by `install::reset`), takes the machine alone (`machine::exclusive()`), and changes machine-wide
//! state: sshd's configuration and its service, the `DefaultShell` values, the install directory, the system
//! `PATH`. A test that runs `install` holds `install::Install`, which puts the install directory, the tasks, the
//! `DefaultShell` values and sshd's files back as `upgrade_windows` does, so that the directory is absent when the
//! test ends whichever binary runs first. The whole binary runs in nextest's `ci-exclusive` profile, where no
//! workflow step has put the exe in the install directory.
#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::Command;

use ssh_broker::acl::{copy_file_security, create_install_dir, install_dir_file_problem, install_dir_problem};
use ssh_broker::provision::path_env::{self, PathPlan};
use ssh_broker::provision::procwait::{Process, Role};
use ssh_broker::provision::registry;
use ssh_broker::provision::schtasks::WaitOutcome;
use ssh_broker::provision::sshd_config::configure::{ConfigRead, SshdHost};
use ssh_broker::provision::sshd_config::machine::{
    configure_this_machine, sshd_host_of_this_machine, sshd_reading_this_machine,
};
use ssh_broker::provision::sshd_config::restart::{ServiceState, StartOutcome, StartReply, StopOutcome};
use ssh_broker::provision::sshd_config::{
    ACCEPT_LINE, DROP_IN_NAME, INCLUDE_LINE, LineKind, SshdReading, accepts, accepts_row, drop_in_text, in_force,
    render, with_line,
};
use ssh_broker::provision::sshd_task;
use ssh_broker::provision::{BASE_DIR, canonical_exe, installed_line, version};
use ssh_broker::provision::{schtasks, taskscheduler};
use ssh_broker::socket_loc::Elevation;

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
#[path = "common/session_end.rs"]
mod session_end;
#[path = "common/sshd_rig.rs"]
mod sshd_rig;
#[path = "common/stand_in.rs"]
mod stand_in;

use account_fixture::{Account, ServiceLogon};
use fs_state::sddl_of;
use install::{Install, ResetAtTheEnd, candidate_path, config_path, drop_in_dir, drop_in_path, reset};
use sshd_rig::{Login, SshSession, run, run_client, set_stock_shell, sshd_event_logs, sshd_service_pid};
use stand_in::Kit;
use windows::Win32::Foundation::WAIT_OBJECT_0;
use windows::Win32::System::Threading::WaitForSingleObject;

/// What `install`'s sshd step did and said: whether the running sshd takes the variable, and its lines as the
/// report holds them (a warning begins with `warning: `, a note with nothing).
fn configure() -> (bool, Vec<String>) {
    let mut said = Vec::new();
    let accepted = configure_this_machine(&mut |kind, text| said.push(render(kind, text)));
    (accepted, said)
}

/// A step that changed a file of sshd's configuration under a running sshd: it restarted the service, and says
/// in a note that sshd restarted and accepts the variable.
fn assert_restarted(accepted: bool, said: &[String]) {
    assert!(accepted, "{said:#?}");
    assert_eq!(
        said.last().expect("the step said nothing"),
        "sshd restarted; it accepts SSH_BROKER_ELEVATION",
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
    let row = accepts_row(&Ok(Elevation::Full), sshd_reading_this_machine);
    assert!(row.pass, "{}", row.detail);
}

/// `install` itself put the variable in force in sshd's configuration, and restarted sshd after it. The rig's
/// `accept_elevation_variable` (run by `Login::new`) would configure sshd itself if `install` had not, so a test that
/// logs in after `install` cannot otherwise tell a defect in `install`'s sshd step.
fn assert_install_configured_sshd() {
    match sshd_reading_this_machine().expect("an elevated administrator can read sshd's configuration") {
        SshdReading::Read { listing, read } => {
            assert!(
                in_force(&listing),
                "install did not put the variable in force:\n{listing}"
            );
            assert_eq!(
                read,
                ConfigRead::Read,
                "install restarted sshd after it wrote the files"
            );
        }
        other => panic!("the sshd service was read as {other:?}"),
    }
}

/// What plain `sshd -T` prints, as the `doctor` row reads it.
fn sshd_t() -> String {
    match sshd_reading_this_machine().expect("sshd -T") {
        SshdReading::Read { listing, .. } => listing,
        other => panic!("the sshd service was read as {other:?}"),
    }
}

/// `exe install`, run by the test process (an elevated administrator): installs the build as the product does.
/// Returns what it printed on standard output and on standard error; fails when it does not end with 0.
fn install_streams(kit: &Kit) -> (String, String) {
    let out = desktop::output(Command::new(&kit.exe).arg("install")).expect("run install");
    let (stdout, stderr) = (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    );
    assert!(
        out.status.success(),
        "install failed ({:?}):\n{stdout}{stderr}",
        out.status.code()
    );
    (stdout, stderr)
}

/// [`install_streams`], both streams in one text.
fn run_install(kit: &Kit) -> String {
    let (stdout, stderr) = install_streams(kit);
    format!("{stdout}{stderr}")
}

/// What the report of `install`'s sshd step holds.
fn report() -> sshd_task::Report {
    let path = sshd_task::report_path();
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read the report {}: {e}", path.display()));
    sshd_task::Report::parse(&text)
}

/// The lines of `report`, as the report file holds them.
fn rendered(report: &sshd_task::Report) -> Vec<String> {
    report.lines.iter().map(|line| render(line.kind, &line.text)).collect()
}

/// No task of the sshd step is left registered.
fn assert_no_sshd_task_is_left() {
    assert_eq!(
        taskscheduler::task_xml(schtasks::INSTALL_SSHD_TASK).expect("ask the Task Scheduler"),
        None,
        "install left the task {} registered",
        schtasks::INSTALL_SSHD_TASK
    );
}

fn system_cmd() -> PathBuf {
    Path::new(&std::env::var("SystemRoot").expect("SystemRoot is set")).join(r"System32\cmd.exe")
}

// The drop-in and the Include line =====

/// The step on the runner's stock file, run by `install` through its task, as SYSTEM: the drop-in, the `Include` line
/// above the first `Match`, the original's security on the replacement (SYSTEM can create the drop-in and
/// `copy_file_security` works as SYSTEM), and the restart of sshd. No task is left after `install`. A healthy first
/// install says the step line, last before the installed line, and nothing of the step on standard error: its
/// report is complete and holds no warning, and what the step did is in its notes. Every line on standard output but
/// the last ends in `...`, and no line on either stream begins with `install`. After the restart the `doctor` row
/// passes and a second run says nothing.
#[test]
fn install_s_sshd_step_adds_the_drop_in_and_the_include_above_the_first_match_and_the_row_passes() {
    let _machine = machine::exclusive();
    account_fixture::assert_elevated();
    let _install = Install::capture();
    let _running = SshdRunningAtTheEnd;
    let stock = reset();
    let kit = Kit::broker_with_helper("sshs");
    let security_before = sddl_of(&config_path());

    let (stdout, stderr) = install_streams(&kit);
    let installed = installed_line(version());
    let out_lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        out_lines.last(),
        Some(&installed.as_str()),
        "install's last line says it is installed:\n{stdout}"
    );
    assert_eq!(
        out_lines[out_lines.len() - 2],
        sshd_task::step_line(&canonical_exe(), &sshd_task::report_path()),
        "the step line is the last before the installed line, and names the report and the installed exe:\n{stdout}"
    );
    assert!(out_lines[out_lines.len() - 2].starts_with(sshd_task::HANDED_OVER_PREFIX));
    for line in &out_lines[..out_lines.len() - 1] {
        assert!(line.ends_with("..."), "a step line says that it is going on: {line}");
    }
    for line in stdout.lines().chain(stderr.lines()) {
        let first = line.split(|c: char| !c.is_alphanumeric()).next().unwrap_or_default();
        assert!(
            !first.eq_ignore_ascii_case("install"),
            "a line begins with the verb: {line}"
        );
    }
    let report = report();
    assert!(
        report.complete,
        "the report ends with its closing line: {:#?}",
        report.lines
    );
    assert_eq!(
        report.warnings().collect::<Vec<_>>(),
        Vec::<&str>::new(),
        "a healthy first install reports no warning"
    );
    assert_eq!(
        report.lines.last().map(|line| line.kind),
        Some(LineKind::Note),
        "the report's last line is a note that says what the step did"
    );
    // Standard error holds no line of the step: not a line of the report, and none of `hand_over`'s own warnings
    // (each of which names the task).
    for line in stderr.lines() {
        assert!(
            !line.contains(schtasks::INSTALL_SSHD_TASK) && report.lines.iter().all(|reported| reported.text != line),
            "standard error holds a line of the sshd step: {line}"
        );
    }
    let said = rendered(&report);
    assert_restarted(true, &said);
    assert_no_sshd_task_is_left();
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
    assert_in_force_and_read();

    // A second run changes nothing: sshd started after every file was written, so the step has nothing to say.
    let (again, said) = configure();
    assert!(again && said.is_empty(), "{said:#?}");
}

/// A warning of the step is on standard error. A drop-in that sshd rejects makes `sshd_config` need a line added by
/// hand: the step changes nothing, says in a warning which line to add, and `install` shows that warning on standard
/// error, where the report (which `install` ran as the task) holds it too. The step line is still said first.
#[test]
fn install_says_on_standard_error_which_line_to_add_when_sshd_config_cannot_be_edited() {
    let _machine = machine::exclusive();
    account_fixture::assert_elevated();
    let _install = Install::capture();
    let _running = SshdRunningAtTheEnd;
    reset();
    let _reset = ResetAtTheEnd;
    create_install_dir(&drop_in_dir()).expect("make the drop-in folder");
    std::fs::write(drop_in_dir().join("99-broken.conf"), "ThisIsNotAnSshdOption yes\r\n").unwrap();
    let kit = Kit::broker_with_helper("sshw");

    let (stdout, stderr) = install_streams(&kit);
    let report = report();
    let advice: Vec<&str> = report
        .warnings()
        .filter(|warning| warning.contains(ACCEPT_LINE) && warning.contains("above the first `Match`"))
        .collect();
    assert_eq!(advice.len(), 1, "{:#?}", report.lines);
    assert!(
        stderr.lines().any(|line| line == advice[0]),
        "the warning is on standard error:\n{stderr}\n{advice:?}"
    );
    assert!(
        stdout
            .lines()
            .any(|line| line.starts_with(sshd_task::HANDED_OVER_PREFIX)),
        "the step line is on standard output:\n{stdout}"
    );
    assert_no_sshd_task_is_left();
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
    assert_restarted(accepted, &said);
    assert_eq!(std::fs::read(config_path()).unwrap(), edited);
    assert_eq!(std::fs::read(drop_in_path()).unwrap(), drop_in_text().as_bytes());
    assert!(accepts(&sshd_t(), ssh_broker::protocol::ElevationPolicy::VARIABLE));
}

/// A file in `sshd_config.d` that sshd rejects makes the candidate fail `sshd -t` only once the `Include` is in it:
/// the original stays as it was, byte for byte, and `install` says which line to add.
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
/// is a folder here), `install` leaves the drop-in with the text it had, says the folder is left as it is, and puts the
/// `AcceptEnv` line into `sshd_config` instead.
#[test]
fn a_drop_in_that_cannot_be_replaced_keeps_the_text_it_had() {
    let _machine = machine::exclusive();
    account_fixture::assert_elevated();
    let stock = reset();
    let _reset = ResetAtTheEnd;
    create_install_dir(&drop_in_dir()).expect("make the drop-in folder");
    // Made in the folder `install` made, the file inherits what the folder gives it, as the step's own does.
    std::fs::write(drop_in_path(), "AcceptEnv OTHER\r\n").unwrap();
    assert_eq!(install_dir_file_problem(&drop_in_path()).unwrap(), None);
    std::fs::create_dir(drop_in_dir().join(format!("{DROP_IN_NAME}.ssh-broker-new")))
        .expect("take the new file's name");

    let (accepted, said) = configure();
    assert_restarted(accepted, &said);
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
/// `install` makes it with: the premise is measured first. The folder is left as it is, no drop-in is written, and
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
        "premise: a folder made by hand is not the folder install makes"
    );

    let (accepted, said) = configure();
    assert_restarted(accepted, &said);
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
    assert_in_force_and_read();
}

/// sshd reads its configuration when it starts, so a file written after that may not have been read: the `doctor`
/// row fails for it until sshd is restarted (by the step, which restarts it): for `sshd_config`, for any other
/// file in `sshd_config.d`, and for the folder itself when an entry goes. This also measures that an elevated
/// administrator can read when sshd's process, which runs as SYSTEM, was created.
#[test]
fn a_configuration_written_after_sshd_started_fails_the_row_until_sshd_is_restarted() {
    let _machine = machine::exclusive();
    account_fixture::assert_elevated();
    reset();
    let _reset = ResetAtTheEnd;

    // The step writes both files and restarts sshd, which then starts after both were written.
    let (accepted, said) = configure();
    assert_restarted(accepted, &said);
    assert_in_force_and_read();

    // The file is written again, with the same text: sshd cannot have read this write.
    std::fs::write(config_path(), std::fs::read(config_path()).unwrap()).unwrap();
    let row = accepts_row(&Ok(Elevation::Full), sshd_reading_this_machine);
    assert!(!row.pass, "{}", row.detail);
    assert!(
        row.detail.contains("started before")
            && row.detail.contains(&config_path().display().to_string())
            && row.detail.contains("restart the sshd service"),
        "{}",
        row.detail
    );

    // The step restarts sshd for a variable already in force, and after the restart the row passes again.
    let (accepted, said) = configure();
    assert_restarted(accepted, &said);
    assert_in_force_and_read();

    // Every file in the folder is judged, whatever its name: another one, written after sshd started, fails the row.
    let other = drop_in_dir().join("50-other.conf");
    std::fs::write(&other, "# nothing\r\n").unwrap();
    let row = accepts_row(&Ok(Elevation::Full), sshd_reading_this_machine);
    assert!(!row.pass, "{}", row.detail);
    assert!(
        row.detail
            .contains(&format!("before {} was last changed", other.display())),
        "{}",
        row.detail
    );
    let (accepted, said) = configure();
    assert_restarted(accepted, &said);
    assert_in_force_and_read();

    // So is the folder: a file that goes changes it, and the row fails for the folder (this measures that a folder's
    // change time moves when an entry goes).
    std::fs::remove_file(&other).unwrap();
    let row = accepts_row(&Ok(Elevation::Full), sshd_reading_this_machine);
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
    // `icacls /setowner` marks the source's DACL auto-inherited (`D:AI`). The marker records how Windows last
    // propagated the entries and is not part of what is copied: the owner and the entries are.
    let entries = |sddl: &str| sddl.replacen("D:AI(", "D:(", 1);
    assert_eq!(
        entries(&destination_after),
        entries(&source_before),
        "the destination has the source's owner and ACL"
    );
}

/// A login that sets the variable through `SetEnv` gets it in its shell after `install`, over the real sshd: the
/// stock `cmd.exe` is the shell here, so what it prints is what sshd delivered.
#[test]
fn a_login_with_set_env_always_gets_the_variable_after_install() {
    let _machine = machine::exclusive();
    account_fixture::assert_elevated();
    let _install = Install::capture();
    reset();
    let kit = Kit::broker_with_helper("sshe");
    run_install(&kit);
    assert_install_configured_sshd();
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

/// `install` puts the install directory on the system `PATH`, and `doctor` (an elevated one) says so.
#[test]
fn install_puts_the_install_directory_on_the_system_path_and_doctor_says_so() {
    let _machine = machine::exclusive();
    account_fixture::assert_elevated();
    let _install = Install::capture();
    reset();
    let kit = Kit::broker_with_helper("sshp");
    run_install(&kit);
    remove_install_dir_from_path();
    assert!(!install_dir_is_on_path(), "the directory was taken off the PATH");

    let said = run_install(&kit);
    assert!(
        install_dir_is_on_path(),
        "install did not put {BASE_DIR} on the PATH:\n{said}"
    );

    let doctor = desktop::output(Command::new(canonical_exe()).arg("doctor")).expect("run doctor");
    let shown = String::from_utf8_lossy(&doctor.stdout).into_owned();
    assert_eq!(
        shown.lines().next(),
        Some(format!("ssh-broker v{} ({})", version(), canonical_exe().display()).as_str()),
        "doctor's report does not begin with the version and the path of the exe that ran:\n{shown}"
    );
    assert!(
        shown
            .lines()
            .any(|line| line.starts_with("[PASS] install directory on PATH")),
        "doctor does not say the directory is on the PATH:\n{shown}"
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

/// A session started after `install` finds `ssh-broker` by name.
#[test]
fn after_install_a_new_session_runs_ssh_broker_by_name() {
    let _machine = machine::exclusive();
    account_fixture::assert_elevated();
    let _install = Install::capture();
    reset();
    let kit = Kit::broker_with_helper("sshn");
    run_install(&kit);
    remove_install_dir_from_path();
    run_install(&kit);
    assert_install_configured_sshd();
    let account = Account::create("sshn", true);
    let _end = session_end::LogOutOnDrop::new(&canonical_exe(), &account, ServiceLogon::Sshd);
    let login = Login::new(&kit, &account);

    // No agent runs for the account: the prompt starts one, after the PATH was written, so its sessions have it.
    let mut session = login.start();
    session.log_in(&account.password);
    let found = type_where_ssh_broker_is(&mut session);
    assert!(
        found.eq_ignore_ascii_case(&canonical_exe().to_string_lossy()),
        "a session started after install does not find ssh-broker by name: {found:?}\n{}",
        session.text()
    );
    session.leave();
}

/// An agent's environment is fixed when it starts, so the sessions of an agent that `install` did not restart lack
/// the install directory until it restarts.
#[test]
fn an_agent_that_install_did_not_restart_keeps_its_old_path_until_it_restarts() {
    let _machine = machine::exclusive();
    account_fixture::assert_elevated();
    let _install = Install::capture();
    reset();
    let kit = Kit::broker_with_helper("sshk");
    run_install(&kit);
    assert_install_configured_sshd();
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

    // `install` of the installed build puts the directory on the PATH and restarts no agent.
    run_install(&kit);
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

// doctor through a session the prompt started =====

/// The `doctor` of an installed build, through a session that the password prompt started: an administrator with no
/// agent logs in with a terminal and types the password at the product's own prompt, so the installed shim starts
/// the installed agent by its batch logon. A login asking `always` then runs the installed exe's `doctor`, whose
/// parity probes go through that agent. A junction row that is not "followed" is the RedirectionGuard signal for the
/// password-prompt start path on the runner: stop and report it. A login asking `auto-approve` runs the same
/// `doctor` unelevated, which is told the ways to check and exits 1; a second login asking `auto-approve` runs one
/// of them, `ssh-broker elevate ssh-broker doctor` by name, which passes.
#[test]
fn after_install_doctor_passes_through_a_session_the_password_prompt_started() {
    use ssh_broker::offer::text::CHECK_BELOW_HIGH_CLAUSE;

    let _machine = machine::exclusive();
    account_fixture::assert_elevated();
    let _install = Install::capture();
    reset();
    let kit = Kit::broker_with_helper("sshv");
    run_install(&kit);
    assert_install_configured_sshd();
    let installed = canonical_exe();
    let account = Account::create("sshv", true);
    account.make_administrator();
    let _end = session_end::LogOutOnDrop::new(&installed, &account, ServiceLogon::Sshd);
    let login = Login::new(&kit, &account);

    let mut prompted = login.start();
    prompted.log_in(&account.password);

    let mut doctor = login.command_asking("always");
    doctor
        .arg("-T")
        .arg("--")
        .arg(format!("& '{}' doctor", installed.display()));
    let outcome = run_client(doctor, false, kit.dir());
    let shown = String::from_utf8_lossy(&outcome.stdout).into_owned();
    assert_eq!(
        outcome.code,
        Some(0),
        "doctor did not pass (exit {:?}):\n{shown}\n{}\n{}",
        outcome.code,
        outcome.stderr,
        (login.diagnostics())()
    );
    agent_conn::assert_doctor_session_rows(&shown);

    let mut unelevated = login.command_asking("auto-approve");
    unelevated
        .arg("-T")
        .arg("--")
        .arg(format!("& '{}' doctor", installed.display()));
    let outcome = run_client(unelevated, false, kit.dir());
    let shown = String::from_utf8_lossy(&outcome.stdout).into_owned();
    assert_eq!(
        outcome.code,
        Some(1),
        "an unelevated doctor did not exit 1 (exit {:?}):\n{shown}\n{}\n{}",
        outcome.code,
        outcome.stderr,
        (login.diagnostics())()
    );
    assert!(
        shown.contains(CHECK_BELOW_HIGH_CLAUSE),
        "the ways to check are missing from:\n{shown}"
    );

    let mut elevated = login.command_asking("auto-approve");
    elevated.arg("-T").arg("--").arg("ssh-broker elevate ssh-broker doctor");
    let outcome = run_client(elevated, false, kit.dir());
    let shown = String::from_utf8_lossy(&outcome.stdout).into_owned();
    assert_eq!(
        outcome.code,
        Some(0),
        "the command doctor names did not pass (exit {:?}):\n{shown}\n{}\n{}",
        outcome.code,
        outcome.stderr,
        (login.diagnostics())()
    );
    agent_conn::assert_doctor_session_rows(&shown);
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
    assert_restarted(accepted, &said);

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

// The service manager =====

/// Starts the sshd service when the test ends, also when it fails: a runner whose sshd is down cannot be reached.
struct SshdRunningAtTheEnd;

impl Drop for SshdRunningAtTheEnd {
    fn drop(&mut self) {
        // Already running is the usual answer, and is not an error here.
        let _ = run("net", &["start", "sshd"]);
    }
}

/// Whether the process held by `process` has exited, as a state read and not as a wait.
fn has_exited(process: &Process) -> bool {
    // SAFETY: the handle is open with SYNCHRONIZE for as long as `process` is.
    let state = unsafe { WaitForSingleObject(process.handle(), 0) }; // sleep-ok: zero-timeout state check of a process handle, not a wait
    state == WAIT_OBJECT_0
}

/// The ports `sshd -T` names, from its listing's `port` lines.
fn ports_in(listing: &str) -> Vec<u16> {
    listing
        .lines()
        .filter_map(|line| line.trim().strip_prefix("port ")?.trim().parse().ok())
        .collect()
}

/// Whether the process `pid` owns a TCP socket in the listening state on `port`, as `netstat -ano` lists the
/// sockets of both families.
fn listens_on(pid: u32, port: u16) -> bool {
    let (ok, text) = run("netstat", &["-ano"]);
    assert!(ok, "netstat -ano failed:\n{text}");
    let (port, pid) = (port.to_string(), pid.to_string());
    text.lines().any(|line| {
        matches!(
            line.split_whitespace().collect::<Vec<_>>().as_slice(),
            ["TCP", local, _, "LISTENING", owner] if local.rsplit(':').next() == Some(port.as_str()) && *owner == pid
        )
    })
}

/// Exclusive listeners of this process on `port`, on the IPv4 and IPv6 wildcard addresses sshd listens on by
/// default: while they are held, sshd cannot bind the port. Dropped, they release it.
fn hold(port: u16) -> Vec<socket2::Socket> {
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::os::windows::io::AsRawSocket;
    use windows::Win32::Networking::WinSock::{SO_EXCLUSIVEADDRUSE, SOCKET, SOL_SOCKET, setsockopt};

    let addresses = [
        (Domain::IPV4, SocketAddr::from((Ipv4Addr::UNSPECIFIED, port))),
        (Domain::IPV6, SocketAddr::from((Ipv6Addr::UNSPECIFIED, port))),
    ];
    addresses
        .into_iter()
        .map(|(domain, address)| {
            let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP)).expect("make a socket");
            if domain == Domain::IPV6 {
                socket.set_only_v6(true).expect("keep the IPv6 socket to IPv6");
            }
            let on = 1i32.to_ne_bytes();
            // SAFETY: the socket is open for the call, and `on` is the int the option takes.
            let set = unsafe {
                setsockopt(
                    SOCKET(socket.as_raw_socket() as usize),
                    SOL_SOCKET,
                    SO_EXCLUSIVEADDRUSE,
                    Some(&on),
                )
            };
            assert_eq!(set, 0, "set SO_EXCLUSIVEADDRUSE on the listener for {address}");
            socket
                .bind(&SockAddr::from(address))
                .unwrap_or_else(|e| panic!("hold {address}: {e}"));
            socket.listen(1).expect("listen");
            socket
        })
        .collect()
}

/// The real service manager through the machine's own methods: `settled()` says running; `stop()` returns stopped
/// only once the process the service had has exited (its handle, held before, is signalled), and a second `stop()`
/// of the stopped service says stopped again; `start()` is accepted and returns only once sshd serves: a socket of
/// the service's process listens on a port that `sshd -T` names; a second `start()` of the running service is
/// refused with 1056 and says serving. sshd is started again when the test ends, also on failure.
#[test]
fn the_service_manager_s_state_follows_a_stop_and_a_start() {
    let _machine = machine::exclusive();
    account_fixture::assert_elevated();
    let _running = SshdRunningAtTheEnd;
    let mut host = sshd_host_of_this_machine().expect("find the sshd service");

    assert_eq!(host.settled().expect("read the state"), ServiceState::Running);
    let old = Process::open(sshd_service_pid())
        .expect("open the process of the sshd service")
        .expect("the sshd service has a process");

    assert_eq!(host.stop(&mut |_| {}).expect("a STOP was sent"), StopOutcome::Stopped);
    assert!(
        has_exited(&old),
        "stop() returned before the old sshd process had exited"
    );
    assert_eq!(host.settled().expect("read the state"), ServiceState::Stopped);
    assert_eq!(
        host.stop(&mut |_| {}).expect("a STOP was sent"),
        StopOutcome::Stopped,
        "a second stop of a stopped service"
    );

    assert_eq!(host.start(), StartOutcome::Serving(StartReply::Accepted));
    assert_eq!(host.settled().expect("read the state"), ServiceState::Running);
    let ports = ports_in(&sshd_t());
    let pid = sshd_service_pid();
    assert!(
        ports.iter().any(|port| listens_on(pid, *port)),
        "start() said that sshd serves, and no listening socket of the service's process ({pid}) is on a port that \
         `sshd -T` names ({ports:?})"
    );
    match host.start() {
        StartOutcome::Serving(StartReply::Refused(reply)) => {
            assert!(reply.contains("1056"), "the service manager's reply: {reply}")
        }
        other => panic!("a start of a running service: {other:?}"),
    }
}

/// An sshd that cannot bind any address is never said to serve, though the service manager says it runs before it
/// has tried. The configuration names an address this machine does not have (192.0.2.1, reserved for
/// documentation): `sshd -t` passes it, and sshd exits when it binds. `start()` is accepted and comes out as
/// `Exited` (the process ended before it listened) or `Stopped` (the service manager saw it end first), never
/// `Serving`; the test prints which, and the code. Where `sshd -t` rejects that file on the runner, the test
/// holds sshd's ports with exclusive listeners of its own instead. The stock configuration is put back and sshd
/// then serves; sshd is started again when the test ends, also on failure.
#[test]
fn an_sshd_that_cannot_bind_any_address_is_never_said_to_serve() {
    let _machine = machine::exclusive();
    account_fixture::assert_elevated();
    // Dropped after `_reset`, so that sshd is started with the stock configuration.
    let _running = SshdRunningAtTheEnd;
    let stock = reset();
    let _reset = ResetAtTheEnd;
    let mut host = sshd_host_of_this_machine().expect("find the sshd service");
    let ports = ports_in(&sshd_t());
    assert!(!ports.is_empty(), "`sshd -T` names no port");

    assert_eq!(host.settled().expect("read the state"), ServiceState::Running);
    assert_eq!(host.stop(&mut |_| {}).expect("a STOP was sent"), StopOutcome::Stopped);

    let unbindable = with_line(stock, "ListenAddress 192.0.2.1").expect("the stock sshd_config can be edited");
    std::fs::write(config_path(), &unbindable).expect("write the configuration");
    let held = match host.sshd_check(&config_path()) {
        Ok(()) => Vec::new(),
        Err(said) => {
            eprintln!(
                "sshd -t rejects an unbindable ListenAddress on this runner ({said}); its ports are held instead"
            );
            reset();
            ports.iter().flat_map(|port| hold(*port)).collect()
        }
    };

    match host.start() {
        StartOutcome::Exited {
            reply: StartReply::Accepted,
            code,
            ..
        } => eprintln!("sshd that cannot bind: the process exited before it listened, with code {code}"),
        StartOutcome::Stopped {
            reply: StartReply::Accepted,
            exit,
        } => eprintln!("sshd that cannot bind: the service manager saw it stop first, with exit codes {exit:?}"),
        other => panic!("an sshd that cannot bind any address came out of start() as {other:?}"),
    }

    // sshd runs again: the ports are free, the configuration is the stock one, and the service is stopped.
    drop(held);
    assert_eq!(host.stop(&mut |_| {}).expect("a STOP was sent"), StopOutcome::Stopped);
    reset();
    assert_eq!(host.start(), StartOutcome::Serving(StartReply::Accepted));
    let pid = sshd_service_pid();
    assert!(
        ports.iter().any(|port| listens_on(pid, *port)),
        "sshd serves, and no listening socket of its process ({pid}) is on a port that `sshd -T` names ({ports:?})"
    );
}

/// `install` run in a job that ends with its connection, as sshd's job does: the test reads `install`'s output through
/// the pipe and ends the job on the line that says the sshd step is the task's. `install` is then gone, and the task
/// (a service started its process, outside the job) finishes the step: its instances end, sshd is running, plain
/// `sshd -T` shows the variable, a login that asks for the variable gets it, and the report's last line says sshd
/// restarted. sshd is started again when the test ends, also on failure.
#[test]
fn an_install_ended_after_it_handed_over_the_sshd_step_leaves_sshd_running_with_the_change() {
    use std::io::{BufRead, BufReader};
    use std::os::windows::io::AsRawHandle;
    use std::process::Stdio;

    let _machine = machine::exclusive();
    account_fixture::assert_elevated();
    let _install = Install::capture();
    let _running = SshdRunningAtTheEnd;
    reset();
    let kit = Kit::broker_with_helper("sshj");
    run_install(&kit);
    let installed = canonical_exe();
    // sshd's files as stock again, and sshd not restarted: the `install` below has a change to make and a restart
    // to do.
    reset();

    let mut job = job::KillOnCloseJob::create();
    let mut command = Command::new(&installed);
    command.arg("install").stdout(Stdio::piped()).stderr(Stdio::null());
    let mut child = desktop::spawn(&mut command).expect("run install");
    job.assign(windows::Win32::Foundation::HANDLE(child.as_raw_handle()));
    let mut printed = Vec::new();
    let mut handed_over = false;
    for line in BufReader::new(child.stdout.take().expect("install's output is piped")).lines() {
        let line = line.expect("read what install prints");
        handed_over = line.starts_with(sshd_task::HANDED_OVER_PREFIX);
        printed.push(line);
        if handed_over {
            break;
        }
    }
    assert!(
        handed_over,
        "install ended without saying that the sshd step is the task's:\n{printed:#?}"
    );
    // The connection ends: every process in the session's job ends with it, `install` among them.
    job.close();
    let _ = child.wait();

    // `waiting` is called when the first listing finds an instance: the task had one that had not ended when the
    // job was closed. A step that had finished by then fails here, loudly, instead of passing for nothing.
    let mut had_an_instance = false;
    let waited =
        taskscheduler::wait_for_instances(schtasks::INSTALL_SSHD_TASK, &installed, Role::InstallSshd, &mut || {
            had_an_instance = true
        })
        .expect("wait for the instances of the task");
    assert!(
        had_an_instance,
        "the task had no instance left when the job was closed, so the test did not show that the step outlives `install`"
    );
    assert_eq!(waited, WaitOutcome::Ended);
    let mut host = sshd_host_of_this_machine().expect("find the sshd service");
    assert_eq!(host.settled().expect("read the state"), ServiceState::Running);
    assert_install_configured_sshd();
    assert!(
        accepts(&sshd_t(), ssh_broker::protocol::ElevationPolicy::VARIABLE),
        "plain `sshd -T` shows the variable"
    );
    let report = report();
    assert!(
        report.complete,
        "the report says that the step ended: {:#?}",
        report.lines
    );
    assert_eq!(
        rendered(&report).last().map(String::as_str),
        Some("sshd restarted; it accepts SSH_BROKER_ELEVATION"),
        "the report's last line is the note that says sshd restarted"
    );

    // A new login gets the variable: the rig is made after the checks above, so that it cannot have configured
    // sshd itself.
    let account = Account::create("sshj", true);
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

/// `install` run in an SSH session restarts the very sshd that session came in through. The shim is
/// sshd's `DefaultShell` and the session is an administrator's at High (`always`). It must end with its exit code,
/// and the session must go on afterwards. Spike 4 measured a restart with the stock shell; this measures it with the
/// shim. If the session does not survive, stop and report: the restart cannot be the last step of an `install` that
/// someone runs over SSH.
#[test]
fn install_run_over_ssh_while_it_restarts_sshd_ends_with_its_exit_code_and_the_session_survives() {
    let _machine = machine::exclusive();
    account_fixture::assert_elevated();
    let _install = Install::capture();
    let _running = SshdRunningAtTheEnd;
    reset();
    let kit = Kit::broker_with_helper("ssha");
    run_install(&kit);
    let installed = canonical_exe();
    let account = Account::create("ssha", true);
    account.make_administrator();
    let _end = session_end::LogOutOnDrop::new(&installed, &account, ServiceLogon::Sshd);
    // sshd accepts the variable (the `install` above; the login's rig finds it so), which the session needs to be
    // elevated: a session that is not cannot run `install`. Then `sshd_config` is written again with the same text,
    // which sshd cannot have read: the `install` in the session has a restart to do. (Putting the files back as
    // stock here instead took the variable from the session: its login came after the drop-in had gone.)
    let login = Login::new(&kit, &account);
    std::fs::write(config_path(), std::fs::read(config_path()).unwrap()).unwrap();
    let row = accepts_row(&Ok(Elevation::Full), sshd_reading_this_machine);
    assert!(
        !row.pass,
        "sshd has a restart to do before the install in the session: {}",
        row.detail
    );

    let mut session = SshSession::start(login.command_asking("always"), login.diagnostics());
    session.log_in(&account.password);
    session.type_line(&format!(
        "& '{}' install; Write-Output ('install-exit' + '=' + $LASTEXITCODE + ';')",
        installed.display()
    ));
    session.read_until("install-exit=0;");
    assert!(
        accepts(&sshd_t(), ssh_broker::protocol::ElevationPolicy::VARIABLE),
        "the install in the session did not make sshd accept the variable"
    );
    assert_install_configured_sshd();
    // The session survived the restart: it answers.
    session.say("still-here-after-the-restart");
    session.leave();
}
