//! Host tests for the order of the hand-over and every sentence of it, over a stand-in for the task and the
//! report. The real Task Scheduler is measured by `tests/sshd_config_windows.rs`, which CI runs.
use super::*;
use crate::provision::sshd_config::{LineKind, render};
use crate::provision::sshd_task::REPORT_END;
use crate::test_support::{FakeSshdTask, TaskLog};
use std::cell::RefCell;
use std::rc::Rc;

const REPORT: &str = r"C:\ProgramData\ssh-broker\install-sshd.log";
const EXE: &str = r"C:\ProgramData\ssh-broker\ssh-broker.exe";
const TASK: &str = "ssh-broker-install-sshd";

const STEP_LINE: &str = "Setting up sshd to accept SSH_BROKER_ELEVATION; sshd may be restarted, and a connection over SSH may drop \
     now. What the step does is written to C:\\ProgramData\\ssh-broker\\install-sshd.log, and \
     C:\\ProgramData\\ssh-broker\\ssh-broker.exe doctor says whether sshd accepts the variable...";

/// What is said of a report that has no closing line, which says both things it can mean and that the lines the
/// step had written follow, whether or not there are any.
const NO_CLOSING_LINE: &str = "the report of the task ssh-broker-install-sshd has no closing line: the task was ended \
     before its step finished, or a line of the report could not be written. Check sshd at this PC: `sc query \
     sshd`; start it with `net start sshd` if it is stopped. The lines the step had written, if any, follow; they \
     say how far it got.";

const ADD_BY_HAND: &str = "add `AcceptEnv SSH_BROKER_ELEVATION` above the first `Match` in \
     C:\\ProgramData\\ssh\\sshd_config, then run `ssh-broker install` again, which restarts sshd";

fn new_log() -> TaskLog {
    Rc::new(RefCell::new(Vec::new()))
}

/// The text of a report that the step closed: its lines as the verb writes them, then the closing line.
fn closed(lines: &[(LineKind, &str)]) -> String {
    format!("{}{REPORT_END}\r\n", unclosed(lines))
}

/// The text of a report that the step did not close.
fn unclosed(lines: &[(LineKind, &str)]) -> String {
    lines
        .iter()
        .flat_map(|(kind, text)| {
            render(*kind, text)
                .lines()
                .map(|line| format!("{line}\r\n"))
                .collect::<Vec<_>>()
        })
        .collect()
}

fn run(fake: &mut FakeSshdTask) -> TaskLog {
    let log = Rc::clone(&fake.log);
    hand_over(fake, Path::new(REPORT), Path::new(EXE), &mut |stream, line| {
        log.borrow_mut().push(format!("said {stream:?}: {line}"))
    });
    log
}

/// What was said, in order, as `Out: <line>` or `Err: <line>`.
fn said(log: &TaskLog) -> Vec<String> {
    log.borrow()
        .iter()
        .filter_map(|entry| entry.strip_prefix("said ").map(str::to_owned))
        .collect()
}

fn calls(log: &TaskLog) -> Vec<String> {
    log.borrow()
        .iter()
        .filter_map(|entry| entry.strip_prefix("task: ").map(str::to_owned))
        .collect()
}

// the order =====

#[test]
fn the_task_is_registered_run_waited_for_read_and_removed_in_that_order_and_its_warning_is_said() {
    let log = new_log();
    let mut fake = FakeSshdTask::new(&log);
    fake.report = Ok(closed(&[
        (LineKind::Note, "a note"),
        (LineKind::Warning, "a warning"),
        (LineKind::Note, "sshd restarted; it accepts SSH_BROKER_ELEVATION"),
    ]));
    let log = run(&mut fake);
    assert_eq!(
        *log.borrow(),
        [
            "task: register",
            "task: run",
            &format!("said Out: {STEP_LINE}"),
            "task: wait",
            "task: report",
            "said Err: a warning",
            "task: remove",
        ]
    );
}

#[test]
fn the_step_line_is_said_after_the_task_is_started_and_before_anything_waits_for_it() {
    // A stop of `install` that comes after this line leaves the task running to its end: the line is what a
    // caller that ends `install` waits for.
    let log = new_log();
    let log = run(&mut FakeSshdTask::new(&log));
    let log = log.borrow();
    let at = |entry: &str| log.iter().position(|e| e == entry).unwrap();
    assert!(at("task: run") < at(&format!("said Out: {STEP_LINE}")));
    assert!(at(&format!("said Out: {STEP_LINE}")) < at("task: wait"));
}

#[test]
fn the_step_line_names_the_report_and_doctor_by_their_paths() {
    assert_eq!(step_line(Path::new(EXE), Path::new(REPORT)), STEP_LINE);
    assert!(STEP_LINE.contains(REPORT) && STEP_LINE.contains(&format!("{EXE} doctor")));
    assert!(
        !STEP_LINE.contains("finished"),
        "`doctor` does not read the task or the report, so it is not said to tell whether the install finished"
    );
    assert!(STEP_LINE.starts_with(HANDED_OVER_PREFIX));
    assert!(
        STEP_LINE.ends_with("..."),
        "a step line says that it is going on, and ends so"
    );
}

// what is said of the report =====

#[test]
fn a_warning_of_the_step_is_said_on_stderr_and_a_note_is_not_said() {
    let log = new_log();
    let mut fake = FakeSshdTask::new(&log);
    fake.report = Ok(closed(&[
        (
            LineKind::Note,
            "sshd was started before sshd_config was last changed, so it has not read it",
        ),
        (LineKind::Warning, ADD_BY_HAND),
        (LineKind::Note, "restarting sshd"),
    ]));
    let log = run(&mut fake);
    assert_eq!(said(&log), [format!("Out: {STEP_LINE}"), format!("Err: {ADD_BY_HAND}")]);
    assert_eq!(calls(&log).last().unwrap(), "remove");
}

#[test]
fn a_warning_of_several_lines_is_said_in_every_line() {
    let log = new_log();
    let mut fake = FakeSshdTask::new(&log);
    fake.report = Ok(closed(&[(
        LineKind::Warning,
        "sshd rejects the edited copy: line 1\nline 2",
    )]));
    let log = run(&mut fake);
    assert_eq!(
        said(&log)[1..],
        ["Err: sshd rejects the edited copy: line 1", "Err: line 2"]
    );
}

#[test]
fn the_closing_line_is_not_said() {
    let log = new_log();
    let mut fake = FakeSshdTask::new(&log);
    fake.report = Ok(closed(&[(LineKind::Warning, "a warning")]));
    let log = run(&mut fake);
    assert!(
        said(&log).iter().all(|line| !line.contains(REPORT_END)),
        "the closing line is for the reader of the report, not for the person"
    );
}

#[test]
fn a_run_that_has_nothing_to_change_says_only_the_step_line() {
    let log = new_log();
    let mut fake = FakeSshdTask::new(&log);
    fake.report = Ok(closed(&[]));
    let log = run(&mut fake);
    assert_eq!(said(&log), [format!("Out: {STEP_LINE}")]);
    assert_eq!(calls(&log).last().unwrap(), "remove");
}

#[test]
fn a_run_with_only_notes_says_only_the_step_line() {
    let log = new_log();
    let mut fake = FakeSshdTask::new(&log);
    fake.report = Ok(closed(&[
        (LineKind::Note, "restarting sshd"),
        (LineKind::Note, "sshd restarted; it accepts SSH_BROKER_ELEVATION"),
    ]));
    let log = run(&mut fake);
    assert_eq!(said(&log), [format!("Out: {STEP_LINE}")]);
}

/// The notes of a report that stopped say how far the step got ("sshd was stopped; starting sshd" means sshd may be
/// stopped now), so they are shown with the warnings, every line in its order, after the warning that the report
/// has no closing line.
#[test]
fn a_report_without_its_closing_line_is_said_whole_after_the_warning_that_it_has_none() {
    let log = new_log();
    let mut fake = FakeSshdTask::new(&log);
    fake.report = Ok(unclosed(&[
        (LineKind::Note, "restarting sshd"),
        (LineKind::Note, "sshd was stopped; starting sshd"),
        (LineKind::Warning, "sshd could not be started (access denied)\nline 2"),
    ]));
    let log = run(&mut fake);
    assert_eq!(
        said(&log)[1..],
        [
            format!("Err: {NO_CLOSING_LINE}"),
            "Err: restarting sshd".to_owned(),
            "Err: sshd was stopped; starting sshd".to_owned(),
            "Err: sshd could not be started (access denied)".to_owned(),
            "Err: line 2".to_owned(),
        ]
    );
    assert_eq!(calls(&log), ["register", "run", "wait", "report", "remove"]);
}

#[test]
fn a_report_with_its_closing_line_is_said_by_its_warnings_alone_even_when_it_has_notes() {
    let log = new_log();
    let mut fake = FakeSshdTask::new(&log);
    fake.report = Ok(closed(&[
        (LineKind::Note, "sshd was stopped; starting sshd"),
        (LineKind::Warning, "a warning"),
    ]));
    let log = run(&mut fake);
    assert_eq!(said(&log)[1..], ["Err: a warning"]);
}

#[test]
fn an_incomplete_report_with_no_line_says_the_task_had_said_nothing() {
    let log = new_log();
    let mut fake = FakeSshdTask::new(&log);
    fake.report = Ok(String::new());
    let log = run(&mut fake);
    assert_eq!(
        said(&log)[1..],
        [
            format!("Err: {NO_CLOSING_LINE}"),
            "Err: the task ssh-broker-install-sshd had said nothing".to_owned(),
        ]
    );
    assert_eq!(calls(&log), ["register", "run", "wait", "report", "remove"]);
}

// what goes wrong =====

#[test]
fn a_task_that_cannot_be_registered_is_said_to_have_changed_nothing_and_nothing_is_run() {
    let log = new_log();
    let mut fake = FakeSshdTask::new(&log);
    fake.register = Err("access denied");
    let log = run(&mut fake);
    assert_eq!(
        said(&log),
        [
            "Err: sshd was not set up to accept SSH_BROKER_ELEVATION: the task ssh-broker-install-sshd could not be \
             registered: access denied. Nothing of sshd's was changed; `ssh-broker elevate` works without it."
        ],
        "a step that was not handed over says no step line"
    );
    assert_eq!(
        calls(&log),
        ["register"],
        "nothing was run, and there is nothing to remove"
    );
}

#[test]
fn a_task_that_cannot_be_started_is_said_so_and_removed_and_says_no_step_line() {
    let log = new_log();
    let mut fake = FakeSshdTask::new(&log);
    fake.run = Err("the task is disabled");
    let log = run(&mut fake);
    assert_eq!(
        said(&log),
        [
            "Err: sshd was not set up to accept SSH_BROKER_ELEVATION: the task ssh-broker-install-sshd could not be \
             started: the task is disabled. Nothing of sshd's was changed; `ssh-broker elevate` works without it."
        ]
    );
    assert_eq!(calls(&log), ["register", "run", "remove"]);
}

#[test]
fn a_task_that_cannot_be_started_and_cannot_be_removed_says_both() {
    let log = new_log();
    let mut fake = FakeSshdTask::new(&log);
    fake.run = Err("the task is disabled");
    fake.remove = Err("access denied");
    let log = run(&mut fake);
    let said = said(&log);
    assert_eq!(said.len(), 2, "{said:#?}");
    assert_eq!(
        said[1],
        "Err: the task ssh-broker-install-sshd could not be removed (access denied); it has no trigger, runs \
         nothing by itself, and the next install replaces it"
    );
}

#[test]
fn a_missing_report_is_said_and_the_task_is_still_removed() {
    let log = new_log();
    let mut fake = FakeSshdTask::new(&log);
    fake.report = Err("the system cannot find the file specified");
    let log = run(&mut fake);
    assert_eq!(
        said(&log).last().unwrap(),
        &format!(
            "Err: the report of the task ssh-broker-install-sshd could not be read in {REPORT} (the system cannot \
             find the file specified); if it is not there, the task did not start or could not create it. Whether \
             sshd accepts SSH_BROKER_ELEVATION and is running is not known: `{EXE} doctor` says, and `sc query \
             sshd` shows whether sshd runs"
        )
    );
    assert_eq!(calls(&log), ["register", "run", "wait", "report", "remove"]);
}

#[test]
fn a_task_that_cannot_be_removed_is_said_after_the_warnings_of_its_report() {
    let log = new_log();
    let mut fake = FakeSshdTask::new(&log);
    fake.report = Ok(closed(&[(LineKind::Warning, "a warning")]));
    fake.remove = Err("access denied");
    let log = run(&mut fake);
    let said = said(&log);
    assert_eq!(
        said[said.len() - 2],
        "Err: a warning",
        "the report's last warning stays the line before"
    );
    assert_eq!(
        said.last().unwrap(),
        "Err: the task ssh-broker-install-sshd could not be removed (access denied); it has no trigger, runs \
         nothing by itself, and the next install replaces it"
    );
}

#[test]
fn an_instance_that_was_listed_and_never_launched_is_taken_as_proof_of_nothing() {
    let log = new_log();
    let mut fake = FakeSshdTask::new(&log);
    fake.wait = Ok(WaitOutcome::NeverLaunched { count: 1 });
    let log = run(&mut fake);
    assert_eq!(
        said(&log).last().unwrap(),
        &format!(
            "Err: the Task Scheduler lists an instance of the task {TASK} that it has not started; it may still \
             run, and nothing is known of what it does. Its report is {REPORT}. End and remove the task (`schtasks \
             /End /TN {TASK}`, then `schtasks /Delete /TN {TASK} /F`, elevated) when it is not wanted; if the step \
             has started meanwhile, ending it can leave sshd stopped. Check sshd at this PC: `sc query sshd`; start \
             it with `net start sshd` if it is stopped."
        )
    );
    assert_eq!(
        calls(&log),
        ["register", "run", "wait"],
        "the report is not read, and the task that may still run is not removed"
    );
}

#[test]
fn a_wait_that_fails_leaves_the_task_and_says_it_may_still_run() {
    let log = new_log();
    let mut fake = FakeSshdTask::new(&log);
    fake.wait = Err("the Task Scheduler did not answer");
    let log = run(&mut fake);
    assert_eq!(
        said(&log).last().unwrap(),
        &format!(
            "Err: waiting for the task {TASK} failed (the Task Scheduler did not answer); it may still run. Its \
             report is {REPORT}"
        )
    );
    assert_eq!(calls(&log), ["register", "run", "wait"]);
}
