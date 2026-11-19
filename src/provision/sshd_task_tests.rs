//! Host tests for the order of the hand-over and every sentence of it, over a stand-in for the task and the
//! report. The real Task Scheduler is measured by `tests/sshd_config_windows.rs`, which CI runs.
use super::*;
use std::cell::RefCell;
use std::rc::Rc;

const REPORT: &str = r"C:\ProgramData\ssh-broker\apply-sshd.log";
const TASK: &str = "ssh-broker-apply-sshd";

/// What happened, in order: the calls on the task as `task: <call>`, the lines said as `said: <line>`.
type Log = Rc<RefCell<Vec<String>>>;

struct Fake {
    log: Log,
    register: Result<(), &'static str>,
    run: Result<(), &'static str>,
    wait: Result<WaitOutcome, &'static str>,
    report: Result<String, &'static str>,
    last_result: Result<u32, &'static str>,
    remove: Result<(), &'static str>,
}

impl Fake {
    fn new(log: &Log) -> Fake {
        Fake {
            log: Rc::clone(log),
            register: Ok(()),
            run: Ok(()),
            wait: Ok(WaitOutcome::Ended),
            report: Ok("apply: sshd restarted; it accepts SSH_BROKER_ELEVATION\r\n".to_owned()),
            last_result: Ok(0),
            remove: Ok(()),
        }
    }

    fn call<T: Clone>(&self, name: &str, answer: &Result<T, &'static str>) -> anyhow::Result<T> {
        self.log.borrow_mut().push(format!("task: {name}"));
        answer.clone().map_err(|cause| anyhow::anyhow!("{cause}"))
    }
}

impl SshdTask for Fake {
    fn register(&mut self) -> anyhow::Result<()> {
        self.call("register", &self.register)
    }
    fn run(&mut self) -> anyhow::Result<()> {
        self.call("run", &self.run)
    }
    fn wait(&mut self) -> anyhow::Result<WaitOutcome> {
        self.call("wait", &self.wait)
    }
    fn report(&mut self) -> anyhow::Result<String> {
        self.call("report", &self.report)
    }
    fn last_result(&mut self) -> anyhow::Result<u32> {
        self.call("last_result", &self.last_result)
    }
    fn remove(&mut self) -> anyhow::Result<()> {
        self.call("remove", &self.remove)
    }
}

fn run(fake: &mut Fake) -> Log {
    let log = Rc::clone(&fake.log);
    hand_over(fake, Path::new(REPORT), &mut |line| {
        log.borrow_mut().push(format!("said: {line}"))
    });
    log
}

fn new_log() -> Log {
    Rc::new(RefCell::new(Vec::new()))
}

fn said(log: &Log) -> Vec<String> {
    log.borrow()
        .iter()
        .filter_map(|entry| entry.strip_prefix("said: ").map(str::to_owned))
        .collect()
}

fn calls(log: &Log) -> Vec<String> {
    log.borrow()
        .iter()
        .filter_map(|entry| entry.strip_prefix("task: ").map(str::to_owned))
        .collect()
}

const HANDED_OVER: &str = "apply: sshd's configuration is set up by the task ssh-broker-apply-sshd, which runs as SYSTEM and \
     finishes even if this apply is ended; what it does follows, and is kept in C:\\ProgramData\\ssh-broker\\apply-sshd.log";

// the order =====

#[test]
fn the_task_is_registered_run_waited_for_read_and_removed_in_that_order_and_its_lines_are_printed() {
    let log = new_log();
    let mut fake = Fake::new(&log);
    fake.report = Ok("apply: a first line\r\napply: sshd restarted; it accepts SSH_BROKER_ELEVATION\r\n".to_owned());
    let log = run(&mut fake);
    assert_eq!(
        *log.borrow(),
        [
            "task: register",
            "task: run",
            &format!("said: {HANDED_OVER}"),
            "task: wait",
            "task: report",
            "task: last_result",
            "said: apply: a first line",
            "said: apply: sshd restarted; it accepts SSH_BROKER_ELEVATION",
            "task: remove",
        ]
    );
}

#[test]
fn the_hand_over_is_said_after_the_task_runs_and_before_anything_waits_for_it() {
    // A stop of `apply` that comes after this line leaves the task running to its end: the line is what a
    // caller that ends `apply` waits for.
    let log = new_log();
    let mut fake = Fake::new(&log);
    let log = run(&mut fake);
    let log = log.borrow();
    let at = |entry: &str| log.iter().position(|e| e == entry).unwrap();
    assert!(at("task: run") < at(&format!("said: {HANDED_OVER}")));
    assert!(at(&format!("said: {HANDED_OVER}")) < at("task: wait"));
}

#[test]
fn the_hand_over_names_the_report_it_is_given() {
    assert_eq!(
        handed_over_line(Path::new(r"D:\x\apply-sshd.log")),
        "apply: sshd's configuration is set up by the task ssh-broker-apply-sshd, which runs as SYSTEM and \
         finishes even if this apply is ended; what it does follows, and is kept in D:\\x\\apply-sshd.log"
    );
    assert!(HANDED_OVER.starts_with(HANDED_OVER_PREFIX));
}

#[test]
fn a_report_with_no_line_is_a_step_that_had_nothing_to_say_and_is_said_so() {
    let log = new_log();
    let mut fake = Fake::new(&log);
    fake.report = Ok(String::new());
    let log = run(&mut fake);
    assert_eq!(
        said(&log).last().unwrap(),
        "apply: sshd accepts SSH_BROKER_ELEVATION and has read its configuration; the task had nothing to change"
    );
    assert_eq!(calls(&log).last().unwrap(), "remove");
}

// a task that ended before it finished =====

const ENDED_EARLY: &str = "apply: the task ssh-broker-apply-sshd ended before it finished (its last result was \
     0xc000013a); what it had said follows. Check sshd at this PC: `sc query sshd`; start it with `net start \
     sshd` if it is stopped.";

#[test]
fn a_task_whose_result_is_not_zero_ended_before_it_finished_and_what_it_said_is_not_taken_as_complete() {
    let log = new_log();
    let mut fake = Fake::new(&log);
    fake.report = Ok("apply: sshd is running with its earlier configuration\r\n".to_owned());
    fake.last_result = Ok(0xC000_013A);
    let log = run(&mut fake);
    assert_eq!(
        said(&log)[1..],
        [ENDED_EARLY, "apply: sshd is running with its earlier configuration",]
    );
    assert_eq!(calls(&log).last().unwrap(), "remove");
}

#[test]
fn a_task_that_ended_before_it_finished_and_had_said_nothing_says_so_and_not_that_there_was_nothing_to_change() {
    let log = new_log();
    let mut fake = Fake::new(&log);
    fake.report = Ok(String::new());
    fake.last_result = Ok(0xC000_013A);
    let log = run(&mut fake);
    assert_eq!(
        said(&log)[1..],
        [ENDED_EARLY, "apply: the task ssh-broker-apply-sshd had said nothing"]
    );
    assert_eq!(
        calls(&log),
        ["register", "run", "wait", "report", "last_result", "remove"]
    );
}

#[test]
fn a_result_that_cannot_be_read_does_not_make_a_report_complete() {
    let log = new_log();
    let mut fake = Fake::new(&log);
    fake.report = Ok("apply: sshd restarted; it accepts SSH_BROKER_ELEVATION\r\n".to_owned());
    fake.last_result = Err("the service did not answer");
    let log = run(&mut fake);
    assert_eq!(
        said(&log)[1..],
        [
            "apply: whether the task ssh-broker-apply-sshd finished could not be told (its last result could not \
             be read (the service did not answer)); what it had said follows. Check sshd at this PC: `sc query \
             sshd`; start it with `net start sshd` if it is stopped.",
            "apply: sshd restarted; it accepts SSH_BROKER_ELEVATION",
        ]
    );
}

// what goes wrong =====

#[test]
fn a_task_that_cannot_be_registered_is_said_to_have_changed_nothing_and_nothing_is_run() {
    let log = new_log();
    let mut fake = Fake::new(&log);
    fake.register = Err("access denied");
    let log = run(&mut fake);
    assert_eq!(
        said(&log),
        [
            "apply: sshd was not set up to accept SSH_BROKER_ELEVATION: the task ssh-broker-apply-sshd could not \
             be registered: access denied. Nothing of sshd's was changed; `ssh-broker elevate` works without it."
        ]
    );
    assert_eq!(
        calls(&log),
        ["register"],
        "nothing was run, and there is nothing to remove"
    );
}

#[test]
fn a_task_that_cannot_be_started_is_said_so_and_removed() {
    let log = new_log();
    let mut fake = Fake::new(&log);
    fake.run = Err("the task is disabled");
    let log = run(&mut fake);
    assert_eq!(
        said(&log),
        [
            "apply: sshd was not set up to accept SSH_BROKER_ELEVATION: the task ssh-broker-apply-sshd could not \
             be started: the task is disabled. Nothing of sshd's was changed; `ssh-broker elevate` works without it."
        ]
    );
    assert_eq!(calls(&log), ["register", "run", "remove"]);
}

#[test]
fn a_task_that_cannot_be_started_and_cannot_be_removed_says_both() {
    let log = new_log();
    let mut fake = Fake::new(&log);
    fake.run = Err("the task is disabled");
    fake.remove = Err("access denied");
    let log = run(&mut fake);
    let said = said(&log);
    assert_eq!(said.len(), 2, "{said:#?}");
    assert_eq!(
        said[1],
        "apply: the task ssh-broker-apply-sshd could not be removed (access denied); it has no trigger, runs \
         nothing by itself, and the next apply replaces it"
    );
}

#[test]
fn a_missing_report_is_said_with_the_tasks_last_result_and_the_task_is_still_removed() {
    let log = new_log();
    let mut fake = Fake::new(&log);
    fake.report = Err("the system cannot find the file specified");
    fake.last_result = Ok(0x8004_1307);
    let log = run(&mut fake);
    assert_eq!(
        said(&log).last().unwrap(),
        &format!(
            "apply: the task ssh-broker-apply-sshd left no report in {REPORT} (the system cannot find the file \
             specified); its last result was 0x80041307. Whether sshd accepts SSH_BROKER_ELEVATION and is running \
             is not known: `ssh-broker verify` says, and `sc query sshd` shows whether sshd runs"
        )
    );
    assert_eq!(calls(&log).last().unwrap(), "remove");
}

#[test]
fn a_last_result_that_cannot_be_read_is_said_to_be_unread() {
    let log = new_log();
    let mut fake = Fake::new(&log);
    fake.report = Err("the system cannot find the file specified");
    fake.last_result = Err("the service did not answer");
    let log = run(&mut fake);
    assert!(
        said(&log)
            .last()
            .unwrap()
            .contains("its last result could not be read (the service did not answer)"),
        "{:?}",
        said(&log)
    );
}

#[test]
fn a_task_that_cannot_be_removed_is_said_so_after_its_report() {
    let log = new_log();
    let mut fake = Fake::new(&log);
    fake.remove = Err("access denied");
    let log = run(&mut fake);
    let said = said(&log);
    assert_eq!(
        said[said.len() - 2],
        "apply: sshd restarted; it accepts SSH_BROKER_ELEVATION",
        "the report's last line stays the line before"
    );
    assert_eq!(
        said.last().unwrap(),
        "apply: the task ssh-broker-apply-sshd could not be removed (access denied); it has no trigger, runs \
         nothing by itself, and the next apply replaces it"
    );
}

#[test]
fn an_instance_that_was_listed_and_never_launched_is_taken_as_proof_of_nothing() {
    let log = new_log();
    let mut fake = Fake::new(&log);
    fake.wait = Ok(WaitOutcome::NeverLaunched { count: 1 });
    let log = run(&mut fake);
    assert_eq!(
        said(&log).last().unwrap(),
        &format!(
            "apply: the Task Scheduler lists an instance of the task {TASK} that it has not started; it may still \
             run, and nothing is known of what it does. Its report is {REPORT}"
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
    let mut fake = Fake::new(&log);
    fake.wait = Err("the Task Scheduler did not answer");
    let log = run(&mut fake);
    assert_eq!(
        said(&log).last().unwrap(),
        &format!(
            "apply: waiting for the task {TASK} failed (the Task Scheduler did not answer); it may still run. Its \
             report is {REPORT}"
        )
    );
    assert_eq!(calls(&log), ["register", "run", "wait"]);
}

// the report =====

#[test]
fn the_verb_writes_each_line_to_the_report_whole_before_it_goes_on() {
    let dir = std::env::temp_dir().join(format!("sb-report-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("apply-sshd.log");
    std::fs::write(&path, "left from an earlier run\r\n").unwrap();

    let mut seen_by_a_reader = Vec::new();
    write_report(&path, |say| {
        say("apply: first");
        seen_by_a_reader.push(std::fs::read_to_string(&path).unwrap());
        say("apply: second");
        seen_by_a_reader.push(std::fs::read_to_string(&path).unwrap());
    })
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(
        seen_by_a_reader,
        ["apply: first\r\n", "apply: first\r\napply: second\r\n"],
        "a line is in the file when `say` returns, and the earlier run's text is gone"
    );
}

#[test]
fn a_report_that_cannot_be_written_is_an_error_and_the_step_does_not_run() {
    let missing = std::env::temp_dir()
        .join(format!("sb-no-such-dir-{}", std::process::id()))
        .join("apply-sshd.log");
    let mut ran = false;
    let err = write_report(&missing, |_| ran = true).unwrap_err();
    assert!(
        !ran,
        "no report to write to, so nothing is run that nobody could read about"
    );
    assert!(format!("{err:#}").contains("apply-sshd.log"), "{err:#}");
}

#[test]
fn a_reported_text_is_read_as_its_lines() {
    assert_eq!(report_lines("a\r\nb\r\n"), ["a", "b"]);
    assert_eq!(report_lines("a\nb"), ["a", "b"]);
    assert!(report_lines("").is_empty());
}
