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
    remove: Result<(), &'static str>,
}

impl Fake {
    fn new(log: &Log) -> Fake {
        Fake {
            log: Rc::clone(log),
            register: Ok(()),
            run: Ok(()),
            wait: Ok(WaitOutcome::Ended),
            report: Ok(complete("apply: sshd restarted; it accepts SSH_BROKER_ELEVATION")),
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
    fn remove(&mut self) -> anyhow::Result<()> {
        self.call("remove", &self.remove)
    }
}

/// A report text of `lines` (written one per line) that the step closed.
fn complete(lines: &str) -> String {
    format!("{}{REPORT_END}\r\n", unclosed(lines))
}

/// A report text of `lines` (written one per line) with no closing line: the step did not end.
fn unclosed(lines: &str) -> String {
    lines.lines().map(|line| format!("{line}\r\n")).collect()
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
     finishes even if this apply is ended; what it does follows when it has finished, and can be read while it \
     runs in C:\\ProgramData\\ssh-broker\\apply-sshd.log";

/// What is said of a report that has no closing line, which says both things it can mean.
const NO_CLOSING_LINE: &str = "apply: the report of the task ssh-broker-apply-sshd has no closing line: the task was \
     ended before its step finished, or a line of the report could not be written; what it had said follows. Check \
     sshd at this PC: `sc query sshd`; start it with `net start sshd` if it is stopped.";

// the order =====

#[test]
fn the_task_is_registered_run_waited_for_read_and_removed_in_that_order_and_its_lines_are_printed() {
    let log = new_log();
    let mut fake = Fake::new(&log);
    fake.report = Ok(complete(
        "apply: a first line\napply: sshd restarted; it accepts SSH_BROKER_ELEVATION",
    ));
    let log = run(&mut fake);
    assert_eq!(
        *log.borrow(),
        [
            "task: register",
            "task: run",
            &format!("said: {HANDED_OVER}"),
            "task: wait",
            "task: report",
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
         finishes even if this apply is ended; what it does follows when it has finished, and can be read while \
         it runs in D:\\x\\apply-sshd.log"
    );
    assert!(HANDED_OVER.starts_with(HANDED_OVER_PREFIX));
}

// the report says itself that it is whole =====

#[test]
fn a_report_that_ends_with_the_closing_line_is_complete_and_the_closing_line_is_not_printed() {
    let log = new_log();
    let mut fake = Fake::new(&log);
    fake.report = Ok(complete("apply: a first line\napply: a second line"));
    let log = run(&mut fake);
    assert_eq!(said(&log)[1..], ["apply: a first line", "apply: a second line"]);
    assert!(
        said(&log).iter().all(|line| line != REPORT_END),
        "the closing line is for the reader, not for the person"
    );
    assert_eq!(calls(&log).last().unwrap(), "remove");

    let parsed = Report::parse(&complete("a\nb"));
    assert!(parsed.complete);
    assert_eq!(parsed.lines, ["a", "b"]);
}

#[test]
fn a_report_without_the_closing_line_is_said_to_be_incomplete_before_what_it_had_said() {
    let log = new_log();
    let mut fake = Fake::new(&log);
    fake.report = Ok(unclosed("apply: sshd is running with its earlier configuration"));
    let log = run(&mut fake);
    assert_eq!(
        said(&log)[1..],
        [NO_CLOSING_LINE, "apply: sshd is running with its earlier configuration",]
    );
    assert_eq!(calls(&log), ["register", "run", "wait", "report", "remove"]);

    let parsed = Report::parse(&unclosed("a\nb"));
    assert!(!parsed.complete);
    assert_eq!(parsed.lines, ["a", "b"]);
}

#[test]
fn an_incomplete_report_with_no_line_says_the_task_had_said_nothing() {
    let log = new_log();
    let mut fake = Fake::new(&log);
    fake.report = Ok(String::new());
    let log = run(&mut fake);
    assert_eq!(
        said(&log)[1..],
        [
            NO_CLOSING_LINE,
            "apply: the task ssh-broker-apply-sshd had said nothing",
        ]
    );
    assert_eq!(calls(&log), ["register", "run", "wait", "report", "remove"]);
}

#[test]
fn a_closing_line_with_nothing_before_it_is_a_step_that_had_nothing_to_change() {
    let log = new_log();
    let mut fake = Fake::new(&log);
    fake.report = Ok(complete(""));
    let log = run(&mut fake);
    assert_eq!(
        said(&log)[1..],
        ["apply: sshd accepts SSH_BROKER_ELEVATION and has read its configuration; the task had nothing to change"]
    );
    assert_eq!(calls(&log).last().unwrap(), "remove");
}

#[test]
fn a_reported_text_is_read_as_its_lines() {
    assert_eq!(Report::parse("a\r\nb\r\n").lines, ["a", "b"]);
    assert_eq!(Report::parse("a\nb").lines, ["a", "b"]);
    assert!(Report::parse("").lines.is_empty());
    assert!(!Report::parse("").complete);
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
fn a_missing_report_is_said_and_the_task_is_still_removed() {
    let log = new_log();
    let mut fake = Fake::new(&log);
    fake.report = Err("the system cannot find the file specified");
    let log = run(&mut fake);
    assert_eq!(
        said(&log).last().unwrap(),
        &format!(
            "apply: the report of the task ssh-broker-apply-sshd could not be read in {REPORT} (the system cannot \
             find the file specified); if it is not there, the task did not start or could not create it. Whether \
             sshd accepts SSH_BROKER_ELEVATION and is running is not known: `ssh-broker verify` says, and `sc query \
             sshd` shows whether sshd runs"
        )
    );
    assert_eq!(calls(&log), ["register", "run", "wait", "report", "remove"]);
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
fn the_closing_line_is_written_only_after_the_step_has_returned() {
    let dir = std::env::temp_dir().join(format!("sb-report-end-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("apply-sshd.log");

    let mut inside = None;
    write_report(&path, |say| {
        say("apply: first");
        inside = Some(Report::parse(&std::fs::read_to_string(&path).unwrap()));
    })
    .unwrap();
    let after = Report::parse(&std::fs::read_to_string(&path).unwrap());
    let raw = std::fs::read_to_string(&path).unwrap();
    let _ = std::fs::remove_dir_all(&dir);

    let inside = inside.unwrap();
    assert!(
        !inside.complete,
        "while the step runs the file does not say that it is whole"
    );
    assert_eq!(inside.lines, ["apply: first"]);
    assert!(after.complete);
    assert_eq!(after.lines, ["apply: first"]);
    assert_eq!(
        raw,
        format!("apply: first\r\n{REPORT_END}\r\n"),
        "the last line of the file"
    );
}

/// A writer that takes the first `accepts` writes and fails every one after them.
struct Failing {
    accepts: usize,
    written: Vec<u8>,
}

impl std::io::Write for Failing {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.accepts == 0 {
            return Err(std::io::Error::other("the disk is full"));
        }
        self.accepts -= 1;
        self.written.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_line_that_cannot_be_written_leaves_the_report_without_a_closing_line_and_is_the_error() {
    let mut out = Failing {
        accepts: 1,
        written: Vec::new(),
    };
    let mut said = Vec::new();
    let err = write_lines(&mut out, |say| {
        say("apply: first");
        say("apply: second");
        say("apply: third");
        said.push("the step ran to its end");
    })
    .unwrap_err();
    assert_eq!(err.to_string(), "the disk is full");
    assert_eq!(
        said,
        ["the step ran to its end"],
        "the step is not cut short by a failed line"
    );
    assert_eq!(
        String::from_utf8(out.written).unwrap(),
        "apply: first\r\n",
        "no closing line follows a failed one: the report says it is not whole"
    );
}

#[test]
fn a_closing_line_that_cannot_be_written_is_the_error() {
    let mut out = Failing {
        accepts: 1,
        written: Vec::new(),
    };
    let err = write_lines(&mut out, |say| say("apply: first")).unwrap_err();
    assert_eq!(err.to_string(), "the disk is full");
    let text = String::from_utf8(out.written).unwrap();
    assert!(!text.contains(REPORT_END), "{text}");
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
