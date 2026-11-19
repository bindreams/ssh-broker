//! provision::sshd_task — `apply`'s sshd step, run by a task so that it finishes even if `apply` is ended.
//!
//! `apply` run over SSH runs inside the session's job, which ends every process in it when the connection
//! ends, and the sshd step restarts the very sshd that carries that connection: an `apply` ended between the
//! stop and the start would leave a machine reached only over SSH without sshd. So `apply` registers the task
//! [`schtasks::APPLY_SSHD_TASK`], which runs the hidden verb `apply-sshd` as SYSTEM, starts it, and waits for
//! it. A service starts the task's process, outside the session's job, and it runs the step to its end
//! whatever happens to `apply`. The verb writes what the step says to a report, a line at a time, and `apply`
//! prints the report once the task's instances have ended.
//!
//! The order and the sentences are here, over [`SshdTask`], which tests stand in for; [`system`] is the Task
//! Scheduler behind it. No failure here fails `apply`: the variable is a convenience.

use std::io::Write as _;
use std::path::Path;

use anyhow::Context;

use super::schtasks::{APPLY_SSHD_TASK, WaitOutcome};
use super::sshd_config::CHECK_SSHD;

#[cfg(windows)]
mod system;
#[cfg(windows)]
pub use system::{hand_over_sshd_step, report_path};

/// What the hand-over needs of the Task Scheduler and the report.
pub trait SshdTask {
    /// Register the task, replacing a copy an earlier `apply` left behind, and clear the report of an earlier
    /// run.
    fn register(&mut self) -> anyhow::Result<()>;
    /// Start the task and return without waiting for it.
    fn run(&mut self) -> anyhow::Result<()>;
    /// Wait, with no bound, for the processes of the task's instances to exit.
    fn wait(&mut self) -> anyhow::Result<WaitOutcome>;
    /// The report the verb wrote.
    fn report(&mut self) -> anyhow::Result<String>;
    /// Delete the task.
    fn remove(&mut self) -> anyhow::Result<()>;
}

/// What the line that says the step was handed over starts with. A caller that ends `apply` once the step is
/// the task's waits for a line that starts with it.
pub const HANDED_OVER_PREFIX: &str = "apply: sshd's configuration is set up by the task ssh-broker-apply-sshd";

/// The line that says the step is the task's, that what it does is printed when it has finished, and where it
/// can be read while it runs.
pub fn handed_over_line(report: &Path) -> String {
    format!(
        "{HANDED_OVER_PREFIX}, which runs as SYSTEM and finishes even if this apply is ended; what it does \
         follows when it has finished, and can be read while it runs in {}",
        report.display()
    )
}

/// Hand the sshd step to the task, wait for it, and say what it reported, on `say`.
///
/// The order: the task is registered, run, and the hand-over line said; only then is the task waited for, so
/// that an `apply` ended from there on leaves the step to the task. When the instances have ended, the report is
/// printed and the task removed. The report is believed to be whole only when it says so itself ([`REPORT_END`]
/// is its last line); one that does not means the task's process ended before the step did, and it is printed as
/// far as it goes. A wait that cannot say the instances ended leaves the task registered and the report unread,
/// and says that the step may still run: nothing is concluded from it. No failure fails `apply`.
pub fn hand_over(task: &mut dyn SshdTask, report: &Path, say: &mut dyn FnMut(&str)) {
    if let Err(e) = task.register() {
        say(&not_set_up("registered", &e));
        return;
    }
    if let Err(e) = task.run() {
        say(&not_set_up("started", &e));
        remove(task, say);
        return;
    }
    say(&handed_over_line(report));

    match task.wait() {
        Ok(WaitOutcome::Ended) => {}
        Ok(WaitOutcome::NeverLaunched { .. }) => {
            say(&format!(
                "apply: the Task Scheduler lists an instance of the task {APPLY_SSHD_TASK} that it has not \
                 started; it may still run, and nothing is known of what it does. Its report is {}",
                report.display()
            ));
            return;
        }
        Err(e) => {
            say(&format!(
                "apply: waiting for the task {APPLY_SSHD_TASK} failed ({e:#}); it may still run. Its report is {}",
                report.display()
            ));
            return;
        }
    }

    // The report says itself that it is whole: a process that ends before the step does (a panic, an
    // administrator ending the task) leaves it without its closing line.
    match task.report() {
        Ok(text) => {
            let Report { lines, complete } = Report::parse(&text);
            if complete {
                if lines.is_empty() {
                    say(
                        "apply: sshd accepts SSH_BROKER_ELEVATION and has read its configuration; the task had nothing to change",
                    );
                }
            } else {
                say(&format!(
                    "apply: the task {APPLY_SSHD_TASK} ended before its report was complete; what it had said \
                     follows. {CHECK_SSHD}"
                ));
                if lines.is_empty() {
                    say(&format!("apply: the task {APPLY_SSHD_TASK} had said nothing"));
                }
            }
            for line in lines {
                say(&line);
            }
        }
        Err(e) => say(&format!(
            "apply: the task {APPLY_SSHD_TASK} left no report in {} ({e:#}). Whether sshd accepts \
             SSH_BROKER_ELEVATION and is running is not known: `ssh-broker verify` says, and `sc query sshd` \
             shows whether sshd runs",
            report.display()
        )),
    }
    remove(task, say);
}

fn not_set_up(did_not: &str, cause: &anyhow::Error) -> String {
    format!(
        "apply: sshd was not set up to accept {}: the task {APPLY_SSHD_TASK} could not be {did_not}: {cause:#}. \
         Nothing of sshd's was changed; `ssh-broker elevate` works without it.",
        crate::protocol::ElevationPolicy::VARIABLE
    )
}

fn remove(task: &mut dyn SshdTask, say: &mut dyn FnMut(&str)) {
    if let Err(e) = task.remove() {
        say(&format!(
            "apply: the task {APPLY_SSHD_TASK} could not be removed ({e:#}); it has no trigger, runs nothing by \
             itself, and the next apply replaces it"
        ));
    }
}

/// The last line of a report whose step ended: the report says itself that it is whole, so that nothing has to
/// be read of the Task Scheduler to know.
pub const REPORT_END: &str = "apply-sshd: the step has ended; this report is complete";

/// A report text read: the lines the step said, and whether the step ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// What the step said, without the closing line.
    pub lines: Vec<String>,
    /// The last line is [`REPORT_END`]: the step ended and said everything it had to.
    pub complete: bool,
}

impl Report {
    /// The lines of `text`, and whether the last of them is [`REPORT_END`] (that line is not in `lines`).
    pub fn parse(text: &str) -> Report {
        let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
        let complete = lines.last().is_some_and(|last| last == REPORT_END);
        if complete {
            lines.pop();
        }
        Report { lines, complete }
    }
}

/// One line and its break, in one write, so that a reader never finds half of a line; in the file when it
/// returns.
fn append(file: &mut std::fs::File, line: &str) -> std::io::Result<()> {
    file.write_all(format!("{line}\r\n").as_bytes())?;
    file.flush()
}

/// The verb's side: empty the report at `path`, then run `step`, whose every line is appended to the report and
/// is in the file when `say` returns. When `step` has returned and every line was written, [`REPORT_END`] is
/// appended: a report that is missing a line never closes. Without a report to write to nothing is run: its
/// words would be lost, and the `apply` that waits for the task would find none.
pub fn write_report(path: &Path, step: impl FnOnce(&mut dyn FnMut(&str))) -> anyhow::Result<()> {
    let mut file = std::fs::File::create(path).with_context(|| format!("empty the report {}", path.display()))?;
    let mut failure = None;
    step(&mut |line| {
        if let Err(e) = append(&mut file, line) {
            failure.get_or_insert(e);
        }
    });
    if failure.is_none() {
        failure = append(&mut file, REPORT_END).err();
    }
    match failure {
        None => Ok(()),
        Some(e) => Err(e).with_context(|| format!("write the report {}", path.display())),
    }
}

#[cfg(test)]
#[path = "sshd_task_tests.rs"]
mod sshd_task_tests;
