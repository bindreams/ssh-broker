//! provision::sshd_task::hand_over — `install`'s side of the sshd step: the task's registration, its start, the
//! wait for it, and what is said of the report it wrote.

use std::path::Path;

use super::Report;
use crate::provision::schtasks::{INSTALL_SSHD_TASK, WaitOutcome, end_and_remove_install_sshd_task};
use crate::provision::sshd_config::CHECK_SSHD;
use crate::provision::{Say, Stream};

/// What the hand-over needs of the Task Scheduler and the report.
pub trait SshdTask {
    /// Register the task, replacing a copy an earlier `install` left behind, and clear the report of an earlier
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

/// Beginning of the line that says the step is the task's; a caller that ends `install` once the step is the task's
/// waits for it.
pub const HANDED_OVER_PREFIX: &str = "Setting up sshd to accept SSH_BROKER_ELEVATION";

/// The step line: what is about to happen to sshd, that a connection over SSH may drop, and where what the step
/// does is written. It is all the person has while the task runs and when the connection drops, so it names the
/// `report`. It promises nothing else: the session a person gets when they reconnect is unelevated, and there
/// `doctor` does not judge the sshd row, so the line does not send them to it.
pub fn step_line(report: &Path) -> String {
    format!(
        "{HANDED_OVER_PREFIX}; sshd may be restarted, and a connection over SSH may drop now. What the step does is \
         written to {}...",
        report.display()
    )
}

/// Hand the sshd step to the task, wait for it, and say on `say` what a person needs of it. `exe` is the installed
/// exe, `report` the file the task writes.
///
/// The step line (stdout) is said right after the task is started and before the wait, so an `install` ended from
/// there on leaves the step to the task. When the instances have ended, each warning of the report is said on
/// stderr, and the task is removed; the notes of the report stay in the report. Every line of this function's own
/// is a warning, said on stderr: the task could not be registered, started or removed, the report could not be
/// read, or it is not whole (its last line, [`REPORT_END`](super::REPORT_END), is missing: the task's process ended
/// before the step did, or a line could not be written). A report that is not whole is said whole after that
/// warning, every line of it, notes and warnings, in order: they are what the step had written. A wait that cannot
/// say the instances ended leaves the task
/// registered and the report unread, and says that the step may still run: nothing is concluded from it. A step
/// that could not be handed over says no step line. No failure fails `install`.
pub fn hand_over(task: &mut dyn SshdTask, report: &Path, exe: &Path, say: &mut Say<'_>) {
    let mut warn = |text: &str| say(Stream::Err, text);
    if let Err(e) = task.register() {
        warn(&not_set_up("registered", &e));
        return;
    }
    if let Err(e) = task.run() {
        warn(&not_set_up("started", &e));
        remove(task, &mut warn);
        return;
    }
    say(Stream::Out, &step_line(report));
    let mut warn = |text: &str| say(Stream::Err, text);

    match task.wait() {
        Ok(WaitOutcome::Ended) => {}
        Ok(WaitOutcome::NeverLaunched { .. }) => {
            warn(&format!(
                "the Task Scheduler lists an instance of the task {INSTALL_SSHD_TASK} that it has not started; it \
                 may still run, and nothing is known of what it does. Its report is {}. End and remove the task {} \
                 when it is not wanted; if the step has started meanwhile, ending it can leave sshd stopped. \
                 {CHECK_SSHD}",
                report.display(),
                end_and_remove_install_sshd_task()
            ));
            return;
        }
        Err(e) => {
            warn(&format!(
                "waiting for the task {INSTALL_SSHD_TASK} failed ({e:#}); it may still run. Its report is {}",
                report.display()
            ));
            return;
        }
    }

    // The report says itself that it is whole: a process that ends before the step does (a panic, an
    // administrator ending the task) leaves it without its closing line.
    match task.report() {
        Ok(text) => {
            let report_read = Report::parse(&text);
            if report_read.complete {
                for text in report_read.warnings() {
                    warn(text);
                }
            } else {
                // What a report that stopped holds is all there is to show of the step: every line, in order.
                warn(&format!(
                    "the report of the task {INSTALL_SSHD_TASK} has no closing line: the task was ended before its \
                     step finished, or a line of the report could not be written. {CHECK_SSHD} The lines the step \
                     had written, if any, follow."
                ));
                if report_read.lines.is_empty() {
                    warn(&format!("the task {INSTALL_SSHD_TASK} had said nothing"));
                }
                for line in &report_read.lines {
                    warn(&line.text);
                }
            }
        }
        Err(e) => warn(&format!(
            "the report of the task {INSTALL_SSHD_TASK} could not be read in {} ({e:#}); if it is not there, the \
             task did not start or could not create it. Whether sshd accepts SSH_BROKER_ELEVATION and is running is \
             not known: `{} doctor`, run elevated by an administrator, says whether sshd accepts it, and `sc query \
             sshd` shows whether sshd runs",
            report.display(),
            exe.display()
        )),
    }
    remove(task, &mut warn);
}

fn not_set_up(did_not: &str, cause: &anyhow::Error) -> String {
    format!(
        "sshd was not set up to accept {}: the task {INSTALL_SSHD_TASK} could not be {did_not}: {cause:#}. Nothing of \
         sshd's was changed; `ssh-broker elevate` works without it.",
        crate::protocol::ElevationPolicy::VARIABLE
    )
}

fn remove(task: &mut dyn SshdTask, warn: &mut dyn FnMut(&str)) {
    if let Err(e) = task.remove() {
        warn(&format!(
            "the task {INSTALL_SSHD_TASK} could not be removed ({e:#}); it has no trigger, runs nothing by itself, and \
             the next install replaces it"
        ));
    }
}

#[cfg(test)]
#[path = "hand_over_tests.rs"]
mod hand_over_tests;
