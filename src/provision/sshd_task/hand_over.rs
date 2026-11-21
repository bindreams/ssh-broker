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
/// `report`. It does not name `doctor`: after a dropped connection the person reconnects unelevated, where
/// `doctor` does not judge the sshd row.
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
/// stderr, and the task is removed; the notes of the report stay in the report.
///
/// Warnings of its own (stderr): the task could not be registered, started or removed, the report could not be
/// read, or it lacks [`REPORT_END`](super::REPORT_END) (then the whole report follows, notes included). A wait
/// that cannot tell the instances ended leaves the task registered and says the step may still run. No step line
/// when the step could not be handed over. No failure fails `install`.
pub fn hand_over(task: &mut dyn SshdTask, report: &Path, exe: &Path, say: &mut Say<'_>) {
    if let Err(e) = task.register() {
        say(Stream::Err, &not_set_up("registered", &e));
        return;
    }
    if let Err(e) = task.run() {
        say(Stream::Err, &not_set_up("started", &e));
        remove(task, say);
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

    // A process that ends before the step (a panic, `schtasks /End`) leaves no closing line.
    match task.report() {
        Ok(text) => {
            let report_read = Report::parse(&text);
            if report_read.complete {
                for text in report_read.warnings() {
                    warn(text);
                }
            } else {
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
    remove(task, say);
}

fn not_set_up(did_not: &str, cause: &anyhow::Error) -> String {
    format!(
        "sshd was not set up to accept {}: the task {INSTALL_SSHD_TASK} could not be {did_not}: {cause:#}. Nothing of \
         sshd's was changed; `ssh-broker elevate` works without it.",
        crate::protocol::ElevationPolicy::VARIABLE
    )
}

fn remove(task: &mut dyn SshdTask, say: &mut Say<'_>) {
    if let Err(e) = task.remove() {
        say(
            Stream::Err,
            &format!(
                "the task {INSTALL_SSHD_TASK} could not be removed ({e:#}); it has no trigger, runs nothing by itself, \
                 and the next install replaces it"
            ),
        );
    }
}

#[cfg(test)]
#[path = "hand_over_tests.rs"]
mod hand_over_tests;
