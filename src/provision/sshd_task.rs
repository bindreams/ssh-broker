//! provision::sshd_task — `install`'s sshd step, run by a task so that it finishes even if `install` is ended.
//!
//! `install` run over SSH runs inside the session's job, which ends every process in it when the connection
//! ends, and the sshd step restarts the very sshd that carries that connection: an `install` ended between the
//! stop and the start would leave a machine reached only over SSH without sshd. So `install` registers the task
//! [`schtasks::INSTALL_SSHD_TASK`], which runs the hidden verb `install-sshd` as SYSTEM, starts it, and waits for
//! it. A service starts the task's process, outside the session's job, and it runs the step to its end
//! whatever happens to `install`. The verb writes what the step says to a report, a line at a time, and `install`
//! shows the warnings of the report once the task's instances have ended; the notes stay in the report.
//!
//! The order and the sentences are in [`hand_over`], over [`SshdTask`], which tests stand in for; [`system`] is the
//! Task Scheduler behind it. The report, and what each of its lines is, are here. No failure here fails `install`:
//! the variable is a convenience.

use std::path::Path;

use anyhow::Context;

#[cfg(windows)]
mod hand_over;
#[cfg(windows)]
mod system;
#[cfg(windows)]
pub use hand_over::{HANDED_OVER_PREFIX, SshdTask, hand_over, step_line};
#[cfg(windows)]
pub use system::{hand_over_sshd_step, report_path};

/// What a line of the sshd step is. A note says what the step did or found; a warning says what the person must do,
/// what the step could not do or could not find out, or that sshd is not running or was not restarted. `install`
/// shows the warnings and leaves the notes in the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineKind {
    Note,
    Warning,
}

/// The beginning of a warning's line in the report; a note's line has none, so the report reads as plain text and
/// `Report::parse` tells the two apart.
pub const WARNING_PREFIX: &str = "warning: ";

/// The report's text for a line of `kind` that says `text`: one report line for each line of `text`, each warning
/// line with [`WARNING_PREFIX`].
pub fn render(kind: LineKind, text: &str) -> String {
    match kind {
        LineKind::Note => {
            debug_assert!(
                text.lines().all(|line| !line.starts_with(WARNING_PREFIX)),
                "a note that begins like a warning would be read as one: {text}"
            );
            text.to_owned()
        }
        LineKind::Warning => text
            .lines()
            .map(|line| format!("{WARNING_PREFIX}{line}"))
            .collect::<Vec<_>>()
            .join("\n"),
    }
}

/// The last line of a report whose step ended: the report says itself that it is whole, so that nothing has to
/// be read of the Task Scheduler to know.
pub const REPORT_END: &str = "the step has ended; this report is complete";

/// One line of a report: what the step said, and what kind of line it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportLine {
    pub kind: LineKind,
    pub text: String,
}

/// A report text read: the lines the step said, and whether the step ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// What the step said, without the closing line.
    pub lines: Vec<ReportLine>,
    /// The last line is [`REPORT_END`]: the step ended and said everything it had to.
    pub complete: bool,
}

impl Report {
    /// The lines of `text`, and whether the last of them is [`REPORT_END`] (that line is not in `lines`).
    pub fn parse(text: &str) -> Report {
        let mut lines: Vec<&str> = text.lines().collect();
        let complete = lines.last().is_some_and(|last| *last == REPORT_END);
        if complete {
            lines.pop();
        }
        Report {
            lines: lines
                .into_iter()
                .map(|line| match line.strip_prefix(WARNING_PREFIX) {
                    Some(text) => ReportLine {
                        kind: LineKind::Warning,
                        text: text.to_owned(),
                    },
                    None => ReportLine {
                        kind: LineKind::Note,
                        text: line.to_owned(),
                    },
                })
                .collect(),
            complete,
        }
    }

    /// The warnings, in the order they were said.
    pub fn warnings(&self) -> impl Iterator<Item = &str> {
        self.lines
            .iter()
            .filter(|line| line.kind == LineKind::Warning)
            .map(|line| line.text.as_str())
    }
}

/// One line and its break, in one write, so that a reader never finds half of a line; in the file when it
/// returns.
fn append(out: &mut impl std::io::Write, line: &str) -> std::io::Result<()> {
    out.write_all(format!("{line}\r\n").as_bytes())?;
    out.flush()
}

/// The verb's side: empty the report at `path`, then run `step`, whose every line is appended to the report and
/// is in the file when `say` returns. When `step` has returned and every line was written, [`REPORT_END`] is
/// appended: a report that is missing a line never closes. Without a report to write to nothing is run: its
/// words would be lost, and the `install` that waits for the task would find none.
pub fn write_report(path: &Path, step: impl FnOnce(&mut dyn FnMut(LineKind, &str))) -> anyhow::Result<()> {
    let mut file = std::fs::File::create(path).with_context(|| format!("empty the report {}", path.display()))?;
    write_lines(&mut file, step).with_context(|| format!("write the report {}", path.display()))
}

/// [`write_report`] over a writer that is already open: the first line that cannot be written is the error, and
/// no closing line follows it.
fn write_lines(
    out: &mut impl std::io::Write,
    step: impl FnOnce(&mut dyn FnMut(LineKind, &str)),
) -> std::io::Result<()> {
    let mut failure = None;
    step(&mut |kind, text| {
        for line in render(kind, text).lines() {
            if let Err(e) = append(out, line) {
                failure.get_or_insert(e);
            }
        }
    });
    match failure {
        None => append(out, REPORT_END),
        Some(e) => Err(e),
    }
}

#[cfg(test)]
#[path = "sshd_task_tests.rs"]
mod sshd_task_tests;
