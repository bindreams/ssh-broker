//! provision::sshd_task — `install`'s sshd step, run by a task so that it finishes even if `install` is ended.
//!
//! `install` run over SSH runs inside the session's job, which ends every process in it when the connection
//! ends, and the sshd step restarts the very sshd that carries that connection: an `install` ended between the
//! stop and the start would leave a machine reached only over SSH without sshd. So `install` registers the task
//! [`schtasks::INSTALL_SSHD_TASK`], which runs the hidden verb `install-sshd` as SYSTEM, starts it, and waits for
//! it. A service starts the task's process, outside the session's job, and it runs the step to its end
//! whatever happens to `install`. The verb writes what the step says to a report, a line at a time, and `install`
//! shows the warnings of the report once the task's instances have ended; the notes stay in the report, unless
//! the report has no closing line, and then `install` shows it whole.
//!
//! The order and the sentences are in [`hand_over`], over [`SshdTask`], which tests stand in for; [`system`] is the
//! Task Scheduler behind it. The report file is here, with the format of its lines: [`render`] and [`Report::parse`]
//! are inverses, and a warning's line begins with [`WARNING_PREFIX`]. Which kind a line is ([`LineKind`]) is
//! [`super::sshd_config`]'s, which does not depend on this module. No failure here fails `install`: the variable is
//! a convenience.

use std::path::Path;

use anyhow::Context;

use super::sshd_config::LineKind;

mod hand_over;
#[cfg(windows)]
mod system;
pub use hand_over::{HANDED_OVER_PREFIX, SshdTask, hand_over, step_line};
#[cfg(windows)]
pub use system::{hand_over_sshd_step, report_path};

/// The last line of a report whose step ended: the report says itself that it is whole, so that nothing has to
/// be read of the Task Scheduler to know.
pub const REPORT_END: &str = "the step has ended; this report is complete";

/// The beginning of a warning's line in the report; a note's line has none, so the report reads as plain text and
/// [`read_line`] tells the two apart.
pub const WARNING_PREFIX: &str = "warning: ";

/// Whether a note's `line`, after any spaces, begins with [`WARNING_PREFIX`] or is [`REPORT_END`]: it would read as
/// a warning or as the closing line, so [`render`] puts one space in front of it.
fn reads_as_the_reports_own(line: &str) -> bool {
    let line = line.trim_start_matches(' ');
    line.starts_with(WARNING_PREFIX) || line == REPORT_END
}

/// The report's text for a line of `kind` that says `text`: one report line for each line of `text` (one empty line
/// for an empty text), each warning line with [`WARNING_PREFIX`]. A note line that [`reads_as_the_reports_own`]
/// gets one more space in front, which [`read_line`] takes off: a note never reads as a warning, and no line of
/// the step reads as the closing line.
pub fn render(kind: LineKind, text: &str) -> String {
    let mut lines: Vec<&str> = text.lines().collect();
    if lines.is_empty() {
        lines.push("");
    }
    lines
        .into_iter()
        .map(|line| match kind {
            LineKind::Warning => format!("{WARNING_PREFIX}{line}"),
            LineKind::Note if reads_as_the_reports_own(line) => format!(" {line}"),
            LineKind::Note => line.to_owned(),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The kind and the text of one line of a report, the inverse of [`render`] for one line.
fn read_line(line: &str) -> (LineKind, &str) {
    if let Some(text) = line.strip_prefix(WARNING_PREFIX) {
        (LineKind::Warning, text)
    } else if line.starts_with(' ') && reads_as_the_reports_own(line) {
        (LineKind::Note, &line[1..])
    } else {
        (LineKind::Note, line)
    }
}

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
                .map(|line| {
                    let (kind, text) = read_line(line);
                    ReportLine {
                        kind,
                        text: text.to_owned(),
                    }
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
/// nothing is written after it (a failed write may have left half a line), the closing line included.
fn write_lines(
    out: &mut impl std::io::Write,
    step: impl FnOnce(&mut dyn FnMut(LineKind, &str)),
) -> std::io::Result<()> {
    let mut failure = None;
    step(&mut |kind, text| {
        for line in render(kind, text).split('\n') {
            if failure.is_none()
                && let Err(e) = append(out, line)
            {
                failure = Some(e);
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
