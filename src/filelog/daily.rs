//! The log file, opened under a folder's handle.
//!
//! `tracing-appender`'s rolling appender joins a path and opens it, which is the by-path step the
//! private folder avoids, so this writes the same files itself: `<prefix>.<YYYY-MM-DD>` in UTC, a
//! new one when the date changes. Each file is opened by [`acl::open_log_file`], relative to the
//! handle, so a link in the folder is refused and never written through.

use std::io::Write;

use anyhow::Context;
use time::Date;

use crate::acl::{self, DirHandle};

/// Appends to `<prefix>.<YYYY-MM-DD>` (UTC, by `clock`) under `dir`, opening the next day's file
/// when the date changes.
pub struct DailyLog<C: Fn() -> Date> {
    dir: DirHandle,
    prefix: String,
    clock: C,
    current: (Date, std::fs::File),
    /// The cause the current file last said, in the note it holds, for the new day's file that would
    /// not open. Cleared when a new file opens.
    noted: Option<String>,
}

/// The name of the log file of `prefix` for `date`.
fn file_name(prefix: &str, date: Date) -> String {
    format!(
        "{prefix}.{:04}-{:02}-{:02}",
        date.year(),
        u8::from(date.month()),
        date.day()
    )
}

impl<C: Fn() -> Date> DailyLog<C> {
    /// Open today's file, so a folder that cannot be logged into is the error of making the log.
    pub fn new(dir: DirHandle, prefix: &str, clock: C) -> anyhow::Result<DailyLog<C>> {
        let today = clock();
        let name = file_name(prefix, today);
        let file = acl::open_log_file(&dir, &name).with_context(|| format!("open the log file {name}"))?;
        Ok(DailyLog {
            dir,
            prefix: prefix.to_owned(),
            clock,
            current: (today, file),
            noted: None,
        })
    }

    /// The file for the date now, opened if the date is not the one the current file is for. When
    /// that open fails the current file is kept and written to, as the rolling appender does, and
    /// says why in a line (see [`Self::note_unopened`]); every later write tries the new name again,
    /// with no limit, until it opens.
    fn file(&mut self) -> &mut std::fs::File {
        let today = (self.clock)();
        if self.current.0 != today {
            let name = file_name(&self.prefix, today);
            match acl::open_log_file(&self.dir, &name) {
                Ok(file) => {
                    self.current = (today, file);
                    self.noted = None;
                }
                Err(error) => self.note_unopened(&name, &error),
            }
        }
        &mut self.current.1
    }

    /// Say in the current file that `name` would not open, the first time and whenever the cause's
    /// text changes. The retry at every write finds the same cause, and that costs no text: it is
    /// compared as it is written, not built.
    fn note_unopened(&mut self, name: &str, error: &anyhow::Error) {
        if self.noted.as_deref().is_some_and(|noted| says(error, noted)) {
            return;
        }
        let cause = format!("{error:#}");
        let _ = writeln!(
            self.current.1,
            "ssh-broker: cannot open the log file {name}, so this one is still being written: {cause}"
        );
        self.noted = Some(cause);
    }
}

/// Whether `error`, as `{error:#}` writes it, is exactly `text`.
fn says(error: &anyhow::Error, text: &str) -> bool {
    struct Expect<'a>(&'a str);
    impl std::fmt::Write for Expect<'_> {
        fn write_str(&mut self, piece: &str) -> std::fmt::Result {
            self.0 = self.0.strip_prefix(piece).ok_or(std::fmt::Error)?;
            Ok(())
        }
    }
    let mut expect = Expect(text);
    std::fmt::write(&mut expect, format_args!("{error:#}")).is_ok() && expect.0.is_empty()
}

impl<C: Fn() -> Date> Write for DailyLog<C> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.current.1.flush()
    }
}

/// A [`DailyLog`] for the UTC date, which is the date `tracing-appender` names its files by.
pub fn daily(dir: DirHandle, prefix: &str) -> anyhow::Result<DailyLog<impl Fn() -> Date + Send + 'static>> {
    DailyLog::new(dir, prefix, || time::OffsetDateTime::now_utc().date())
}

#[cfg(test)]
#[path = "daily_tests.rs"]
mod daily_tests;
