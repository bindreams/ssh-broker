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
        })
    }

    /// The file for the date now, opened if the date is not the one the current file is for. A
    /// failed open leaves the current file as it was, so the next write tries again.
    fn file(&mut self) -> std::io::Result<&mut std::fs::File> {
        let today = (self.clock)();
        if self.current.0 != today {
            let file = acl::open_log_file(&self.dir, &file_name(&self.prefix, today)).map_err(std::io::Error::other)?;
            self.current = (today, file);
        }
        Ok(&mut self.current.1)
    }
}

impl<C: Fn() -> Date> Write for DailyLog<C> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file()?.write(buf)
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
