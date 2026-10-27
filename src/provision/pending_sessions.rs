//! provision::pending_sessions — the auto-login tasks `apply` has disabled and owes an enable.
//!
//! `apply` disables each auto-login task that is on before it replaces the exe, and enables it
//! again at the end. A task that was off stays off, so a task found disabled cannot be told from
//! one an `apply` killed in between left that way. This file, written before the first task is
//! disabled and removed once every one is enabled again, is the difference. It lives in the
//! install directory, which only an administrator can write, and is read only after that
//! directory has passed its ACL check.

use std::io::Write;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use anyhow::Context;
use windows::Win32::Storage::FileSystem::{MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW};
use windows::core::PCWSTR;

use super::session_task::TASK_PREFIX;

/// The names of the tasks owed an enable, in the order they were stored. No file is none. A line
/// that is not the name of an auto-login task is skipped: nothing else is ever enabled from here.
pub fn load(path: &Path) -> anyhow::Result<Vec<String>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
    };
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with(TASK_PREFIX))
        .map(str::to_string)
        .collect())
}

/// Make `names` the tasks owed an enable; none removes the file.
///
/// The new contents replace the old in one step and are on disk when this returns (the file is
/// flushed, and the replacement is written through), so a crash, also of the machine, leaves the
/// old list or the new one. Removing the file is not written through: a removal that a crash undoes
/// leaves a list whose tasks are enabled already, and enabling them again is harmless.
pub fn store(path: &Path, names: &[String]) -> anyhow::Result<()> {
    if names.is_empty() {
        return match std::fs::remove_file(path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                Err(e).with_context(|| format!("remove {}", path.display()))
            }
            _ => Ok(()),
        };
    }
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(".new");
    let temporary = std::path::PathBuf::from(temporary);
    let write = || -> std::io::Result<()> {
        let mut file = std::fs::File::create(&temporary)?;
        for name in names {
            writeln!(file, "{name}")?;
        }
        file.sync_all()?;
        replace_file(&temporary, path)
    };
    write().with_context(|| format!("write {}", path.display()))
}

/// Move `from` over `to`, replacing it, and return only once the move is on disk: `std::fs::rename`
/// is not written through, so a crash just after it could undo the move.
fn replace_file(from: &Path, to: &Path) -> std::io::Result<()> {
    let wide = |path: &Path| -> Vec<u16> { path.as_os_str().encode_wide().chain(std::iter::once(0)).collect() };
    let (from, to) = (wide(from), wide(to));
    // SAFETY: both paths are NUL-terminated and outlive the call.
    unsafe {
        MoveFileExW(
            PCWSTR(from.as_ptr()),
            PCWSTR(to.as_ptr()),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    }
    .map_err(std::io::Error::from)
}

#[cfg(test)]
#[path = "pending_sessions_tests.rs"]
mod pending_sessions_tests;
