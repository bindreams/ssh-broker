//! provision::path_env — the install directory on the system `PATH`.
//!
//! `apply` appends [`super::BASE_DIR`] to the machine's `Path` value so that a session finds `ssh-broker` by
//! name (`ssh-broker elevate ...`). This module is the pure part: what to write for what is stored, and the
//! `verify` row. Reading and writing the value is `registry`'s.

use super::report::Check;

/// What the system `Path` value holds, as the registry stores it. Which of the two string types it is must
/// survive a write: a `REG_EXPAND_SZ` that became a `REG_SZ` would stop its `%SystemRoot%` from expanding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stored {
    Sz(String),
    ExpandSz(String),
    /// Any other registry type, by its number.
    Other(u32),
}

/// What reading the system `Path` gave: the value, `None` when there is none, or why it could not be read.
pub type Reading = Result<Option<Stored>, String>;

/// What `apply` does about the `PATH`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathPlan {
    /// The directory is on it.
    Present,
    /// Write `value`, as `REG_EXPAND_SZ` when `expand` and as `REG_SZ` when not.
    Write { value: String, expand: bool },
    /// Change nothing, for this reason.
    Refuse(String),
}

/// The longest environment variable Windows hands a process, in characters.
const LONGEST_VARIABLE: usize = 32767;

/// Whether `segment` of a `PATH` names `dir`: without regard to case, a trailing backslash, surrounding
/// spaces or quotes. A `%VAR%` is not expanded, so a segment that spells the directory through one is not
/// recognised, and the directory is added.
fn is_directory(segment: &str, dir: &str) -> bool {
    let plain = |text: &str| {
        text.trim()
            .trim_matches('"')
            .trim_end_matches('\\')
            .trim()
            .to_ascii_lowercase()
    };
    plain(segment) == plain(dir)
}

/// `path` with `dir` appended after a `;`, or `None` when `dir` is one of its segments already.
pub fn with_directory(path: &str, dir: &str) -> Option<String> {
    if path.split(';').any(|segment| is_directory(segment, dir)) {
        return None;
    }
    let separator = if path.is_empty() || path.ends_with(';') {
        ""
    } else {
        ";"
    };
    Some(format!("{path}{separator}{dir}"))
}

/// What to do about the stored value. A value of any other type, one that is not there, one that could not
/// be read and one that would pass the longest an environment variable can be change nothing.
pub fn plan(current: &Reading, dir: &str) -> PathPlan {
    let (value, expand) = match current {
        Err(why) => return PathPlan::Refuse(format!("cannot read the system PATH: {why}")),
        Ok(None) => return PathPlan::Refuse("the system PATH has no Path value".into()),
        Ok(Some(Stored::Other(kind))) => {
            return PathPlan::Refuse(format!(
                "the system PATH is stored as registry type {kind}, not as a string"
            ));
        }
        Ok(Some(Stored::Sz(value))) => (value, false),
        Ok(Some(Stored::ExpandSz(value))) => (value, true),
    };
    match with_directory(value, dir) {
        None => PathPlan::Present,
        Some(longer) if longer.encode_utf16().count() > LONGEST_VARIABLE => PathPlan::Refuse(format!(
            "adding {dir} would make the system PATH longer than {LONGEST_VARIABLE} characters"
        )),
        Some(value) => PathPlan::Write { value, expand },
    }
}

/// The `verify` row: the install directory is on the system `PATH`.
pub fn row(current: &Reading, dir: &str) -> Check {
    const NAME: &str = "install directory on PATH";
    match current {
        Err(why) => Check::new(NAME, false, format!("cannot read the system PATH: {why}")),
        Ok(None) => Check::new(NAME, false, "the system PATH has no Path value"),
        Ok(Some(Stored::Other(kind))) => Check::new(
            NAME,
            false,
            format!("the system PATH is stored as registry type {kind}, so it cannot be checked"),
        ),
        Ok(Some(Stored::Sz(value) | Stored::ExpandSz(value))) => match with_directory(value, dir) {
            None => Check::new(NAME, true, format!("{dir} is on the system PATH")),
            Some(_) => Check::new(
                NAME,
                false,
                format!("{dir} is not on the system PATH; run `ssh-broker apply`"),
            ),
        },
    }
}

#[cfg(test)]
#[path = "path_env_tests.rs"]
mod path_env_tests;
