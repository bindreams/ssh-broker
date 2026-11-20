//! provision::path_env — the install directory on the system `PATH`.
//!
//! `apply` appends [`super::BASE_DIR`] to the machine's `Path` value so that a session finds `ssh-broker` by
//! name (`ssh-broker elevate ...`). This module is the pure part: what to write for what is stored, and the
//! `doctor` row. Reading and writing the value is `registry`'s.
//!
//! The value is read, changed and written back whole, as every program that edits it does: a write another
//! program makes between the two is lost. Nothing can guard that from one side (see the README).

use super::report::Check;

/// Which of the two string types the system `Path` value is must survive a write: a `REG_EXPAND_SZ` that
/// became a `REG_SZ` would stop its `%SystemRoot%` from expanding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stored {
    Sz(String),
    ExpandSz(String),
    /// Any other registry type, by its number.
    Other(u32),
}

/// What reading the system `Path` gave: the value, `None` when there is none, or why it could not be read.
pub type Reading = Result<Option<Stored>, String>;

/// The data of a `REG_SZ` or (`expand`) `REG_EXPAND_SZ` value as [`Stored`]: UTF-16, little-endian, with the
/// terminator the registry keeps (or none, or several). A value that would not be written back as it was read
/// is `Err` with the reason: one that is not whole code units, one with an unpaired surrogate (a lossy decode
/// would write U+FFFD in its place), one with a NUL before its terminators (the data after it would be cut
/// off). Writing the system `PATH` back after any of those would change it machine-wide.
pub fn decode_string(data: &[u8], expand: bool) -> Result<Stored, String> {
    let (pairs, rest) = data.as_chunks::<2>();
    if !rest.is_empty() {
        return Err("its data is not a whole number of UTF-16 code units".into());
    }
    let units: Vec<u16> = pairs.iter().map(|pair| u16::from_le_bytes(*pair)).collect();
    let end = units.iter().rposition(|&unit| unit != 0).map_or(0, |last| last + 1);
    let units = &units[..end];
    if units.contains(&0) {
        return Err("it holds a NUL before its end, so the data after it would be lost".into());
    }
    let text = String::from_utf16(units).map_err(|_| "it is not valid UTF-16 (it has an unpaired surrogate)")?;
    Ok(if expand {
        Stored::ExpandSz(text)
    } else {
        Stored::Sz(text)
    })
}

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
/// be read and one that would pass the longest an environment variable can be change nothing. A process gets
/// a `REG_EXPAND_SZ` value expanded, so that is the length checked: `expanded_length` gives the number of
/// characters of the text once its `%VARIABLES%` are expanded, or why it cannot be had (which changes nothing
/// either). A `REG_SZ` value is measured as stored.
pub fn plan(current: &Reading, dir: &str, expanded_length: impl Fn(&str) -> Result<usize, String>) -> PathPlan {
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
    let Some(longer) = with_directory(value, dir) else {
        return PathPlan::Present;
    };
    let length = if expand {
        match expanded_length(&longer) {
            Ok(length) => length,
            Err(why) => {
                return PathPlan::Refuse(format!(
                    "adding {dir} would make a system PATH whose length once expanded cannot be told: {why}"
                ));
            }
        }
    } else {
        longer.encode_utf16().count()
    };
    if length > LONGEST_VARIABLE {
        let expanded = if expand { " once expanded" } else { "" };
        return PathPlan::Refuse(format!(
            "adding {dir} would make the system PATH longer than {LONGEST_VARIABLE} characters{expanded}"
        ));
    }
    PathPlan::Write { value: longer, expand }
}

/// The `doctor` row: the install directory is on the system `PATH`.
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
