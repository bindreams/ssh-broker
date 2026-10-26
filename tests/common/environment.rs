//! An environment block for `CreateProcess*`'s `lpEnvironment`.
#![allow(dead_code)]

use std::ffi::OsString;
use std::os::windows::ffi::OsStrExt;

/// `NAME=value` entries, each NUL-terminated, sorted by name without regard to case (as the
/// system's own blocks are), and closed by an extra NUL. Pass it with `CREATE_UNICODE_ENVIRONMENT`.
pub fn block(vars: impl IntoIterator<Item = (OsString, OsString)>) -> Vec<u16> {
    let mut entries: Vec<(Vec<u16>, Vec<u16>)> = vars
        .into_iter()
        .map(|(name, value)| (name.encode_wide().collect(), value.encode_wide().collect()))
        .collect();
    let folded = |name: &[u16]| String::from_utf16_lossy(name).to_uppercase();
    entries.sort_by_key(|(name, _)| folded(name));

    let mut out = Vec::new();
    for (name, value) in entries {
        out.extend(name);
        out.push(u16::from(b'='));
        out.extend(value);
        out.push(0);
    }
    out.push(0);
    if out.len() == 1 {
        out.push(0); // an empty block is two NULs
    }
    out
}

/// This process's environment as a block.
pub fn current_block() -> Vec<u16> {
    block(std::env::vars_os())
}
