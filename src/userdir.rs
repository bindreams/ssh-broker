//! userdir: the current account's profile, and the socket location inside it.
//!
//! The location comes from the account's *token* and from nothing the caller controls. That is
//! the property that keeps an SSH session as one account away from another account's agent:
//! `%USERPROFILE%` and `%LOCALAPPDATA%` are environment, which the caller (or a parent process)
//! can set to anything, and they are not reliably present in an sshd session (a network or S4U
//! logon has no loaded profile hive). The profile directory is read from the `ProfileList` key
//! under HKLM by `GetUserProfileDirectoryW`, which needs no hive.

use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;

use anyhow::Context;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::TOKEN_QUERY;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::UI::Shell::GetUserProfileDirectoryW;
use windows::core::PWSTR;

use crate::socket_loc::{self, SocketLocation};
use crate::winutil::OwnedHandle;

/// The profile directory of the account `token` belongs to. `token` needs `TOKEN_QUERY`.
pub fn profile_dir_of_token(token: HANDLE) -> anyhow::Result<PathBuf> {
    // Size probe: the first call fails with the needed length, in UTF-16 units with the NUL.
    let mut len = 0u32;
    // SAFETY: a null buffer with a zero length is the documented size probe.
    let _ = unsafe { GetUserProfileDirectoryW(token, None, &mut len) };
    anyhow::ensure!(
        len > 0,
        "the account has no profile directory (the size probe returned 0)"
    );
    let mut buf = vec![0u16; len as usize];
    // SAFETY: `buf` holds `len` units, which is what the call is told.
    unsafe { GetUserProfileDirectoryW(token, Some(PWSTR(buf.as_mut_ptr())), &mut len) }
        .context("GetUserProfileDirectoryW")?;
    let units = buf.iter().position(|&u| u == 0).unwrap_or(buf.len());
    anyhow::ensure!(units > 0, "the profile directory is empty");
    Ok(PathBuf::from(std::ffi::OsString::from_wide(&buf[..units])))
}

/// The socket location of the account `token` belongs to.
pub fn socket_location_of_token(token: HANDLE) -> anyhow::Result<SocketLocation> {
    let profile = profile_dir_of_token(token)?;
    // `TooLong` stays downcastable for a caller that wants to name the cause.
    Ok(socket_loc::for_profile(&profile)?)
}

/// The socket location of the account this process runs as.
pub fn current_socket_location() -> anyhow::Result<SocketLocation> {
    let mut token = HANDLE::default();
    // SAFETY: `token` is a valid out-pointer; the handle is closed by `OwnedHandle`.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.context("open the process token")?;
    let token = OwnedHandle(token);
    socket_location_of_token(token.0)
}

#[cfg(test)]
#[path = "userdir_tests.rs"]
mod userdir_tests;
