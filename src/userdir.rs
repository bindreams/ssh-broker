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
use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, HANDLE};
use windows::Win32::Security::TOKEN_QUERY;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::UI::Shell::GetUserProfileDirectoryW;
use windows::core::{HRESULT, PWSTR};

use crate::acl::{self, DirHandle, Sid};
use crate::socket_loc::{self, SocketLocation};
use crate::winutil::OwnedHandle;

/// The account has no profile directory yet: it has never been signed on. Downcastable from the
/// error of [`profile_dir_of_token`].
#[derive(Debug, thiserror::Error)]
#[error("the account has no profile directory (the size probe returned 0)")]
pub struct NoProfile;

/// The profile directory of the account `token` belongs to. `token` needs `TOKEN_QUERY`. An
/// account without a profile fails with [`NoProfile`].
pub fn profile_dir_of_token(token: HANDLE) -> anyhow::Result<PathBuf> {
    // Size probe: the first call fails with the needed length, in UTF-16 units with the NUL.
    let mut len = 0u32;
    // SAFETY: a null buffer with a zero length is the documented size probe.
    if let Err(e) = unsafe { GetUserProfileDirectoryW(token, None, &mut len) } {
        len = probe_failure(&e, len)?;
    }
    let mut buf = vec![0u16; len as usize];
    // SAFETY: `buf` holds `len` units, which is what the call is told.
    unsafe { GetUserProfileDirectoryW(token, Some(PWSTR(buf.as_mut_ptr())), &mut len) }
        .context("GetUserProfileDirectoryW")?;
    let units = buf.iter().position(|&u| u == 0).unwrap_or(buf.len());
    anyhow::ensure!(units > 0, "the profile directory is empty");
    Ok(PathBuf::from(std::ffi::OsString::from_wide(&buf[..units])))
}

/// What the size probe's failure means. The probe is expected to fail with the length it needs
/// (`ERROR_INSUFFICIENT_BUFFER`); with no length that is an account that has never been signed on
/// (measured), and with any other error it is that error, named.
fn probe_failure(error: &windows::core::Error, len: u32) -> anyhow::Result<u32> {
    if len != 0 {
        return Ok(len);
    }
    if error.code() == HRESULT::from_win32(ERROR_INSUFFICIENT_BUFFER.0) {
        return Err(NoProfile.into());
    }
    Err(anyhow::Error::new(error.clone()).context("GetUserProfileDirectoryW (size probe)"))
}

/// The socket location of the account `token` belongs to.
pub fn socket_location_of_token(token: HANDLE) -> anyhow::Result<SocketLocation> {
    let profile = profile_dir_of_token(token)?;
    // `TooLong` stays downcastable for a caller that wants to name the cause.
    Ok(socket_loc::for_profile(&profile)?)
}

/// A `TOKEN_QUERY` handle on this process's token.
fn own_token() -> anyhow::Result<OwnedHandle> {
    let mut token = HANDLE::default();
    // SAFETY: `token` is a valid out-pointer; the handle is closed by `OwnedHandle`.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.context("open the process token")?;
    Ok(OwnedHandle(token))
}

/// The profile directory of the account this process runs as, from its token and not from the
/// environment.
pub fn current_profile_dir() -> anyhow::Result<PathBuf> {
    profile_dir_of_token(own_token()?.0)
}

/// The socket location of the account this process runs as.
pub fn current_socket_location() -> anyhow::Result<SocketLocation> {
    socket_location_of_token(own_token()?.0)
}

/// The user's private folder and its `logs` folder, open by handle.
pub struct SocketDir {
    pub dir: DirHandle,
    pub logs: DirHandle,
}

/// Make `loc.dir` and its `logs` folder if they are missing, leave both exactly
/// `{user, SYSTEM, Administrators}` with ACEs the files made inside inherit, and return them open.
///
/// The folders are reached by handle from the profile directory (the administrator's: links in it
/// are followed), each name opened relative to the handle above it, so a link at `AppData`,
/// `Local`, `ssh-broker` or `logs` is refused instead of followed (see [`acl::open_dir`]). Only the
/// two private folders are created: `AppData` and `Local` must already exist, because a missing one
/// means there is no profile and inventing one would put a socket where no logon ever looks. A
/// folder that exists is verified, never changed: one that is not a real directory with an owner in
/// {user, SYSTEM, Administrators} and exactly the private ACL is refused and left as it is, and
/// removing it makes it be created again. A folder this accepts is not thereby trusted:
/// `Listener::bind` verifies it again before it binds.
pub fn open_socket_dir(loc: &SocketLocation, user: &Sid) -> anyhow::Result<SocketDir> {
    let profile = loc
        .profile_dir()
        .with_context(|| format!(r"{} is not <profile>\AppData\Local\ssh-broker", loc.dir.display()))?;
    let make = || -> anyhow::Result<SocketDir> {
        let root = acl::open_root(profile)?;
        let app_data = acl::open_dir(&root, "AppData")?;
        let local = acl::open_dir(&app_data, "Local")?;
        let dir = acl::ensure_private_dir(&local, socket_loc::SOCKET_DIR_NAME, user)?;
        let logs = acl::ensure_private_dir(&dir, socket_loc::LOGS_DIR_NAME, user)?;
        Ok(SocketDir { dir, logs })
    };
    make().with_context(|| format!("make the private folder {}", loc.dir.display()))
}

/// [`open_socket_dir`] for a caller that only needs the folders to be there.
pub fn ensure_socket_dir(loc: &SocketLocation, user: &Sid) -> anyhow::Result<()> {
    open_socket_dir(loc, user).map(drop)
}

#[cfg(test)]
#[path = "userdir_tests.rs"]
mod userdir_tests;
