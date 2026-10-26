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

use crate::acl::{self, Sid};
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

/// Create `loc.dir` and its `logs` folder if they are missing, and leave both exactly
/// `{user, SYSTEM, Administrators}`, with ACEs the files made inside inherit.
///
/// Only the leaves are created: the parent (`AppData\Local`) must already exist, because a
/// missing parent means there is no profile and inventing one would put a socket where no
/// logon ever looks. An existing leaf is repaired only if it is a real directory (not a junction
/// or symlink: hardening follows the path and would re-own whatever it points to) whose owner is
/// the user, SYSTEM or Administrators; anything else is refused and left untouched. A directory
/// this accepts is not thereby trusted: `Listener::bind` verifies it again before it binds.
pub fn ensure_socket_dir(loc: &SocketLocation, user: &Sid) -> anyhow::Result<()> {
    ensure_private_dir(&loc.dir, user)?;
    ensure_private_dir(&loc.logs_dir(), user)
}

fn ensure_private_dir(dir: &std::path::Path, user: &Sid) -> anyhow::Result<()> {
    match std::fs::create_dir(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e).with_context(|| format!("create {}", dir.display())),
    }
    if let Some(problem) = acl::private_dir_problem(dir, user)? {
        anyhow::bail!("{} cannot be used as the private folder: {problem}", dir.display());
    }
    // Already exactly right: leave it. Re-applying the DACL re-propagates it to the socket file,
    // and the shim runs this on every connection while an agent serves.
    if acl::verify_dir_acl(dir, user)? {
        return Ok(());
    }
    acl::harden_dir(dir, user).with_context(|| format!("harden {}", dir.display()))?;
    anyhow::ensure!(
        acl::verify_dir_acl(dir, user).with_context(|| format!("verify the ACL of {}", dir.display()))?,
        "the ACL of {} did not verify after hardening it",
        dir.display()
    );
    Ok(())
}

#[cfg(test)]
#[path = "userdir_tests.rs"]
mod userdir_tests;
