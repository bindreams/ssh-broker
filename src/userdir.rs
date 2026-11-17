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
use windows::Win32::UI::Shell::GetUserProfileDirectoryW;
use windows::core::{HRESULT, PWSTR};

use crate::acl::{self, DirHandle, Sharing, Sid};
use crate::socket_loc::{self, SocketLocation};
use crate::winutil;

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

/// The profile directory of the account this process runs as, from its token and not from the
/// environment.
pub fn current_profile_dir() -> anyhow::Result<PathBuf> {
    profile_dir_of_token(winutil::own_token()?.0)
}

/// The socket location of the account this process runs as.
pub fn current_socket_location() -> anyhow::Result<SocketLocation> {
    socket_location_of_token(winutil::own_token()?.0)
}

/// The user's private folder and its `logs` folder, open by handle after a walk from the profile
/// directory. They fail separately: serving needs the folder and not a log, so a `logs` that is
/// refused or broken costs the log only.
///
/// The private folder is opened without `FILE_SHARE_DELETE`, so while this is held it cannot be
/// renamed or removed, and neither can `Local` or `AppData` (Windows does not rename a directory with
/// an open descendant). The walk confirmed that the path of [`SocketLocation`] leads to the folder held
/// before it returned, so what is done by that path (the lock files, the marker, `bind`,
/// [`SocketDir::connect`]) reaches this folder and no other. What may be written inside the folder, or
/// to its attributes, is decided by its ACL (and, for the elevated agent's folder, by the label a later
/// change adds), not by the hold. `logs` is held by nothing: it is used through its handle only.
pub struct SocketDir {
    location: SocketLocation,
    pub dir: DirHandle,
    pub logs: anyhow::Result<DirHandle>,
}

impl SocketDir {
    /// Where the folders are.
    pub fn location(&self) -> &SocketLocation {
        &self.location
    }

    /// Connect to the agent's socket in the folder held. The only way to connect to an agent: the
    /// path it connects to names the folders this holds.
    pub fn connect(&self) -> anyhow::Result<socket2::Socket> {
        crate::afunix::connect(self.location.path())
    }
}

/// Make `loc.dir` and its `logs` folder if they are missing, leave both exactly
/// `{user, SYSTEM, Administrators}` with ACEs the files made inside inherit, and return them open.
///
/// Reached by handle from the profile directory (see `acl::private_dir`). `AppData` and `Local`
/// must already exist: a missing one means no profile, and inventing one would put a socket where no
/// logon looks. Only `ssh-broker` and `logs` are created; an existing one is verified, never changed.
/// `Listener::bind` verifies it again before binding.
///
/// A refusal of the socket folder (or of the way to it) is this function's error. A refusal of
/// `logs` alone is in [`SocketDir::logs`], with the socket folder still open: it costs only the log.
pub fn open_socket_dir(loc: &SocketLocation, user: &Sid) -> anyhow::Result<SocketDir> {
    walk(loc, "make", |parent, name, sharing| {
        acl::ensure_private_dir(parent, name, user, sharing)
    })
}

/// [`open_socket_dir`] for a caller that only looks (`verify`): the same walk, and the same judgement
/// of each folder, and nothing is made. A folder that is not there is [`acl::Missing`], in the error
/// for the socket folder and in [`SocketDir::logs`] for `logs`.
pub fn inspect_socket_dir(loc: &SocketLocation, user: &Sid) -> anyhow::Result<SocketDir> {
    walk(loc, "look at", |parent, name, sharing| {
        acl::open_private_dir(parent, name, user, sharing)
    })
}

/// [`inspect_socket_dir`] for the account this process runs as, whose location is the one its token
/// gives: for a caller that connects to its own agent without making anything (`verify`, `logout`).
/// An account without a profile fails with [`NoProfile`].
pub fn inspect_current_socket_dir() -> anyhow::Result<SocketDir> {
    inspect_socket_dir(&current_socket_location()?, &Sid::current_user()?)
}

/// The walk of [`open_socket_dir`] and [`inspect_socket_dir`]; `step` makes or opens the folder `name`
/// under `parent`, held (the private folder) or not (`logs`) as `sharing` says.
fn walk(
    loc: &SocketLocation,
    verb: &str,
    step: impl Fn(&DirHandle, &str, Sharing) -> anyhow::Result<DirHandle>,
) -> anyhow::Result<SocketDir> {
    let dir = walk_to_private_folder(loc, verb, |local| {
        step(local, socket_loc::SOCKET_DIR_NAME, Sharing::NotDelete)
    })?;
    let logs = step(&dir, socket_loc::LOGS_DIR_NAME, Sharing::All)
        .with_context(|| format!("{verb} the log folder {}", loc.logs_dir().display()));
    Ok(SocketDir {
        location: loc.clone(),
        dir,
        logs,
    })
}

/// The one walk to the private folder, for every caller: [`open_parents`], then [`hold_and_confirm`].
/// `open` makes or opens the private folder under the `Local` handle and must hold it.
fn walk_to_private_folder(
    loc: &SocketLocation,
    verb: &str,
    open: impl FnOnce(&DirHandle) -> anyhow::Result<DirHandle>,
) -> anyhow::Result<DirHandle> {
    open_parents(loc)
        .and_then(|parents| hold_and_confirm(loc, parents, open))
        .with_context(|| format!("{verb} the private folder {}", loc.dir().display()))
}

/// `AppData` and `Local` of the profile `loc` is in, from the first half of the walk: the profile
/// directory, then the folders of [`socket_loc::FOLDERS_IN_PROFILE`] as real directories, a link
/// refused. They are opened only to read their ACL and attributes, sharing everything: such a handle
/// takes no part in a sharing check, so it neither stops another program from using the folder nor is
/// stopped by one. [`SocketLocation::dir`] is made from the same names, so the walk ends where it says.
fn open_parents(loc: &SocketLocation) -> anyhow::Result<[DirHandle; 2]> {
    let root = acl::open_root(loc.profile_dir())?;
    let [app_data, local] = socket_loc::FOLDERS_IN_PROFILE;
    let app_data = acl::open_dir(&root, app_data)?;
    let local = acl::open_dir(&app_data, local)?;
    debug_assert_eq!(local.path(), loc.dir().parent().unwrap());
    Ok([app_data, local])
}

/// The second half of the walk: `open` the private folder under the `Local` handle, and with it held
/// confirm the path to it, top-down. `<profile>\AppData` and then `<profile>\AppData\Local` are opened
/// by their full path strings, the ones `bind` and `connect` resolve, and refused unless each is the
/// folder the walk went through. A parent that was swapped for a link or another folder while the
/// walk was opening it is caught here; once this passes the private folder's open descendant keeps
/// every name on the path from being renamed. The parents' handles are closed on return. Never retried.
fn hold_and_confirm(
    loc: &SocketLocation,
    parents: [DirHandle; 2],
    open: impl FnOnce(&DirHandle) -> anyhow::Result<DirHandle>,
) -> anyhow::Result<DirHandle> {
    let dir = open(&parents[1])?;
    let [app_data, local] = socket_loc::FOLDERS_IN_PROFILE;
    let app_data_path = loc.profile_dir().join(app_data);
    acl::confirm_dir(&app_data_path, &parents[0])?;
    acl::confirm_dir(&app_data_path.join(local), &parents[1])?;
    Ok(dir)
}

/// The user's private folder if it is there, opened by the same walk and never made, changed or
/// verified: for a caller that only looks at what the agent keeps in it (the elevated shim). `None`
/// when the folder or a folder above it is missing; a link on the way is an error, as in
/// [`open_socket_dir`].
pub fn open_existing_socket_dir(loc: &SocketLocation) -> anyhow::Result<Option<DirHandle>> {
    let found = walk_to_private_folder(loc, "open", |local| {
        acl::open_existing_private_dir(local, socket_loc::SOCKET_DIR_NAME)
    });
    match found {
        Ok(dir) => Ok(Some(dir)),
        Err(e) if e.is::<acl::Missing>() => Ok(None),
        Err(e) => Err(e),
    }
}

/// [`open_socket_dir`] for a caller that only needs the folders to be there.
pub fn ensure_socket_dir(loc: &SocketLocation, user: &Sid) -> anyhow::Result<()> {
    open_socket_dir(loc, user).map(drop)
}

#[cfg(test)]
#[path = "userdir_tests.rs"]
mod userdir_tests;
