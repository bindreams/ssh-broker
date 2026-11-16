//! The user's private folder, reached by handle and never through a link.
//!
//! Anything a process of the same account can do to the tree under the profile (replace
//! `AppData`, `Local`, `ssh-broker` or `logs` with a junction or symlink) must not lead this code to
//! check, create or write anywhere else. So the walk starts at one handle on the profile directory,
//! which is the administrator's and is opened following links, and every name below it is opened
//! as a single component relative to the handle above, with `FILE_OPEN_REPARSE_POINT`, and refused
//! when the handle it gave is itself a reparse point. The open and the check are on the same
//! handle, so nothing can be swapped in between. No call below the root names a path.
//!
//! Like [`super::ensure_admin_only_file`], a folder is created with its security descriptor given
//! at creation and an existing one is verified and never modified: one that is not exactly right
//! may have been opened by anyone already, and a handle opened before a repair stays open after
//! it. The fix for a refused folder is to remove it; it is created again.

use std::mem::ManuallyDrop;
use std::os::windows::io::FromRawHandle;
use std::path::{Path, PathBuf};

use anyhow::Context;
use windows::Wdk::Storage::FileSystem::{
    FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_IF, FILE_OPEN_REPARSE_POINT,
    FILE_SYNCHRONOUS_IO_NONALERT,
};
use windows::Win32::Foundation::{
    DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE, STATUS_ACCESS_DENIED, STATUS_NOT_A_DIRECTORY,
    STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND,
};
use windows::Win32::Storage::FileSystem::{
    FILE_ACCESS_RIGHTS, FILE_APPEND_DATA, FILE_ATTRIBUTE_REPARSE_POINT, FILE_READ_ATTRIBUTES, READ_CONTROL, SYNCHRONIZE,
};
use windows::Win32::System::Threading::GetCurrentProcess;

use super::{
    Made, OpenOutcome, Security, Sid, classify_open, denied_problem, describe_sid, descriptor_from_sddl, dir_policy,
    file_attributes, nt_create, nt_path, owner_acl_problem, private_dir_dacl_sddl, status_error,
};
use crate::winutil::OwnedHandle;

/// The rights a folder handle holds: to read its ACL and attributes, which is what verifying it takes.
/// Creating inside it is checked against the folder's own ACL, not against the handle.
const DIR_ACCESS: u32 = READ_CONTROL.0 | FILE_READ_ATTRIBUTES.0;

/// The name opened does not exist. Downcastable from the error of [`open_root`], [`open_dir`] and
/// [`open_existing_file`], for a caller that looks at what may not be there yet.
#[derive(Debug, thiserror::Error)]
#[error("{} does not exist", path.display())]
pub struct Missing {
    path: PathBuf,
}

/// The folder or file is there and may not be used: a link, not a directory, an owner or ACL that is
/// not the private one. Downcastable from the error of every function here that refuses one, for a
/// caller that tells the user why. The text names the object and the remedy.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Refused(String);

/// A directory opened by handle, never reached through a link.
pub struct DirHandle {
    handle: OwnedHandle,
    /// Where the handle was reached from, for messages only. It is never opened.
    path: PathBuf,
}

impl DirHandle {
    pub fn raw(&self) -> HANDLE {
        self.handle.0
    }

    /// The path the folder was reached by, for messages and for tests that read it back. The
    /// folder may have been moved since: nothing here opens it.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Another handle on the same folder, for a holder that outlives the borrow (a writer thread).
    pub fn try_clone(&self) -> anyhow::Result<DirHandle> {
        let mut copy = HANDLE::default();
        // SAFETY: both processes are this one; `copy` is a valid out-pointer and is owned below.
        unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                self.handle.0,
                GetCurrentProcess(),
                &mut copy,
                0,
                false,
                DUPLICATE_SAME_ACCESS,
            )
        }
        .with_context(|| format!("duplicate the handle on {}", self.path.display()))?;
        Ok(DirHandle {
            handle: OwnedHandle(copy),
            path: self.path.clone(),
        })
    }
}

/// Open the profile directory `dir` as the root of a walk. Links above it (the folder of all
/// profiles moved to another drive) are the administrator's and are followed; `dir` itself is the
/// user's, who holds Full Control on it, so a link there is refused like every component below it.
pub fn open_root(dir: &Path) -> anyhow::Result<DirHandle> {
    let name = nt_path(dir)?;
    let purpose = "as the profile directory";
    let made = nt_create(
        None,
        &name,
        DIR_ACCESS,
        FILE_OPEN,
        FILE_DIRECTORY_FILE.0 | FILE_OPEN_REPARSE_POINT.0,
        None,
    )?;
    let handle = opened(made, dir, purpose)?;
    refuse_link(&handle, dir, purpose, SET_THE_PROFILE_PATH)?;
    Ok(DirHandle {
        handle,
        path: dir.to_path_buf(),
    })
}

/// Open the existing directory `name` under `parent`, which is not made if it is missing. A link
/// is refused: this is how the folders between the profile and the private folder are entered.
pub fn open_dir(parent: &DirHandle, name: &str) -> anyhow::Result<DirHandle> {
    let units = single_name(name)?;
    let path = parent.path.join(name);
    let made = nt_create(
        Some(parent.raw()),
        &units,
        DIR_ACCESS,
        FILE_OPEN,
        FILE_DIRECTORY_FILE.0 | FILE_OPEN_REPARSE_POINT.0,
        None,
    )?;
    let handle = opened(made, &path, "on the way to the private folder")?;
    refuse_link(&handle, &path, "on the way to the private folder", REMOVE_THE_LINK)?;
    Ok(DirHandle { handle, path })
}

/// Open or create `name` under `parent` as the user's private folder: created with the private
/// descriptor; an existing one must be a real directory whose owner is in {user, SYSTEM,
/// Administrators} and whose ACL is exactly the private one. One that is not is refused and left
/// untouched. Nothing existing is modified.
pub fn ensure_private_dir(parent: &DirHandle, name: &str, user: &Sid) -> anyhow::Result<DirHandle> {
    private_dir(parent, name, user, true)
}

/// [`ensure_private_dir`] for a caller that only looks (`verify`): the same open and the same
/// judgement, and a folder that is not there is [`Missing`] and is not made.
pub fn open_private_dir(parent: &DirHandle, name: &str, user: &Sid) -> anyhow::Result<DirHandle> {
    private_dir(parent, name, user, false)
}

fn private_dir(parent: &DirHandle, name: &str, user: &Sid, create: bool) -> anyhow::Result<DirHandle> {
    let units = single_name(name)?;
    let path = parent.path.join(name);
    let purpose = "as the private folder";
    let descriptor = if create {
        Some(descriptor_from_sddl(&private_dir_dacl_sddl(user)?)?)
    } else {
        None
    };
    let made = nt_create(
        Some(parent.raw()),
        &units,
        DIR_ACCESS,
        if create { FILE_OPEN_IF } else { FILE_OPEN },
        FILE_DIRECTORY_FILE.0 | FILE_OPEN_REPARSE_POINT.0,
        descriptor.as_ref().map(|descriptor| descriptor.0),
    )?;
    if made.status == STATUS_ACCESS_DENIED {
        return Err(Refused(format!(
            "{} cannot be used {purpose}: {} (or, if it is not there, this process may not make it in {}). \
             {LEFT_AS_IT_IS}",
            path.display(),
            denied_problem("the private one"),
            parent.path.display()
        ))
        .into());
    }
    let handle = opened(made, &path, purpose)?;
    refuse_link(&handle, &path, purpose, REMOVE_THE_LINK)?;

    let security = Security::from_handle(handle.0).with_context(|| format!("read the ACL of {}", path.display()))?;
    let (owner_ok, acl_ok) = dir_policy(&security, user)?;
    if let Some(problem) = owner_acl_problem(
        &describe_sid(security.owner),
        owner_ok,
        acl_ok,
        &format!("{}, SYSTEM or Administrators", user.describe()),
        &format!(
            "exactly Full Control for {}, SYSTEM and Administrators, protected and inherited by what is made \
             inside",
            user.describe()
        ),
    ) {
        return Err(Refused(format!(
            "{} cannot be used {purpose}: {problem}. {LEFT_AS_IT_IS}",
            path.display()
        ))
        .into());
    }
    Ok(DirHandle { handle, path })
}

/// Open the file `name` under `dir` if it exists, with `access` (and the right to wait on the
/// handle, which a blocking lock needs). Looking never creates: a missing name is `None`. A link is
/// refused, so the file is this folder's own.
pub fn open_existing_file(
    dir: &DirHandle,
    name: &str,
    access: FILE_ACCESS_RIGHTS,
) -> anyhow::Result<Option<std::fs::File>> {
    let units = single_name(name)?;
    let path = dir.path.join(name);
    let made = nt_create(
        Some(dir.raw()),
        &units,
        access.0 | SYNCHRONIZE.0 | FILE_READ_ATTRIBUTES.0,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE.0 | FILE_SYNCHRONOUS_IO_NONALERT.0 | FILE_OPEN_REPARSE_POINT.0,
        None,
    )?;
    let handle = match opened(made, &path, "as a file of the private folder") {
        Ok(handle) => handle,
        Err(e) if e.is::<Missing>() => return Ok(None),
        Err(e) => return Err(e),
    };
    refuse_link(&handle, &path, "as a file of the private folder", REMOVE_THE_LINK)?;
    Ok(Some(into_file(handle)))
}

/// Open or create the file `name` under `dir` for appending. A link is refused, so the file written
/// is this folder's own.
pub fn open_log_file(dir: &DirHandle, name: &str) -> anyhow::Result<std::fs::File> {
    let units = single_name(name)?;
    let path = dir.path.join(name);
    let made = nt_create(
        Some(dir.raw()),
        &units,
        FILE_APPEND_DATA.0 | SYNCHRONIZE.0 | FILE_READ_ATTRIBUTES.0,
        FILE_OPEN_IF,
        FILE_NON_DIRECTORY_FILE.0 | FILE_SYNCHRONOUS_IO_NONALERT.0 | FILE_OPEN_REPARSE_POINT.0,
        None,
    )?;
    let handle = opened(made, &path, "as a log file")?;
    refuse_link(&handle, &path, "as a log file", REMOVE_THE_LINK)?;
    Ok(into_file(handle))
}

fn into_file(handle: OwnedHandle) -> std::fs::File {
    let handle = ManuallyDrop::new(handle);
    // SAFETY: the handle is open and owned here, ownership passes to the `File` and it is not
    // closed twice because `ManuallyDrop` keeps `OwnedHandle` from doing it.
    unsafe { std::fs::File::from_raw_handle(handle.0.0) }
}

/// `name` as UTF-16 if it is one directory-entry name: nothing that would walk to another folder.
fn single_name(name: &str) -> anyhow::Result<Vec<u16>> {
    anyhow::ensure!(
        !name.is_empty() && name != "." && name != ".." && !name.contains(['\\', '/', ':', '\0']),
        "{name:?} is not a single name"
    );
    Ok(name.encode_utf16().collect())
}

/// The handle an open gave, or why there is none. A name that is a file where a directory is
/// wanted is a refusal that says so, a name that is not there is [`Missing`]; everything else is
/// the system's error, naming `path`.
fn opened(made: Made, path: &Path, purpose: &str) -> anyhow::Result<OwnedHandle> {
    let status = made.status;
    if classify_open(status) == OpenOutcome::Opened {
        return Ok(OwnedHandle(made.handle));
    }
    if status == STATUS_NOT_A_DIRECTORY {
        return Err(Refused(format!(
            "{} cannot be used {purpose}: it is not a directory. Remove it, and a folder is made there",
            path.display()
        ))
        .into());
    }
    if status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND {
        return Err(Missing {
            path: path.to_path_buf(),
        }
        .into());
    }
    Err(status_error(status)).with_context(|| format!("open {}", path.display()))
}

/// What a refused private folder says about itself and about what to do.
const LEFT_AS_IT_IS: &str = "It is left as it is: inspect it, remove it, and it is created again";

/// What a refused link says to do, for a name below the profile directory.
const REMOVE_THE_LINK: &str = "remove the link so that the name is a real folder";

/// What a refused link says to do, for the profile directory itself.
const SET_THE_PROFILE_PATH: &str =
    "give the account its real profile directory (set ProfileImagePath to it) instead of a link";

/// Refuse `handle` if it is a link; `remedy` says what to do about it. It was opened as itself
/// (`FILE_OPEN_REPARSE_POINT`), so this is the object at the name and not what the name leads to.
fn refuse_link(handle: &OwnedHandle, path: &Path, purpose: &str, remedy: &str) -> anyhow::Result<()> {
    let attributes = file_attributes(handle.0).with_context(|| format!("read the attributes of {}", path.display()))?;
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Err(Refused(format!(
            "{} cannot be used {purpose}: it is a reparse point (junction or symlink). Nothing is read or written \
             through it; {remedy}",
            path.display()
        ))
        .into());
    }
    Ok(())
}

#[cfg(test)]
#[path = "private_dir_tests.rs"]
mod private_dir_tests;
