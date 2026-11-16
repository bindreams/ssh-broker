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
    FILE_SYNCHRONOUS_IO_NONALERT, NTCREATEFILE_CREATE_DISPOSITION, NTCREATEFILE_CREATE_OPTIONS, NtCreateFile,
};
use windows::Win32::Foundation::{
    DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE, NTSTATUS, STATUS_NOT_A_DIRECTORY, STATUS_OBJECT_NAME_NOT_FOUND,
    STATUS_OBJECT_PATH_NOT_FOUND,
};
use windows::Win32::Security::PSECURITY_DESCRIPTOR;
use windows::Win32::Storage::FileSystem::{
    FILE_ACCESS_RIGHTS, FILE_APPEND_DATA, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAGS_AND_ATTRIBUTES, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_MODE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, READ_CONTROL, SYNCHRONIZE,
};
use windows::Win32::System::IO::IO_STATUS_BLOCK;
use windows::Win32::System::Threading::GetCurrentProcess;

use super::{
    Security, Sid, describe_sid, descriptor_from_sddl, dir_policy_holds, file_attributes, nt_path, open_nt,
    private_dir_dacl_sddl, status_error, with_attributes,
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

/// Open `dir` (the administrator's: links in it are followed) as the root of a walk.
pub fn open_root(dir: &Path) -> anyhow::Result<DirHandle> {
    let name = nt_path(dir)?;
    let (status, handle) = open_nt(None, &name, DIR_ACCESS, FILE_DIRECTORY_FILE.0)?;
    let handle = opened(status, handle, dir, "as the profile directory")?;
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
    let (status, handle) = open_nt(
        Some(parent.raw()),
        &units,
        DIR_ACCESS,
        FILE_DIRECTORY_FILE.0 | FILE_OPEN_REPARSE_POINT.0,
    )?;
    let handle = opened(status, handle, &path, "on the way to the private folder")?;
    refuse_link(&handle, &path, "on the way to the private folder")?;
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
    let made = create_nt(
        Some(parent.raw()),
        &units,
        DIR_ACCESS,
        if create { FILE_OPEN_IF } else { FILE_OPEN },
        FILE_DIRECTORY_FILE.0 | FILE_OPEN_REPARSE_POINT.0,
        descriptor.as_ref().map(|descriptor| descriptor.0),
    )?;
    let handle = opened(made.status, made.handle, &path, purpose)?;
    refuse_link(&handle, &path, purpose)?;

    let security = Security::from_handle(handle.0).with_context(|| format!("read the ACL of {}", path.display()))?;
    if !dir_policy_holds(&security, user)? {
        return Err(Refused(format!(
            "{} cannot be used {purpose}: its owner is {}, or its ACL is not exactly Full Control \
             for {}, SYSTEM and Administrators, protected and inherited by what is made inside. It is left \
             as it is: inspect it, remove it, and it is created again",
            path.display(),
            describe_sid(security.owner),
            user.describe()
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
    let (status, handle) = open_nt(
        Some(dir.raw()),
        &units,
        access.0 | SYNCHRONIZE.0 | FILE_READ_ATTRIBUTES.0,
        FILE_NON_DIRECTORY_FILE.0 | FILE_SYNCHRONOUS_IO_NONALERT.0 | FILE_OPEN_REPARSE_POINT.0,
    )?;
    let handle = match opened(status, handle, &path, "as a file of the private folder") {
        Ok(handle) => handle,
        Err(e) if e.is::<Missing>() => return Ok(None),
        Err(e) => return Err(e),
    };
    refuse_link(&handle, &path, "as a file of the private folder")?;
    Ok(Some(into_file(handle)))
}

/// Open or create the file `name` under `dir` for appending. A link is refused, so the file written
/// is this folder's own.
pub fn open_log_file(dir: &DirHandle, name: &str) -> anyhow::Result<std::fs::File> {
    let units = single_name(name)?;
    let path = dir.path.join(name);
    let made = create_nt(
        Some(dir.raw()),
        &units,
        FILE_APPEND_DATA.0 | SYNCHRONIZE.0 | FILE_READ_ATTRIBUTES.0,
        FILE_OPEN_IF,
        FILE_NON_DIRECTORY_FILE.0 | FILE_SYNCHRONOUS_IO_NONALERT.0 | FILE_OPEN_REPARSE_POINT.0,
        None,
    )?;
    let handle = opened(made.status, made.handle, &path, "as a log file")?;
    refuse_link(&handle, &path, "as a log file")?;
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

/// What `NtCreateFile` made of a name.
struct Made {
    status: NTSTATUS,
    handle: HANDLE,
}

/// `NtCreateFile` of `name` under `root`, sharing read, write and delete, with `descriptor` as the
/// object's security descriptor if it is created. The caller owns `handle` when `status` is not an
/// error.
fn create_nt(
    root: Option<HANDLE>,
    name: &[u16],
    access: u32,
    disposition: NTCREATEFILE_CREATE_DISPOSITION,
    options: u32,
    descriptor: Option<PSECURITY_DESCRIPTOR>,
) -> anyhow::Result<Made> {
    let mut handle = HANDLE::default();
    let mut io = IO_STATUS_BLOCK::default();
    let status = with_attributes(root, name, descriptor, |attributes| {
        // SAFETY: every pointer is to a local that outlives the call.
        unsafe {
            NtCreateFile(
                &mut handle,
                FILE_ACCESS_RIGHTS(access),
                attributes,
                &mut io,
                None,
                FILE_FLAGS_AND_ATTRIBUTES(FILE_ATTRIBUTE_NORMAL.0),
                FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0),
                disposition,
                NTCREATEFILE_CREATE_OPTIONS(options),
                None,
                0,
            )
        }
    })?;
    Ok(Made { status, handle })
}

/// The handle an open gave, or why there is none. A name that is a file where a directory is
/// wanted is a refusal that says so, a name that is not there is [`Missing`]; everything else is
/// the system's error, naming `path`.
fn opened(status: NTSTATUS, handle: HANDLE, path: &Path, purpose: &str) -> anyhow::Result<OwnedHandle> {
    if status.0 >= 0 {
        return Ok(OwnedHandle(handle));
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

/// Refuse `handle` if it is a link. It was opened as itself (`FILE_OPEN_REPARSE_POINT`), so this
/// is the object at the name and not what the name leads to.
fn refuse_link(handle: &OwnedHandle, path: &Path, purpose: &str) -> anyhow::Result<()> {
    let attributes = file_attributes(handle.0).with_context(|| format!("read the attributes of {}", path.display()))?;
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Err(Refused(format!(
            "{} cannot be used {purpose}: it is a reparse point (junction or symlink). Nothing is read or written \
             through it; remove the link so that the name is a real folder",
            path.display()
        ))
        .into());
    }
    Ok(())
}

#[cfg(test)]
#[path = "private_dir_tests.rs"]
mod private_dir_tests;
