//! The user's private folder, reached by handle and never through a link below the profile.
//!
//! Anything a process of the same account can do to the tree under the profile (replace
//! `AppData`, `Local`, `ssh-broker` or `logs` with a junction or symlink) must not lead this code to
//! check, create or write anywhere else. So the walk starts at one handle on the profile directory
//! and every name below it is opened as a single component relative to the handle above, with
//! `FILE_OPEN_REPARSE_POINT`, and refused when the handle it gave is itself a reparse point. One name
//! below the profile directory is opened by its path: `<profile>\AppData`, by [`confirm_dir`], to confirm
//! that the path a bind or a connect resolves leads to the folder the walk held. A path that is gone
//! then is a [`Refused`], never [`Missing`].
//!
//! The profile directory is opened following a link, because Windows loads the profile through
//! ProfileImagePath, links included. The residual case is the contract in CONTRIBUTING.
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
    FILE_SYNCHRONOUS_IO_NONALERT, NTCREATEFILE_CREATE_DISPOSITION,
};
use windows::Win32::Foundation::{DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE};
use windows::Win32::Security::PSECURITY_DESCRIPTOR;
use windows::Win32::Storage::FileSystem::{
    FILE_ACCESS_RIGHTS, FILE_APPEND_DATA, FILE_ATTRIBUTE_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_TRAVERSE,
    READ_CONTROL, SYNCHRONIZE,
};
use windows::Win32::System::Threading::GetCurrentProcess;

use super::{
    Made, OpenOutcome, OwnerAclWords, Security, Sharing, Sid, classify_open, denied_problem, describe_sid,
    descriptor_from_sddl, dir_policy, file_attributes, file_information, nt_create, nt_path, owner_acl_problem,
    private_dir_sddl, status_error,
};
use crate::socket_loc::Integrity;
use crate::winutil::{FileId, OwnedHandle};

/// The rights a folder handle holds: to read its ACL and attributes, which is what verifying it takes.
/// Creating inside it is checked against the folder's own ACL, not against the handle.
const DIR_ACCESS: u32 = READ_CONTROL.0 | FILE_READ_ATTRIBUTES.0;

/// Held: opened without `FILE_SHARE_DELETE`, with traverse access, so nobody can rename or remove the
/// folder while the handle lives. Sharing is judged only for opens asking data, execute or delete access,
/// so [`DIR_ACCESS`] alone would not hold it. Shared: shares everything, takes no part in sharing checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hold {
    Held,
    Shared,
}

impl Hold {
    fn sharing(self) -> Sharing {
        match self {
            Hold::Held => Sharing::NotDelete,
            Hold::Shared => Sharing::All,
        }
    }

    /// The rights asked for besides the request's own.
    fn extra_access(self) -> u32 {
        match self {
            Hold::Held => FILE_TRAVERSE.0,
            Hold::Shared => 0,
        }
    }
}

/// The name opened does not exist. Downcastable from the error of [`open_root`], [`open_dir`] and
/// [`open_existing_file`], for a caller that looks at what may not be there yet.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{} does not exist", path.display())]
pub struct Missing {
    path: PathBuf,
}

/// The folder or file is there and may not be used: a link, not a directory, an owner or ACL that is
/// not the private one. Downcastable from the error of every function here that refuses one, for a
/// caller that tells the user why. The text names the object and the remedy. [`confirm_dir`] and
/// [`confirm_child`] refuse a folder that is not the one the walk went through, one that is gone
/// included.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Refused(String);

/// The open that holds a folder was denied. Never leaves this file: [`open_private_child`] opens the
/// folder again, unheld, to say what is wrong with it.
#[derive(Debug, thiserror::Error)]
#[error("the open that holds the folder was denied")]
struct HoldDenied;

/// A directory opened by handle, never reached through a link.
pub struct DirHandle {
    handle: OwnedHandle,
    /// Where the handle was reached from, for messages only; never opened.
    path: PathBuf,
}

// SAFETY: a `DirHandle` is moved between threads like its `OwnedHandle`, and shared by reference
// only for what is thread-safe: `raw` copies the handle value, `path` reads a field nothing changes,
// and `try_clone` is `DuplicateHandle`, which the kernel serialises. Closing is `drop`, which needs
// the only reference.
unsafe impl Sync for DirHandle {}

impl DirHandle {
    pub fn raw(&self) -> HANDLE {
        self.handle.0
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Another handle on the same folder.
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

/// How one name is opened and what a refusal of it says.
struct Request<'a> {
    /// What the object is for, in a refusal: "as the private folder".
    purpose: &'a str,
    /// What a refusal says to do when a file is where a directory is wanted.
    not_a_directory: &'a str,
    /// Everything after the colon of a refusal when the open is denied, or `None` to report the
    /// system's error. Only a caller that can say what the denial means gives one.
    denied: Option<String>,
    /// The rights asked for, besides those the hold adds.
    access: u32,
    /// Shared, except for the folder that is held (see [`Request::held`]).
    hold: Hold,
    disposition: NTCREATEFILE_CREATE_DISPOSITION,
    options: u32,
    descriptor: Option<PSECURITY_DESCRIPTOR>,
    /// A file that was there must have this name only: another name for it elsewhere would make
    /// what is written through this one land in a file that is not the folder's own.
    sole_name: bool,
}

impl<'a> Request<'a> {
    /// An existing directory, opened as itself to read its ACL and attributes, sharing everything.
    fn directory(purpose: &'a str, not_a_directory: &'a str) -> Self {
        Request {
            purpose,
            not_a_directory,
            denied: None,
            access: DIR_ACCESS,
            hold: Hold::Shared,
            disposition: FILE_OPEN,
            options: FILE_DIRECTORY_FILE.0 | FILE_OPEN_REPARSE_POINT.0,
            descriptor: None,
            sole_name: false,
        }
    }

    /// The folder is held: opened without `FILE_SHARE_DELETE`, so that it cannot be renamed or removed
    /// for as long as the handle lives.
    fn held(self) -> Self {
        Request {
            hold: Hold::Held,
            ..self
        }
    }

    /// The same open, shared: it asks for nothing but [`DIR_ACCESS`] and takes no part in sharing checks.
    fn unheld(&self) -> Self {
        Request {
            denied: self.denied.clone(),
            hold: Hold::Shared,
            ..*self
        }
    }

    /// The rights the open asks for, and how it shares: one place, from what the request says it is.
    fn rights(&self) -> u32 {
        self.access | self.hold.extra_access()
    }

    fn sharing(&self) -> Sharing {
        self.hold.sharing()
    }

    /// A file of the private folder, opened as itself and for `access` (and the right to wait on the
    /// handle, which a blocking lock needs).
    fn file(purpose: &'a str, access: u32, disposition: NTCREATEFILE_CREATE_DISPOSITION) -> Self {
        Request {
            access: access | SYNCHRONIZE.0 | FILE_READ_ATTRIBUTES.0,
            hold: Hold::Shared,
            disposition,
            options: FILE_NON_DIRECTORY_FILE.0 | FILE_SYNCHRONOUS_IO_NONALERT.0 | FILE_OPEN_REPARSE_POINT.0,
            sole_name: true,
            ..Request::directory(purpose, MADE_AGAIN)
        }
    }
}

/// Open the profile directory `dir` as the root of a walk. A link at `dir` or above it is followed
/// (see the module doc for why); every name below it is not. The profile directory is not held:
/// Windows owns it (see the module doc).
pub fn open_root(dir: &Path) -> anyhow::Result<DirHandle> {
    let request = Request {
        options: FILE_DIRECTORY_FILE.0,
        ..Request::directory("as the profile directory", PROFILE_AS_IT_IS)
    };
    let handle = open_by_path(dir, &request)?;
    Ok(DirHandle {
        handle,
        path: dir.to_path_buf(),
    })
}

/// Open `path` by the whole of it, as `request` says, and judge the result.
fn open_by_path(path: &Path, request: &Request) -> anyhow::Result<OwnedHandle> {
    let name = nt_path(path)?;
    let made = nt_create(
        None,
        &name,
        request.rights(),
        request.sharing(),
        request.disposition,
        request.options,
        None,
    )?;
    judge(made, path, request)
}

/// Confirm that `path`, resolved as a bind or a connect by a path through it resolves it, leads to
/// `held`. The folder is opened by `path`, its last name not followed if it is a link, and refused if
/// it is not the folder `held` is open on (not the same volume and 128-bit file id; a link is another
/// object, so it is refused): a folder swapped for a link or another one while `held` was being opened is caught here. A path that
/// is gone is a [`Refused`] too, not [`Missing`]: the walk went through that folder, so a caller must not
/// read it as "nothing made yet". The handle takes no part in a sharing check
/// (`FILE_READ_ATTRIBUTES`, sharing everything) and is closed on return.
pub fn confirm_dir(path: &Path, held: &DirHandle) -> anyhow::Result<()> {
    let request = confirming();
    let seen = open_by_path(path, &request).map_err(|e| gone_is_refused(e, request.purpose))?;
    if !is_held(&seen, held, path)? {
        return Err(replaced(path, request.purpose));
    }
    Ok(())
}

/// Confirm that `name` under `parent` is, now, the folder `held` is open on: opened as one name below
/// the handle `parent` (a link not followed, `FILE_READ_ATTRIBUTES` only, sharing everything), and
/// refused if it is a link, another folder, or no longer there ([`Refused`], not [`Missing`]). It shows
/// that `held` is a child of the folder `parent` is open on and not only of whatever a path to it names
/// at the moment. Once `held` has an open descendant it cannot leave `parent`, which then cannot be
/// renamed either.
pub fn confirm_child(parent: &DirHandle, name: &str, held: &DirHandle) -> anyhow::Result<()> {
    let request = confirming();
    let (seen, path) = open_child(parent, name, &request).map_err(|e| gone_is_refused(e, request.purpose))?;
    if !is_held(&seen, held, &path)? {
        return Err(replaced(&path, request.purpose));
    }
    Ok(())
}

/// How a folder of the walk is opened to confirm it: to read its attributes only, taking no part in a
/// sharing check.
fn confirming() -> Request<'static> {
    Request {
        access: FILE_READ_ATTRIBUTES.0,
        ..Request::directory("on the way to the private folder", PROFILE_AS_IT_IS)
    }
}

/// Whether `seen` is the folder `held` is open on: the same volume and file id.
fn is_held(seen: &OwnedHandle, held: &DirHandle, path: &Path) -> anyhow::Result<bool> {
    let identity =
        |handle: HANDLE| FileId::of_handle(handle).with_context(|| format!("read the identity of {}", path.display()));
    Ok(identity(seen.0)? == identity(held.raw())?)
}

/// The refusal of a folder that is not the one the walk went through.
fn replaced(path: &Path, purpose: &str) -> anyhow::Error {
    Refused(format!(
        "{} cannot be used {purpose}: it was replaced by a link or another folder while it was being opened. \
         Nothing is read or written through it",
        path.display()
    ))
    .into()
}

/// `error` with a [`Missing`] turned into the refusal of a folder that was moved or removed after the
/// walk went through it.
fn gone_is_refused(error: anyhow::Error, purpose: &str) -> anyhow::Error {
    match error.downcast_ref::<Missing>() {
        Some(missing) => Refused(format!(
            "{} cannot be used {purpose}: it was moved or removed after the walk went through it. Nothing is \
             read or written through it",
            missing.path.display()
        ))
        .into(),
        None => error,
    }
}

/// Open the existing directory `name` under `parent` that the profile has, which is not made if it is
/// missing: `AppData` and `Local`. A link is refused. A file there makes the profile unusable. The
/// handle shares everything and takes part in no sharing check.
pub fn open_dir(parent: &DirHandle, name: &str) -> anyhow::Result<DirHandle> {
    let request = Request::directory("on the way to the private folder", PROFILE_AS_IT_IS);
    let (handle, path) = open_child(parent, name, &request)?;
    Ok(DirHandle { handle, path })
}

/// [`open_dir`] for the private folder (`ssh-broker`), when only what is in it matters: it is not made
/// if missing and its owner and ACL are not judged, unless its ACL denies the access that holding it
/// takes: then they are, as [`ensure_private_dir`] does for `integrity`, to say why. A file there is removed
/// and a folder is made again. The folder is held (see [`ensure_private_dir`]).
pub fn open_existing_private_dir(parent: &DirHandle, name: &str, integrity: Integrity) -> anyhow::Result<DirHandle> {
    let request = Request {
        denied: Some(denied_text("")),
        ..Request::directory("as the private folder", MADE_AGAIN).held()
    };
    let (handle, path) = open_private_child(parent, name, &request, None, integrity)?;
    Ok(DirHandle { handle, path })
}

/// Open or create `name` under `parent` as the user's private folder: created with the private
/// descriptor; an existing one must be a real directory whose owner is in {user, SYSTEM,
/// Administrators} and whose ACL is exactly the private one. One that is not is refused and left
/// untouched. Nothing existing is modified.
///
/// For `Integrity::High` (the elevated agent's folder) the creation descriptor carries the High
/// mandatory label, and an existing folder must carry exactly that label too: the label is born with
/// the folder and never set after, so an unlabelled one is refused like any other that is not exactly
/// right. `Medium` asks for none.
///
/// With [`Hold::Held`] nobody can rename or remove the folder while the handle lives, and a sharing
/// violation on the open is a [`Refused`] that says another program holds the folder open. With
/// [`Hold::Shared`] the handle takes no part in sharing checks.
pub fn ensure_private_dir(
    parent: &DirHandle,
    name: &str,
    user: &Sid,
    hold: Hold,
    integrity: Integrity,
) -> anyhow::Result<DirHandle> {
    private_dir(parent, name, user, true, hold, integrity)
}

/// [`ensure_private_dir`] for a caller that only looks (`verify`): the same open and the same
/// judgement, and a folder that is not there is [`Missing`] and is not made.
pub fn open_private_dir(
    parent: &DirHandle,
    name: &str,
    user: &Sid,
    hold: Hold,
    integrity: Integrity,
) -> anyhow::Result<DirHandle> {
    private_dir(parent, name, user, false, hold, integrity)
}

fn private_dir(
    parent: &DirHandle,
    name: &str,
    user: &Sid,
    create: bool,
    hold: Hold,
    integrity: Integrity,
) -> anyhow::Result<DirHandle> {
    let descriptor = if create {
        Some(descriptor_from_sddl(&private_dir_sddl(user, integrity)?)?)
    } else {
        None
    };
    let may_not_make = if create {
        format!(
            " (or, if it is not there, this process may not make it in {})",
            parent.path.display()
        )
    } else {
        String::new()
    };
    let request = Request {
        denied: Some(denied_text(&may_not_make)),
        disposition: if create { FILE_OPEN_IF } else { FILE_OPEN },
        descriptor: descriptor.as_ref().map(|descriptor| descriptor.0),
        hold,
        ..Request::directory("as the private folder", MADE_AGAIN)
    };
    let (handle, path) = open_private_child(parent, name, &request, Some(user), integrity)?;
    refuse_unless_private(&handle, &path, user, request.purpose, integrity)?;
    Ok(DirHandle { handle, path })
}

/// What a refusal says after the colon when the open of the private folder is denied: this process may
/// not read its ACL, and `may_not_make` is what else the denial can mean.
fn denied_text(may_not_make: &str) -> String {
    format!("{}{may_not_make}. {LEFT_AS_IT_IS}", denied_problem("the private one"))
}

/// Refuse the folder `handle` is open on, at `path`, if its owner or its ACL is not the private one for
/// `integrity` (for `High`, the label too).
fn refuse_unless_private(
    handle: &OwnedHandle,
    path: &Path,
    user: &Sid,
    purpose: &str,
    integrity: Integrity,
) -> anyhow::Result<()> {
    let security =
        Security::from_handle(handle.0, integrity).with_context(|| format!("read the ACL of {}", path.display()))?;
    let (owner_ok, acl_ok) = dir_policy(&security, user, integrity)?;
    if let Some(problem) = owner_acl_problem(owner_ok, acl_ok, || OwnerAclWords {
        owner: describe_sid(security.owner),
        owner_set: format!("{}, SYSTEM or Administrators", user.describe()),
        acl_is: format!(
            "exactly Full Control for {}, SYSTEM and Administrators, protected and inherited by what is made \
             inside{}",
            user.describe(),
            match integrity {
                Integrity::Medium => "",
                Integrity::High => ", with the High mandatory label (no write up) that what is made inside inherits",
            }
        ),
    }) {
        return Err(Refused(format!(
            "{} cannot be used {purpose}: {problem}. {LEFT_AS_IT_IS}",
            path.display()
        ))
        .into());
    }
    Ok(())
}

/// [`open_child`] for the private folder. Holding it asks for the right to traverse, which a folder whose
/// ACL denies it refuses, and a denial says nothing of why. So when the held open is denied the folder is
/// opened again, unheld, and judged as an open one is (as `user`, or as the account this process runs as
/// when there is none): it is refused for what is wrong with it. The error is always the refusal, never
/// a handle: a folder with the right owner and ACL grants its owner the access.
fn open_private_child(
    parent: &DirHandle,
    name: &str,
    request: &Request,
    user: Option<&Sid>,
    integrity: Integrity,
) -> anyhow::Result<(OwnedHandle, PathBuf)> {
    let denied = match open_child(parent, name, request) {
        Err(e) if e.is::<HoldDenied>() => e,
        opened => return opened,
    };
    let (handle, path) = open_child(parent, name, &request.unheld())?;
    let current;
    let user = match user {
        Some(user) => user,
        None => {
            current = Sid::current_user()?;
            &current
        }
    };
    refuse_unless_private(&handle, &path, user, request.purpose, integrity)?;
    Err(Refused(format!(
        "{} cannot be used {}: its owner and ACL are right, yet this process could not hold it ({denied}). \
         {LEFT_AS_IT_IS}",
        path.display(),
        request.purpose
    ))
    .into())
}

/// Open the file `name` under `dir` if it exists, with `access`. Looking never creates: a missing
/// name is `None`. A link, or a file with another name elsewhere, is refused, so the file is this
/// folder's own.
pub fn open_existing_file(
    dir: &DirHandle,
    name: &str,
    access: FILE_ACCESS_RIGHTS,
) -> anyhow::Result<Option<std::fs::File>> {
    let request = Request::file("as a file of the private folder", access.0, FILE_OPEN);
    match open_child(dir, name, &request) {
        Ok((handle, _)) => Ok(Some(into_file(handle))),
        Err(e) if e.is::<Missing>() => Ok(None),
        Err(e) => Err(e),
    }
}

/// Open or create the file `name` under `dir` for appending. A link, or a file that was there with
/// another name elsewhere, is refused, so the file written is this folder's own.
pub fn open_log_file(dir: &DirHandle, name: &str) -> anyhow::Result<std::fs::File> {
    let request = Request::file("as a log file", FILE_APPEND_DATA.0, FILE_OPEN_IF);
    let (handle, _) = open_child(dir, name, &request)?;
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

/// Open the one name `name` under `parent` as `request` says, and return the handle with the path it
/// was reached by. The name is opened as itself and the handle then refused if it is a link, so the
/// object judged is the object held. Every way into a name below the profile directory goes through
/// here, except that [`confirm_dir`] opens `<profile>\AppData` by its path, to confirm it.
fn open_child(parent: &DirHandle, name: &str, request: &Request) -> anyhow::Result<(OwnedHandle, PathBuf)> {
    let units = single_name(name)?;
    let path = parent.path.join(name);
    let made = nt_create(
        Some(parent.raw()),
        &units,
        request.rights(),
        request.sharing(),
        request.disposition,
        request.options,
        request.descriptor,
    )?;
    let created = made.created;
    let handle = judge(made, &path, request)?;
    refuse_link(&handle, &path, request.purpose)?;
    if request.sole_name && !created {
        refuse_other_names(&handle, &path, request.purpose)?;
    }
    Ok((handle, path))
}

/// The handle an open gave, or why there is none: the one place a status becomes an error here. A name
/// that is not there is [`Missing`]; a file where a directory is wanted, and a denial the caller can
/// explain, are [`Refused`]; everything else is the system's error, naming `path`.
fn judge(made: Made, path: &Path, request: &Request) -> anyhow::Result<OwnedHandle> {
    let purpose = request.purpose;
    match (classify_open(made.status), &request.denied) {
        (OpenOutcome::Opened, _) => Ok(OwnedHandle(made.handle)),
        (OpenOutcome::Denied, _) if request.hold == Hold::Held => Err(HoldDenied.into()),
        (OpenOutcome::NotADirectory, _) => Err(Refused(format!(
            "{} cannot be used {purpose}: it is not a directory. {}",
            path.display(),
            request.not_a_directory
        ))
        .into()),
        (OpenOutcome::Denied, Some(denied)) => {
            Err(Refused(format!("{} cannot be used {purpose}: {denied}", path.display())).into())
        }
        (OpenOutcome::SharingViolation, _) if request.hold == Hold::Held => {
            Err(Refused(crate::offer::text::folder_held(path)).into())
        }
        (OpenOutcome::Missing, _) => Err(Missing {
            path: path.to_path_buf(),
        }
        .into()),
        (OpenOutcome::Denied, None) | (OpenOutcome::SharingViolation, _) | (OpenOutcome::Failed(_), _) => {
            Err(status_error(made.status)).with_context(|| format!("open {}", path.display()))
        }
    }
}

/// What a refused private folder says about itself and about what to do.
const LEFT_AS_IT_IS: &str = "It is left as it is: inspect it, remove it, and it is created again";

/// What a refusal says to do about a link.
const REMOVE_THE_LINK: &str = "remove the link so that the name is a real folder";

/// What a refusal says when a file is where a folder this code makes should be.
const MADE_AGAIN: &str = "Remove it, and it is made again";

/// What a refusal says when a file is where a folder of the profile itself should be: the folder is
/// not this code's to make.
const PROFILE_AS_IT_IS: &str = "The profile is not usable as it is";

/// Refuse `handle` if it is a link. It was opened as itself (`FILE_OPEN_REPARSE_POINT`), so this is
/// the object at the name and not what the name leads to.
fn refuse_link(handle: &OwnedHandle, path: &Path, purpose: &str) -> anyhow::Result<()> {
    let attributes = file_attributes(handle.0).with_context(|| format!("read the attributes of {}", path.display()))?;
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Err(Refused(format!(
            "{} cannot be used {purpose}: it is a reparse point (junction or symlink). Nothing is read or written \
             through it; {REMOVE_THE_LINK}",
            path.display()
        ))
        .into());
    }
    Ok(())
}

/// Refuse `handle` if the file has another name: a hard link. A file this call made has one, and
/// whoever adds a name to it afterwards has only reached the folder's own file.
fn refuse_other_names(handle: &OwnedHandle, path: &Path, purpose: &str) -> anyhow::Result<()> {
    let links = file_information(handle.0)
        .with_context(|| format!("read the attributes of {}", path.display()))?
        .nNumberOfLinks;
    if links > 1 {
        return Err(Refused(format!(
            "{} cannot be used {purpose}: it has {links} names, so it is a hard link to a file that is not this \
             folder's own. Nothing is read or written through it; remove it so that the name is a file of this \
             folder",
            path.display()
        ))
        .into());
    }
    Ok(())
}

#[cfg(test)]
#[path = "private_dir_tests.rs"]
mod private_dir_tests;
