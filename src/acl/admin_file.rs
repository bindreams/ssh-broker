//! A file only SYSTEM and Administrators can open: the machine-wide `apply` lock.
//!
//! A byte-range lock needs only a handle with read or write access, so whoever can open the file
//! for reading can hold the lock for ever and stall every `apply` and the boot self-heal. The
//! install directory lets `BUILTIN\Users` read what is in it, so a file made there with the
//! inherited DACL would be open to them. This file gets its own protected DACL at creation, and one
//! that is already there must match it exactly (fail-closed, like [`super::verify_file_acl`]).

use std::path::Path;

use anyhow::Context;
use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_FILE_EXISTS, ERROR_INVALID_OWNER};
use windows::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateFileW, FILE_ALL_ACCESS, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    GetFileInformationByHandle,
};
use windows::core::{BOOL, HRESULT, PCWSTR};

use super::{Grant, LocalSd, Security, Sid, WellKnown, describe_sid, open_for_inspection, wide};
use crate::winutil::OwnedHandle;

/// Owner Administrators; protected DACL; SYSTEM and Administrators Full Control, no inheritable ACE.
/// Handed to `CreateFileW`, so the file never exists with any other DACL.
const ADMIN_FILE_SDDL: &str = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)";

/// Create `path` with [`ADMIN_FILE_SDDL`], or accept it if it already is exactly that. Its parent
/// must exist. A file or directory that is there and is not is an error naming it and is never
/// modified: it may have been opened by anyone already, and a handle opened before a repair stays
/// open after it.
pub fn ensure_admin_only_file(path: &Path) -> anyhow::Result<()> {
    create_admin_only_file(path)?;
    if let Some(problem) = admin_only_file_problem(path)? {
        anyhow::bail!(
            "{} exists but cannot be trusted as private to SYSTEM and Administrators: {problem}. \
             Inspect it, remove it, and run `apply` again",
            path.display()
        );
    }
    Ok(())
}

/// `CreateFileW` with `CREATE_NEW` and [`ADMIN_FILE_SDDL`]. "Already exists" is not an error here:
/// the caller decides whether what exists is acceptable.
fn create_admin_only_file(path: &Path) -> anyhow::Result<()> {
    let sddl_w: Vec<u16> = ADMIN_FILE_SDDL.encode_utf16().chain(std::iter::once(0)).collect();
    let path_w = wide(path);
    // SAFETY: NUL-terminated strings; the descriptor outlives the call and is freed by `LocalSd`.
    unsafe {
        let mut psd = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(sddl_w.as_ptr()), SDDL_REVISION_1, &mut psd, None)?;
        let _sd = LocalSd(psd);
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: psd.0,
            bInheritHandle: BOOL(0),
        };
        match CreateFileW(
            PCWSTR(path_w.as_ptr()),
            FILE_ALL_ACCESS.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            Some(&attributes),
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            None,
        ) {
            Ok(handle) => drop(OwnedHandle(handle)),
            Err(e) if e.code() == HRESULT::from_win32(ERROR_FILE_EXISTS.0) => {}
            // Creating over a directory is refused as "access denied", not as "exists": what is
            // there is the caller's to judge, whatever the code.
            Err(_) if std::fs::symlink_metadata(path).is_ok() => {}
            Err(e) => return Err(create_failure(e, path)),
        }
    }
    Ok(())
}

/// The error for a create that failed. Only a refusal of rights (access denied, or the owner in the
/// descriptor not being assignable to this token) says what to do about it: the other causes (a
/// missing parent directory, a sharing violation) are the OS's to name.
fn create_failure(error: windows::core::Error, path: &Path) -> anyhow::Error {
    let refused = [ERROR_ACCESS_DENIED, ERROR_INVALID_OWNER]
        .iter()
        .any(|code| error.code() == HRESULT::from_win32(code.0));
    let context = if refused {
        format!("create {} (this needs an elevated administrator)", path.display())
    } else {
        format!("create {}", path.display())
    };
    anyhow::Error::new(error).context(context)
}

/// Why `path` is not a file this build made, or `None` if it is one. It is read without following a
/// link.
pub fn admin_only_file_problem(path: &Path) -> anyhow::Result<Option<String>> {
    let Some(handle) = open_for_inspection(path)? else {
        return Ok(Some(
            "this process is denied access to read its ACL, so it cannot be shown to be private".to_owned(),
        ));
    };
    let security = Security::from_handle(handle.0).with_context(|| format!("read the ACL of {}", path.display()))?;
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: a valid handle and an out-pointer to a local.
    unsafe { GetFileInformationByHandle(handle.0, &mut info) }
        .with_context(|| format!("read the attributes of {}", path.display()))?;
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Ok(Some("it is a reparse point (a link)".to_owned()));
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0 {
        return Ok(Some("it is a directory".to_owned()));
    }
    Ok(problem_from_security(&security))
}

/// [`admin_only_file_problem`] on a security descriptor already read.
fn problem_from_security(security: &Security) -> Option<String> {
    let (Ok(system), Ok(admins)) = (
        Sid::well_known(WellKnown::System),
        Sid::well_known(WellKnown::Administrators),
    ) else {
        return Some("the well-known SIDs cannot be built".to_owned());
    };
    let full = |sid| Grant {
        sid,
        mask: FILE_ALL_ACCESS.0,
        flags: Some(0),
    };
    // The owner can rewrite the DACL whatever it says, so it has to be as trusted as the grantees.
    let owner_ok = security.owner_in(&[&system, &admins]).unwrap_or(false);
    let acl_ok = security.dacl_matches(&[full(&system), full(&admins)]).unwrap_or(false);
    let owner = describe_sid(security.owner);
    match (owner_ok, acl_ok) {
        (true, true) => None,
        (false, true) => Some(format!("its owner is {owner}, not SYSTEM or Administrators")),
        (true, false) => Some(format!(
            "its ACL is not exactly SYSTEM and Administrators (owner {owner} is fine)"
        )),
        (false, false) => Some(format!(
            "its owner is {owner}, not SYSTEM or Administrators, and its ACL is not exactly SYSTEM and Administrators"
        )),
    }
}

#[cfg(test)]
#[path = "admin_file_tests.rs"]
mod admin_file_tests;
