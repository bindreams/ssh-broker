//! Giving one file the security descriptor of another: what `apply` does so that the `sshd_config` it
//! replaces keeps the owner, the group and the DACL the original had.

use std::path::Path;

use anyhow::Context;
use windows::Win32::Foundation::{ERROR_NOT_ALL_ASSIGNED, GetLastError, HANDLE, LUID};
use windows::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT, SetNamedSecurityInfoW};
use windows::Win32::Security::{
    ACL, AdjustTokenPrivileges, DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, GetSecurityDescriptorControl,
    LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, SE_PRIVILEGE_ENABLED, SE_RESTORE_NAME, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_PRIVILEGES, TOKEN_QUERY, UNPROTECTED_DACL_SECURITY_INFORMATION,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::PCWSTR;

use super::{LocalSd, wide};
use crate::winutil::OwnedHandle;

/// Give `to` the owner, the group and the DACL of `from`, the DACL protected or not as it is there. An owner
/// other than the caller's can be set only with `SeRestorePrivilege`, which an elevated administrator holds
/// and has disabled, so it is enabled for this process for the copy and put back as it was after it; a caller
/// that does not hold it gets the error.
pub fn copy_file_security(from: &Path, to: &Path) -> anyhow::Result<()> {
    let _privilege = RestorePrivilege::enable().context("enable SeRestorePrivilege to set the owner")?;
    let (from_w, to_w) = (wide(from), wide(to));
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let (mut owner, mut group) = (PSID::default(), PSID::default());
    // SAFETY: `from_w` is NUL-terminated and the out-pointers are locals; `LocalSd` frees the descriptor, which
    // the owner, the group and the DACL point into.
    let read = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(from_w.as_ptr()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&mut owner),
            Some(&mut group),
            Some(&mut dacl),
            None,
            &mut descriptor,
        )
    };
    let _descriptor = LocalSd(descriptor);
    read.ok()
        .with_context(|| format!("read the security of {}", from.display()))?;
    let (mut control, mut revision) = (0u16, 0u32);
    // SAFETY: the descriptor is valid until `_descriptor` is dropped.
    unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) }
        .context("read the control bits of the descriptor")?;
    let protection = if control & SE_DACL_PROTECTED.0 != 0 {
        PROTECTED_DACL_SECURITY_INFORMATION
    } else {
        UNPROTECTED_DACL_SECURITY_INFORMATION
    };
    // SAFETY: `to_w` is NUL-terminated; the SIDs and the DACL point into `_descriptor`, which is alive.
    unsafe {
        SetNamedSecurityInfoW(
            PCWSTR(to_w.as_ptr()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | protection,
            Some(owner),
            Some(group),
            Some(dacl as *const ACL),
            None,
        )
    }
    .ok()
    .with_context(|| format!("set the security of {}", to.display()))
}

/// `SeRestorePrivilege` enabled on this process's token for as long as the guard lives. Dropping it puts the
/// privilege back as `AdjustTokenPrivileges` reported it: a privilege that was enabled already stays so.
struct RestorePrivilege {
    token: OwnedHandle,
    /// What the call changed, as it was before; empty when it changed nothing.
    previous: TOKEN_PRIVILEGES,
}

impl RestorePrivilege {
    /// Enable the privilege. `AdjustTokenPrivileges` succeeds when it assigns nothing, so
    /// `ERROR_NOT_ALL_ASSIGNED` (the token does not hold the privilege) is read back and is the error.
    fn enable() -> anyhow::Result<RestorePrivilege> {
        let mut token = HANDLE::default();
        // SAFETY: the pseudo-handle of this process is valid for the call; the token is closed by `OwnedHandle`.
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token) }
            .context("open the process token")?;
        let token = OwnedHandle(token);
        let mut luid = LUID::default();
        // SAFETY: a null system name means this machine; `luid` is a local.
        unsafe { LookupPrivilegeValueW(PCWSTR::null(), SE_RESTORE_NAME, &mut luid) }
            .context("look up the privilege")?;
        let privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        let mut previous = TOKEN_PRIVILEGES::default();
        let mut returned = 0u32;
        // SAFETY: the token has `TOKEN_ADJUST_PRIVILEGES`; `privileges` is one entry as its count says;
        // `previous` has room for the one entry the call can report.
        unsafe {
            AdjustTokenPrivileges(
                token.0,
                false,
                Some(&privileges),
                std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
                Some(&mut previous),
                Some(&mut returned),
            )
        }
        .context("adjust the token")?;
        // SAFETY: reads the thread's last error, set by the call above.
        anyhow::ensure!(
            unsafe { GetLastError() } != ERROR_NOT_ALL_ASSIGNED,
            "this token does not hold the privilege: run elevated"
        );
        Ok(RestorePrivilege { token, previous })
    }
}

impl Drop for RestorePrivilege {
    fn drop(&mut self) {
        if self.previous.PrivilegeCount == 0 {
            return;
        }
        // SAFETY: the token is open with `TOKEN_ADJUST_PRIVILEGES`; `previous` is what the call that enabled the
        // privilege reported. There is nobody to tell if this fails: the privilege stays enabled.
        let _ = unsafe { AdjustTokenPrivileges(self.token.0, false, Some(&self.previous), 0, None, None) };
    }
}
