//! Account rights (`SeBatchLogonRight` and the like) through the LSA policy.

use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Authentication::Identity::{
    LSA_HANDLE, LSA_OBJECT_ATTRIBUTES, LSA_UNICODE_STRING, LsaAddAccountRights, LsaClose, LsaEnumerateAccountRights,
    LsaFreeMemory, LsaNtStatusToWinError, LsaOpenPolicy,
};
use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows::Win32::Security::PSID;
use windows::core::{PCWSTR, PWSTR};

use crate::win::wide;

const POLICY_CREATE_ACCOUNT: u32 = 0x10;
const POLICY_LOOKUP_NAMES: u32 = 0x800;

struct Policy(LSA_HANDLE);

impl Drop for Policy {
    fn drop(&mut self) {
        // SAFETY: opened by `LsaOpenPolicy`, closed once.
        let _ = unsafe { LsaClose(self.0) };
    }
}

fn open() -> Result<Policy, String> {
    let attributes = LSA_OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<LSA_OBJECT_ATTRIBUTES>() as u32,
        ..Default::default()
    };
    let mut handle = LSA_HANDLE::default();
    // SAFETY: valid pointers; the local policy is addressed by a null system name.
    let status = unsafe {
        LsaOpenPolicy(
            None,
            &attributes,
            POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES,
            &mut handle,
        )
    };
    if status.0 != 0 {
        // SAFETY: plain value argument.
        return Err(format!("LsaOpenPolicy win32 {}", unsafe {
            LsaNtStatusToWinError(status)
        }));
    }
    Ok(Policy(handle))
}

fn unicode(text: &mut Vec<u16>) -> LSA_UNICODE_STRING {
    // `text` holds a NUL terminator the API does not count.
    let bytes = ((text.len() - 1) * 2) as u16;
    LSA_UNICODE_STRING {
        Length: bytes,
        MaximumLength: bytes + 2,
        Buffer: PWSTR(text.as_mut_ptr()),
    }
}

/// Grant `right` (for example `SeBatchLogonRight`) to the account with SID text `sid_text`.
pub fn grant(sid_text: &str, right: &str) -> Result<(), String> {
    let policy = open()?;
    let mut sid = PSID::default();
    // SAFETY: NUL-terminated input; the SID is freed below.
    unsafe { ConvertStringSidToSidW(PCWSTR(wide(sid_text).as_ptr()), &mut sid) }.map_err(|e| e.to_string())?;
    let mut name = wide(right);
    let rights = [unicode(&mut name)];
    // SAFETY: valid policy handle, SID and one right.
    let status = unsafe { LsaAddAccountRights(policy.0, sid, &rights) };
    // SAFETY: allocated by `ConvertStringSidToSidW`.
    let _ = unsafe { LocalFree(Some(HLOCAL(sid.0))) };
    if status.0 != 0 {
        // SAFETY: plain value argument.
        return Err(format!("LsaAddAccountRights win32 {}", unsafe {
            LsaNtStatusToWinError(status)
        }));
    }
    Ok(())
}

/// The rights the account holds explicitly (not the ones its groups give).
pub fn explicit_rights(sid_text: &str) -> Result<Vec<String>, String> {
    let policy = open()?;
    let mut sid = PSID::default();
    // SAFETY: NUL-terminated input; the SID is freed below.
    unsafe { ConvertStringSidToSidW(PCWSTR(wide(sid_text).as_ptr()), &mut sid) }.map_err(|e| e.to_string())?;
    let mut list: *mut LSA_UNICODE_STRING = std::ptr::null_mut();
    let mut count = 0u32;
    // SAFETY: valid policy handle, SID and out-pointers; the list is freed below.
    let status = unsafe { LsaEnumerateAccountRights(policy.0, sid, &mut list, &mut count) };
    // SAFETY: allocated by `ConvertStringSidToSidW`.
    let _ = unsafe { LocalFree(Some(HLOCAL(sid.0))) };
    if status.0 != 0 {
        // SAFETY: plain value argument. 2 is "file not found": the account has no explicit rights.
        let win32 = unsafe { LsaNtStatusToWinError(status) };
        return if win32 == 2 {
            Ok(Vec::new())
        } else {
            Err(format!("LsaEnumerateAccountRights win32 {win32}"))
        };
    }
    // SAFETY: the system returned `count` strings at `list`, each `Length` bytes at `Buffer`.
    let rights = unsafe {
        std::slice::from_raw_parts(list, count as usize)
            .iter()
            .map(|s| String::from_utf16_lossy(std::slice::from_raw_parts(s.Buffer.0, usize::from(s.Length) / 2)))
            .collect()
    };
    // SAFETY: allocated by the LSA.
    let _ = unsafe { LsaFreeMemory(Some(list.cast())) };
    Ok(rights)
}
