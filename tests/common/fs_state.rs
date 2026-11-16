//! What the tests of the private folder compare before and after to see that nothing was changed, and
//! the link they put in the way. One source for both homes: the integration tests include it with
//! `#[path]`, and so does the unit tests' `src/test_support.rs`. It needs only `std` and `windows`.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW, GetNamedSecurityInfoW,
    SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    DACL_SECURITY_INFORMATION, GetTokenInformation, OBJECT_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, TOKEN_OWNER, TOKEN_QUERY, TokenOwner,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::{PCWSTR, PWSTR};

/// The parts `which` of the security descriptor of `path` as SDDL, read through the path. Well-known
/// SIDs print as two-letter aliases, so this does not depend on the display language. Compare two
/// such strings with each other, never one with SDDL a test wrote; for an owner use `owner_sid_of`.
fn security_sddl(path: &Path, which: OBJECT_SECURITY_INFORMATION) -> String {
    let w: Vec<u16> = std::os::windows::ffi::OsStrExt::encode_wide(path.as_os_str())
        .chain(std::iter::once(0))
        .collect();
    let mut psd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: valid out-pointers; both allocations are freed below.
    unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(w.as_ptr()),
            SE_FILE_OBJECT,
            which,
            None,
            None,
            None,
            None,
            &mut psd,
        )
        .ok()
        .unwrap_or_else(|e| panic!("read the security of {}: {e}", path.display()));
        let mut text = PWSTR::null();
        ConvertSecurityDescriptorToStringSecurityDescriptorW(psd, SDDL_REVISION_1, which, &mut text, None).unwrap();
        let out = text.to_string().unwrap();
        let _ = LocalFree(Some(HLOCAL(text.0 as *mut _)));
        let _ = LocalFree(Some(HLOCAL(psd.0)));
        out
    }
}

/// The SID `sid` as `S-1-5-...` text, always numeric. SDDL text prints some SIDs as aliases (the
/// built-in Administrator account, RID 500, as `LA`), so a SID is compared in this form, never as a
/// substring of SDDL.
///
/// # Safety
/// `sid` is a valid SID.
unsafe fn sid_text(sid: PSID) -> String {
    // SAFETY: the caller's valid SID; the string is freed below.
    unsafe {
        let mut text = PWSTR::null();
        ConvertSidToStringSidW(sid, &mut text).unwrap();
        let out = text.to_string().unwrap();
        let _ = LocalFree(Some(HLOCAL(text.0 as *mut _)));
        out
    }
}

/// The owner of `path` as `S-1-5-...` text, read through the path.
pub fn owner_sid_of(path: &Path) -> String {
    let w: Vec<u16> = std::os::windows::ffi::OsStrExt::encode_wide(path.as_os_str())
        .chain(std::iter::once(0))
        .collect();
    let mut owner = PSID::default();
    let mut psd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: valid out-pointers; the owner points into `psd`, which is freed after it is printed.
    unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(w.as_ptr()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            None,
            None,
            &mut psd,
        )
        .ok()
        .unwrap_or_else(|e| panic!("read the owner of {}: {e}", path.display()));
        let out = sid_text(owner);
        let _ = LocalFree(Some(HLOCAL(psd.0)));
        out
    }
}

/// The owner a folder made by this process gets when its descriptor names none, as `S-1-5-...` text:
/// the default owner of the process token, which is the user for a plain token and Administrators for
/// an elevated one.
pub fn default_owner_sid() -> String {
    // SAFETY: valid out-pointers and a buffer as long as the call is told; the token handle is closed
    // after the owner is printed, and the owner points into the buffer.
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).unwrap();
        let mut len = 0u32;
        let _ = GetTokenInformation(token, TokenOwner, None, 0, &mut len);
        let mut buf = vec![0u8; len as usize];
        GetTokenInformation(token, TokenOwner, Some(buf.as_mut_ptr().cast()), len, &mut len).unwrap();
        let _ = CloseHandle(token);
        sid_text((*(buf.as_ptr() as *const TOKEN_OWNER)).Owner)
    }
}

/// The DACL of `path` as SDDL (`D:AI(A;OICIID;FA;;;SY)...`).
pub fn dacl_sddl(path: &Path) -> String {
    security_sddl(path, DACL_SECURITY_INFORMATION)
}

/// The owner and the DACL of `path` as SDDL (`O:BAD:...`).
pub fn sddl_of(path: &Path) -> String {
    security_sddl(path, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION)
}

/// Every path under `root` (and `root`), relative to it, with its owner and DACL and, for a file, its
/// bytes: what a test compares before and after to see that nothing was changed, added or removed.
/// A link is listed, not followed.
pub fn tree_state(root: &Path) -> BTreeMap<String, String> {
    fn visit(root: &Path, at: &Path, out: &mut BTreeMap<String, String>) {
        let meta = at
            .symlink_metadata()
            .unwrap_or_else(|e| panic!("stat {}: {e}", at.display()));
        let bytes = if meta.is_file() {
            let read = std::fs::read(at).unwrap_or_else(|e| panic!("read {}: {e}", at.display()));
            format!(" bytes={read:?}")
        } else {
            String::new()
        };
        let relative = at.strip_prefix(root).unwrap().display().to_string();
        out.insert(relative, format!("{}{bytes}", sddl_of(at)));
        if meta.is_dir() {
            for entry in std::fs::read_dir(at).unwrap_or_else(|e| panic!("list {}: {e}", at.display())) {
                visit(
                    root,
                    &entry.unwrap_or_else(|e| panic!("list {}: {e}", at.display())).path(),
                    out,
                );
            }
        }
    }
    let mut out = BTreeMap::new();
    visit(root, root, &mut out);
    out
}

/// Make `link` a junction to `target`, by the token of this process (no privilege needed).
pub fn junction(link: &Path, target: &Path) {
    let out = Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "mklink /J: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}
