//! Helpers shared by the Windows unit tests: reading a DACL by well-known SID alias, and a
//! stand-in profile directory.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::socket_loc::{SOCKET_DIR_NAME, SOCKET_FILE_NAME, SocketLocation};

use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows::Win32::Security::{DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};
use windows::core::{PCWSTR, PWSTR};

// Reading a DACL by SID -----

pub const FILE_ALL: u32 = 0x1f_01ff;
pub const FILE_READ_EXECUTE: u32 = 0x12_00a9;

/// The DACL of `path` as an SDDL string (`D:AI(A;OICIID;FA;;;SY)...`). Well-known SIDs print as
/// two-letter aliases, so this does not depend on the display language.
pub fn dacl_sddl(path: &Path) -> String {
    let path_w: Vec<u16> = std::os::windows::ffi::OsStrExt::encode_wide(path.as_os_str())
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        let mut psd = PSECURITY_DESCRIPTOR::default();
        GetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            &mut psd,
        )
        .ok()
        .unwrap();
        let mut text = PWSTR::null();
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            psd,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut text,
            None,
        )
        .unwrap();
        let sddl = text.to_string().unwrap();
        let _ = LocalFree(Some(HLOCAL(text.0 as *mut core::ffi::c_void)));
        let _ = LocalFree(Some(HLOCAL(psd.0)));
        sddl
    }
}

/// `(type, flags, access mask, trustee)` of each ACE in an SDDL DACL, in order.
pub fn aces(sddl: &str) -> Vec<(&str, &str, u32, &str)> {
    sddl.split('(')
        .skip(1)
        .map(|ace| {
            let f: Vec<&str> = ace.trim_end_matches(')').split(';').collect();
            let mask = match f[2] {
                "FA" => FILE_ALL,
                "FRFX" => FILE_READ_EXECUTE,
                hex => u32::from_str_radix(hex.trim_start_matches("0x"), 16)
                    .unwrap_or_else(|_| panic!("unrecognised rights {hex:?} in {sddl}")),
            };
            (f[0], f[1], mask, f[5])
        })
        .collect()
}

// A stand-in profile -----

/// A stand-in profile under the temp dir, removed on drop. `AppData\Local` exists inside it, as
/// it does in a real profile.
pub struct TempProfile(pub PathBuf);

impl TempProfile {
    pub fn new(tag: &str) -> TempProfile {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("sb-ud-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(root.join("AppData").join("Local")).unwrap();
        TempProfile(root)
    }

    pub fn location(&self) -> SocketLocation {
        let dir = self.0.join("AppData").join("Local").join(SOCKET_DIR_NAME);
        SocketLocation {
            path: dir.join(SOCKET_FILE_NAME),
            dir,
        }
    }
}

impl Drop for TempProfile {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
