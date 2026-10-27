//! Helpers shared by the Windows unit tests: reading a DACL by well-known SID alias, and a
//! stand-in profile directory.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::socket_loc::SocketLocation;

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
        crate::socket_loc::for_profile(&self.0).expect("the stand-in profile path is short enough")
    }
}

impl Drop for TempProfile {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// Elevation -----

/// Fail loudly unless this process is an elevated administrator. For the tests that need it, so
/// they stop before they touch anything when run by hand on an ordinary host.
pub fn assert_elevated() {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = HANDLE::default();
    // SAFETY: valid out-pointers; the handle is closed below.
    let elevated = unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).unwrap();
        let mut info = TOKEN_ELEVATION::default();
        let mut len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut info as *mut _ as *mut core::ffi::c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        );
        let _ = CloseHandle(token);
        ok.is_ok() && info.TokenIsElevated != 0
    };
    assert!(
        elevated,
        "this test needs an elevated administrator (CI runs it); not running it here"
    );
}

// Scheduled tasks -----

use crate::provision::schtasks::{create_from_xml_argv, query_task_argv, xml_file_bytes};

/// A uniquely named throwaway scheduled task, deleted when dropped. Elevated tests only: `new`
/// refuses to run anywhere else, before it touches the Task Scheduler.
pub struct ThrowawayTask(pub String);

impl ThrowawayTask {
    pub fn new(tag: &str) -> ThrowawayTask {
        assert_elevated();
        ThrowawayTask(format!("ssh-broker-test-{tag}-{}", std::process::id()))
    }

    pub fn register(&self, xml: &str) {
        let file = std::env::temp_dir().join(format!("{}.xml", self.0));
        std::fs::write(&file, xml_file_bytes(xml)).unwrap();
        let out = Command::new("schtasks")
            .args(create_from_xml_argv(&self.0, &file.to_string_lossy()))
            .output()
            .unwrap();
        let _ = std::fs::remove_file(&file);
        assert!(
            out.status.success(),
            "schtasks /Create failed: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    pub fn queried_xml(&self) -> String {
        let out = Command::new("schtasks")
            .args(query_task_argv(&self.0))
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        // A redirected `schtasks` may emit UTF-16 or the console code page.
        let bytes = out.stdout;
        if bytes.starts_with(&[0xFF, 0xFE]) {
            let (pairs, _) = bytes[2..].as_chunks::<2>();
            String::from_utf16_lossy(&pairs.iter().copied().map(u16::from_le_bytes).collect::<Vec<_>>())
        } else {
            String::from_utf8_lossy(&bytes).into_owned()
        }
    }
}

impl Drop for ThrowawayTask {
    fn drop(&mut self) {
        let _ = Command::new("schtasks")
            .args(["/Delete", "/TN", &self.0, "/F"])
            .output();
    }
}

// Waiting for a file -----

/// Block until `file` exists, by watching its folder `dir` for changes and re-checking after each.
/// For a test that waits for a child process to say it got somewhere; there is no bound, because the
/// test runner ends a test that never finishes and names it.
pub fn wait_for_file(dir: &Path, file: &Path) {
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Storage::FileSystem::{
        FILE_NOTIFY_CHANGE_FILE_NAME, FindCloseChangeNotification, FindFirstChangeNotificationW,
        FindNextChangeNotification,
    };
    use windows::Win32::System::Threading::{INFINITE, WaitForSingleObject};

    let dir_w: Vec<u16> = dir.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    // Armed before the first check, so a creation between the check and the wait still signals.
    // SAFETY: a NUL-terminated path; the handle is closed below.
    let watch = unsafe { FindFirstChangeNotificationW(PCWSTR(dir_w.as_ptr()), false, FILE_NOTIFY_CHANGE_FILE_NAME) }
        .expect("watch the folder for the file");
    while !file.exists() {
        // SAFETY: the valid watch handle; re-armed after each wake so the next change signals again.
        unsafe {
            WaitForSingleObject(watch, INFINITE);
            FindNextChangeNotification(watch).expect("re-arm the folder watch");
        }
    }
    // SAFETY: the handle from above.
    let _ = unsafe { FindCloseChangeNotification(watch) };
}
