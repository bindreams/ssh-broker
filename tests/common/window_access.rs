//! Letting a throwaway account use this process's window station and desktop.
//!
//! `CreateProcessWithTokenW` starts a process under another account's token, but unlike
//! `CreateProcessWithLogonW` it does not give that account access to the window station and
//! desktop the process is placed on. Without it, `user32.dll` fails to initialise in the child
//! (`ERROR_DLL_INIT_FAILED`), and so does everything that imports it, such as `ole32.dll`. A grant
//! made here is for one account, lasts as long as its guard, and is revoked on drop.
#![allow(dead_code)]

use std::sync::Mutex;

use windows::Win32::Foundation::{HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertStringSidToSidW, EXPLICIT_ACCESS_W, GRANT_ACCESS,
    GetSecurityInfo, REVOKE_ACCESS, SE_WINDOW_OBJECT, SetEntriesInAclW, SetSecurityInfo, TRUSTEE_IS_SID,
    TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows::Win32::Security::{ACL, DACL_SECURITY_INFORMATION, NO_INHERITANCE, PSECURITY_DESCRIPTOR, PSID};
use windows::Win32::System::StationsAndDesktops::{
    CloseDesktop, CloseWindowStation, DESKTOP_CONTROL_FLAGS, GetProcessWindowStation, GetThreadDesktop,
    GetUserObjectInformationW, OpenDesktopW, OpenWindowStationW, UOI_NAME,
};
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::core::{PCWSTR, PWSTR};

/// `WINSTA_ALL_ACCESS`: the window station rights, without the standard rights (no `WRITE_DAC`,
/// no `DELETE`), so the account can use the station and not change who else may.
pub const STATION_RIGHTS: u32 = 0x37F;
/// Every `DESKTOP_*` right (`DESKTOP_READOBJECTS` through `DESKTOP_SWITCHDESKTOP`), likewise
/// without the standard rights.
pub const DESKTOP_RIGHTS: u32 = 0x1FF;

const READ_CONTROL_AND_WRITE_DAC: u32 = 0x0006_0000;

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// A SID parsed from its text form, freed on drop.
struct LocalSid(PSID);

impl LocalSid {
    fn parse(text: &str) -> LocalSid {
        let mut sid = PSID::default();
        // SAFETY: NUL-terminated input, a valid out-pointer; the allocation is freed in `drop`.
        unsafe { ConvertStringSidToSidW(PCWSTR(wide(text).as_ptr()), &mut sid) }
            .unwrap_or_else(|e| panic!("{text} is not a SID: {e}"));
        LocalSid(sid)
    }
}

impl Drop for LocalSid {
    fn drop(&mut self) {
        // SAFETY: allocated by `ConvertStringSidToSidW`, freed once.
        let _ = unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
    }
}

/// Which kind of object a name refers to, and so how to open it.
#[derive(Clone, Copy)]
enum Kind {
    Station,
    Desktop,
}

/// An object opened for reading and writing its DACL, closed on drop.
struct Opened(Kind, HANDLE);

impl Opened {
    fn open(kind: Kind, name: &str) -> windows::core::Result<Opened> {
        let name = wide(name);
        // SAFETY: NUL-terminated name; the handle is closed in `drop`.
        let handle = unsafe {
            match kind {
                Kind::Station => OpenWindowStationW(PCWSTR(name.as_ptr()), false, READ_CONTROL_AND_WRITE_DAC)?.0,
                Kind::Desktop => {
                    OpenDesktopW(
                        PCWSTR(name.as_ptr()),
                        DESKTOP_CONTROL_FLAGS(0),
                        false,
                        READ_CONTROL_AND_WRITE_DAC,
                    )?
                    .0
                }
            }
        };
        Ok(Opened(kind, HANDLE(handle)))
    }
}

impl Drop for Opened {
    fn drop(&mut self) {
        // SAFETY: opened by `Opened::open`, closed once.
        let _ = unsafe {
            match self.0 {
                Kind::Station => CloseWindowStation(windows::Win32::System::StationsAndDesktops::HWINSTA(self.1.0)),
                Kind::Desktop => CloseDesktop(windows::Win32::System::StationsAndDesktops::HDESK(self.1.0)),
            }
        };
    }
}

/// Serialises read-modify-write of a DACL: tests run in parallel and each edits the same station
/// and desktop for its own account, and two interleaved edits would lose one of them.
static DACL_EDIT: Mutex<()> = Mutex::new(());

/// Grant or revoke `rights` for `sid` on `object`, keeping every other ACE.
fn edit_dacl(
    object: &Opened,
    sid: &LocalSid,
    rights: u32,
    mode: windows::Win32::Security::Authorization::ACCESS_MODE,
) -> windows::core::Result<()> {
    let _guard = DACL_EDIT.lock().unwrap_or_else(|e| e.into_inner());
    let entry = EXPLICIT_ACCESS_W {
        grfAccessPermissions: rights,
        grfAccessMode: mode,
        grfInheritance: NO_INHERITANCE,
        Trustee: TRUSTEE_W {
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_UNKNOWN,
            ptstrName: PWSTR(sid.0.0.cast()),
            ..Default::default()
        },
    };
    // SAFETY: valid out-pointers; the old descriptor and the new ACL are freed after
    // `SetSecurityInfo` has copied the new ACL.
    unsafe {
        let mut old: *mut ACL = std::ptr::null_mut();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        GetSecurityInfo(
            object.1,
            SE_WINDOW_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut old),
            None,
            Some(&mut descriptor),
        )
        .ok()?;
        let mut new: *mut ACL = std::ptr::null_mut();
        let result = SetEntriesInAclW(Some(&[entry]), Some(old), &mut new)
            .ok()
            .and_then(|()| {
                SetSecurityInfo(
                    object.1,
                    SE_WINDOW_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    None,
                    None,
                    Some(new),
                    None,
                )
                .ok()
            });
        let _ = LocalFree(Some(HLOCAL(new.cast())));
        let _ = LocalFree(Some(HLOCAL(descriptor.0)));
        result
    }
}

/// The DACL of the named object as SDDL, or the reason it cannot be read in parentheses.
fn sddl(kind: Kind, name: &str) -> String {
    let object = match Opened::open(kind, name) {
        Ok(object) => object,
        Err(e) => return format!("(cannot open {name}: {e})"),
    };
    // SAFETY: valid out-pointers; both allocations are freed below.
    unsafe {
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        if let Err(e) = GetSecurityInfo(
            object.1,
            SE_WINDOW_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            Some(&mut descriptor),
        )
        .ok()
        {
            return format!("(cannot read the DACL of {name}: {e})");
        }
        let mut text = PWSTR::null();
        let converted = ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            1,
            DACL_SECURITY_INFORMATION,
            &mut text,
            None,
        );
        let out = match converted {
            Ok(()) => text.to_string().unwrap_or_else(|e| format!("(not UTF-16: {e})")),
            Err(e) => format!("(cannot convert the DACL of {name}: {e})"),
        };
        let _ = LocalFree(Some(HLOCAL(text.0.cast())));
        let _ = LocalFree(Some(HLOCAL(descriptor.0)));
        out
    }
}

pub fn station_sddl(name: &str) -> String {
    sddl(Kind::Station, name)
}

pub fn desktop_sddl(name: &str) -> String {
    sddl(Kind::Desktop, name)
}

/// One account's access to one window station or desktop; revoked on drop.
pub struct Grant {
    kind: Kind,
    name: String,
    sid: LocalSid,
}

impl Grant {
    fn new(kind: Kind, name: &str, sid_text: &str, rights: u32) -> Grant {
        let object = Opened::open(kind, name).unwrap_or_else(|e| panic!("open {name} to change its DACL: {e}"));
        let sid = LocalSid::parse(sid_text);
        edit_dacl(&object, &sid, rights, GRANT_ACCESS)
            .unwrap_or_else(|e| panic!("give {sid_text} access to {name}: {e}"));
        Grant {
            kind,
            name: name.to_owned(),
            sid,
        }
    }
}

impl Drop for Grant {
    fn drop(&mut self) {
        // Only reported: a panic here during an unwind would abort the test binary.
        let revoked =
            Opened::open(self.kind, &self.name).and_then(|object| edit_dacl(&object, &self.sid, 0, REVOKE_ACCESS));
        if let Err(e) = revoked {
            eprintln!("could not revoke an account's access to {}: {e}", self.name);
        }
    }
}

pub fn grant_station(name: &str, sid_text: &str) -> Grant {
    Grant::new(Kind::Station, name, sid_text, STATION_RIGHTS)
}

pub fn grant_desktop(name: &str, sid_text: &str) -> Grant {
    Grant::new(Kind::Desktop, name, sid_text, DESKTOP_RIGHTS)
}

fn object_name(object: HANDLE) -> String {
    let mut needed = 0u32;
    // SAFETY: a zero-length query reports the size needed in `needed`.
    let _ = unsafe { GetUserObjectInformationW(object, UOI_NAME, None, 0, Some(&mut needed)) };
    let mut buf = vec![0u16; (needed as usize).div_ceil(2).max(1)];
    // SAFETY: `buf` holds `needed` bytes.
    unsafe {
        GetUserObjectInformationW(
            object,
            UOI_NAME,
            Some(buf.as_mut_ptr().cast()),
            (buf.len() * 2) as u32,
            Some(&mut needed),
        )
    }
    .expect("GetUserObjectInformationW(UOI_NAME)");
    let len = buf.iter().position(|&u| u == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}

/// The names of this process's window station and of this thread's desktop.
pub fn current_names() -> (String, String) {
    // SAFETY: both handles belong to the process and thread and are not closed here.
    unsafe {
        let station = GetProcessWindowStation().expect("GetProcessWindowStation");
        let desktop = GetThreadDesktop(GetCurrentThreadId()).expect("GetThreadDesktop");
        (object_name(HANDLE(station.0)), object_name(HANDLE(desktop.0)))
    }
}

/// The `STARTUPINFO.lpDesktop` text that places a process on `station` and `desktop`.
pub fn lp_desktop(station: &str, desktop: &str) -> String {
    format!(r"{station}\{desktop}")
}

/// An account's access to this process's own window station and desktop, and the `lpDesktop` text
/// that places its process there. Revoked on drop.
pub struct CurrentDesktopAccess {
    pub lp_desktop: String,
    _desktop: Grant,
    _station: Grant,
}

pub fn grant_current(sid_text: &str) -> CurrentDesktopAccess {
    let (station, desktop) = current_names();
    CurrentDesktopAccess {
        lp_desktop: lp_desktop(&station, &desktop),
        _station: grant_station(&station, sid_text),
        _desktop: grant_desktop(&desktop, sid_text),
    }
}
