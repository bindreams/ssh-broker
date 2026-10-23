//! Temporary measurement: what a child started as another account sees. Delete once the shim test
//! passes in CI.
//!
//! The child reports its window station and desktop, whether the account's registry hive is
//! loaded, its `USERPROFILE`, and whether one named DLL loads. User32 is called through
//! `GetProcAddress`, never imported: a child that imported it would fail to start in exactly the
//! case this measures.
#![allow(dead_code)]

use std::ffi::c_void;
use std::fmt::Write as _;

use windows::Win32::Foundation::HMODULE;
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::Win32::System::Registry::{HKEY, HKEY_USERS, KEY_READ, RegCloseKey, RegOpenCurrentUser, RegOpenKeyExW};
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::core::{PCSTR, PCWSTR};

/// The DLLs to load, one child each: a failing initializer must not poison the next load.
pub const DLLS: [&str; 4] = ["user32.dll", "gdi32.dll", "combase.dll", "ole32.dll"];

/// `UOI_NAME` of `GetUserObjectInformationW`.
const UOI_NAME: i32 = 2;

type GetStation = unsafe extern "system" fn() -> isize;
type GetDesktop = unsafe extern "system" fn(u32) -> isize;
type GetInfo = unsafe extern "system" fn(isize, i32, *mut c_void, u32, *mut u32) -> i32;

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn load(dll: &str) -> windows::core::Result<HMODULE> {
    // SAFETY: NUL-terminated name.
    unsafe { LoadLibraryW(PCWSTR(wide(dll).as_ptr())) }
}

/// The address of `name` (NUL-terminated) in `module`.
fn address(module: HMODULE, name: &'static [u8]) -> Option<usize> {
    assert_eq!(name.last(), Some(&0));
    // SAFETY: `name` is NUL-terminated and `module` is a loaded module.
    unsafe { GetProcAddress(module, PCSTR(name.as_ptr())) }.map(|f| f as usize)
}

/// The name of a window station or desktop handle.
fn object_name(info: GetInfo, handle: isize) -> String {
    if handle == 0 {
        return format!("no handle: {}", windows::core::Error::from_thread());
    }
    let mut buf = [0u16; 256];
    let mut needed = 0u32;
    // SAFETY: `buf` is a writable buffer of the byte length given; `needed` is a valid out-pointer.
    let ok = unsafe {
        info(
            handle,
            UOI_NAME,
            buf.as_mut_ptr().cast(),
            std::mem::size_of_val(&buf) as u32,
            &mut needed,
        )
    };
    if ok == 0 {
        return format!(
            "GetUserObjectInformationW failed: {}",
            windows::core::Error::from_thread()
        );
    }
    let len = buf.iter().position(|&u| u == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}

/// The window station and desktop of the calling thread, by name.
fn station_and_desktop() -> Result<(String, String), String> {
    let user32 = load("user32.dll").map_err(|e| format!("user32.dll did not load: {e}"))?;
    let missing = |name: &str| format!("user32.dll has no {name}");
    let station = address(user32, b"GetProcessWindowStation\0").ok_or_else(|| missing("GetProcessWindowStation"))?;
    let desktop = address(user32, b"GetThreadDesktop\0").ok_or_else(|| missing("GetThreadDesktop"))?;
    let info = address(user32, b"GetUserObjectInformationW\0").ok_or_else(|| missing("GetUserObjectInformationW"))?;
    // SAFETY: the three are the documented user32 exports with exactly these signatures.
    unsafe {
        let station: GetStation = std::mem::transmute(station);
        let desktop: GetDesktop = std::mem::transmute(desktop);
        let info: GetInfo = std::mem::transmute(info);
        Ok((
            object_name(info, station()),
            object_name(info, desktop(GetCurrentThreadId())),
        ))
    }
}

/// What opening `HKEY_CURRENT_USER` and `HKEY_USERS\<sid>` returned (0 is success, 2 is "not
/// there": the hive is not loaded).
fn hive(sid: &str) -> (u32, u32) {
    let mut key = HKEY::default();
    // SAFETY: valid out-pointers, NUL-terminated name; each opened key is closed.
    unsafe {
        let current = RegOpenCurrentUser(KEY_READ.0, &mut key);
        if current.0 == 0 {
            let _ = RegCloseKey(key);
        }
        let users = RegOpenKeyExW(HKEY_USERS, PCWSTR(wide(sid).as_ptr()), None, KEY_READ, &mut key);
        if users.0 == 0 {
            let _ = RegCloseKey(key);
        }
        (current.0, users.0)
    }
}

/// The child's report, one fact per line. `sid` is the account's SID text; `dll` is loaded last.
pub fn report(sid: &str, dll: &str) -> String {
    let mut out = String::new();
    match station_and_desktop() {
        Ok((station, desktop)) => {
            let _ = writeln!(out, "window station: {station}\ndesktop: {desktop}");
        }
        Err(e) => {
            let _ = writeln!(out, "window station and desktop: {e}");
        }
    }
    let (current, users) = hive(sid);
    let _ = writeln!(out, "HKEY_CURRENT_USER: RegOpenCurrentUser returned {current}");
    let _ = writeln!(
        out,
        "HKEY_USERS\\{sid}: RegOpenKeyExW returned {users} (2 means the hive is not loaded)"
    );
    let _ = writeln!(
        out,
        "USERPROFILE={}",
        std::env::var("USERPROFILE").unwrap_or_else(|e| format!("({e})"))
    );
    match load(dll) {
        Ok(_) => {
            let _ = writeln!(out, "LoadLibraryW({dll}): ok");
        }
        Err(e) => {
            let _ = writeln!(out, "LoadLibraryW({dll}): failed: {e}");
        }
    }
    out
}
