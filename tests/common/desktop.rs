//! A window station and desktop made for one child, so that child can initialise user32.
//!
//! A process started as another account (`CreateProcessWithTokenW`) gets no access to the window
//! station and desktop it inherits from a service-context runner: user32 fails to initialise in it
//! (`0x8007045A`, then `0xC0000142` for anything that needs a console). Editing the runner's own
//! objects did not help. Here the objects are created with the access list they need from the
//! start, and live for one child.
//!
//! user32 is bound at run time, never imported: the test binary is also the child, and a binary
//! that imports user32 cannot even start where user32 cannot initialise.
#![allow(dead_code)]

use std::ffi::c_void;
use std::io;
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{OnceLock, PoisonError, RwLock, RwLockReadGuard};

use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::Win32::System::StationsAndDesktops::{HDESK, HWINSTA};
use windows::core::{BOOL, PCSTR, PCWSTR};

/// `READ_CONTROL | WINSTA_ALL_ACCESS`: Microsoft, "Window Station Security and Access Rights".
pub const STATION_ACCESS: u32 = 0x0002_037F;
/// `READ_CONTROL | ` every `DESKTOP_*` right: Microsoft, "Desktop Security and Access Rights".
pub const DESKTOP_ACCESS: u32 = 0x0002_01FF;
/// `CWF_CREATE_ONLY`: a name that is already taken fails instead of opening the other station.
const CWF_CREATE_ONLY: u32 = 1;
const SYSTEM: &str = "S-1-5-18";

/// A DACL granting each of `sids` (SDDL SID strings) exactly the rights in `mask`.
pub fn grant_sddl(sids: &[&str], mask: u32) -> String {
    let aces: String = sids.iter().map(|sid| format!("(A;;{mask:#x};;;{sid})")).collect();
    format!("D:{aces}")
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

// A security descriptor ------------------------------------------------------------------

/// A security descriptor parsed from SDDL, freed on drop.
pub struct Descriptor(PSECURITY_DESCRIPTOR);

impl Descriptor {
    pub fn parse(sddl: &str) -> windows::core::Result<Descriptor> {
        let mut sd = PSECURITY_DESCRIPTOR::default();
        // SAFETY: NUL-terminated input, valid out-pointer; the result is freed in `drop`.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide(sddl).as_ptr()),
                1, // SDDL_REVISION_1
                &mut sd,
                None,
            )?;
        }
        Ok(Descriptor(sd))
    }

    /// Attributes for a new object: this descriptor, not inheritable. Valid while `self` lives.
    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0.0,
            bInheritHandle: BOOL(0),
        }
    }
}

impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: allocated by the parse call; freed once.
        let _ = unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
    }
}

// user32, bound at run time ----------------------------------------------------------------

type GetProcessWindowStation = unsafe extern "system" fn() -> HWINSTA;
type SetProcessWindowStation = unsafe extern "system" fn(HWINSTA) -> BOOL;
type CreateWindowStationW = unsafe extern "system" fn(PCWSTR, u32, u32, *const SECURITY_ATTRIBUTES) -> HWINSTA;
type CreateDesktopW =
    unsafe extern "system" fn(PCWSTR, PCWSTR, *const c_void, u32, u32, *const SECURITY_ATTRIBUTES) -> HDESK;
type CloseWindowStation = unsafe extern "system" fn(HWINSTA) -> BOOL;
type CloseDesktop = unsafe extern "system" fn(HDESK) -> BOOL;

struct User32 {
    get_process_window_station: GetProcessWindowStation,
    set_process_window_station: SetProcessWindowStation,
    create_window_station: CreateWindowStationW,
    create_desktop: CreateDesktopW,
    close_window_station: CloseWindowStation,
    close_desktop: CloseDesktop,
}

/// The address of the NUL-terminated export `name` of `module`; panics naming it if absent.
fn export(module: windows::Win32::Foundation::HMODULE, name: &'static [u8]) -> usize {
    assert_eq!(name.last(), Some(&0));
    // SAFETY: NUL-terminated name, a loaded module.
    unsafe { GetProcAddress(module, PCSTR(name.as_ptr())) }
        .unwrap_or_else(|| panic!("user32.dll has no {}", String::from_utf8_lossy(&name[..name.len() - 1])))
        as usize
}

fn user32() -> &'static User32 {
    static API: OnceLock<User32> = OnceLock::new();
    API.get_or_init(|| {
        // SAFETY: NUL-terminated name.
        let module = unsafe { LoadLibraryW(PCWSTR(wide("user32.dll").as_ptr())) }.expect("load user32.dll");
        // SAFETY: each export is the documented user32 function with exactly the signature of its alias.
        unsafe {
            let get: GetProcessWindowStation = std::mem::transmute(export(module, b"GetProcessWindowStation\0"));
            let set: SetProcessWindowStation = std::mem::transmute(export(module, b"SetProcessWindowStation\0"));
            let create_station: CreateWindowStationW = std::mem::transmute(export(module, b"CreateWindowStationW\0"));
            let create_desktop: CreateDesktopW = std::mem::transmute(export(module, b"CreateDesktopW\0"));
            let close_station: CloseWindowStation = std::mem::transmute(export(module, b"CloseWindowStation\0"));
            let close_desktop: CloseDesktop = std::mem::transmute(export(module, b"CloseDesktop\0"));
            User32 {
                get_process_window_station: get,
                set_process_window_station: set,
                create_window_station: create_station,
                create_desktop,
                close_window_station: close_station,
                close_desktop,
            }
        }
    })
}

// The process's window station ----------------------------------------------------------------

/// Held exclusively while [`PrivateDesktop::create`] has this process on a station of its own, and
/// shared by everything that starts a child or reads the process's station. `CreateDesktopW`
/// puts the desktop on the calling process's current station and offers no other way to name one
/// (Microsoft, "CreateDesktopW": "associates it with the current window station of the calling
/// process"; the name may not contain a backslash), so the switch cannot be avoided, only made
/// invisible.
static STATION: RwLock<()> = RwLock::new(());

/// Shared hold on the window station: while it lives, the process's station is the original.
fn station_unchanged() -> RwLockReadGuard<'static, ()> {
    STATION.read().unwrap_or_else(PoisonError::into_inner)
}

/// This process's window station handle, as a number (to compare before and after).
pub fn process_window_station() -> usize {
    let _unchanged = station_unchanged();
    // SAFETY: takes no arguments; the handle is the process's own and is not closed.
    unsafe { (user32().get_process_window_station)() }.0 as usize
}

/// Start `command`. A child started without a desktop of its own takes this process's current
/// window station, so the start waits for any switch to finish and holds it off until the child
/// exists. Every start of a child in this binary goes through here, [`status`] or [`output`]
/// (a test checks the sources).
pub fn spawn(command: &mut Command) -> io::Result<Child> {
    let _unchanged = station_unchanged();
    command.spawn()
}

/// Like [`Command::status`]: inherited stdio, wait for the exit.
pub fn status(command: &mut Command) -> io::Result<ExitStatus> {
    spawn(command)?.wait()
}

/// Like [`Command::output`]: stdin closed, stdout and stderr captured.
pub fn output(command: &mut Command) -> io::Result<Output> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    spawn(command)?.wait_with_output()
}

// The pair -----------------------------------------------------------------------------------

/// A window station of its own with one desktop, `Default`, that only the SIDs given at creation
/// can use. Closed on drop; a child started on it keeps both alive until it exits.
pub struct PrivateDesktop {
    station: HWINSTA,
    desktop: HDESK,
    name: String,
}

static NEXT: AtomicU32 = AtomicU32::new(0);

impl PrivateDesktop {
    /// Create the pair for a child started by an account in `sids` (SDDL SID strings: the child's
    /// account and the one starting it); SYSTEM, which the secondary-logon service runs as, is added.
    /// Naming a window station needs an administrator (Microsoft, `CreateWindowStationW`).
    pub fn create(sids: &[&str]) -> windows::core::Result<PrivateDesktop> {
        let users: Vec<&str> = sids.iter().copied().chain([SYSTEM]).collect();
        let station_sd = Descriptor::parse(&grant_sddl(&users, STATION_ACCESS))?;
        let desktop_sd = Descriptor::parse(&grant_sddl(&users, DESKTOP_ACCESS))?;
        let station_name = format!("sb-iso-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed));
        let api = user32();

        // Creating the desktop needs the new station to be this process's for a moment. Exclusive:
        // no child starts and no reader looks while it is, and it is put back before release.
        let _switching = STATION.write().unwrap_or_else(PoisonError::into_inner);
        // SAFETY: NUL-terminated names, descriptors that outlive the calls, handles owned here.
        unsafe {
            let original = (api.get_process_window_station)();
            let station = (api.create_window_station)(
                PCWSTR(wide(&station_name).as_ptr()),
                CWF_CREATE_ONLY,
                STATION_ACCESS,
                &station_sd.attributes(),
            );
            if station.is_invalid() {
                return Err(windows::core::Error::from_thread());
            }
            if !(api.set_process_window_station)(station).as_bool() {
                let e = windows::core::Error::from_thread();
                let _ = (api.close_window_station)(station);
                return Err(e);
            }
            let desktop = (api.create_desktop)(
                PCWSTR(wide("Default").as_ptr()),
                PCWSTR::null(),
                std::ptr::null(),
                0,
                DESKTOP_ACCESS,
                &desktop_sd.attributes(),
            );
            let created = if desktop.is_invalid() {
                Err(windows::core::Error::from_thread())
            } else {
                Ok(())
            };
            let restored = if (api.set_process_window_station)(original).as_bool() {
                Ok(())
            } else {
                Err(windows::core::Error::from_thread())
            };
            if let Err(e) = created.and(restored) {
                if !desktop.is_invalid() {
                    let _ = (api.close_desktop)(desktop);
                }
                let _ = (api.close_window_station)(station);
                return Err(e);
            }
            Ok(PrivateDesktop {
                station,
                desktop,
                name: format!("{station_name}\\Default"),
            })
        }
    }

    /// `station\desktop`, for `STARTUPINFO.lpDesktop`.
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl Drop for PrivateDesktop {
    fn drop(&mut self) {
        let api = user32();
        // SAFETY: both handles were created by `create` and are closed once.
        unsafe {
            let _ = (api.close_desktop)(self.desktop);
            let _ = (api.close_window_station)(self.station);
        }
    }
}
