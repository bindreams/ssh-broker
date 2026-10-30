//! The production [`Host`]: the process's environment, the file system, `SearchPathW` and the
//! system directory.

use std::ffi::OsString;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use ::windows::Win32::Storage::FileSystem::SearchPathW;
use ::windows::Win32::System::SystemInformation::GetSystemDirectoryW;
use ::windows::core::PCWSTR;

use super::{Host, join_windows};
use crate::provision::layout::Layout;
use crate::provision::procwait::file_id;

/// The machine this process runs on.
pub struct WindowsHost;

impl Host for WindowsHost {
    fn env(&self, name: &str) -> Option<OsString> {
        std::env::var_os(name)
    }

    fn profile_dir(&self) -> anyhow::Result<PathBuf> {
        crate::userdir::current_profile_dir()
    }

    fn read_file(&self, path: &Path) -> std::io::Result<Option<Vec<u8>>> {
        match std::fs::read(path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn is_file(&self, path: &Path) -> bool {
        std::fs::metadata(path).is_ok_and(|m| m.is_file())
    }

    fn find_program(&self, name: &str) -> Option<PathBuf> {
        let path = std::env::var_os("PATH")?;
        find_in(&std::env::split_paths(&path).collect::<Vec<_>>(), name)
    }

    fn is_system_cmd(&self, path: &Path) -> std::io::Result<bool> {
        let system_cmd = self.system_cmd().map_err(std::io::Error::other)?;
        Ok(file_id(path)? == file_id(&system_cmd)?)
    }

    fn system_cmd(&self) -> anyhow::Result<PathBuf> {
        Ok(join_windows(&system_directory()?, &["cmd.exe"]))
    }

    fn system_config_path(&self) -> PathBuf {
        Layout::production().system_config_path()
    }
}

/// The first file called `name` in `dirs`, in order; `.exe` is appended when `name` has no
/// extension.
///
/// Only the listed directories are searched: not the current directory, not the exe's directory
/// (what `SearchPathW` does with no list), so a relative entry, which would mean the current
/// directory, is skipped. `SearchPathW` returns a directory called `name` and stops (measured), so
/// a result that is not a file sends the search on to the next entry.
pub(super) fn find_in(dirs: &[PathBuf], name: &str) -> Option<PathBuf> {
    let name_w = wide(name.as_ref());
    let ext = wide(".exe".as_ref());
    for dir in dirs.iter().filter(|dir| dir.is_absolute()) {
        let dir_w = wide(dir.as_os_str());
        let call = |buffer: Option<&mut [u16]>| {
            // SAFETY: the three strings are NUL-terminated and outlive the call; the buffer is
            // the length the call is told.
            unsafe {
                SearchPathW(
                    PCWSTR(dir_w.as_ptr()),
                    PCWSTR(name_w.as_ptr()),
                    PCWSTR(ext.as_ptr()),
                    buffer,
                    None,
                )
            }
        };
        // With no buffer the call returns the length it needs, NUL included; 0 is "not here".
        let needed = call(None) as usize;
        if needed == 0 {
            continue;
        }
        let mut buffer = vec![0u16; needed];
        let len = call(Some(&mut buffer)) as usize;
        if len == 0 || len >= buffer.len() {
            continue;
        }
        let found = PathBuf::from(OsString::from_wide(&buffer[..len]));
        if found.is_file() {
            return Some(found);
        }
    }
    None
}

fn wide(text: &std::ffi::OsStr) -> Vec<u16> {
    text.encode_wide().chain(std::iter::once(0)).collect()
}

/// `C:\Windows\System32`, from the system and not from the `SystemRoot` variable: the
/// environment belongs to whoever started the process.
fn system_directory() -> anyhow::Result<PathBuf> {
    // SAFETY: the buffer is the length the call is told. With no buffer it returns the length it
    // needs, NUL included.
    let needed = unsafe { GetSystemDirectoryW(None) } as usize;
    anyhow::ensure!(
        needed > 0,
        "GetSystemDirectoryW failed: {}",
        std::io::Error::last_os_error()
    );
    let mut buffer = vec![0u16; needed];
    // SAFETY: as above.
    let len = unsafe { GetSystemDirectoryW(Some(&mut buffer)) } as usize;
    anyhow::ensure!(
        len > 0 && len < needed,
        "GetSystemDirectoryW failed: {}",
        std::io::Error::last_os_error()
    );
    Ok(PathBuf::from(OsString::from_wide(&buffer[..len])))
}

#[cfg(test)]
#[path = "windows_tests.rs"]
mod windows_tests;
