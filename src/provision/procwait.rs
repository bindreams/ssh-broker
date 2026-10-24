//! provision::procwait — wait for the agent processes of a stopped task to be gone.
//!
//! `IRegisteredTask::Stop` ends a process with `TerminateProcess`, which returns before the
//! process is gone: its image stays mapped and its handles stay open until teardown ends. Anything
//! that replaces the exe, or starts a replacement agent that takes the session's lock, has to wait
//! for the process itself.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;
use windows::Win32::Foundation::{ERROR_INVALID_PARAMETER, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    QueryFullProcessImageNameW, WaitForSingleObject,
};
use windows::core::{HRESULT, PWSTR};

use crate::winutil::OwnedHandle;

/// How long a stopped agent may take to exit before the stop is reported as failed. The exit is
/// the kernel's to finish and nothing here can hurry it, so this only bounds a process that never
/// ends (a wedged driver), and says which one.
pub const EXIT_BOUND: Duration = Duration::from_secs(60);

/// An open handle on a process, which stays the same process even if its PID is reused.
pub struct Process {
    pub pid: u32,
    handle: OwnedHandle,
}

/// Open the process `pid` for waiting, if it is running `image`.
///
/// `None` means there is nothing to wait for: no such process (it has exited), or a process of
/// another image (the PID was reused after the agent exited). Holding the handle is what keeps the
/// identity from here on.
pub fn open_if_image(pid: u32, image: &Path) -> anyhow::Result<Option<Process>> {
    // SAFETY: plain value arguments; the handle is owned by `OwnedHandle` from here.
    let handle = match unsafe { OpenProcess(PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
        Ok(handle) => OwnedHandle(handle),
        Err(e) if e.code() == HRESULT::from_win32(ERROR_INVALID_PARAMETER.0) => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("open process {pid}")),
    };
    let running = image_of(&handle).with_context(|| format!("read the image of process {pid}"))?;
    let same = running.to_string_lossy().eq_ignore_ascii_case(&image.to_string_lossy());
    Ok(same.then_some(Process { pid, handle }))
}

fn image_of(process: &OwnedHandle) -> anyhow::Result<PathBuf> {
    // 32 767 units is the longest path Windows has, plus the NUL.
    let mut buf = vec![0u16; 32_768];
    let mut len = buf.len() as u32;
    // SAFETY: `buf` holds `len` units, which is what the call is told.
    unsafe { QueryFullProcessImageNameW(process.0, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len) }?;
    Ok(PathBuf::from(String::from_utf16_lossy(&buf[..len as usize])))
}

/// Return once every process in `processes` has exited. A process still alive after `bound` is an
/// error naming it: the exit is an external event that might never come.
pub fn wait_all_exited(processes: &[Process], bound: Duration) -> anyhow::Result<()> {
    // `INFINITE` is `u32::MAX`; a bound that large is clamped below it so it stays a bound.
    let millis = u32::try_from(bound.as_millis()).unwrap_or(u32::MAX - 1);
    for process in processes {
        // SAFETY: the handle is open for the life of `process`.
        let outcome = unsafe { WaitForSingleObject(process.handle.0, millis) }; // sleep-ok: failure bound on an external process exit, reported as an error
        if outcome == WAIT_OBJECT_0 {
            continue;
        }
        if outcome == WAIT_TIMEOUT {
            anyhow::bail!(
                "process {} did not exit within {} s of being stopped",
                process.pid,
                bound.as_secs()
            );
        }
        return Err(std::io::Error::last_os_error()).with_context(|| format!("wait for process {}", process.pid));
    }
    Ok(())
}

#[cfg(test)]
#[path = "procwait_tests.rs"]
mod procwait_tests;
