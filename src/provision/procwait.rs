//! provision::procwait — wait for the agent processes of a stopped task to be gone.
//!
//! `IRegisteredTask::Stop` ends a process with `TerminateProcess`, which returns before the
//! process is gone: its image stays mapped and its handles stay open until teardown ends. Anything
//! that replaces the exe, or starts a replacement agent that takes the session's lock, has to wait
//! for the process itself.

use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::Context;
use windows::Win32::Foundation::{ERROR_INVALID_PARAMETER, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::Storage::FileSystem::{FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx};
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
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

/// What names a file whatever path it is reached by: the volume and the file's id on it.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct FileId {
    volume: u64,
    file: [u8; 16],
}

/// The identity of the file at `path`.
fn file_id(path: &Path) -> std::io::Result<FileId> {
    /// `FILE_READ_ATTRIBUTES`: enough to ask for the id, and needs no read access to the file.
    const FILE_READ_ATTRIBUTES: u32 = 0x80;
    /// Read, write and delete sharing: this open must not get in the way of a running exe.
    const SHARE_ALL: u32 = 0x7;
    let file = std::fs::OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(SHARE_ALL)
        .open(path)?;
    let mut info = FILE_ID_INFO::default();
    // SAFETY: the handle is open for the call; `info` is the size the call is told.
    unsafe {
        GetFileInformationByHandleEx(
            HANDLE(file.as_raw_handle()),
            FileIdInfo,
            (&raw mut info).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    }
    .map_err(std::io::Error::from)?;
    Ok(FileId {
        volume: info.VolumeSerialNumber,
        file: info.FileId.Identifier,
    })
}

/// Open the process `pid` for waiting, if it is running `image`.
///
/// `None` means there is nothing to wait for: no such process (it has exited), a process of
/// another file (the PID was reused after the agent exited), or no `image` at all (nothing can be
/// running a file that is not there). Files are compared by identity, so a junction, a short name
/// or another case of the path is still the same exe. A process whose file cannot be identified is
/// an error: it might be the agent. Holding the handle is what keeps the identity from here on.
pub fn open_if_image(pid: u32, image: &Path) -> anyhow::Result<Option<Process>> {
    open_if_image_by(pid, image, &file_id)
}

/// [`open_if_image`] with the identity of a file by path as a parameter, so a test can make it fail.
fn open_if_image_by(
    pid: u32,
    image: &Path,
    identify: &dyn Fn(&Path) -> std::io::Result<FileId>,
) -> anyhow::Result<Option<Process>> {
    let wanted = match identify(image) {
        Ok(id) => id,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("identify {}", image.display())),
    };
    // SAFETY: plain value arguments; the handle is owned by `OwnedHandle` from here.
    let handle = match unsafe { OpenProcess(PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
        Ok(handle) => OwnedHandle(handle),
        Err(e) if e.code() == HRESULT::from_win32(ERROR_INVALID_PARAMETER.0) => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("open process {pid}")),
    };
    let path = image_of(&handle).with_context(|| format!("read the image of process {pid}"))?;
    let running = identify(&path).with_context(|| {
        format!(
            "identify {}, which process {pid} runs, to tell if it runs the agent",
            path.display()
        )
    })?;
    Ok((running == wanted).then_some(Process { pid, handle }))
}

fn image_of(process: &OwnedHandle) -> anyhow::Result<PathBuf> {
    // 32 767 units is the longest path Windows has, plus the NUL.
    let mut buf = vec![0u16; 32_768];
    let mut len = buf.len() as u32;
    // SAFETY: `buf` holds `len` units, which is what the call is told.
    unsafe { QueryFullProcessImageNameW(process.0, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len) }?;
    Ok(PathBuf::from(String::from_utf16_lossy(&buf[..len as usize])))
}

/// A process that outlived the bound, or whose exit could not be confirmed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Survivor {
    pub pid: u32,
    /// The session it runs in, or `None` if that could not be read.
    pub session: Option<u32>,
    /// Why its exit could not be confirmed, if the wait itself failed; `None` if it timed out.
    pub unconfirmed: Option<String>,
}

/// Agent processes still alive when the bound ran out, or that could not be confirmed gone. The
/// old agent of each holds its session's slot, so an agent started in that session meanwhile would
/// find the slot taken, exit, and leave the session with none once the old one dies.
#[derive(Debug)]
pub struct StillRunning {
    pub survivors: Vec<Survivor>,
    bound: Duration,
}

impl StillRunning {
    pub fn new(survivors: Vec<Survivor>, bound: Duration) -> Self {
        StillRunning { survivors, bound }
    }
}

impl std::fmt::Display for StillRunning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (unconfirmed, timed_out): (Vec<_>, Vec<_>) = self.survivors.iter().partition(|s| s.unconfirmed.is_some());
        let mut parts = Vec::new();
        if !timed_out.is_empty() {
            let pids: Vec<String> = timed_out.iter().map(|s| s.pid.to_string()).collect();
            parts.push(format!(
                "process {} did not exit within {} s of being stopped",
                pids.join(", "),
                self.bound.as_secs()
            ));
        }
        for survivor in unconfirmed {
            parts.push(format!(
                "could not confirm that process {} has exited ({})",
                survivor.pid,
                survivor.unconfirmed.as_deref().unwrap_or_default()
            ));
        }
        write!(
            f,
            "{}; run apply again once {} exited",
            parts.join("; "),
            if self.survivors.len() == 1 {
                "it has"
            } else {
                "they have"
            }
        )
    }
}

impl std::error::Error for StillRunning {}

/// Return once every process in `processes` has exited. Processes still alive after `bound`
/// (shared by all of them, counted from the call) are an error, [`StillRunning`], naming each: the
/// exit is an external event that might never come. A process whose wait fails is one whose exit
/// is not confirmed, and is carried the same way, with the error.
pub fn wait_all_exited(processes: &[Process], bound: Duration) -> anyhow::Result<()> {
    wait_all_exited_by(processes, bound, &wait_on)
}

/// Wait up to `millis` for `process` to exit: `true` if it did, `false` if the time ran out.
fn wait_on(process: &Process, millis: u32) -> std::io::Result<bool> {
    // SAFETY: the handle is open for the life of `process`.
    let outcome = unsafe { WaitForSingleObject(process.handle.0, millis) }; // sleep-ok: failure bound on an external process exit, reported as an error
    if outcome == WAIT_OBJECT_0 {
        Ok(true)
    } else if outcome == WAIT_TIMEOUT {
        Ok(false)
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// [`wait_all_exited`] with the wait on one process as a parameter, so a test can make it fail.
fn wait_all_exited_by(
    processes: &[Process],
    bound: Duration,
    wait: &dyn Fn(&Process, u32) -> std::io::Result<bool>,
) -> anyhow::Result<()> {
    let deadline = Instant::now().checked_add(bound);
    let mut survivors = Vec::new();
    for process in processes {
        // `INFINITE` is `u32::MAX`; a wait that long is clamped below it so it stays a bound. Once
        // the deadline has passed the rest are only polled, so every one still alive is found.
        let millis = match deadline {
            Some(deadline) => deadline.saturating_duration_since(Instant::now()).as_millis(),
            None => u128::from(u32::MAX - 1),
        };
        let millis = u32::try_from(millis).unwrap_or(u32::MAX - 1);
        let unconfirmed = match wait(process, millis) {
            Ok(true) => continue,
            Ok(false) => None,
            Err(e) => Some(e.to_string()),
        };
        survivors.push(Survivor {
            pid: process.pid,
            session: session_of(process.pid),
            unconfirmed,
        });
    }
    if survivors.is_empty() {
        Ok(())
    } else {
        Err(StillRunning::new(survivors, bound).into())
    }
}

fn session_of(pid: u32) -> Option<u32> {
    let mut session = 0u32;
    // SAFETY: `session` is a valid out pointer.
    unsafe { ProcessIdToSessionId(pid, &mut session) }
        .ok()
        .map(|()| session)
}

#[cfg(test)]
#[path = "procwait_tests.rs"]
mod procwait_tests;
