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
use windows::Wdk::System::Threading::{NtQueryInformationProcess, ProcessCommandLineInformation};
use windows::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, HANDLE, UNICODE_STRING, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::Storage::FileSystem::{FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
    QueryFullProcessImageNameW, TerminateProcess, WaitForSingleObject,
};
use windows::core::{HRESULT, PWSTR};

use crate::acl::Sid;
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

impl Process {
    /// The process handle, for waiting on it. Owned by `self`.
    pub fn handle(&self) -> HANDLE {
        self.handle.0
    }

    /// End the process. The handle held here keeps its PID from being reused, so reopening it by
    /// PID for the right to terminate it reaches the same process.
    ///
    /// A process that has ended by the time this fails is the goal state, not an error:
    /// `TerminateProcess` on one is refused with access denied.
    pub fn terminate(&self) -> anyhow::Result<()> {
        match self.try_terminate() {
            Err(_) if has_exited(&self.handle) => Ok(()),
            result => result,
        }
    }

    fn try_terminate(&self) -> anyhow::Result<()> {
        // SAFETY: plain value arguments; the handle is owned by `OwnedHandle` from here.
        let handle = unsafe { OpenProcess(PROCESS_TERMINATE, false, self.pid) }
            .map(OwnedHandle)
            .with_context(|| format!("open process {} to end it", self.pid))?;
        // SAFETY: a live process handle with the right to terminate.
        unsafe { TerminateProcess(handle.0, 1) }.with_context(|| format!("end process {}", self.pid))
    }
}

/// Whether the process held by `handle` has ended. It can still be listed while some handle on it
/// is open, with its image and command line unreadable.
fn has_exited(handle: &OwnedHandle) -> bool {
    // SAFETY: the handle carries SYNCHRONIZE.
    let state = unsafe { WaitForSingleObject(handle.0, 0) }; // sleep-ok: zero-timeout state check of a process handle, not a wait
    state == WAIT_OBJECT_0
}

/// What an ssh-broker process is, from its command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The shim of an SSH session (sshd's `DefaultShell`), or any other verb.
    Shim,
    /// `agent`: started by the logon task in a user's desktop session.
    DesktopAgent,
    /// `agent --background`: started by the password prompt or by an auto-login task.
    BackgroundAgent,
}

/// The role of the process whose command line is `command_line`. The first argument after the
/// program decides: `agent` with `--background` among its flags is a background agent, `agent`
/// without it a desktop agent; anything else is a shim, including no argument and `-c <text>`
/// (sshd's form), whose text may itself contain the word `agent`.
pub fn role_of(command_line: &str) -> Role {
    let args = crate::cmdline::split_args(command_line);
    match args.get(1).map(String::as_str) {
        Some("agent") if args[2..].iter().any(|arg| arg == "--background") => Role::BackgroundAgent,
        Some("agent") => Role::DesktopAgent,
        _ => Role::Shim,
    }
}

/// The items of `roles` that are background agents.
pub fn select_background_agents<P>(roles: impl Iterator<Item = (P, Role)>) -> impl Iterator<Item = P> {
    roles.filter_map(|(item, role)| (role == Role::BackgroundAgent).then_some(item))
}

/// The command line `process` was started with. A process that is running the installed exe and
/// whose command line cannot be read is an error, the way an unidentifiable image is: it might be
/// the agent.
pub fn command_line_of(process: &Process) -> anyhow::Result<String> {
    let mut needed = 0u32;
    // SAFETY: a size probe: no buffer, zero length.
    let _ = unsafe {
        NtQueryInformationProcess(
            process.handle.0,
            ProcessCommandLineInformation,
            std::ptr::null_mut(),
            0,
            &mut needed,
        )
    };
    anyhow::ensure!(needed > 0, "process {} reported no command line size", process.pid);
    // Aligned for the `UNICODE_STRING` the answer starts with.
    let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
    // SAFETY: the buffer holds at least `needed` bytes, which is what the call is told.
    let status = unsafe {
        NtQueryInformationProcess(
            process.handle.0,
            ProcessCommandLineInformation,
            buffer.as_mut_ptr().cast(),
            (buffer.len() * 8) as u32,
            &mut needed,
        )
    };
    anyhow::ensure!(
        status.is_ok(),
        "read the command line of process {} (NTSTATUS {:#010x})",
        process.pid,
        status.0
    );
    // SAFETY: on success the buffer starts with a `UNICODE_STRING` whose `Buffer` points into the buffer.
    let text = unsafe {
        let string = &*(buffer.as_ptr() as *const UNICODE_STRING);
        std::slice::from_raw_parts(string.Buffer.0, usize::from(string.Length) / 2)
    };
    Ok(String::from_utf16_lossy(text))
}

/// Every background agent running `image` right now, other than this process, each held by a
/// handle. The image of a process is compared by file identity; its role by its command line.
///
/// A process the snapshot names `ssh-broker.exe` that cannot be identified or whose command line
/// cannot be read is an error: it might be a background agent. Any other process whose image
/// cannot be read (protected system processes, for one) cannot be the installed exe and is skipped.
pub fn background_agents(image: &Path) -> anyhow::Result<Vec<Process>> {
    let own = std::process::id();
    let mut candidates = Vec::new();
    for (pid, name) in process_names()? {
        if pid == own {
            continue;
        }
        let ours_by_name = name.eq_ignore_ascii_case(super::EXE_NAME);
        let process = match open_if_image(pid, image) {
            Ok(Some(process)) => process,
            Ok(None) => continue,
            Err(e) if ours_by_name => return Err(e),
            Err(_) => continue,
        };
        match command_line_of(&process) {
            Ok(line) => candidates.push((process, role_of(&line))),
            Err(_) if has_exited(&process.handle) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(select_background_agents(candidates.into_iter()).collect())
}

/// The process ids of the machine with the name of each one's image.
fn process_names() -> anyhow::Result<Vec<(u32, String)>> {
    // SAFETY: a snapshot of all processes; the handle is closed by `OwnedHandle`.
    let snapshot =
        OwnedHandle(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.context("snapshot the process list")?);
    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut names = Vec::new();
    // SAFETY: `entry` is a valid out-pointer with `dwSize` set; the snapshot outlives the loop.
    let mut more = unsafe { Process32FirstW(snapshot.0, &mut entry) }.is_ok();
    while more {
        let len = entry
            .szExeFile
            .iter()
            .position(|&unit| unit == 0)
            .unwrap_or(entry.szExeFile.len());
        names.push((entry.th32ProcessID, String::from_utf16_lossy(&entry.szExeFile[..len])));
        // SAFETY: as above.
        more = unsafe { Process32NextW(snapshot.0, &mut entry) }.is_ok();
    }
    Ok(names)
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
    let Some(handle) = open_for_waiting(pid)? else {
        return Ok(None);
    };
    // Ended but still listed: nothing to wait for, and its image can no longer be read.
    if has_exited(&handle) {
        return Ok(None);
    }
    match runs_image(&handle, pid, &wanted, identify) {
        Ok(runs) => Ok(runs.then_some(Process { pid, handle })),
        // It may have ended since the check above.
        Err(_) if has_exited(&handle) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Open the process `pid` for waiting and reading; `None` if it has exited.
fn open_for_waiting(pid: u32) -> anyhow::Result<Option<OwnedHandle>> {
    // SAFETY: plain value arguments; the handle is owned by `OwnedHandle` from here.
    match unsafe { OpenProcess(PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
        Ok(handle) => Ok(Some(OwnedHandle(handle))),
        Err(e) if e.code() == HRESULT::from_win32(ERROR_INVALID_PARAMETER.0) => Ok(None),
        Err(e) => Err(e).with_context(|| format!("open process {pid}")),
    }
}

/// Whether the process held by `handle` runs the file `wanted`.
fn runs_image(
    handle: &OwnedHandle,
    pid: u32,
    wanted: &FileId,
    identify: &dyn Fn(&Path) -> std::io::Result<FileId>,
) -> anyhow::Result<bool> {
    let path = image_of(handle).with_context(|| format!("read the image of process {pid}"))?;
    let running = identify(&path).with_context(|| {
        format!(
            "identify {}, which process {pid} runs, to tell if it runs the agent",
            path.display()
        )
    })?;
    Ok(running == *wanted)
}

/// Every agent (desktop or background) of `user` that is running `image` right now, other than this
/// process, each held by a handle: the agents that exist, whether or not they serve yet. A process
/// that has ended is not one.
///
/// A process of another user is none of this user's: it cannot be opened, or its token names
/// someone else, and it is skipped. A process of `user` whose image cannot be identified or whose
/// command line cannot be read is an error: it might be the agent.
pub fn user_agents(image: &Path, user: &Sid) -> anyhow::Result<Vec<Process>> {
    let wanted_user = user.to_sddl()?;
    let wanted = match file_id(image) {
        Ok(id) => id,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("identify {}", image.display())),
    };
    let own = std::process::id();
    let mut agents = Vec::new();
    for (pid, name) in process_names()? {
        if pid == own || !name.eq_ignore_ascii_case(super::EXE_NAME) {
            continue;
        }
        let handle = match open_for_waiting(pid) {
            Ok(Some(handle)) => handle,
            Ok(None) => continue,
            Err(e) if is_denied(&e) => continue,
            Err(e) => return Err(e),
        };
        match Sid::of_process(handle.0) {
            Ok(owner) if owner.to_sddl()? == wanted_user => {}
            Ok(_) => continue,
            Err(e) if is_denied(&e) => continue,
            Err(e) => return Err(e).with_context(|| format!("read the owner of process {pid}")),
        }
        if !runs_image(&handle, pid, &wanted, &file_id)? {
            continue;
        }
        if has_exited(&handle) {
            // Ended, but still listed while some handle on it is open. Waiting on it returns at once.
            continue;
        }
        let process = Process { pid, handle };
        match command_line_of(&process) {
            Ok(line) if role_of(&line) != Role::Shim => agents.push(process),
            Ok(_) => {}
            Err(_) if has_exited(&process.handle) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(agents)
}

/// Whether `error` is Windows refusing access.
fn is_denied(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<windows::core::Error>())
        .any(|e| e.code() == HRESULT::from_win32(ERROR_ACCESS_DENIED.0))
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
