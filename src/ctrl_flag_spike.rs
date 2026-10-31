//! SPIKE, NOT FOR MERGE. Reads the "ignore Ctrl+C" setting of a process and of its ancestors, to find
//! the process that first has it. CI only.
//!
//! The setting `SetConsoleCtrlHandler(NULL, TRUE)` and `CREATE_NEW_PROCESS_GROUP` make is bit 0 of
//! `RTL_USER_PROCESS_PARAMETERS.ConsoleFlags` (offset 0x18 on x64) in the process's own PEB. The probe
//! `calibrate` in `examples/ctrl_flag.rs` checks that reading against the setters.

use std::fmt::Write as _;

use windows::Wdk::System::Threading::{NtQueryInformationProcess, ProcessBasicInformation};
use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::JobObjects::IsProcessInJob;
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PEB, PROCESS_BASIC_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
    RTL_USER_PROCESS_PARAMETERS,
};

const _: () = assert!(size_of::<usize>() == 8, "the ConsoleFlags offset below is the x64 one");

/// `ConsoleFlags & CONSOLE_IGNORE_CTRL_C` is the setting.
pub const IGNORE_CTRL_C: u32 = 1;

struct Owned(HANDLE);
impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: the handle came from `OpenProcess` and is closed once.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

fn read<T: Copy + Default>(process: HANDLE, address: *const core::ffi::c_void) -> Result<T, String> {
    let mut value = T::default();
    // SAFETY: `value` is a writable `T`; the call reports a short or failed read as an error.
    unsafe { ReadProcessMemory(process, address, (&raw mut value).cast(), size_of::<T>(), None) }
        .map_err(|e| format!("read memory: {e}"))?;
    Ok(value)
}

/// `ConsoleFlags` of the process `pid`.
pub fn console_flags(pid: u32) -> Result<u32, String> {
    // SAFETY: plain value arguments.
    let process = Owned(
        unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, false, pid) }
            .map_err(|e| format!("open for reading its memory: {e}"))?,
    );
    let mut basic = PROCESS_BASIC_INFORMATION::default();
    let mut needed = 0u32;
    // SAFETY: `basic` is the size the call is told.
    unsafe {
        NtQueryInformationProcess(
            process.0,
            ProcessBasicInformation,
            (&raw mut basic).cast(),
            size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut needed,
        )
    }
    .ok()
    .map_err(|e| format!("query its PEB address: {e}"))?;
    let peb: PEB = read(process.0, basic.PebBaseAddress.cast())?;
    let parameters: RTL_USER_PROCESS_PARAMETERS = read(process.0, peb.ProcessParameters.cast())?;
    // `Reserved1: [u8; 16]` ends at 0x10; `Reserved2[0]` is ConsoleHandle (0x10) and `Reserved2[1]` starts
    // with ConsoleFlags (0x18), a ULONG.
    Ok(parameters.Reserved2[1] as usize as u32)
}

struct Entry {
    pid: u32,
    parent: u32,
    exe: String,
}

fn snapshot() -> Vec<Entry> {
    // SAFETY: a snapshot of all processes, closed below.
    let Ok(snapshot) = (unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }) else {
        return Vec::new();
    };
    let snapshot = Owned(snapshot);
    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut entries = Vec::new();
    // SAFETY: `entry` is a valid out-pointer with `dwSize` set.
    let mut more = unsafe { Process32FirstW(snapshot.0, &mut entry) }.is_ok();
    while more {
        let len = entry.szExeFile.iter().position(|&u| u == 0).unwrap_or(entry.szExeFile.len());
        entries.push(Entry {
            pid: entry.th32ProcessID,
            parent: entry.th32ParentProcessID,
            exe: String::from_utf16_lossy(&entry.szExeFile[..len]),
        });
        // SAFETY: as above.
        more = unsafe { Process32NextW(snapshot.0, &mut entry) }.is_ok();
    }
    entries
}

fn creation_time(pid: u32) -> Option<u64> {
    // SAFETY: plain value arguments.
    let process = Owned(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?);
    let (mut created, mut exited, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: valid out-pointers.
    unsafe { GetProcessTimes(process.0, &mut created, &mut exited, &mut kernel, &mut user) }.ok()?;
    Some((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
}

fn in_job(pid: u32) -> String {
    // SAFETY: plain value arguments.
    let Ok(process) = (unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }) else {
        return "?".into();
    };
    let process = Owned(process);
    let mut result = windows::core::BOOL(0);
    // SAFETY: a valid out-pointer; no job handle asks "any job".
    match unsafe { IsProcessInJob(process.0, None, &mut result) } {
        Ok(()) => result.as_bool().to_string(),
        Err(_) => "?".into(),
    }
}

fn describe(pid: u32, entries: &[Entry]) -> String {
    let exe = entries.iter().find(|e| e.pid == pid).map_or("?", |e| e.exe.as_str());
    let mut session = 0u32;
    // SAFETY: a valid out-pointer.
    let session = if unsafe { ProcessIdToSessionId(pid, &mut session) }.is_ok() {
        session.to_string()
    } else {
        "?".into()
    };
    let flags = match console_flags(pid) {
        Ok(flags) => format!("consoleflags={flags:#x} ignore_ctrl_c={}", flags & IGNORE_CTRL_C != 0),
        Err(e) => format!("consoleflags=UNREADABLE({e})"),
    };
    format!("pid={pid} {exe} session={session} in_job={} {flags}", in_job(pid))
}

/// `pid` and each ancestor that is still the process its child recorded: a parent that was created after
/// its child, or that is gone, ends the chain. The ends are said.
pub fn chain(pid: u32) -> String {
    let entries = snapshot();
    let mut text = String::new();
    let mut current = pid;
    loop {
        let _ = writeln!(text, "  {}", describe(current, &entries));
        let Some(parent) = entries.iter().find(|e| e.pid == current).map(|e| e.parent) else {
            let _ = writeln!(text, "  (pid {current} is not listed)");
            return text;
        };
        if parent == 0 {
            let _ = writeln!(text, "  (no parent recorded)");
            return text;
        }
        let (child_created, parent_created) = (creation_time(current), creation_time(parent));
        match (child_created, parent_created) {
            (Some(child), Some(parent_time)) if parent_time < child => current = parent,
            (Some(_), Some(_)) => {
                let _ = writeln!(text, "  (recorded parent {parent} was created after its child: pid reused)");
                return text;
            }
            _ => {
                let _ = writeln!(text, "  (recorded parent {parent} is gone or unopenable: end of the chain)");
                return text;
            }
        }
    }
}

fn append(label: &str, pid: u32) {
    let me = std::process::id();
    let path = format!(r"C:\ProgramData\sb-ctrl-spike-{me}.log");
    let command_line = std::env::args().collect::<Vec<_>>().join(" ");
    let body = format!("[{label}] recorded by pid {me} ({command_line})\n{}", chain(pid));
    let written = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .and_then(|mut file| std::io::Write::write_all(&mut file, body.as_bytes()));
    if let Err(e) = written {
        eprintln!("ctrl_flag_spike: could not write {path}: {e}");
    }
}

/// Append the chain of this process to `C:\ProgramData\sb-ctrl-spike-<pid>.log`.
pub fn record(label: &str) {
    append(label, std::process::id());
}

/// Append the chain of `process` (a child just created, perhaps suspended) to this process's file.
pub fn record_process(label: &str, process: HANDLE) {
    // SAFETY: a live process handle.
    let pid = unsafe { windows::Win32::System::Threading::GetProcessId(process) };
    append(label, pid);
}
