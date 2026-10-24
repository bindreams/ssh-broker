//! The live descendants of a process, found without mistaking a reused process id for one.
//!
//! Windows never updates a process's recorded parent id, and ids are reused, so "the processes
//! whose parent id is X" can include one that is no descendant of X. A process counts only if it
//! was created after its parent, and each is held by handle, which keeps its id from being reused
//! while the tree is in use. A process that cannot be opened is not a member: it is named in
//! [`Descendants::unopened`] instead, so a process left alive is never silent.
#![allow(dead_code)]

use std::collections::BTreeSet;

use ssh_broker::winutil::OwnedHandle;
use windows::Win32::Foundation::{ERROR_INVALID_PARAMETER, FILETIME, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    GetExitCodeProcess, GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
    TerminateProcess,
};

/// A descendant, held open.
pub struct Member {
    pub pid: u32,
    pub parent: u32,
    /// The executable name as the system lists it, for example `PING.EXE`.
    pub exe: String,
    created: u64,
    process: OwnedHandle,
}

impl Member {
    /// Names this process object for good: an id alone can be reused.
    fn key(&self) -> (u32, u64) {
        (self.pid, self.created)
    }
}

/// What [`descendants`] found.
pub struct Descendants {
    pub members: Vec<Member>,
    /// Entries that name a member of the tree as their parent but could not be opened to tell
    /// whether they are descendants, each with the reason.
    pub unopened: Vec<String>,
}

struct Entry {
    pid: u32,
    parent: u32,
    exe: String,
}

fn snapshot() -> Vec<Entry> {
    // SAFETY: a snapshot of all processes; the handle is closed by `OwnedHandle`.
    let snapshot =
        OwnedHandle(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.expect("snapshot the process list"));
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut entries = Vec::new();
    // SAFETY: `entry` is a valid out-pointer with `dwSize` set; the snapshot outlives the loop.
    let mut more = unsafe { Process32FirstW(snapshot.0, &mut entry) }.is_ok();
    while more {
        let len = entry
            .szExeFile
            .iter()
            .position(|&u| u == 0)
            .unwrap_or(entry.szExeFile.len());
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

/// The creation time of `process` as a 64-bit FILETIME.
fn creation_time(process: HANDLE) -> windows::core::Result<u64> {
    let (mut created, mut exited, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: `process` is a live handle with query access; the out-pointers are valid.
    unsafe { GetProcessTimes(process, &mut created, &mut exited, &mut kernel, &mut user) }?;
    Ok((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
}

/// Every process under `root` (process `root_pid`, itself excluded) that is provably a
/// descendant: its recorded parent is `root_pid` or a descendant, and it was created after that
/// parent. `root` stays open for the call, so `root_pid` cannot have been reused.
pub fn descendants(root: HANDLE, root_pid: u32) -> Descendants {
    let root_created = creation_time(root).expect("GetProcessTimes of the root process");
    let entries = snapshot();
    let mut members: Vec<Member> = Vec::new();
    let mut unopened = Vec::new();
    // (pid, creation time) of the processes whose children are looked for; the root first.
    let mut parents = vec![(root_pid, root_created)];
    while let Some((parent_pid, parent_created)) = parents.pop() {
        for entry in entries.iter().filter(|e| e.parent == parent_pid && e.pid != 0) {
            if entry.pid == root_pid || members.iter().any(|m| m.pid == entry.pid) {
                continue;
            }
            // SAFETY: a plain open by id; the handle is closed by `OwnedHandle`.
            let opened =
                unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE, false, entry.pid) };
            let process = match opened {
                Ok(handle) => OwnedHandle(handle),
                // Gone since the snapshot: it cannot be a survivor.
                Err(e) if e.code() == ERROR_INVALID_PARAMETER.to_hresult() => continue,
                Err(e) => {
                    unopened.push(format!("pid {} {}: {e}", entry.pid, entry.exe));
                    continue;
                }
            };
            let Ok(created) = creation_time(process.0) else {
                unopened.push(format!("pid {} {}: no creation time", entry.pid, entry.exe));
                continue;
            };
            if created < parent_created {
                continue; // older than the process it names: a reused id, not a child
            }
            parents.push((entry.pid, created));
            members.push(Member {
                pid: entry.pid,
                parent: entry.parent,
                exe: entry.exe.clone(),
                created,
                process,
            });
        }
    }
    Descendants { members, unopened }
}

/// Terminate `root` and every descendant of it, including any started while this runs. Returns
/// what could not be ended: a member that could not be opened or terminated, each with the reason.
/// Does not wait for the processes to be gone.
pub fn terminate_tree(root: HANDLE, root_pid: u32) -> BTreeSet<String> {
    let mut problems = BTreeSet::new();
    // SAFETY: `root` is a live process handle owned by the caller.
    if let Err(e) = unsafe { TerminateProcess(root, 1) }
        && !has_exited(root)
    {
        problems.insert(format!("root pid {root_pid}: {e}"));
    }
    // Each pass ends the members it has not ended before. The root is already ended, so nothing
    // new starts under it; a pass that finds nothing new is the last.
    let mut ended = BTreeSet::new();
    loop {
        let found = descendants(root, root_pid);
        problems.extend(found.unopened);
        let mut fresh = false;
        for member in &found.members {
            if !ended.insert(member.key()) {
                continue;
            }
            fresh = true;
            // SAFETY: the member's handle is open for this loop iteration.
            if let Err(e) = unsafe { TerminateProcess(member.process.0, 1) }
                && !has_exited(member.process.0)
            {
                problems.insert(format!("pid {} {}: {e}", member.pid, member.exe));
            }
        }
        if !fresh {
            return problems;
        }
    }
}

fn has_exited(process: HANDLE) -> bool {
    /// `STILL_ACTIVE`: the exit code of a process that has not exited.
    const STILL_ACTIVE: u32 = 259;
    let mut code = 0u32;
    // SAFETY: a live process handle and a valid out-pointer.
    unsafe { GetExitCodeProcess(process, &mut code) }.is_ok() && code != STILL_ACTIVE
}
