//! The live descendants of a process, found without mistaking a reused process id for one.
//!
//! Windows never updates a process's recorded parent id, and ids are reused, so "the processes
//! whose parent id is X" can include one that is no descendant of X. A process counts only if it
//! was created after its parent and its own recorded parent, read from the handle just opened
//! (not from the earlier snapshot), is that parent. Each member is held by handle, which keeps its
//! id from being reused while the tree is in use. A process that cannot be opened is not a member:
//! it is named in [`Descendants::unopened`] instead, so a process left alive is never silent.
#![allow(dead_code)]

use std::collections::BTreeSet;

use ssh_broker::winutil::OwnedHandle;
use windows::Wdk::System::Threading::{NtQueryInformationProcess, ProcessBasicInformation};
use windows::Win32::Foundation::{ERROR_INVALID_PARAMETER, FILETIME, HANDLE, WAIT_OBJECT_0};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    GetExitCodeProcess, GetProcessTimes, OpenProcess, PROCESS_BASIC_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SYNCHRONIZE, PROCESS_TERMINATE, TerminateProcess, WaitForSingleObject,
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

/// What [`descendants`] found.
pub struct Descendants {
    pub members: Vec<Member>,
    /// Entries that name a member of the tree as their parent but could not be opened to tell
    /// whether they are descendants, each with the reason.
    pub unopened: Vec<String>,
}

/// A process the system lists.
pub struct Entry {
    pub pid: u32,
    pub parent: u32,
    pub exe: String,
}

pub fn snapshot() -> Vec<Entry> {
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

/// The parent id recorded in `process` itself.
fn recorded_parent(process: HANDLE) -> windows::core::Result<u32> {
    let mut info = PROCESS_BASIC_INFORMATION::default();
    // SAFETY: `info` is a valid out buffer of the size passed; `process` is a live handle with query
    // access.
    unsafe {
        NtQueryInformationProcess(
            process,
            ProcessBasicInformation,
            &mut info as *mut PROCESS_BASIC_INFORMATION as *mut std::ffi::c_void,
            std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            std::ptr::null_mut(),
        )
    }
    .ok()?;
    Ok(info.InheritedFromUniqueProcessId as u32)
}

/// Every process under `root` (process `root_pid`, itself excluded) that is provably a
/// descendant: its recorded parent is `root_pid` or a descendant, and it was created after that
/// parent. `root` stays open for the call, so `root_pid` cannot have been reused.
pub fn descendants(root: HANDLE, root_pid: u32) -> Descendants {
    walk(root, root_pid, &[])
}

/// The descendants of `root` that are not in `known`, looking under `known` too. A member of
/// `known` is held open, so its id cannot have been reused, even after it has exited.
fn walk(root: HANDLE, root_pid: u32, known: &[Member]) -> Descendants {
    let root_created = creation_time(root).expect("GetProcessTimes of the root process");
    let entries = snapshot();
    let mut members: Vec<Member> = Vec::new();
    let mut unopened = Vec::new();
    // (pid, creation time) of the processes whose children are looked for; the root first.
    let mut parents = vec![(root_pid, root_created)];
    parents.extend(known.iter().map(|m| (m.pid, m.created)));
    while let Some((parent_pid, parent_created)) = parents.pop() {
        for entry in entries.iter().filter(|e| e.parent == parent_pid && e.pid != 0) {
            if entry.pid == root_pid
                || known.iter().any(|m| m.pid == entry.pid)
                || members.iter().any(|m| m.pid == entry.pid)
            {
                continue;
            }
            // SAFETY: a plain open by id; the handle is closed by `OwnedHandle`.
            let opened = unsafe {
                OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | PROCESS_SYNCHRONIZE,
                    false,
                    entry.pid,
                )
            };
            let process = match opened {
                Ok(handle) => OwnedHandle(handle),
                // Gone since the snapshot: it cannot be a survivor.
                Err(e) if e.code() == ERROR_INVALID_PARAMETER.to_hresult() => continue,
                Err(e) => {
                    unopened.push(format!("pid {} {}: {e}", entry.pid, entry.exe));
                    continue;
                }
            };
            let (Ok(created), Ok(parent)) = (creation_time(process.0), recorded_parent(process.0)) else {
                unopened.push(format!("pid {} {}: no creation time or parent", entry.pid, entry.exe));
                continue;
            };
            // The id may have been reused since the snapshot: what was opened must itself say that
            // it is a child of this parent (held open, so no newcomer has the parent's id), and be
            // younger than it.
            if parent != parent_pid || created < parent_created {
                continue;
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

/// Terminate `root` and the descendants reachable from it through a chain of parents this holds
/// open (a child of a process that exited before it was found is not), and wait for each to exit.
/// A pass looks only after
/// every process ended so far has exited, and looks under all of them, so a child that one of
/// them started before it exited is found by its recorded parent, as [`descendants`] does; the
/// last pass finds nothing new. Returns what could not be ended: a member that could not be
/// opened, terminated or waited for, each with the reason.
pub fn terminate_tree(root: HANDLE, root_pid: u32) -> BTreeSet<String> {
    let mut problems = BTreeSet::new();
    end(root, &format!("root pid {root_pid}"), &mut problems);
    let mut ended: Vec<Member> = Vec::new();
    loop {
        let found = walk(root, root_pid, &ended);
        problems.extend(found.unopened);
        if found.members.is_empty() {
            return problems;
        }
        for member in found.members {
            end(
                member.process.0,
                &format!("pid {} {}", member.pid, member.exe),
                &mut problems,
            );
            ended.push(member);
        }
    }
}

/// The user `process` runs as, in SDDL form, or `None` when that cannot be read.
pub fn owner_sddl(process: HANDLE) -> Option<String> {
    ssh_broker::acl::Sid::of_process(process).ok()?.to_sddl().ok()
}

/// Terminate every process that runs as the user `sid_text` (SDDL form) and wait for each to exit,
/// pass after pass until a pass finds none: a process ended in one pass can have started another.
/// A process that cannot be ended is reported and is not looked at again.
///
/// Processes that cannot be opened are skipped: the system's own are, and an account's own are
/// opened by the administrator that runs the tests.
pub fn terminate_processes_of(sid_text: &str) -> BTreeSet<String> {
    let own = std::process::id();
    let mut problems = BTreeSet::new();
    let mut given_up: BTreeSet<u32> = BTreeSet::new();
    loop {
        let mut found = Vec::new();
        for entry in snapshot() {
            if entry.pid == own || entry.pid == 0 || given_up.contains(&entry.pid) {
                continue;
            }
            // SAFETY: a plain open by id; the handle is closed by `OwnedHandle`.
            let Ok(handle) = (unsafe {
                OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | PROCESS_SYNCHRONIZE,
                    false,
                    entry.pid,
                )
            }) else {
                continue;
            };
            let process = OwnedHandle(handle);
            if owner_sddl(process.0).is_some_and(|owner| owner == sid_text) {
                found.push((entry, process));
            }
        }
        if found.is_empty() {
            return problems;
        }
        for (entry, process) in found {
            let before = problems.len();
            end(process.0, &format!("pid {} {}", entry.pid, entry.exe), &mut problems);
            if problems.len() != before {
                given_up.insert(entry.pid);
            }
        }
    }
}

/// How long a terminated process may take to be gone. Termination is asynchronous but quick; a
/// process still there after this is stuck in the kernel, and is reported instead of waited for.
const EXIT_AFTER_TERMINATE_BOUND_MS: u32 = 30_000;

/// Terminate `process` and wait for it to exit, up to [`EXIT_AFTER_TERMINATE_BOUND_MS`]; a
/// process that is still there then is added to `problems`.
fn end(process: HANDLE, name: &str, problems: &mut BTreeSet<String>) {
    // SAFETY: `process` is a live process handle with terminate access.
    let terminated = unsafe { TerminateProcess(process, 1) };
    if let Err(e) = &terminated
        && !has_exited(process)
    {
        problems.insert(format!("{name}: {e}"));
        return;
    }
    // SAFETY: as above; the handle carries SYNCHRONIZE.
    let rc = unsafe { WaitForSingleObject(process, EXIT_AFTER_TERMINATE_BOUND_MS) }; // sleep-ok: failure bound on a terminated process's exit, an external event; expiry is reported and is not read as state
    if rc != WAIT_OBJECT_0 {
        // An exit status that is already set while the process is listed means it began to end by
        // itself and is stuck ending; a refused `TerminateProcess` then says nothing about the kernel.
        let how = match terminated {
            Ok(()) => "after being terminated".to_string(),
            Err(e) => format!(
                "(TerminateProcess was refused: {e}; the exit status was already set, so the process had begun to end by itself and is stuck ending)"
            ),
        };
        problems.insert(format!(
            "{name}: still there {EXIT_AFTER_TERMINATE_BOUND_MS} ms {how} ({rc:?})"
        ));
    }
}

pub fn has_exited(process: HANDLE) -> bool {
    /// `STILL_ACTIVE`: the exit code of a process that has not exited.
    const STILL_ACTIVE: u32 = 259;
    let mut code = 0u32;
    // SAFETY: a live process handle and a valid out-pointer.
    unsafe { GetExitCodeProcess(process, &mut code) }.is_ok() && code != STILL_ACTIVE
}
