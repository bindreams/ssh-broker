//! Which processes exist, for a test that needs a grandchild to exist before it goes on.
#![allow(dead_code)]

use ssh_broker::winutil::OwnedHandle;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};

/// The executable names (as the system lists them, for example `PING.EXE`) of the processes whose
/// parent is `parent` right now.
pub fn children_of(parent: u32) -> Vec<String> {
    // SAFETY: a snapshot of all processes; the handle is closed by `OwnedHandle`.
    let snapshot =
        OwnedHandle(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.expect("snapshot the process list"));
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut names = Vec::new();
    // SAFETY: `entry` is a valid out-pointer with `dwSize` set; the snapshot outlives the loop.
    let mut more = unsafe { Process32FirstW(snapshot.0, &mut entry) }.is_ok();
    while more {
        if entry.th32ParentProcessID == parent {
            let len = entry
                .szExeFile
                .iter()
                .position(|&u| u == 0)
                .unwrap_or(entry.szExeFile.len());
            names.push(String::from_utf16_lossy(&entry.szExeFile[..len]));
        }
        // SAFETY: as above.
        more = unsafe { Process32NextW(snapshot.0, &mut entry) }.is_ok();
    }
    names
}
