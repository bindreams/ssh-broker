//! Waiting for a child process that might never exit, without hanging the test binary.
//!
//! A child's exit is an external event: if it never comes, libtest never reaches its summary and
//! CI shows nothing but a cancelled job. So the wait has a failure bound, and its expiry is
//! reported as the failure it is, never read as proof of anything about the child.
#![allow(dead_code)]

use std::fmt::Write as _;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use ssh_broker::winutil::OwnedHandle;
use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::System::Threading::{
    GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
    WaitForSingleObject,
};

use crate::{desktop, process_list};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// How long a child started as another account may take to exit. Generous: the slowest step seen
/// on a CI runner is creating a profile, at about a minute, and that is not part of a child's run.
pub const CHILD_EXIT_BOUND: Duration = Duration::from_secs(120);

/// Wait for `process` (process id `pid`, described as `what`) to exit and return its exit code.
///
/// On expiry of `bound` this prints what the child left behind (`evidence`: files, or the files
/// of a directory), the process tree under `pid` with each thread's state and wait reason, then
/// ends that tree (only processes provably descended from `pid`: see [`process_list`]) and panics
/// naming `what`. Every wait after the kill is bounded, and an expired one is in the report.
pub fn wait_for_exit(process: HANDLE, pid: u32, what: &str, bound: Duration, evidence: &[PathBuf]) -> u32 {
    let millis = u32::try_from(bound.as_millis()).expect("a bound shorter than INFINITE");
    // SAFETY: `process` is a live process handle owned by the caller.
    let rc = unsafe { WaitForSingleObject(process, millis) }; // sleep-ok: failure bound on a child's exit, an external event; expiry fails the test and is not read as state
    if rc == WAIT_OBJECT_0 {
        let mut code = 0u32;
        // SAFETY: as above; `code` is a valid out-pointer.
        unsafe { GetExitCodeProcess(process, &mut code) }.expect("GetExitCodeProcess");
        return code;
    }
    assert_eq!(rc, WAIT_TIMEOUT, "waiting for {what} (pid {pid}) failed: {rc:?}");

    let mut report = format!("{what} (pid {pid}) did not exit within {bound:?}.\n");
    // The caller's handle may carry no right to terminate; the report and the kill need that right, and
    // a handle held keeps the pid from being reused, so reopening by pid reaches the same process.
    // SAFETY: a plain open by id; the handle is closed by `OwnedHandle`.
    let reopened = unsafe {
        OpenProcess(
            PROCESS_TERMINATE | PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
            false,
            pid,
        )
    };
    let reopened = match reopened {
        Ok(handle) => Some(OwnedHandle(handle)),
        Err(e) => {
            let _ = writeln!(report, "could not reopen the process with the right to end it: {e}");
            None
        }
    };
    let process = reopened.as_ref().map_or(process, |handle| handle.0);
    let _ = writeln!(report, "exit status: {}", exit_status(process));
    report.push_str("\nprocess tree:\n");
    report.push_str(&process_tree(process, pid));
    for path in evidence {
        report.push_str(&format!("\nevidence {}:\n", path.display()));
        dump(path, &mut report);
    }
    let left = process_list::terminate_tree(process, pid);
    panic!("{report}\nprocesses that could not be ended: {left:?}");
}

/// The exit status of `process` as it reads while the process is still listed: `STILL_ACTIVE` means it
/// runs; any other value means it began to end (`ExitProcess` or `TerminateProcess` ran) and has not
/// finished, which is a different hang from a process that never tried to end.
fn exit_status(process: HANDLE) -> String {
    const STILL_ACTIVE: u32 = 259;
    let mut code = 0u32;
    // SAFETY: a live process handle and a valid out-pointer.
    match unsafe { GetExitCodeProcess(process, &mut code) } {
        Ok(()) if code == STILL_ACTIVE => "STILL_ACTIVE (259): it never began to end".to_string(),
        Ok(()) => format!("{code:#x}: it began to end and has not finished"),
        Err(e) => format!("unreadable: {e}"),
    }
}

/// `root` and its descendants (see [`process_list`]) with each one's command line, and its
/// threads with their state and wait reason: what a hung tree is blocked on.
pub fn process_tree(root: HANDLE, root_pid: u32) -> String {
    let tree = process_list::descendants(root, root_pid);
    let mut ids = vec![root_pid];
    ids.extend(tree.members.iter().map(|m| m.pid));
    let ids: Vec<String> = ids.iter().map(u32::to_string).collect();
    let script = format!(
        "foreach ($id in @({ids})) {{ \
           $p = Get-CimInstance Win32_Process -Filter \"ProcessId=$id\"; \
           if ($p) {{ \
             '{{0}} parent={{1}} {{2}}: {{3}}' -f $p.ProcessId, $p.ParentProcessId, $p.Name, $p.CommandLine; \
             $proc = Get-Process -Id $id -ErrorAction SilentlyContinue; \
             if ($proc) {{ foreach ($t in $proc.Threads) {{ '    thread {{0}} {{1}} {{2}}' -f $t.Id, $t.ThreadState, $t.WaitReason }} }} \
           }} \
         }}",
        ids = ids.join(",")
    );
    let mut report = match desktop::output(
        Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .creation_flags(CREATE_NO_WINDOW),
    ) {
        Ok(out) => format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
        Err(e) => format!("powershell did not run: {e}\n"),
    };
    for note in &tree.unopened {
        report.push_str(&format!("not examined: {note}\n"));
    }
    report
}

/// Append the text of `path` to `into`: a file's contents, or each file of a directory (one
/// level), or the reason there is nothing to show.
fn dump(path: &Path, into: &mut String) {
    if path.is_dir() {
        match std::fs::read_dir(path) {
            Ok(entries) => {
                let mut files: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
                files.sort();
                if files.is_empty() {
                    into.push_str("(empty directory)\n");
                }
                for file in files {
                    let _ = writeln!(into, "-- {}", file.display());
                    dump(&file, into);
                }
            }
            Err(e) => {
                let _ = writeln!(into, "(cannot list: {e})");
            }
        }
        return;
    }
    match std::fs::read(path) {
        Ok(bytes) => {
            into.push_str(&String::from_utf8_lossy(&bytes));
            into.push('\n');
        }
        Err(e) => {
            let _ = writeln!(into, "(cannot read: {e})");
        }
    }
}
