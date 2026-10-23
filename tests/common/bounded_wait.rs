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

use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::System::Threading::{GetExitCodeProcess, TerminateProcess, WaitForSingleObject};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// How long a child started as another account may take to exit. Generous: the slowest step seen
/// on a CI runner is creating a profile, at about a minute, and that is not part of a child's run.
pub const CHILD_EXIT_BOUND: Duration = Duration::from_secs(120);

/// Wait for `process` (process id `pid`, described as `what`) to exit and return its exit code.
///
/// On expiry of `bound` this prints what the child left behind (`evidence`: files, or the files
/// of a directory), the process tree under `pid` with each thread's wait reason, then kills that
/// tree, and panics naming `what`. Never waits again after the kill, so it cannot hang itself.
pub fn wait_for_exit(process: HANDLE, pid: u32, what: &str, bound: Duration, evidence: &[PathBuf]) -> u32 {
    let millis = u32::try_from(bound.as_millis()).expect("a bound shorter than INFINITE");
    // SAFETY: `process` is a live process handle owned by the caller.
    let rc = unsafe { WaitForSingleObject(process, millis) };
    if rc == WAIT_OBJECT_0 {
        let mut code = 0u32;
        // SAFETY: as above; `code` is a valid out-pointer.
        unsafe { GetExitCodeProcess(process, &mut code) }.expect("GetExitCodeProcess");
        return code;
    }
    assert_eq!(rc, WAIT_TIMEOUT, "waiting for {what} (pid {pid}) failed: {rc:?}");

    let mut report = format!("{what} (pid {pid}) did not exit within {bound:?}.\n\nprocess tree:\n");
    report.push_str(&process_tree(pid));
    for path in evidence {
        report.push_str(&format!("\nevidence {}:\n", path.display()));
        dump(path, &mut report);
    }
    let killed = kill_tree(pid);
    // The kill is by id; the handle is a second way to end the root if the first one failed.
    // SAFETY: as above.
    let _ = unsafe { TerminateProcess(process, 1) };
    panic!("{report}\ntaskkill: {killed}");
}

/// Every process under `root` (itself included) with its command line, and each one's threads
/// with their state and wait reason: what a hung tree is blocked on.
fn process_tree(root: u32) -> String {
    let script = format!(
        "$all = @(Get-CimInstance Win32_Process); \
         $tree = @{{}}; $tree[[int]{root}] = $true; \
         do {{ $n = $tree.Count; \
           foreach ($p in $all) {{ if ($tree.ContainsKey([int]$p.ParentProcessId)) {{ $tree[[int]$p.ProcessId] = $true }} }} \
         }} while ($tree.Count -ne $n); \
         foreach ($p in $all) {{ if ($tree.ContainsKey([int]$p.ProcessId)) {{ \
           '{{0}} parent={{1}} {{2}}: {{3}}' -f $p.ProcessId, $p.ParentProcessId, $p.Name, $p.CommandLine; \
           $proc = Get-Process -Id $p.ProcessId -ErrorAction SilentlyContinue; \
           if ($proc) {{ foreach ($t in $proc.Threads) {{ '    thread {{0}} {{1}} {{2}}' -f $t.Id, $t.ThreadState, $t.WaitReason }} }} \
         }} }}"
    );
    match Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
    {
        Ok(out) => format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
        Err(e) => format!("powershell did not run: {e}\n"),
    }
}

/// `taskkill /T /F` on the tree under `pid`: only the process this test started and its
/// descendants. Returns what it printed.
fn kill_tree(pid: u32) -> String {
    match Command::new("taskkill")
        .args(["/T", "/F", "/PID", &pid.to_string()])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
    {
        Ok(out) => format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout).trim(),
            String::from_utf8_lossy(&out.stderr).trim()
        ),
        Err(e) => format!("taskkill did not run: {e}"),
    }
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
