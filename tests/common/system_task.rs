//! What the SYSTEM account's credential store holds, read the way the spike read it (M5(e)): Task
//! Scheduler keeps a stored password under SYSTEM, and `cmdkey /list` shows it only to SYSTEM.
//! **CI only.**
//!
//! The including crate declares `desktop` and `stand_in`.
#![allow(dead_code)]

use std::process::Command;

/// How long the task may take to run `cmdkey` once started. Task Scheduler running it is an external
/// event; expiry fails the test and names the task.
const TASK_RUN_BOUND: std::time::Duration = std::time::Duration::from_secs(180);

/// Removes the one-shot task when the read is over, also when it panics.
struct Task(String);

impl Drop for Task {
    fn drop(&mut self) {
        let script = format!(
            "Unregister-ScheduledTask -TaskName '{}' -Confirm:$false -ErrorAction SilentlyContinue",
            self.0
        );
        let _ = crate::desktop::output(Command::new("powershell").args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &script,
        ]));
    }
}

/// The output of `cmdkey /list` run as SYSTEM by a one-shot scheduled task. The task writes the
/// listing beside the result file and renames it into place, so the result file existing is the task's
/// end; the wait is on that file and queries nothing about the task (a query can miss it).
pub fn cmdkey_list_as_system(tag: &str) -> String {
    let out_file = std::env::temp_dir().join(format!("sb-cmdkey-{tag}-{}.txt", std::process::id()));
    let part_file = out_file.with_extension("part");
    let _ = std::fs::remove_file(&out_file);
    let _ = std::fs::remove_file(&part_file);
    let task = Task(format!("sb-cmdkey-{tag}-{}", std::process::id()));
    let script = format!(
        "$ErrorActionPreference = 'Stop'; \
         $action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c cmdkey /list > \"{part}\" & move /y \"{part}\" \"{out}\"'; \
         $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest; \
         Register-ScheduledTask -TaskName '{task}' -Action $action -Principal $principal | Out-Null; \
         Start-ScheduledTask -TaskName '{task}'",
        part = part_file.display(),
        out = out_file.display(),
        task = task.0,
    );
    let output =
        crate::desktop::output(Command::new("powershell").args(["-NoProfile", "-NonInteractive", "-Command", &script]))
            .expect("run powershell");
    assert!(
        output.status.success(),
        "starting the SYSTEM task that reads the credential store failed:\n{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    crate::stand_in::file_signal::wait_for_file(
        &out_file,
        None,
        Some(TASK_RUN_BOUND),
        &format!("the scheduled task {} reading the SYSTEM credential store", task.0),
    );
    let text = std::fs::read_to_string(&out_file).unwrap_or_else(|e| panic!("cmdkey wrote no output ({e})"));
    let _ = std::fs::remove_file(&out_file);
    text
}

/// The `Task Scheduler` entries of `cmdkey /list` output whose user is `user`.
pub fn task_entries_for(listing: &str, user: &str) -> usize {
    let user = user.to_lowercase();
    let mut count = 0;
    let mut in_task_entry = false;
    for line in listing.lines() {
        let line = line.trim();
        if let Some(target) = line.strip_prefix("Target:") {
            in_task_entry = target.contains("TaskScheduler:Task:");
        } else if in_task_entry && let Some(entry_user) = line.strip_prefix("User:") {
            if entry_user.to_lowercase().contains(&user) {
                count += 1;
            }
            in_task_entry = false;
        }
    }
    count
}
