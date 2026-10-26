//! What the SYSTEM account's credential store holds, read the way the spike read it (M5(e)): Task
//! Scheduler keeps a stored password under SYSTEM, and `cmdkey /list` shows it only to SYSTEM.
//! **CI only.**
//!
//! The including crate declares `desktop`.
#![allow(dead_code)]

use std::process::Command;

/// The output of `cmdkey /list` run as SYSTEM by a one-shot scheduled task. The wait is on the
/// task's own last result, which moves off "never run" (267011) when it has run, and on it being
/// ready again: real conditions of the task, re-checked.
pub fn cmdkey_list_as_system(tag: &str) -> String {
    let out_file = std::env::temp_dir().join(format!("sb-cmdkey-{tag}-{}.txt", std::process::id()));
    let _ = std::fs::remove_file(&out_file);
    let task = format!("sb-cmdkey-{tag}-{}", std::process::id());
    let script = format!(
        "$ErrorActionPreference = 'Stop'; \
         $action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c cmdkey /list > \"{out}\"'; \
         $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest; \
         Register-ScheduledTask -TaskName '{task}' -Action $action -Principal $principal | Out-Null; \
         try {{ \
           Start-ScheduledTask -TaskName '{task}'; \
           do {{ $info = Get-ScheduledTaskInfo -TaskName '{task}'; $state = (Get-ScheduledTask -TaskName '{task}').State }} \
           while ($info.LastTaskResult -eq 267011 -or $state -ne 'Ready') \
         }} finally {{ Unregister-ScheduledTask -TaskName '{task}' -Confirm:$false }}",
        out = out_file.display(),
    );
    let output =
        crate::desktop::output(Command::new("powershell").args(["-NoProfile", "-NonInteractive", "-Command", &script]))
            .expect("run powershell");
    assert!(
        output.status.success(),
        "reading the SYSTEM credential store failed:\n{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
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
