//! provision::sshd_task::system — the Task Scheduler and the report file behind [`SshdTask`].

use std::path::{Path, PathBuf};

use anyhow::Context;

use super::{SshdTask, hand_over};
use crate::provision::handover::Say;
use crate::provision::layout::Layout;
use crate::provision::procwait::Role;
use crate::provision::schtasks::{INSTALL_SSHD_TASK, WaitOutcome, install_sshd_task_xml};
use crate::provision::taskscheduler;

/// The task's permissions: SYSTEM and Administrators full control, nobody else anything. The task runs code as
/// SYSTEM, so whoever can edit it can run code as SYSTEM.
const TASK_SDDL: &str = "D:P(A;;FA;;;SY)(A;;FA;;;BA)";

/// Where the production report is.
pub fn report_path() -> PathBuf {
    Layout::production().install_sshd_report_path()
}

/// The Task Scheduler's task, run from `exe`, with its report at `report`.
struct SystemTask<'a> {
    exe: &'a Path,
    report: &'a Path,
}

impl SshdTask for SystemTask<'_> {
    fn register(&mut self) -> anyhow::Result<()> {
        // What an earlier run reported is not this run's: a task that never ran must find no report.
        match std::fs::remove_file(self.report) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                return Err(e)
                    .with_context(|| format!("remove the report of an earlier run, {}", self.report.display()));
            }
            _ => {}
        }
        let exe = self.exe.to_string_lossy();
        taskscheduler::register_system_task(INSTALL_SSHD_TASK, &install_sshd_task_xml(&exe), TASK_SDDL)
    }

    fn run(&mut self) -> anyhow::Result<()> {
        taskscheduler::run_task(INSTALL_SSHD_TASK)
    }

    fn wait(&mut self) -> anyhow::Result<WaitOutcome> {
        taskscheduler::wait_for_instances(INSTALL_SSHD_TASK, self.exe, Role::InstallSshd, &mut || {})
    }

    fn report(&mut self) -> anyhow::Result<String> {
        let bytes = std::fs::read(self.report).with_context(|| format!("read {}", self.report.display()))?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    fn remove(&mut self) -> anyhow::Result<()> {
        taskscheduler::delete_task(INSTALL_SSHD_TASK).map(drop)
    }
}

/// Hand `install`'s sshd step to the task that runs `exe` (the installed one), and say what it did on `say`.
/// See [`hand_over`].
pub fn hand_over_sshd_step(layout: &Layout, exe: &Path, say: &mut Say<'_>) {
    let report = layout.install_sshd_report_path();
    hand_over(&mut SystemTask { exe, report: &report }, &report, exe, say);
}
