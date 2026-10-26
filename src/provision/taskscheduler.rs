//! provision::taskscheduler — stop and start the agent task through the Task Scheduler API.
//!
//! The agent task has a group principal, so `schtasks /Run` cannot say whose agent to start: it
//! has no session or user argument. `IRegisteredTask::RunEx` with `TASK_RUN_USE_SESSION_ID`
//! starts the task "interactively as the user who is logged on to the specified session", which
//! is what `apply` needs to give each logged-on user an agent without waiting for their next
//! logon. And `schtasks /End` is the only CLI way to stop instances, which a migration needs
//! before it replaces the exe a running legacy agent holds open; COM does it without parsing text.
//!
//! Stopping is more than `Stop`: the call returns before the processes are gone, so it also waits
//! for them (see [`procwait`]), looks again for an instance that was still starting, and disables
//! the task meanwhile so that no logon starts a fresh agent from the exe about to be replaced.
//!
//! Each call initialises COM on the calling thread and uninitialises it before returning, so the
//! caller needs no COM state and must be a plain thread (not one already in another COM mode).

use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::Context;
use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, S_FALSE, S_OK};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize,
};
use windows::Win32::System::TaskScheduler::{
    IRegisteredTask, ITaskService, TASK_CREATE_OR_UPDATE, TASK_LOGON_PASSWORD, TASK_RUN_USE_SESSION_ID, TaskScheduler,
};
use windows::Win32::System::Variant::VARIANT;
use windows::core::{BSTR, HRESULT, Interface};

use super::password_variant::PasswordVariant;
use super::procwait::{self, Process};
use super::session_task::TaskState;
use crate::password_entry::Password;

/// `SCHED_E_TASK_NOT_RUNNING`: `Stop` on a task with no running instance.
const SCHED_E_TASK_NOT_RUNNING: HRESULT = HRESULT(0x8004130Bu32 as i32);

/// COM initialised on this thread, released on drop.
struct Com;

impl Com {
    fn init() -> anyhow::Result<Com> {
        // SAFETY: a null reserved pointer is the documented argument. `S_FALSE` (already
        // initialised on this thread in this mode) still counts a reference that drop releases.
        unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }
            .ok()
            .context("initialise COM (the calling thread may already be in another COM mode)")?;
        Ok(Com)
    }
}

impl Drop for Com {
    fn drop(&mut self) {
        // SAFETY: balances the successful `CoInitializeEx` in `init`.
        unsafe { CoUninitialize() };
    }
}

/// A connection to the local Task Scheduler service. Must not outlive the [`Com`] it was made under.
fn connect() -> anyhow::Result<ITaskService> {
    // SAFETY: COM is initialised by the caller; the interfaces are used on this thread only.
    unsafe {
        let service: ITaskService = CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER)
            .context("create the Task Scheduler service")?;
        let none = VARIANT::default();
        service
            .Connect(&none, &none, &none, &none)
            .context("connect to the Task Scheduler service")?;
        Ok(service)
    }
}

/// The task named `name` in the root folder, or `None` if there is none.
fn registered_task(service: &ITaskService, name: &str) -> anyhow::Result<Option<IRegisteredTask>> {
    // SAFETY: as in `connect`.
    unsafe {
        let folder = service
            .GetFolder(&BSTR::from("\\"))
            .context("open the root task folder")?;
        match folder.GetTask(&BSTR::from(name)) {
            Ok(task) => Ok(Some(task)),
            Err(e) if e.code() == HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0) => Ok(None),
            Err(e) => Err(e).with_context(|| format!("look up the task {name}")),
        }
    }
}

/// The XML definition of the task `name`, or `None` if there is no such task. A query that could
/// not be answered (access denied, the service unreachable) is an error, never `None`.
pub fn task_xml(name: &str) -> anyhow::Result<Option<String>> {
    let _com = Com::init()?;
    let service = connect()?;
    let Some(task) = registered_task(&service, name)? else {
        return Ok(None);
    };
    // SAFETY: `task` is a live interface on this thread.
    let xml = unsafe { task.Xml() }.with_context(|| format!("read the definition of the task {name}"))?;
    Ok(Some(xml.to_string()))
}

/// Enable or disable the task `name`. A task that does not exist has nothing to change and is not
/// an error, as in [`stop_instances`].
pub fn set_enabled(name: &str, enabled: bool) -> anyhow::Result<()> {
    let _com = Com::init()?;
    let service = connect()?;
    let Some(task) = registered_task(&service, name)? else {
        return Ok(());
    };
    set_task_enabled(&task, name, enabled)
}

fn set_task_enabled(task: &IRegisteredTask, name: &str, enabled: bool) -> anyhow::Result<()> {
    // SAFETY: `task` is a live interface on this thread; `SetEnabled` takes a plain boolean.
    unsafe { task.SetEnabled(enabled.into()) }
        .with_context(|| format!("{} the task {name}", if enabled { "enable" } else { "disable" }))
}

/// Stop every running instance of `task_name` and return once the process of each has exited. A
/// task that does not exist, or has no running instance, is not an error: there is nothing to stop.
///
/// `image` is the exe the task runs. The task is left **disabled**, so that no logon can start an
/// agent from the old exe before the caller has replaced it; the caller enables it again with
/// [`set_enabled`] (registering the task afresh does so too).
///
/// A process that outlives [`procwait::EXIT_BOUND`] fails the stop with [`procwait::StillRunning`];
/// so does an instance the service still lists that long after the first `Stop`.
pub fn stop_instances(task_name: &str, image: &Path) -> anyhow::Result<()> {
    let _com = Com::init()?;
    let service = connect()?;
    let Some(task) = registered_task(&service, task_name)? else {
        return Ok(());
    };
    stop_and_wait(
        task_name,
        procwait::EXIT_BOUND,
        || set_task_enabled(&task, task_name, false),
        || running_instances(&task, image),
        // SAFETY: `task` is a live interface on this thread; `Stop` takes no pointers. The raw
        // vtable call keeps the HRESULT, which the generated wrapper turns into `Ok` for S_FALSE.
        || {
            stop_outcome(task_name, unsafe {
                (Interface::vtable(&task).Stop)(Interface::as_raw(&task), 0)
            })
        },
        |processes| procwait::wait_all_exited(&processes, procwait::EXIT_BOUND),
    )
}

/// The running instances of a task: how many there are, and the processes among them that are
/// the agent. An instance the engine has not launched yet has no process to show, and is still
/// an instance.
struct Instances<P> {
    count: usize,
    /// The process id of each instance, 0 for one the engine has not launched.
    pids: Vec<u32>,
    processes: Vec<P>,
}

/// The steps of a stop, in the only order that is safe. Disabled first, so the logon trigger cannot
/// start an agent from the old exe meanwhile; listed before each stop, because the instances are
/// gone afterwards; waited for before the next look, so the caller goes on only when every process
/// has exited.
///
/// The look is repeated until the task has no instance. An instance that was queued or starting
/// when `Stop` ran has no process yet, and the engine can launch it afterwards, so one stop is not
/// enough. This is a condition re-checked, not an attempt count: each pass is two calls to the
/// service, which cancels a starting instance when it is stopped. The service is an external party
/// that might keep listing an instance `Stop` cannot clear (a stale entry), so once `bound` has
/// passed since the first stop the look that still finds one fails, naming the task and the
/// instances; the caller's failure path enables the task again. A pass that waits for processes
/// blocks on their exit, so it does not spin; a pass with only unlaunched instances looks again
/// at once, bounded by the same failure bound.
fn stop_and_wait<P>(
    task_name: &str,
    bound: Duration,
    disable: impl FnOnce() -> anyhow::Result<()>,
    mut list: impl FnMut() -> anyhow::Result<Instances<P>>,
    mut stop: impl FnMut() -> anyhow::Result<()>,
    mut wait: impl FnMut(Vec<P>) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    disable()?;
    let mut first_stop = None;
    loop {
        let instances = list()?;
        if instances.count == 0 {
            return Ok(());
        }
        if first_stop.is_some_and(|first: Instant| first.elapsed() >= bound) {
            anyhow::bail!(
                "the task {task_name} still has {} running instance(s) after being stopped for {} s ({}); run apply again",
                instances.count,
                bound.as_secs(),
                describe_instances(&instances.pids)
            );
        }
        first_stop.get_or_insert_with(Instant::now);
        stop()?;
        wait(instances.processes)?;
    }
}

fn describe_instances(pids: &[u32]) -> String {
    let each: Vec<String> = pids
        .iter()
        .map(|pid| match pid {
            0 => "one not launched yet".to_string(),
            pid => format!("process {pid}"),
        })
        .collect();
    each.join(", ")
}

/// The running instances of `task`, and the processes among them that run `image`. An instance
/// whose process is gone, or is not `image`, has nothing to wait for.
fn running_instances(task: &IRegisteredTask, image: &Path) -> anyhow::Result<Instances<Process>> {
    // SAFETY: `task` and the interfaces taken from it are live and used on this thread only.
    unsafe {
        let instances = task.GetInstances(0).context("list the running instances")?;
        let count = instances.Count().context("count the running instances")?;
        let mut found = Vec::new();
        let mut pids = Vec::new();
        // The collection is indexed from 1.
        for index in 1..=count {
            let instance = instances
                .get_Item(&VARIANT::from(index))
                .with_context(|| format!("read running instance {index}"))?;
            let pid = instance.EnginePID().context("read the process of a running instance")?;
            pids.push(pid);
            if pid == 0 {
                continue;
            }
            found.extend(procwait::open_if_image(pid, image)?);
        }
        Ok(Instances {
            count: usize::try_from(count).unwrap_or(0),
            pids,
            processes: found,
        })
    }
}

/// What `Stop` returned. `S_FALSE` is a success code ("the user cannot successfully stop instances
/// of the task") and means nothing was stopped; only `S_OK`, or a task with nothing running, is
/// a stop.
fn stop_outcome(task_name: &str, code: HRESULT) -> anyhow::Result<()> {
    if code == S_OK || code == SCHED_E_TASK_NOT_RUNNING {
        Ok(())
    } else if code == S_FALSE {
        anyhow::bail!("the current user cannot stop the running instances of {task_name} (Stop returned S_FALSE)")
    } else if code.is_err() {
        Err(windows::core::Error::from(code)).with_context(|| format!("stop the running instances of {task_name}"))
    } else {
        anyhow::bail!(
            "stopping {task_name} returned the unexpected success code {:#010x}",
            code.0
        )
    }
}

/// Start `task_name` in the interactive session `session_id`, as the user logged on there.
pub fn run_in_session(task_name: &str, session_id: u32) -> anyhow::Result<()> {
    anyhow::ensure!(
        session_id != 0,
        "refusing to start {task_name} in session 0: nobody is logged on there, and an agent there \
         would have the limited environment this tool exists to avoid"
    );
    let session = i32::try_from(session_id).with_context(|| format!("session id {session_id} is out of range"))?;
    let _com = Com::init()?;
    let service = connect()?;
    let task = registered_task(&service, task_name)?
        .with_context(|| format!("the task {task_name} is not registered; run `apply` elevated"))?;
    // SAFETY: the variant and BSTR are empty values that outlive the call.
    unsafe { task.RunEx(&VARIANT::default(), TASK_RUN_USE_SESSION_ID.0, session, &BSTR::new()) }
        .with_context(|| format!("start {task_name} in session {session_id}"))?;
    Ok(())
}

/// Register (or replace) a task that runs as `account` (`MACHINE\user`) with the password stored in
/// Task Scheduler's credential store, from the definition `xml`, with the DACL `sddl`.
///
/// Task Scheduler refuses a wrong password here (`0x8007052e`, spike M5(c)) and a boot trigger to a
/// token that is not an elevated administrator's (`0x80070005`, M5(a)).
pub fn register_password_task(
    name: &str,
    xml: &str,
    account: &str,
    password: &Password,
    sddl: &str,
) -> anyhow::Result<()> {
    let _com = Com::init()?;
    let service = connect()?;
    let stored = PasswordVariant::new(password);
    // SAFETY: as in `connect`; every argument outlives the call.
    unsafe {
        service
            .GetFolder(&BSTR::from("\\"))
            .context("open the root task folder")?
            .RegisterTask(
                &BSTR::from(name),
                &BSTR::from(xml),
                TASK_CREATE_OR_UPDATE.0,
                &VARIANT::from(account),
                stored.variant(),
                TASK_LOGON_PASSWORD,
                &VARIANT::from(sddl),
            )
    }
    .with_context(|| format!("register the task {name} for {account}"))?;
    Ok(())
}

/// The auto-login tasks (`ssh-broker-session-*`) and whether each is enabled.
pub fn session_tasks() -> anyhow::Result<Vec<super::flow::SessionTask>> {
    let _com = Com::init()?;
    let service = connect()?;
    // SAFETY: as in `connect`; 1 is TASK_ENUM_HIDDEN, so hidden tasks are listed too.
    unsafe {
        let tasks = service
            .GetFolder(&BSTR::from("\\"))
            .context("open the root task folder")?
            .GetTasks(1)
            .context("list the tasks")?;
        let count = tasks.Count().context("count the tasks")?;
        let mut found = Vec::new();
        // The collection is indexed from 1.
        for index in 1..=count {
            let task = tasks
                .get_Item(&VARIANT::from(index))
                .with_context(|| format!("read task {index}"))?;
            let name = task.Name().context("read a task name")?.to_string();
            if name.starts_with(super::session_task::TASK_PREFIX) {
                let enabled = task
                    .Enabled()
                    .with_context(|| format!("read whether {name} is enabled"))?
                    .as_bool();
                found.push(super::flow::SessionTask { name, enabled });
            }
        }
        Ok(found)
    }
}

/// Delete the task `name`, which also deletes the credential stored for it (spike M5(e)). Whether
/// there was a task.
pub fn delete_task(name: &str) -> anyhow::Result<bool> {
    let _com = Com::init()?;
    let service = connect()?;
    // SAFETY: as in `connect`.
    let deleted = unsafe {
        service
            .GetFolder(&BSTR::from("\\"))
            .context("open the root task folder")?
            .DeleteTask(&BSTR::from(name), 0)
    };
    match deleted {
        Ok(()) => Ok(true),
        Err(e) if e.code() == HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0) => Ok(false),
        Err(e) => Err(e).with_context(|| format!("delete the task {name}")),
    }
}

/// What the service holds for the task `name`: its definition, its DACL and its last result. `None`
/// if there is no such task; a query that cannot be answered is an error.
pub fn task_state(name: &str) -> anyhow::Result<Option<TaskState>> {
    let _com = Com::init()?;
    let service = connect()?;
    let Some(task) = registered_task(&service, name)? else {
        return Ok(None);
    };
    // SAFETY: `task` is a live interface on this thread. 4 is DACL_SECURITY_INFORMATION.
    unsafe {
        Ok(Some(TaskState {
            xml: task
                .Xml()
                .with_context(|| format!("read the definition of the task {name}"))?
                .to_string(),
            sddl: task
                .GetSecurityDescriptor(4)
                .with_context(|| format!("read the permissions of the task {name}"))?
                .to_string(),
            last_result: task
                .LastTaskResult()
                .with_context(|| format!("read the last result of the task {name}"))? as u32,
        }))
    }
}

/// Start the task `name` now, without waiting for it.
pub fn run_task(name: &str) -> anyhow::Result<()> {
    let _com = Com::init()?;
    let service = connect()?;
    let task = registered_task(&service, name)?.with_context(|| format!("the task {name} is not registered"))?;
    // SAFETY: the variant is an empty value that outlives the call.
    unsafe { task.Run(&VARIANT::default()) }.with_context(|| format!("start the task {name}"))?;
    Ok(())
}

#[cfg(test)]
#[path = "taskscheduler_tests.rs"]
mod taskscheduler_tests;
