//! provision::taskscheduler — stop and start the agent task through the Task Scheduler API.
//!
//! The agent task has a group principal, so `schtasks /Run` cannot say whose agent to start: it
//! has no session or user argument. `IRegisteredTask::RunEx` with `TASK_RUN_USE_SESSION_ID`
//! starts the task "interactively as the user who is logged on to the specified session", which
//! is what `apply` needs to give each logged-on user an agent without waiting for their next
//! logon. And `schtasks /End` is the only CLI way to stop instances, which a migration needs
//! before it replaces the exe a running legacy agent holds open; COM does it without parsing text.
//!
//! Each call initialises COM on the calling thread and uninitialises it before returning, so the
//! caller needs no COM state and must be a plain thread (not one already in another COM mode).

use anyhow::Context;
use windows::Win32::Foundation::ERROR_FILE_NOT_FOUND;
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize,
};
use windows::Win32::System::TaskScheduler::{IRegisteredTask, ITaskService, TASK_RUN_USE_SESSION_ID, TaskScheduler};
use windows::Win32::System::Variant::VARIANT;
use windows::core::{BSTR, HRESULT};

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

/// Stop every running instance of `task_name`. A task that does not exist, or has no running
/// instance, is not an error: there is nothing to stop.
pub fn stop_instances(task_name: &str) -> anyhow::Result<()> {
    let _com = Com::init()?;
    let service = connect()?;
    let Some(task) = registered_task(&service, task_name)? else {
        return Ok(());
    };
    // SAFETY: `task` is a live interface on this thread; `Stop` takes no pointers.
    match unsafe { task.Stop(0) } {
        Ok(()) => Ok(()),
        Err(e) if e.code() == SCHED_E_TASK_NOT_RUNNING => Ok(()),
        Err(e) => Err(e).with_context(|| format!("stop the running instances of {task_name}")),
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

#[cfg(test)]
#[path = "taskscheduler_tests.rs"]
mod taskscheduler_tests;
