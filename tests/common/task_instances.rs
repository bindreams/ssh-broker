//! Task Scheduler instances of a task, seen from outside. **CI only.**
#![allow(dead_code)]

use std::time::Duration;
use windows::Win32::Foundation::WAIT_TIMEOUT;
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize,
};
use windows::Win32::System::TaskScheduler::{ITaskService, TaskScheduler};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject};
use windows::Win32::System::Variant::VARIANT;
use windows::core::{BSTR, HRESULT};

use ssh_broker::winutil::OwnedHandle;

/// `SCHED_E_TASK_NOT_RUNNING`: the instance was listed and has ended since. That is the condition
/// this module waits for, not an error.
const TASK_NOT_RUNNING: HRESULT = HRESULT(0x8004_130Bu32 as i32);

/// Block until the task `name` has no running instance. `Run` on a task whose instance is still
/// listed is dropped by `IgnoreNew` without an error, so a test that wants a fresh run must wait
/// for the last one to be gone from the service, not only for its process.
///
/// Each pass waits on the exit of the instances' processes; an instance with no process yet is
/// looked at again at once. An instance that has ended since it was listed
/// (`SCHED_E_TASK_NOT_RUNNING`) is the condition being waited for. The exit of an instance's process
/// is an external event that may never come, so each such wait has the failure bound `bound`, and
/// its expiry fails the test naming the task and the process.
pub fn wait_until_none(name: &str, bound: Duration) {
    let millis = u32::try_from(bound.as_millis()).expect("a bound shorter than INFINITE");
    // SAFETY: COM is initialised for this call and released before it returns; the interfaces are
    // used on this thread only.
    unsafe {
        CoInitializeEx(None, COINIT_MULTITHREADED).ok().expect("initialise COM");
        let service: ITaskService =
            CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER).expect("create the Task Scheduler service");
        let none = VARIANT::default();
        service
            .Connect(&none, &none, &none, &none)
            .expect("connect to the Task Scheduler service");
        let task = service
            .GetFolder(&BSTR::from("\\"))
            .expect("open the root task folder")
            .GetTask(&BSTR::from(name))
            .unwrap_or_else(|e| panic!("look up the task {name}: {e}"));
        loop {
            let instances = task.GetInstances(0).expect("list the running instances");
            let count = instances.Count().expect("count the running instances");
            if count == 0 {
                break;
            }
            for index in 1..=count {
                let instance = match instances.get_Item(&VARIANT::from(index)) {
                    Ok(instance) => instance,
                    Err(e) if e.code() == TASK_NOT_RUNNING => continue,
                    Err(e) => panic!("read a running instance of {name}: {e}"),
                };
                let pid = match instance.EnginePID() {
                    Ok(pid) => pid,
                    Err(e) if e.code() == TASK_NOT_RUNNING => continue,
                    Err(e) => panic!("read the process of an instance of {name}: {e}"),
                };
                if pid == 0 {
                    continue;
                }
                // A process that cannot be opened is already gone.
                if let Ok(process) = OpenProcess(PROCESS_SYNCHRONIZE, false, pid) {
                    let process = OwnedHandle(process);
                    let rc = WaitForSingleObject(process.0, millis); // sleep-ok: failure bound on the exit of the instance's own process, an external event; expiry fails the test and is not read as state
                    assert_ne!(
                        rc, WAIT_TIMEOUT,
                        "an instance of the task {name} (process {pid}) was still running after {bound:?}"
                    );
                }
            }
        }
        CoUninitialize();
    }
}
