//! Task Scheduler instances of a task, seen from outside. **CI only.**
#![allow(dead_code)]

use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize,
};
use windows::Win32::System::TaskScheduler::{ITaskService, TaskScheduler};
use windows::Win32::System::Threading::{INFINITE, OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject};
use windows::Win32::System::Variant::VARIANT;
use windows::core::BSTR;

use ssh_broker::winutil::OwnedHandle;

/// Block until the task `name` has no running instance. `Run` on a task whose instance is still
/// listed is dropped by `IgnoreNew` without an error, so a test that wants a fresh run must wait
/// for the last one to be gone from the service, not only for its process.
///
/// Each pass waits on the exit of the instances' processes; an instance with no process yet is
/// looked at again at once. Both are the service's own state, so there is no time limit.
pub fn wait_until_none(name: &str) {
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
                let instance = instances
                    .get_Item(&VARIANT::from(index))
                    .expect("read a running instance");
                let pid = instance.EnginePID().expect("read the process of an instance");
                if pid == 0 {
                    continue;
                }
                // A process that cannot be opened is already gone.
                if let Ok(process) = OpenProcess(PROCESS_SYNCHRONIZE, false, pid) {
                    let process = OwnedHandle(process);
                    WaitForSingleObject(process.0, INFINITE); // sleep-ok: the exit of the instance's own process, re-checked against the service's list by the loop
                }
            }
        }
        CoUninitialize();
    }
}
