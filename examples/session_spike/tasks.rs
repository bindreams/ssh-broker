//! Task Scheduler through COM, for M5 (`auto-login`).

use std::path::Path;

use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx};
use windows::Win32::System::TaskScheduler::{
    IRegisteredTask, ITaskService, TASK_CREATE_OR_UPDATE, TASK_LOGON_PASSWORD, TASK_LOGON_SERVICE_ACCOUNT,
    TaskScheduler,
};
use windows::Win32::System::Variant::VARIANT;
use windows::core::BSTR;

use crate::win::describe;

/// COM for this thread, for the life of the process.
pub fn init_com() {
    // SAFETY: a null reserved pointer is the documented argument; S_FALSE (already initialised) is fine.
    let _ = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
}

fn service() -> windows::core::Result<ITaskService> {
    init_com();
    // SAFETY: COM is initialised on this thread.
    unsafe {
        let service: ITaskService = CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER)?;
        let none = VARIANT::default();
        service.Connect(&none, &none, &none, &none)?;
        Ok(service)
    }
}

fn task(name: &str) -> windows::core::Result<IRegisteredTask> {
    // SAFETY: as in `service`.
    unsafe { service()?.GetFolder(&BSTR::from("\\"))?.GetTask(&BSTR::from(name)) }
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// A boot-trigger task that runs `exe args` as `user_text` with the password logon type and the
/// least-privilege run level.
fn password_xml(user_text: &str, exe: &Path, args: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>session spike (throwaway)</Description></RegistrationInfo>
  <Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>{user}</UserId><LogonType>Password</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author"><Exec><Command>{exe}</Command><Arguments>{args}</Arguments></Exec></Actions>
</Task>"#,
        user = escape(user_text),
        exe = escape(&exe.to_string_lossy()),
        args = escape(args)
    )
}

fn system_xml(exe: &Path, args: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><LogonType>ServiceAccount</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled></Settings>
  <Actions Context="Author"><Exec><Command>{exe}</Command><Arguments>{args}</Arguments></Exec></Actions>
</Task>"#,
        exe = escape(&exe.to_string_lossy()),
        args = escape(args)
    )
}

/// Which text the XML names the account with: the SID, the qualified name, or the bare name.
pub const USER_TEXT_VARIANTS: usize = 3;

pub struct Spec<'a> {
    pub name: &'a str,
    pub qualified_name: &'a str,
    pub bare_name: &'a str,
    pub sid: &'a str,
    pub password: &'a str,
    pub exe: &'a Path,
    pub args: &'a str,
    pub sddl: Option<&'a str>,
}

/// Register the task, trying each way of naming the account in the XML until one is accepted.
/// `Ok` carries the variant that worked; `Err` every failure.
pub fn register_password_task(spec: &Spec) -> Result<usize, Vec<String>> {
    let mut failures = Vec::new();
    for variant in 0..USER_TEXT_VARIANTS {
        let user_text = match variant {
            0 => spec.sid,
            1 => spec.qualified_name,
            _ => spec.bare_name,
        };
        let xml = password_xml(user_text, spec.exe, spec.args);
        let registered = (|| -> windows::core::Result<()> {
            // SAFETY: as in `service`.
            unsafe {
                service()?.GetFolder(&BSTR::from("\\"))?.RegisterTask(
                    &BSTR::from(spec.name),
                    &BSTR::from(xml.as_str()),
                    TASK_CREATE_OR_UPDATE.0,
                    &VARIANT::from(spec.qualified_name),
                    &VARIANT::from(spec.password),
                    TASK_LOGON_PASSWORD,
                    &spec.sddl.map_or_else(VARIANT::default, VARIANT::from),
                )?;
            }
            Ok(())
        })();
        match registered {
            Ok(()) => return Ok(variant),
            Err(e) => failures.push(format!(
                "account named in the XML by variant {variant}: {}",
                describe(&e)
            )),
        }
    }
    Err(failures)
}

/// A task that runs `exe args` once on demand as SYSTEM.
pub fn register_system_task(name: &str, exe: &Path, args: &str) -> windows::core::Result<()> {
    // SAFETY: as in `service`.
    unsafe {
        service()?.GetFolder(&BSTR::from("\\"))?.RegisterTask(
            &BSTR::from(name),
            &BSTR::from(system_xml(exe, args).as_str()),
            TASK_CREATE_OR_UPDATE.0,
            &VARIANT::from("SYSTEM"),
            &VARIANT::default(),
            TASK_LOGON_SERVICE_ACCOUNT,
            &VARIANT::default(),
        )?;
    }
    Ok(())
}

pub fn run(name: &str) -> windows::core::Result<()> {
    // SAFETY: as in `service`.
    unsafe { task(name)?.Run(&VARIANT::default()) }.map(drop)
}

/// The task's state (3 Ready, 4 Running) and its last result (an HRESULT).
pub fn state_and_result(name: &str) -> windows::core::Result<(i32, i32)> {
    let task = task(name)?;
    // SAFETY: as in `service`.
    unsafe { Ok((task.State()?.0, task.LastTaskResult()?)) }
}

/// The task's DACL as SDDL.
pub fn sddl(name: &str) -> windows::core::Result<String> {
    // SAFETY: as in `service`. 4 is DACL_SECURITY_INFORMATION.
    unsafe { task(name)?.GetSecurityDescriptor(4) }.map(|s| s.to_string())
}

pub fn delete(name: &str) -> windows::core::Result<()> {
    // SAFETY: as in `service`.
    unsafe {
        service()?
            .GetFolder(&BSTR::from("\\"))?
            .DeleteTask(&BSTR::from(name), 0)
    }
}
