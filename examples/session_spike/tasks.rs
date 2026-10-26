//! Task Scheduler through COM, for M5 (`auto-login`).

use std::path::Path;

use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx};
use windows::Win32::System::TaskScheduler::{
    IRegisteredTask, IRunningTask, ITaskService, TASK_CREATE_OR_UPDATE, TASK_LOGON_PASSWORD,
    TASK_LOGON_SERVICE_ACCOUNT, TaskScheduler,
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

/// What starts the task. The product's is [`Trigger::Boot`]; the others exist to find out whether
/// the trigger is what a standard user's registration is refused for.
#[derive(Clone, Copy)]
pub enum Trigger {
    Boot,
    Logon,
    /// No trigger: the task runs only on demand.
    None,
}

/// A task that runs `exe args` as `user_text` with the password logon type and the
/// least-privilege run level.
fn password_xml(user_text: &str, exe: &Path, args: &str, trigger: Trigger) -> String {
    let triggers = match trigger {
        Trigger::Boot => "<Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers>".to_owned(),
        Trigger::Logon => format!(
            "<Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{}</UserId></LogonTrigger></Triggers>",
            escape(user_text)
        ),
        Trigger::None => String::new(),
    };
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>session spike (throwaway)</Description></RegistrationInfo>
  {triggers}
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

/// The SYSTEM task. The first version named `<LogonType>ServiceAccount</LogonType>` and Task
/// Scheduler refused it (`0x80041318`, line 3 column 91): that is a `TASK_LOGON_TYPE` name of the
/// COM API, not a value of the XML schema's `LogonType` (`InteractiveToken`, `Password`, `S4U`,
/// `InteractiveTokenOrPassword`). A SYSTEM principal in XML is `UserId` plus `RunLevel` only, the
/// shape `schtasks /Create /RU SYSTEM` writes; the COM call's `TASK_LOGON_SERVICE_ACCOUNT` carries
/// the logon type.
fn system_xml(exe: &Path, args: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled></Settings>
  <Actions Context="Author"><Exec><Command>{exe}</Command><Arguments>{args}</Arguments></Exec></Actions>
</Task>"#,
        exe = escape(&exe.to_string_lossy()),
        args = escape(args)
    )
}

/// The ways to name the account: the SID, the qualified name (`MACHINE\user`), the bare name.
const FORMS: [&str; 3] = ["sid", "qualified", "bare"];

pub struct Spec<'a> {
    pub name: &'a str,
    pub qualified_name: &'a str,
    pub bare_name: &'a str,
    pub sid: &'a str,
    pub password: &'a str,
    pub exe: &'a Path,
    pub args: &'a str,
    pub sddl: Option<&'a str>,
    pub trigger: Trigger,
    /// `false`: the XML names the account in each of the three forms and the call's `userId`
    /// argument is the qualified name. `true`: every form in the XML with every form as the
    /// argument (nine registrations at most).
    pub sweep_names: bool,
}

/// Register the task, trying ways of naming the account until one is accepted. `Ok` carries the
/// combination that worked; `Err` every combination with its error, as `(combination, error)`.
pub fn register_password_task(spec: &Spec) -> Result<String, Vec<(String, String)>> {
    let mut failures = Vec::new();
    for (xml_form, xml_user) in FORMS.iter().zip([spec.sid, spec.qualified_name, spec.bare_name]) {
        let argument_forms: &[(&str, &str)] = if spec.sweep_names {
            &[
                (FORMS[0], spec.sid),
                (FORMS[1], spec.qualified_name),
                (FORMS[2], spec.bare_name),
            ]
        } else {
            &[(FORMS[1], spec.qualified_name)]
        };
        for (argument_form, argument_user) in argument_forms {
            let xml = password_xml(xml_user, spec.exe, spec.args, spec.trigger);
            let combination = format!("XML UserId as {xml_form}, userId argument as {argument_form}");
            let registered = (|| -> windows::core::Result<()> {
                // SAFETY: as in `service`.
                unsafe {
                    service()?.GetFolder(&BSTR::from("\\"))?.RegisterTask(
                        &BSTR::from(spec.name),
                        &BSTR::from(xml.as_str()),
                        TASK_CREATE_OR_UPDATE.0,
                        &VARIANT::from(*argument_user),
                        &VARIANT::from(spec.password),
                        TASK_LOGON_PASSWORD,
                        &spec.sddl.map_or_else(VARIANT::default, VARIANT::from),
                    )?;
                }
                Ok(())
            })();
            match registered {
                Ok(()) => return Ok(combination),
                Err(e) => failures.push((combination, describe(&e))),
            }
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

/// Start the task now. The instance it returns is what a wait looks at.
pub fn run(name: &str) -> windows::core::Result<IRunningTask> {
    // SAFETY: as in `service`.
    unsafe { task(name)?.Run(&VARIANT::default()) }
}

/// The state of a running instance (2 Queued, 3 Ready, 4 Running). An error means it is gone.
pub fn instance_state(instance: &IRunningTask) -> windows::core::Result<i32> {
    // SAFETY: as in `service`.
    unsafe { instance.State() }.map(|s| s.0)
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
