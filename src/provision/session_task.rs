//! provision::session_task — the auto-login task: its definition, its read-back, its `verify` row.
//!
//! `auto-login on` registers, for one account, a task that starts `agent --background` at boot with
//! the account's password stored in Task Scheduler's credential store, so nobody types it after a
//! restart. Everything here is pure: the COM calls are in `taskscheduler`, the flow in `autologin`.
//!
//! The definition is the security-relevant part. The task runs the installed exe with a stored
//! credential, so anyone who can edit the task can run code as that user: the DACL must grant
//! write, delete, change-permissions and take-ownership to SYSTEM and Administrators only, and
//! the read-back compares what the service holds with what was asked, by facts and not by text.

use super::report::Check;
use super::schtasks::{settings_xml, xml_escape};

/// Every auto-login task is named with this prefix and the account's SID.
pub const TASK_PREFIX: &str = "ssh-broker-session-";

pub fn task_name(sid: &str) -> String {
    format!("{TASK_PREFIX}{sid}")
}

/// The arguments the task passes: the same flags the prompt path's logon passes, minus the ready
/// event (nobody waits for a boot task).
fn arguments(sid: &str) -> String {
    format!("agent --background --expect-user {sid}")
}

/// The descriptor requested for the task: SYSTEM and Administrators full control, the account read
/// and execute. The service adds inherited entries of its own; see [`task_problem`].
pub fn requested_sddl(sid: &str) -> String {
    format!("D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;{sid})")
}

/// The task definition: a boot trigger, the account by SID with a stored password
/// (`LogonType Password`), the plain token (`LeastPrivilege`: elevation would re-arm
/// RedirectionGuard), and `exe agent --background --expect-user <sid>`. One agent per user.
pub fn task_xml(exe: &str, sid: &str) -> String {
    let exe = xml_escape(exe);
    let sid = xml_escape(sid);
    let arguments = arguments(&sid);
    let settings = settings_xml("IgnoreNew");
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>ssh-broker background session for {sid}, started at boot</Description></RegistrationInfo>
  <Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers>
  <Principals><Principal id="User">
    <UserId>{sid}</UserId>
    <LogonType>Password</LogonType>
    <RunLevel>LeastPrivilege</RunLevel>
  </Principal></Principals>
{settings}
  <Actions Context="User"><Exec>
    <Command>{exe}</Command>
    <Arguments>{arguments}</Arguments>
  </Exec></Actions>
</Task>
"#
    )
}

/// What the service holds for a registered task.
pub struct TaskState {
    pub xml: String,
    /// The task's DACL as SDDL.
    pub sddl: String,
    /// `LastTaskResult`.
    pub last_result: u32,
}

/// `xml` without whitespace, lower-cased: the service re-serialises what it is given.
fn squeeze(xml: &str) -> String {
    xml.chars()
        .filter(|c| !c.is_ascii_whitespace())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// The contents of `<tag>…</tag>` in squeezed XML, for each occurrence.
fn elements<'a>(squeezed: &'a str, tag: &str) -> Vec<&'a str> {
    let (open, close) = (format!("<{tag}>"), format!("</{tag}>"));
    let mut found = Vec::new();
    let mut rest = squeezed;
    while let Some(start) = rest.find(&open) {
        let body = &rest[start + open.len()..];
        let Some(end) = body.find(&close) else { break };
        found.push(&body[..end]);
        rest = &body[end + close.len()..];
    }
    found
}

/// The inside of the `Triggers` element of squeezed XML.
fn triggers_of(squeezed: &str) -> &str {
    let Some(start) = squeezed.find("<triggers>") else {
        return "";
    };
    let triggers = &squeezed[start + "<triggers>".len()..];
    triggers.find("</triggers>").map_or(triggers, |end| &triggers[..end])
}

/// The names of the triggers in squeezed XML (`boottrigger`, `logontrigger`, ...).
fn trigger_names(squeezed: &str) -> Vec<String> {
    let triggers = triggers_of(squeezed);
    let mut names = Vec::new();
    let mut rest = triggers;
    while let Some(open) = rest.find('<') {
        let tag = &rest[open + 1..];
        let end = tag.find(['>', '/']).unwrap_or(tag.len());
        let name = &tag[..end];
        if name.ends_with("trigger") {
            names.push(name.to_string());
            // Skip to the end of this trigger so its children are not read as triggers.
            let closing = format!("</{name}>");
            rest = tag.find(&closing).map_or(&tag[end..], |at| &tag[at + closing.len()..]);
        } else {
            rest = &tag[end..];
        }
    }
    names
}

/// The `Settings` element of squeezed XML.
fn settings_of(squeezed: &str) -> &str {
    let Some(start) = squeezed.find("<settings>") else {
        return "";
    };
    let settings = &squeezed[start..];
    settings.find("</settings>").map_or(settings, |end| &settings[..end])
}

/// The rights mask of an SDDL rights field, or `None` if it holds something this cannot read.
fn rights_mask(rights: &str) -> Option<u32> {
    if let Some(hex) = rights.strip_prefix("0x") {
        return u32::from_str_radix(hex, 16).ok();
    }
    let mut mask = 0u32;
    let mut rest = rights;
    while !rest.is_empty() {
        let (alias, tail) = rest.split_at_checked(2)?;
        mask |= match alias {
            "GA" => 0x1000_0000,
            "GX" => 0x2000_0000,
            "GW" => 0x4000_0000,
            "GR" => 0x8000_0000,
            "FA" => 0x001f_01ff,
            "FR" => 0x0012_0089,
            "FW" => 0x0012_0116,
            "FX" => 0x0012_00a0,
            "RC" => 0x0002_0000,
            "SD" => 0x0001_0000,
            "WD" => 0x0004_0000,
            "WO" => 0x0008_0000,
            _ => return None,
        };
        rest = tail;
    }
    Some(mask)
}

/// Rights that let a principal change what the task does: write the file's data, attributes or
/// extended attributes, delete it or its children, change its permissions or take its ownership,
/// or any generic right that implies one.
const CHANGES_THE_TASK: u32 = 0x0000_0002
    | 0x0000_0004
    | 0x0000_0010
    | 0x0000_0040
    | 0x0000_0100
    | 0x0001_0000
    | 0x0004_0000
    | 0x0008_0000
    | 0x1000_0000
    | 0x4000_0000;

/// What is wrong with a task DACL, if anything: an allow entry for a principal other than SYSTEM
/// and Administrators that grants a right to change the task, or a descriptor this cannot read.
/// The service adds inherited full-control entries for SYSTEM and Administrators and read for the
/// account, so the judgement is by principal and rights, not by string.
fn dacl_problem(sddl: &str) -> Option<String> {
    let Some(start) = sddl.find("D:") else {
        return Some("the task has no DACL".to_string());
    };
    let dacl = &sddl[start + 2..];
    let dacl = dacl.find("S:").map_or(dacl, |end| &dacl[..end]);
    for ace in dacl.split('(').skip(1) {
        let ace = ace.trim_end_matches(')');
        let fields: Vec<&str> = ace.split(';').collect();
        let [kind, _flags, rights, _object, _inherit, trustee] = fields[..] else {
            return Some(format!("cannot read the DACL entry ({ace})"));
        };
        if kind != "A" {
            continue;
        }
        let Some(mask) = rights_mask(rights) else {
            return Some(format!("cannot read the rights {rights:?} in the DACL entry ({ace})"));
        };
        let trusted = matches!(trustee, "SY" | "BA" | "S-1-5-18" | "S-1-5-32-544");
        if !trusted && mask & CHANGES_THE_TASK != 0 {
            return Some(format!(
                "the DACL lets {trustee} change the task (rights {rights}); only SYSTEM and Administrators may"
            ));
        }
    }
    None
}

/// What differs between the task the service holds and the one `task_xml(exe, sid)` asks for, or
/// `None`: principal SID, password logon type, least-privilege run level, exactly the boot trigger,
/// exactly the action, the settings that are not defaults, enabled, and the DACL.
pub fn task_problem(state: &TaskState, exe: &str, sid: &str) -> Option<String> {
    let xml = squeeze(&state.xml);
    let users = elements(&xml, "userid");
    if users != [sid.to_ascii_lowercase()] {
        return Some(format!("principal: expected only {sid}, found {users:?}"));
    }
    if elements(&xml, "logontype") != ["password"] {
        return Some("logon type: expected a stored password (Password)".to_string());
    }
    if elements(&xml, "runlevel")
        .iter()
        .any(|level| *level != "leastprivilege")
    {
        return Some("run level: expected the plain token (LeastPrivilege)".to_string());
    }
    let triggers = trigger_names(&xml);
    if triggers != ["boottrigger"] {
        return Some(format!("trigger: expected only a boot trigger, found {triggers:?}"));
    }
    if ["false", "0"]
        .iter()
        .any(|value| triggers_of(&xml).contains(&format!("<enabled>{value}</enabled>")))
    {
        return Some("trigger: the boot trigger is disabled, so the task never starts at boot".to_string());
    }
    let commands = elements(&xml, "command");
    let expected_exe = squeeze(&xml_escape(exe));
    if commands != [expected_exe.as_str()] {
        return Some(format!("action: expected to run only {exe}, found {commands:?}"));
    }
    let expected_arguments = squeeze(&xml_escape(&arguments(sid)));
    if elements(&xml, "arguments") != [expected_arguments.as_str()] {
        return Some(format!("action: expected the arguments {:?}", arguments(sid)));
    }
    if xml.matches("<exec>").count() != 1 {
        return Some("action: expected exactly one command".to_string());
    }
    let settings = settings_of(&xml);
    for flag in ["disallowstartifonbatteries", "stopifgoingonbatteries"] {
        if !settings.contains(&format!("<{flag}>false</{flag}>")) {
            return Some(format!("settings: {flag} must be false (the default is true)"));
        }
    }
    if !(settings.is_empty() || settings.contains("<multipleinstancespolicy>ignorenew</multipleinstancespolicy>"))
        && settings.contains("<multipleinstancespolicy>")
    {
        return Some("settings: expected one agent per user (IgnoreNew)".to_string());
    }
    if ["false", "0"]
        .iter()
        .any(|value| settings.contains(&format!("<enabled>{value}</enabled>")))
    {
        return Some("settings: the task is disabled".to_string());
    }
    dacl_problem(&state.sddl).map(|problem| format!("permissions: {problem}"))
}

/// `LastTaskResult` values that are not a failure: success, running, never run.
fn last_result_is_fine(code: u32) -> bool {
    matches!(code, 0x0000_0000 | 0x0004_1301 | 0x0004_1303)
}

/// The `auto-login task` row of `verify`: `state` is the query of this account's task (`Ok(None)`
/// for none, the cause if it could not be answered).
///
/// The row checks the definition and reports the last result. It says plainly that a failed logon
/// is not recorded there: after the stored password goes stale, or the batch right is missing, the
/// next run fails to log on and `LastTaskResult` keeps the previous run's value (spike M5(g)).
pub fn task_row(state: &anyhow::Result<Option<TaskState>>, exe: &str, sid: &str) -> Check {
    const NAME: &str = "auto-login task";
    let state = match state {
        Ok(Some(state)) => state,
        Ok(None) => return Check::new(NAME, true, "not registered: auto-login is off"),
        Err(e) => return Check::new(NAME, false, format!("could not query the task: {e:#}")),
    };
    if let Some(problem) = task_problem(state, exe, sid) {
        return Check::new(
            NAME,
            false,
            format!("the registered task differs from what auto-login on makes: {problem}"),
        );
    }
    if !last_result_is_fine(state.last_result) {
        return Check::new(
            NAME,
            false,
            format!(
                "last result {:#010x}: the task did not run to a success",
                state.last_result
            ),
        );
    }
    Check::new(
        NAME,
        true,
        format!(
            "registered; last result {:#010x}; a failed logon is not recorded there: a stale password or a missing \
             \"Log on as a batch job\" right shows only as a session that did not start",
            state.last_result
        ),
    )
}

#[cfg(test)]
#[path = "session_task_tests.rs"]
mod session_task_tests;
