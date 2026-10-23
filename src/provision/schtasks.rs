//! provision::schtasks — Task Scheduler XML + argv builders and query parsers (pure).
//!
//! The agent task is registered from XML because the bare CLI cannot express its principal. It
//! runs for **any member of `BUILTIN\Users`** (`<GroupId>`), with a logon trigger that names no
//! user: the service starts one instance per interactive logon, in that user's session, as that
//! user, and registering it needs no password. A group principal is itself the interactive-session
//! form, so it carries no `<LogonType>`; this is the shape of the `Wininet\CacheTask` and
//! `MsCtfMonitor` tasks Windows ships. A bare `/SC ONLOGON /RU <user>`, `/RU SYSTEM`, or an S4U
//! principal would land in session 0 — silently reproducing the limited environment this project
//! exists to escape. `MultipleInstancesPolicy` is `Parallel`: `IgnoreNew` is documented without a
//! per-user qualifier, so it could drop the second user's agent while the first is running.
//! `RunLevel=LeastPrivilege` (not Highest) keeps the plain token: elevation would re-arm
//! RedirectionGuard (breaking symlink-traversal parity) and not match the folder ACL.

pub const AGENT_TASK: &str = "ssh-broker-agent";
pub const SELFHEAL_TASK: &str = "ssh-broker-apply";

/// `BUILTIN\Users`: every account that can log on interactively, administrators included.
pub const USERS_GROUP_SID: &str = "S-1-5-32-545";

/// Minimal XML escaping for the few characters that can appear in a path.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// The agent logon task definition: runs `<exe> agent` in the interactive session of whichever
/// user logs on. Names no account; `apply` registers it without a password.
pub fn agent_task_xml(exe: &str) -> String {
    let exe = xml_escape(exe);
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>ssh-broker relay agent, one per logged-on user</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
  <Principals><Principal id="Users">
    <GroupId>{USERS_GROUP_SID}</GroupId>
    <RunLevel>LeastPrivilege</RunLevel>
  </Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <!-- The project forbids arbitrary retry caps; this is a documented numeric bound that is
         not one (see CONTRIBUTING.md's invariants). The Task Scheduler schema requires a Count
         with RestartOnFailure and has no unbounded form.
         A failure outlasting these attempts is covered at the next boot or logon, by the
         ONSTART self-heal task and the agent task's own logon trigger — not before. -->
    <RestartOnFailure><Interval>PT1M</Interval><Count>3</Count></RestartOnFailure>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Users"><Exec>
    <Command>{exe}</Command>
    <Arguments>agent</Arguments>
  </Exec></Actions>
</Task>
"#
    )
}

/// Encode the task XML for the file `schtasks /Create /XML` reads. schtasks requires UTF-16,
/// so this emits UTF-16LE with a BOM (a UTF-8 file is rejected: "unable to switch the
/// encoding"). The declaration in `agent_task_xml` says `encoding="UTF-16"` to match.
pub fn xml_file_bytes(xml: &str) -> Vec<u8> {
    let mut bytes = vec![0xFF, 0xFE]; // UTF-16LE BOM
    for u in xml.encode_utf16() {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    bytes
}

/// `schtasks /Create … /XML <file> /F` — register a task from an XML definition (idempotent).
pub fn create_from_xml_argv(name: &str, xml_path: &str) -> Vec<String> {
    vec![
        "/Create".into(),
        "/TN".into(),
        name.into(),
        "/XML".into(),
        xml_path.into(),
        "/F".into(),
    ]
}

/// The ONSTART self-heal task argv: re-runs `apply` as SYSTEM on boot. `apply` knows no user, so
/// nothing is baked in. It runs `apply`, never `agent` (an agent here would bind in session 0).
pub fn selfheal_task_argv(exe: &str) -> Vec<String> {
    vec![
        "/Create".into(),
        "/TN".into(),
        SELFHEAL_TASK.into(),
        "/TR".into(),
        // Quote the exe: a path with a space would otherwise truncate when CommandLineToArgvW
        // re-parses this on the SYSTEM boot run.
        format!("\"{exe}\" apply"),
        "/SC".into(),
        "ONSTART".into(),
        "/RU".into(),
        "SYSTEM".into(),
        "/RL".into(),
        "HIGHEST".into(),
        "/F".into(),
    ]
}

/// `schtasks /Query /TN <name> /XML` — dump a task's definition (for the verify checks).
pub fn query_task_argv(name: &str) -> Vec<String> {
    vec!["/Query".into(), "/TN".into(), name.into(), "/XML".into()]
}

/// A task is registered iff the query succeeded and returned a task definition.
pub fn parse_query_registered(stdout: &str, exit_ok: bool) -> bool {
    exit_ok && stdout.contains("<Task")
}

/// Whether a queried task XML is the group logon task [`agent_task_xml`] makes: a principal in
/// [`USERS_GROUP_SID`] and a logon trigger. Case- and whitespace-insensitive, since the service
/// re-serialises what it is given. The older per-user task has no `GroupId`.
pub fn xml_is_group_logon_task(query_xml: &str) -> bool {
    let squeezed: String = query_xml
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    let group = format!("<groupid>{}</groupid>", USERS_GROUP_SID.to_ascii_lowercase());
    squeezed.contains(&group) && (squeezed.contains("<logontrigger>") || squeezed.contains("<logontrigger/>"))
}

#[cfg(test)]
#[path = "schtasks_tests.rs"]
mod schtasks_tests;
