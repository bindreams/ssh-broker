//! provision::schtasks — Task Scheduler XML + argv builders and query parsers (pure).
//!
//! The agent task is registered from XML (not the bare CLI) specifically to set
//! `<LogonType>InteractiveToken</LogonType>`: that, NOT the trigger, is what makes the agent
//! run in the interactive console session (session 1) instead of session 0. A bare
//! `/SC ONLOGON /RU <user>` (no interactive token), `/RU SYSTEM`, or an S4U principal all land
//! in session 0 — silently reproducing the limited environment this project exists to escape.
//! `RunLevel=LeastPrivilege` (not Highest) keeps the plain auto-login token: elevation would
//! re-arm RedirectionGuard (breaking symlink-traversal parity) and not match the dir ACL.

pub const AGENT_TASK: &str = "ssh-broker-agent";
pub const SELFHEAL_TASK: &str = "ssh-broker-apply";

/// Minimal XML escaping for the few characters that can appear in a path/account name.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// The agent logon task definition: runs `<exe> agent` in session 1 via InteractiveToken,
/// triggered on the target user's logon, started immediately by `apply` via `/Run`.
pub fn agent_task_xml(exe: &str, user: &str) -> String {
    let exe = xml_escape(exe);
    let user = xml_escape(user);
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>ssh-broker session-1 relay agent</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{user}</UserId></LogonTrigger></Triggers>
  <Principals><Principal id="Author">
    <UserId>{user}</UserId>
    <LogonType>InteractiveToken</LogonType>
    <RunLevel>LeastPrivilege</RunLevel>
  </Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <!-- The project forbids arbitrary retry caps, and this is the one documented exception: the
         Task Scheduler schema requires a Count with RestartOnFailure and has no unbounded form.
         A failure outlasting these attempts is covered at the next boot or logon, by the
         ONSTART self-heal task and the agent task's own logon trigger — not before. -->
    <RestartOnFailure><Interval>PT1M</Interval><Count>3</Count></RestartOnFailure>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author"><Exec>
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

/// The ONSTART self-heal task argv: re-runs `apply` as SYSTEM on boot. `--user` is baked in so
/// the SYSTEM run resolves the SAME ACL grantee (never its own SYSTEM token). It runs `apply`,
/// never `agent` (an agent here would bind in session 0).
pub fn selfheal_task_argv(exe: &str, user: &str) -> Vec<String> {
    vec![
        "/Create".into(),
        "/TN".into(),
        SELFHEAL_TASK.into(),
        "/TR".into(),
        // Quote BOTH the exe and the user: a space-containing account (valid on Windows) would
        // otherwise truncate when CommandLineToArgvW re-parses this on the SYSTEM boot run,
        // hardening the socket dir for the wrong account and bricking the agent's bind gate.
        format!("\"{exe}\" apply --user \"{user}\""),
        "/SC".into(),
        "ONSTART".into(),
        "/RU".into(),
        "SYSTEM".into(),
        "/RL".into(),
        "HIGHEST".into(),
        "/F".into(),
    ]
}

/// `schtasks /Run /TN <name>` — start the (InteractiveToken) agent task now, so the user need
/// not re-login. `/Run` honours the task's principal, landing the agent in session 1.
pub fn run_task_argv(name: &str) -> Vec<String> {
    vec!["/Run".into(), "/TN".into(), name.into()]
}

/// `schtasks /Query /TN <name> /XML` — dump a task's definition (for the verify checks).
pub fn query_task_argv(name: &str) -> Vec<String> {
    vec!["/Query".into(), "/TN".into(), name.into(), "/XML".into()]
}

/// A task is registered iff the query succeeded and returned a task definition.
pub fn parse_query_registered(stdout: &str, exit_ok: bool) -> bool {
    exit_ok && stdout.contains("<Task")
}

/// Whether a queried task XML declares the InteractiveToken logon type (i.e. it will run in
/// the interactive session). Case-insensitive and whitespace-tolerant.
pub fn xml_has_interactive_token(query_xml: &str) -> bool {
    query_xml.to_ascii_lowercase().contains("interactivetoken")
}

#[cfg(test)]
#[path = "schtasks_tests.rs"]
mod schtasks_tests;
