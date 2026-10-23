//! Host tests for the pure schtasks builders/parsers, plus two elevated registration tests that
//! run in CI only. The group-principal assertions are the build-time guard against the two
//! ways this task can silently stop working: naming one user again, or landing in session 0.
use super::*;

/// The agent task as an older build registered it: one account, InteractiveToken.
fn legacy_task_xml(user: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{user}</UserId></LogonTrigger></Triggers>
  <Principals><Principal id="Author">
    <UserId>{user}</UserId>
    <LogonType>InteractiveToken</LogonType>
    <RunLevel>LeastPrivilege</RunLevel>
  </Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy></Settings>
  <Actions Context="Author"><Exec><Command>C:\x.exe</Command><Arguments>agent</Arguments></Exec></Actions>
</Task>
"#
    )
}

#[test]
fn agent_xml_runs_for_any_member_of_users() {
    let xml = agent_task_xml(r"C:\ProgramData\ssh-broker\ssh-broker.exe");
    assert!(xml.contains("<GroupId>S-1-5-32-545</GroupId>"), "BUILTIN\\Users");
    assert!(xml.contains("<LogonTrigger>"));
    assert!(
        xml.contains("<MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy>"),
        "IgnoreNew could drop the second user's agent"
    );
    assert!(
        xml.contains("<RunLevel>LeastPrivilege</RunLevel>"),
        "elevation would re-arm RedirectionGuard"
    );
    assert!(xml.contains(r"C:\ProgramData\ssh-broker\ssh-broker.exe"));
    assert!(xml.contains("<Arguments>agent</Arguments>"));
    // schtasks /XML rejects UTF-8; the declaration must match the UTF-16 file we write.
    assert!(xml.contains(r#"encoding="UTF-16""#));
}

#[test]
fn agent_xml_names_no_user_and_no_logon_type() {
    let xml = agent_task_xml(r"C:\x.exe");
    assert!(
        !xml.contains("UserId"),
        "a user in the task is the bug this unit removes"
    );
    assert!(
        !xml.contains("LogonType"),
        "a group principal is itself the interactive-session form; a LogonType here is untested \
         against the service"
    );
}

#[test]
fn xml_file_bytes_is_utf16le_with_bom() {
    let xml = agent_task_xml("C:\\x.exe");
    let bytes = xml_file_bytes(&xml);
    assert_eq!(&bytes[..2], &[0xFF, 0xFE], "must start with a UTF-16LE BOM");
    // The body after the BOM decodes back to the original XML.
    let (pairs, rest) = bytes[2..].as_chunks::<2>();
    assert!(rest.is_empty(), "UTF-16LE body must be a whole number of code units");
    let u16s: Vec<u16> = pairs.iter().copied().map(u16::from_le_bytes).collect();
    assert_eq!(String::from_utf16(&u16s).unwrap(), xml);
}

#[test]
fn agent_xml_escapes_special_chars() {
    let xml = agent_task_xml(r"C:\a&b\x<y>.exe");
    assert!(xml.contains("a&amp;b"));
    assert!(xml.contains("x&lt;y&gt;"));
    assert!(!xml.contains("a&b\\x")); // raw '&' must not survive
}

#[test]
fn agent_xml_keeps_a_path_with_spaces_whole() {
    let xml = agent_task_xml(r"C:\Program Data\ssh-broker\ssh-broker.exe");
    assert!(xml.contains(r"<Command>C:\Program Data\ssh-broker\ssh-broker.exe</Command>"));
}

#[test]
fn selfheal_argv_is_system_onstart_and_takes_no_user() {
    let argv = selfheal_task_argv(r"C:\x\ssh-broker.exe");
    assert!(argv.contains(&"ONSTART".to_string()));
    assert!(argv.contains(&"SYSTEM".to_string()));
    assert!(argv.contains(&"HIGHEST".to_string()));
    // /TR quotes the exe and carries `apply` alone; never `agent`, never a user.
    let tr = argv.iter().position(|a| a == "/TR").map(|i| &argv[i + 1]).unwrap();
    assert_eq!(tr, "\"C:\\x\\ssh-broker.exe\" apply");
    assert!(!tr.contains(" agent") && !tr.contains("--user"));
}

#[test]
fn create_and_query_argv_shapes() {
    assert_eq!(
        create_from_xml_argv(AGENT_TASK, r"C:\t\task.xml"),
        vec!["/Create", "/TN", "ssh-broker-agent", "/XML", r"C:\t\task.xml", "/F"]
    );
    assert_eq!(
        query_task_argv(AGENT_TASK),
        vec!["/Query", "/TN", "ssh-broker-agent", "/XML"]
    );
}

#[test]
fn query_parsing_registered() {
    let xml = agent_task_xml("C:\\x.exe");
    assert!(parse_query_registered(&xml, true)); // exists + XML returned
    assert!(!parse_query_registered(&xml, false)); // nonzero exit = not registered
    assert!(!parse_query_registered("ERROR: task not found", true)); // no <Task
}

#[test]
fn xml_is_group_logon_task_accepts_the_new_xml_and_rejects_the_legacy_one() {
    assert!(xml_is_group_logon_task(&agent_task_xml(r"C:\x.exe")));
    assert!(
        !xml_is_group_logon_task(&legacy_task_xml("DOMAIN\\someone")),
        "a per-user InteractiveToken task is the legacy form"
    );
    assert!(!xml_is_group_logon_task(""), "no task");
}

#[test]
fn xml_is_group_logon_task_rejects_another_group_and_a_missing_trigger() {
    let other_group = agent_task_xml(r"C:\x.exe").replace("S-1-5-32-545", "S-1-5-32-544");
    assert!(!xml_is_group_logon_task(&other_group), "Administrators is not Users");
    let no_trigger = agent_task_xml(r"C:\x.exe").replace("LogonTrigger", "BootTrigger");
    assert!(!xml_is_group_logon_task(&no_trigger));
}

#[test]
fn xml_is_group_logon_task_tolerates_case_and_whitespace_in_the_queried_form() {
    let queried = agent_task_xml(r"C:\x.exe")
        .replace(
            "<GroupId>S-1-5-32-545</GroupId>",
            "<GroupId>\n  s-1-5-32-545 \n</GroupId>",
        )
        .replace("<LogonTrigger>", "<LogonTrigger >");
    assert!(xml_is_group_logon_task(&queried));
}

#[test]
fn agent_task_row_passes_for_the_group_task() {
    let row = agent_task_row(&agent_task_xml(r"C:\x.exe"), true);
    assert!(row.pass, "{}", row.detail);
}

#[test]
fn agent_task_row_fails_for_a_legacy_per_user_task() {
    let row = agent_task_row(&legacy_task_xml("DOMAIN\\someone"), true);
    assert!(!row.pass);
    assert!(row.detail.contains("apply"), "it says what to do: {}", row.detail);
}

#[test]
fn agent_task_row_fails_when_the_task_is_not_registered() {
    let row = agent_task_row("", false);
    assert!(!row.pass);
    assert!(row.detail.contains("registered=false"), "{}", row.detail);
}

// Task Scheduler itself (Elevated, CI only) ---------------------------------------------

#[cfg(windows)]
mod service {
    use super::*;
    use crate::test_support::ThrowawayTask as Throwaway;

    /// Elevated (CI only).
    #[test]
    fn task_scheduler_accepts_the_group_agent_task() {
        let task = Throwaway::new("group");
        task.register(&agent_task_xml(r"C:\Windows\System32\cmd.exe"));
        let xml = task.queried_xml();
        assert!(parse_query_registered(&xml, true));
        assert!(
            xml_is_group_logon_task(&xml),
            "the service must keep the group principal and the logon trigger:\n{xml}"
        );
    }

    /// Elevated (CI only).
    #[test]
    fn reapplying_replaces_a_legacy_per_user_task() {
        let task = Throwaway::new("legacy");
        let me = format!(
            "{}\\{}",
            std::env::var("USERDOMAIN").unwrap(),
            std::env::var("USERNAME").unwrap()
        );
        task.register(&legacy_task_xml(&me));
        assert!(
            !xml_is_group_logon_task(&task.queried_xml()),
            "control: the legacy form"
        );

        task.register(&agent_task_xml(r"C:\Windows\System32\cmd.exe"));
        assert!(
            xml_is_group_logon_task(&task.queried_xml()),
            "`/F` replaced it in place"
        );
    }
}
