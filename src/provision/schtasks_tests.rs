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
fn apply_takes_the_queried_xml_and_treats_an_absent_task_as_none() {
    let xml = agent_task_xml(r"C:\x.exe");
    assert_eq!(registered_xml(Ok(Some(xml.clone()))).unwrap(), Some(xml));
    assert_eq!(registered_xml(Ok(None)).unwrap(), None);
}

#[test]
fn apply_refuses_to_guess_when_the_query_was_inconclusive() {
    // "Could not ask" is not "not registered": taking it for absent skips the migration and the
    // restart after a failed apply.
    let err = registered_xml(Err(anyhow::anyhow!("access is denied"))).unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("access is denied"), "{text}");
    assert!(text.contains(AGENT_TASK), "{text}");
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
    let row = agent_task_row(&Ok(Some(agent_task_xml(r"C:\x.exe"))));
    assert!(row.pass, "{}", row.detail);
}

#[test]
fn agent_task_row_fails_for_a_legacy_per_user_task() {
    let row = agent_task_row(&Ok(Some(legacy_task_xml("DOMAIN\\someone"))));
    assert!(!row.pass);
    assert!(row.detail.contains("apply"), "it says what to do: {}", row.detail);
}

#[test]
fn agent_task_row_fails_when_the_task_is_not_registered() {
    let row = agent_task_row(&Ok(None));
    assert!(!row.pass);
    assert!(row.detail.contains("registered=false"), "{}", row.detail);
}

#[test]
fn agent_task_row_gives_the_cause_when_the_query_failed() {
    let row = agent_task_row(&Err(anyhow::anyhow!("access is denied")));
    assert!(!row.pass);
    assert!(row.detail.contains("access is denied"), "{}", row.detail);
    assert!(
        !row.detail.contains("registered=false"),
        "a failed query is not an absent task: {}",
        row.detail
    );
}

/// The agent task as the service stores it after the task is disabled: the setting is in
/// `Settings`, apart from the logon trigger's own `Enabled`.
fn disabled_agent_task_xml() -> String {
    let xml = agent_task_xml(r"C:\x.exe");
    let settings = xml.find("<Settings>").unwrap();
    let (head, tail) = xml.split_at(settings);
    format!(
        "{head}{}",
        tail.replacen("<Enabled>true</Enabled>", "<Enabled>false</Enabled>", 1)
    )
}

#[test]
fn agent_task_row_fails_for_a_disabled_task_and_says_to_run_apply() {
    // A killed `apply` leaves the task disabled; nothing then starts at any logon.
    let xml = disabled_agent_task_xml();
    assert!(xml_is_group_logon_task(&xml), "control: otherwise the group task");
    let row = agent_task_row(&Ok(Some(xml)));
    assert!(!row.pass, "{}", row.detail);
    assert!(row.detail.contains("disabled"), "{}", row.detail);
    assert!(row.detail.contains("apply"), "{}", row.detail);
}

#[test]
fn a_task_with_no_enabled_setting_is_enabled() {
    // The service leaves the element out when it holds its default, true.
    let xml = agent_task_xml(r"C:\x.exe").replace("    <Enabled>true</Enabled>\n  </Settings>", "  </Settings>");
    let settings = &xml[xml.find("<Settings>").unwrap()..];
    assert!(!settings.contains("<Enabled>"), "control: no setting");
    assert!(agent_task_row(&Ok(Some(xml))).pass);
}

#[test]
fn a_disabled_logon_trigger_alone_is_not_a_disabled_task() {
    // The trigger's own `Enabled` is not the task's; only `Settings` says the task is off.
    let xml = agent_task_xml(r"C:\x.exe").replacen("<Enabled>true</Enabled>", "<Enabled>false</Enabled>", 1);
    assert!(agent_task_row(&Ok(Some(xml))).pass);
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
