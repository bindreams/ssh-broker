//! Host tests for the pure schtasks builders/parsers, plus two elevated registration tests that
//! run in CI only. The group-principal assertions are the build-time guard against the two
//! ways this task can silently stop working: naming one user again, or landing in session 0.
use super::*;

/// A per-user agent task: one account, InteractiveToken, no group.
fn per_user_task_xml(user: &str) -> String {
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
        xml.contains("<RunLevel>HighestAvailable</RunLevel>"),
        "an administrator's agent is elevated, a standard account's has its only token"
    );
    assert!(
        !xml.contains("LeastPrivilege"),
        "the filtered token is refused by the agent"
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
fn apply_sshd_xml_runs_the_verb_as_system_with_no_trigger() {
    let xml = apply_sshd_task_xml(r"C:\ProgramData\ssh-broker\ssh-broker.exe");
    assert!(xml.contains("<UserId>S-1-5-18</UserId>"), "SYSTEM, by its SID");
    assert!(xml.contains("<RunLevel>HighestAvailable</RunLevel>"));
    assert!(
        !xml.contains("Trigger"),
        "a task with no trigger runs nothing by itself, only when `apply` starts it"
    );
    assert!(xml.contains(r"<Command>C:\ProgramData\ssh-broker\ssh-broker.exe</Command>"));
    assert!(xml.contains("<Arguments>apply-sshd</Arguments>"));
    assert!(xml.contains(r#"encoding="UTF-16""#));
}

#[test]
fn apply_sshd_xml_queues_a_second_run_and_never_restarts_a_failed_one() {
    let xml = apply_sshd_task_xml(r"C:\x.exe");
    assert!(
        xml.contains("<MultipleInstancesPolicy>Queue</MultipleInstancesPolicy>"),
        "an `apply` over a task that still runs waits its turn, and the run it asked for happens"
    );
    assert!(
        !xml.contains("RestartOnFailure"),
        "a failed run is reported by its report; a restart would restart sshd again"
    );
    assert!(
        xml.contains("<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>"),
        "no time limit"
    );
    assert!(xml.contains("<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>"));
    assert!(xml.contains("<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>"));
}

#[test]
fn the_other_tasks_keep_their_settings() {
    let agent = agent_task_xml(r"C:\x.exe");
    assert!(agent.contains("<RestartOnFailure><Interval>PT1M</Interval><Count>3</Count></RestartOnFailure>"));
    assert!(agent.contains("<MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy>"));
}

#[test]
fn apply_sshd_xml_escapes_special_chars() {
    let xml = apply_sshd_task_xml(r"C:\a&b\x.exe");
    assert!(xml.contains("a&amp;b"));
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
fn xml_is_group_logon_task_accepts_the_group_xml_and_rejects_a_per_user_one() {
    assert!(xml_is_group_logon_task(&agent_task_xml(r"C:\x.exe")));
    assert!(
        !xml_is_group_logon_task(&per_user_task_xml("DOMAIN\\someone")),
        "a per-user InteractiveToken task is not the group form"
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
    assert!(
        row.detail.contains("run_level=HighestAvailable"),
        "the row names the run level it read: {}",
        row.detail
    );
}

#[test]
fn agent_task_row_prints_the_run_level_as_the_queried_xml_spells_it() {
    let queried = agent_task_xml(r"C:\x.exe").replace(
        "<RunLevel>HighestAvailable</RunLevel>",
        "<RunLevel>\n  highestavailable \n</RunLevel>",
    );
    let row = agent_task_row(&Ok(Some(queried)));
    assert!(row.pass, "{}", row.detail);
    assert!(row.detail.contains("run_level=highestavailable"), "{}", row.detail);
}

#[test]
fn xml_run_level_reads_the_level_and_finds_none_when_it_is_left_out() {
    assert_eq!(
        xml_run_level(&agent_task_xml(r"C:\x.exe")).as_deref(),
        Some("HighestAvailable")
    );
    assert_eq!(
        xml_run_level(&least_privilege_agent_task_xml()).as_deref(),
        Some("LeastPrivilege")
    );
    let omitted = agent_task_xml(r"C:\x.exe").replace("    <RunLevel>HighestAvailable</RunLevel>\n", "");
    assert_eq!(xml_run_level(&omitted), None);
}

/// The agent task as an earlier `apply` registered it.
fn least_privilege_agent_task_xml() -> String {
    agent_task_xml(r"C:\x.exe").replace("HighestAvailable", "LeastPrivilege")
}

#[test]
fn xml_is_group_logon_task_requires_the_highest_available_run_level() {
    assert!(xml_is_group_logon_task(&agent_task_xml(r"C:\x.exe")));
    assert!(
        !xml_is_group_logon_task(&least_privilege_agent_task_xml()),
        "an administrator's agent from this task would be filtered, and refuse to start"
    );
    let omitted = agent_task_xml(r"C:\x.exe").replace("    <RunLevel>HighestAvailable</RunLevel>\n", "");
    assert!(!omitted.contains("RunLevel"), "control: no run level");
    assert!(
        !xml_is_group_logon_task(&omitted),
        "the service leaves LeastPrivilege out when it holds the default"
    );
}

#[test]
fn xml_is_group_logon_task_tolerates_case_and_whitespace_in_the_run_level() {
    let queried = agent_task_xml(r"C:\x.exe").replace(
        "<RunLevel>HighestAvailable</RunLevel>",
        "<RunLevel>\n  highestavailable \n</RunLevel>",
    );
    assert!(xml_is_group_logon_task(&queried));
}

#[test]
fn agent_task_row_fails_for_the_run_level_of_an_earlier_apply_and_says_to_run_apply() {
    let row = agent_task_row(&Ok(Some(least_privilege_agent_task_xml())));
    assert!(!row.pass, "{}", row.detail);
    assert!(row.detail.contains("HighestAvailable"), "{}", row.detail);
    assert!(row.detail.contains("apply"), "{}", row.detail);
}

#[test]
fn agent_task_row_fails_for_a_per_user_task() {
    let row = agent_task_row(&Ok(Some(per_user_task_xml("DOMAIN\\someone"))));
    assert!(!row.pass);
    assert!(row.detail.contains("apply"), "it says what to do: {}", row.detail);
}

#[test]
fn agent_task_row_fails_when_the_task_is_not_registered() {
    let row = agent_task_row(&Ok(None));
    assert!(!row.pass);
    assert!(row.detail.contains("registered=false"), "{}", row.detail);
    assert!(
        !row.detail.contains("run_level"),
        "there is no task to have a run level: {}",
        row.detail
    );
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
fn a_failing_row_says_which_run_level_it_read() {
    let without_level = agent_task_xml(r"C:\x.exe").replace("    <RunLevel>HighestAvailable</RunLevel>\n", "");
    let disabled_least = disabled_agent_task_xml().replace("HighestAvailable", "LeastPrivilege");
    for (xml, said) in [
        (least_privilege_agent_task_xml(), "run_level=LeastPrivilege"),
        (per_user_task_xml("DOMAIN\\someone"), "run_level=LeastPrivilege"),
        (without_level, "run_level=none: `LeastPrivilege` by default"),
        (disabled_agent_task_xml(), "run_level=HighestAvailable"),
        (disabled_least, "run_level=LeastPrivilege"),
    ] {
        let row = agent_task_row(&Ok(Some(xml)));
        assert!(!row.pass, "{}", row.detail);
        assert!(row.detail.contains(said), "{said}: {}", row.detail);
    }
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
}
