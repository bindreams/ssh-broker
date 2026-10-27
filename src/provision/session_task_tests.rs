//! Host tests for the auto-login task's definition, its read-back and its `verify` row.
use super::*;

const EXE: &str = r"C:\ProgramData\ssh-broker\ssh-broker.exe";
const SID: &str = "S-1-5-21-1-2-3-1001";

/// What Task Scheduler reports for the task `task_xml` registered (SYSTEM and Administrators full,
/// the account read): measured in CI, spike M5(f).
fn measured_sddl(sid: &str) -> String {
    format!(
        "D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;{sid})(A;ID;0x1f019f;;;BA)(A;ID;0x1f019f;;;SY)(A;ID;FA;;;BA)(A;;FR;;;{sid})"
    )
}

fn state(xml: String) -> TaskState {
    TaskState {
        xml,
        sddl: measured_sddl(SID),
        last_result: 0x0004_1303,
    }
}

/// The task as the service hands it back: the definition we gave it, which is also what it
/// re-serialises with its defaults left out is not assumed here.
fn registered() -> TaskState {
    state(task_xml(EXE, SID))
}

// the definition -----

#[test]
fn task_name_is_stable_per_sid() {
    assert_eq!(task_name(SID), "ssh-broker-session-S-1-5-21-1-2-3-1001");
    assert_eq!(task_name(SID), task_name(SID));
    assert_ne!(task_name(SID), task_name("S-1-5-21-1-2-3-1002"));
    assert!(task_name(SID).starts_with(TASK_PREFIX));
}

#[test]
fn task_xml_has_exactly_the_planned_principal_trigger_and_action() {
    let xml = task_xml(EXE, SID);
    assert!(xml.contains("<BootTrigger>"), "{xml}");
    assert_eq!(
        xml.matches("Trigger>").count(),
        2,
        "one trigger, opened and closed: {xml}"
    );
    assert!(xml.contains(&format!("<UserId>{SID}</UserId>")), "{xml}");
    assert!(xml.contains("<LogonType>Password</LogonType>"), "{xml}");
    assert!(xml.contains("<RunLevel>LeastPrivilege</RunLevel>"), "{xml}");
    assert!(!xml.contains("HighestAvailable"), "{xml}");
    assert!(xml.contains(&format!("<Command>{EXE}</Command>")), "{xml}");
    assert!(
        xml.contains(&format!(
            "<Arguments>agent --background --expect-user {SID}</Arguments>"
        )),
        "{xml}"
    );
    assert_eq!(xml.matches("<Exec>").count(), 1, "{xml}");
    assert!(xml.contains(r#"encoding="UTF-16""#));
}

#[test]
fn task_xml_keeps_running_on_battery_and_restarts_on_failure() {
    let xml = task_xml(EXE, SID);
    assert!(
        xml.contains("<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>"),
        "the default is true, which keeps a laptop on battery from starting the session at boot"
    );
    assert!(xml.contains("<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>"));
    assert!(xml.contains("<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>"));
    assert!(xml.contains("<RestartOnFailure><Interval>PT1M</Interval><Count>3</Count></RestartOnFailure>"));
    assert!(
        xml.contains("<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"),
        "one agent per user"
    );
}

#[test]
fn task_xml_escapes_xml_special_chars_in_the_exe_path_and_account() {
    let xml = task_xml(r#"C:\Tom & "Jerry" <1>\ssh-broker.exe"#, "S-1-5-21-<&>");
    assert!(
        xml.contains("C:\\Tom &amp; &quot;Jerry&quot; &lt;1&gt;\\ssh-broker.exe"),
        "{xml}"
    );
    assert!(xml.contains("S-1-5-21-&lt;&amp;&gt;"), "{xml}");
    assert!(!xml.contains("<&>"));
}

#[test]
fn the_agent_task_xml_is_unchanged_by_sharing_its_settings() {
    let xml = crate::provision::schtasks::agent_task_xml(EXE);
    assert!(xml.contains("<MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy>"));
    assert!(xml.contains("<RestartOnFailure><Interval>PT1M</Interval><Count>3</Count></RestartOnFailure>"));
    assert!(xml.contains("<Arguments>agent</Arguments>"));
}

// the read-back -----

#[test]
fn a_task_that_is_what_was_registered_has_no_problem() {
    assert_eq!(task_problem(&registered(), EXE, SID), None);
}

#[test]
fn task_problem_accepts_the_dacl_task_scheduler_produces() {
    // The explicit descriptor is honoured, and the service adds inherited full control for BA and SY
    // and read for the account: judged by principal and rights, not by string.
    let mut s = registered();
    s.sddl = measured_sddl(SID);
    assert_eq!(task_problem(&s, EXE, SID), None);
    s.sddl = "D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;S-1-5-21-1-2-3-1001)".to_string();
    assert_eq!(task_problem(&s, EXE, SID), None);
}

#[test]
fn task_problem_flags_each_mismatch() {
    let good = task_xml(EXE, SID);
    let cases: Vec<(&str, TaskState)> = vec![
        (
            "other user SID",
            state(good.replace(
                &format!("<UserId>{SID}</UserId>"),
                "<UserId>S-1-5-21-1-2-3-9999</UserId>",
            )),
        ),
        (
            "interactive logon type",
            state(good.replace(
                "<LogonType>Password</LogonType>",
                "<LogonType>InteractiveToken</LogonType>",
            )),
        ),
        (
            "highest run level",
            state(good.replace(
                "<RunLevel>LeastPrivilege</RunLevel>",
                "<RunLevel>HighestAvailable</RunLevel>",
            )),
        ),
        (
            "a different action",
            state(good.replace(EXE, r"C:\Users\Public\evil.exe")),
        ),
        (
            "different arguments",
            state(good.replace("agent --background --expect-user", "agent --expect-user")),
        ),
        (
            "an extra trigger",
            state(good.replace(
                "</Triggers>",
                "<LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>",
            )),
        ),
        (
            "no boot trigger",
            state(
                good.replace("<BootTrigger>", "<LogonTrigger>")
                    .replace("</BootTrigger>", "</LogonTrigger>"),
            ),
        ),
        (
            "DisallowStartIfOnBatteries true",
            state(good.replace(
                "<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>",
                "<DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>",
            )),
        ),
        (
            "a second action",
            state(good.replace("</Actions>", "<Exec><Command>C:\\x.exe</Command></Exec></Actions>")),
        ),
        (
            "disabled",
            state(good.replace(
                "<Enabled>true</Enabled>\n  </Settings>",
                "<Enabled>false</Enabled>\n  </Settings>",
            )),
        ),
        (
            "a disabled boot trigger",
            state(good.replace(
                "<BootTrigger><Enabled>true</Enabled></BootTrigger>",
                "<BootTrigger><Enabled>false</Enabled></BootTrigger>",
            )),
        ),
        (
            "a DACL granting Everyone write",
            TaskState {
                sddl: format!("{}(A;;FA;;;WD)", measured_sddl(SID)),
                ..registered()
            },
        ),
        (
            "a DACL letting the account change permissions",
            TaskState {
                sddl: format!("D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1e0000;;;{SID})"),
                ..registered()
            },
        ),
        (
            "no DACL",
            TaskState {
                sddl: String::new(),
                ..registered()
            },
        ),
        (
            "a DACL with rights it cannot read",
            TaskState {
                sddl: format!("D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;ZZ;;;{SID})"),
                ..registered()
            },
        ),
    ];
    for (what, state) in cases {
        assert!(
            task_problem(&state, EXE, SID).is_some(),
            "a task with {what} must be reported"
        );
    }
}

#[test]
fn a_service_that_leaves_defaults_out_is_not_a_mismatch() {
    // Run level LeastPrivilege and MultipleInstancesPolicy IgnoreNew are defaults and may be omitted
    // from what the service reads back; the battery flags are not defaults and must stay.
    let xml = task_xml(EXE, SID)
        .replace("<RunLevel>LeastPrivilege</RunLevel>", "")
        .replace("<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>", "");
    assert_eq!(task_problem(&state(xml), EXE, SID), None);
}

#[test]
fn an_exe_compared_case_insensitively_is_the_same_exe() {
    let xml = task_xml(&EXE.to_uppercase(), SID);
    assert_eq!(task_problem(&state(xml), EXE, SID), None);
}

// the verify row -----

#[test]
fn task_row_absent_task_passes() {
    let row = task_row(&Ok(None), EXE, SID);
    assert!(row.pass);
    assert!(
        row.detail.contains("not registered: auto-login is off"),
        "{}",
        row.detail
    );
}

#[test]
fn task_row_unanswerable_query_fails() {
    let row = task_row(&Err(anyhow::anyhow!("access denied")), EXE, SID);
    assert!(!row.pass);
    assert!(row.detail.contains("access denied"), "{}", row.detail);
}

#[test]
fn task_row_wrong_definition_fails() {
    let mut wrong = registered();
    wrong.xml = wrong.xml.replace(EXE, r"C:\evil.exe");
    let row = task_row(&Ok(Some(wrong)), EXE, SID);
    assert!(!row.pass);
    assert!(row.detail.contains("action"), "it names the mismatch: {}", row.detail);
}

#[test]
fn task_row_not_yet_run_and_running_pass() {
    for last_result in [0x0004_1303, 0x0004_1301, 0] {
        let row = task_row(
            &Ok(Some(TaskState {
                last_result,
                ..registered()
            })),
            EXE,
            SID,
        );
        assert!(row.pass, "{last_result:#x}: {}", row.detail);
    }
}

#[test]
fn task_row_other_last_result_fails() {
    let row = task_row(
        &Ok(Some(TaskState {
            last_result: 0x8007_052e,
            ..registered()
        })),
        EXE,
        SID,
    );
    assert!(!row.pass);
    assert!(row.detail.contains("0x8007052e"), "{}", row.detail);
}

#[test]
fn task_row_says_a_failed_logon_is_not_recorded() {
    let row = task_row(&Ok(Some(registered())), EXE, SID);
    assert!(row.pass);
    assert!(
        row.detail.contains("a failed logon is not recorded"),
        "the row must not claim to have checked the password or the batch right: {}",
        row.detail
    );
}

#[test]
fn a_disabled_boot_trigger_is_named_as_the_problem() {
    let xml = task_xml(EXE, SID).replace(
        "<BootTrigger><Enabled>true</Enabled></BootTrigger>",
        "<BootTrigger><Enabled>false</Enabled></BootTrigger>",
    );
    let problem = task_problem(&state(xml), EXE, SID).expect("a trigger that never fires is a problem");
    assert!(problem.contains("trigger") && problem.contains("disabled"), "{problem}");
}

#[test]
fn a_boot_trigger_the_service_wrote_without_its_default_enabled_is_fine() {
    let xml = task_xml(EXE, SID).replace("<BootTrigger><Enabled>true</Enabled></BootTrigger>", "<BootTrigger />");
    assert_eq!(task_problem(&state(xml), EXE, SID), None);
}
