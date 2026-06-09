//! Host tests for the pure schtasks builders/parsers. The InteractiveToken assertion is the
//! build-time guard against the silent-session-0 footgun.
use super::*;

#[test]
fn agent_xml_sets_interactive_token_and_least_privilege() {
    let xml = agent_task_xml(r"C:\ProgramData\ssh-broker\ssh-broker.exe", "Test.User");
    assert!(xml.contains("<LogonType>InteractiveToken</LogonType>"), "must be InteractiveToken");
    assert!(xml.contains("<RunLevel>LeastPrivilege</RunLevel>"), "must be LeastPrivilege");
    assert!(xml.contains(r"C:\ProgramData\ssh-broker\ssh-broker.exe"));
    assert!(xml.contains("<Arguments>agent</Arguments>"));
    assert!(xml.contains("<UserId>Test.User</UserId>"));
    assert!(xml_has_interactive_token(&xml));
}

#[test]
fn agent_xml_escapes_special_chars() {
    let xml = agent_task_xml(r"C:\a&b\x.exe", "DOM\\u<r");
    assert!(xml.contains("a&amp;b"));
    assert!(xml.contains("u&lt;r"));
    assert!(!xml.contains("a&b\\x")); // raw '&' must not survive
}

#[test]
fn selfheal_argv_is_system_onstart_and_bakes_user() {
    let argv = selfheal_task_argv(r"C:\x\ssh-broker.exe", "Test.User");
    assert!(argv.contains(&"ONSTART".to_string()));
    assert!(argv.contains(&"SYSTEM".to_string()));
    assert!(argv.contains(&"HIGHEST".to_string()));
    // /TR quotes BOTH the exe and the user, carries `apply --user <name>`, never `agent`.
    let tr = argv.iter().position(|a| a == "/TR").map(|i| &argv[i + 1]).unwrap();
    assert_eq!(tr, "\"C:\\x\\ssh-broker.exe\" apply --user \"Test.User\"");
    assert!(!tr.contains(" agent"));
}

#[test]
fn selfheal_tr_quotes_a_spaced_account_so_it_survives_reparse() {
    // A space-containing account must stay ONE token through CommandLineToArgvW on the SYSTEM
    // boot run; the quotes are what guarantee that (an unquoted name would truncate).
    let argv = selfheal_task_argv(r"C:\x\ssh-broker.exe", "Test User");
    let tr = argv.iter().position(|a| a == "/TR").map(|i| &argv[i + 1]).unwrap();
    assert!(tr.ends_with("apply --user \"Test User\""), "user not quoted: {tr}");
}

#[test]
fn create_run_query_argv_shapes() {
    assert_eq!(
        create_from_xml_argv(AGENT_TASK, r"C:\t\task.xml"),
        vec!["/Create", "/TN", "ssh-broker-agent", "/XML", r"C:\t\task.xml", "/F"]
    );
    assert_eq!(run_task_argv(AGENT_TASK), vec!["/Run", "/TN", "ssh-broker-agent"]);
    assert_eq!(
        query_task_argv(AGENT_TASK),
        vec!["/Query", "/TN", "ssh-broker-agent", "/XML"]
    );
}

#[test]
fn query_parsing_registered_and_token() {
    let xml = agent_task_xml("C:\\x.exe", "u");
    assert!(parse_query_registered(&xml, true)); // exists + XML returned
    assert!(!parse_query_registered(&xml, false)); // nonzero exit = not registered
    assert!(!parse_query_registered("ERROR: task not found", true)); // no <Task
    // A task that is NOT InteractiveToken must be detected as such.
    assert!(!xml_has_interactive_token("<Principal><LogonType>S4U</LogonType></Principal>"));
    assert!(xml_has_interactive_token(&xml));
}
