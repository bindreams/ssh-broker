//! Unit tests for `ready`. They touch only the objects they create themselves: each makes a named
//! event of a random name, which is closed when the test ends.
use super::*;
use std::os::windows::io::AsRawHandle;
use std::process::Command;
use windows::Win32::System::Threading::{GetCurrentProcessId, OpenProcess, PROCESS_SYNCHRONIZE};

const HEX32: &str = "0123456789abcdef0123456789abcdef";

#[test]
fn ready_name_is_unguessable_shaped() {
    let a = generate_name().unwrap();
    let b = generate_name().unwrap();
    assert!(is_ready_name(&a), "{a}");
    assert!(is_ready_name(&b), "{b}");
    assert_ne!(a, b);
    assert!(a.starts_with(r"Global\ssh-broker-ready-"), "{a}");
    assert_eq!(a.len(), r"Global\ssh-broker-ready-".len() + 32);
}

#[test]
fn open_rejects_foreign_names() {
    for name in [
        String::new(),
        r"Global\other".to_string(),
        format!(r"Local\ssh-broker-ready-{HEX32}"),
        format!(r"Global\ssh-broker-ready-{}", &HEX32[1..]),
        format!(r"Global\ssh-broker-ready-{HEX32}0"),
        format!(r"Global\ssh-broker-ready-{}", HEX32.to_uppercase()),
        format!(r"Global\ssh-broker-ready-{}g", &HEX32[1..]),
        format!(r"Global\ssh-broker-ready-{HEX32}\..\x"),
        format!(r"ssh-broker-ready-{HEX32}"),
    ] {
        assert!(!is_ready_name(&name), "{name:?}");
        assert!(ReadyEvent::open(&name).is_err(), "{name:?}");
    }
}

#[test]
fn the_descriptor_names_exactly_the_account_system_and_administrators() {
    let sddl = descriptor_sddl("S-1-5-21-1-2-3-1001");
    assert_eq!(
        sddl,
        "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x100002;;;S-1-5-21-1-2-3-1001)S:(ML;;NW;;;ME)"
    );
}

#[test]
fn a_created_event_is_signalled_through_a_second_handle_and_wakes_the_waiter() {
    let (event, name) = ReadyEvent::create().unwrap();
    let opened = ReadyEvent::open(&name).unwrap();
    opened.signal().unwrap();
    // This process stands in for an agent that has not ended: its handle is not signalled.
    // SAFETY: a plain open of the current process; the handle is closed by `OwnedHandle`.
    let this_process = OwnedHandle(unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, GetCurrentProcessId()) }.unwrap());
    assert_eq!(event.wait_with(this_process.0).unwrap(), Waited::Ready);
}

#[test]
fn an_agent_that_ended_is_reported_with_its_exit_code() {
    let (event, _name) = ReadyEvent::create().unwrap();
    let mut child = Command::new("cmd").args(["/c", "exit", "7"]).spawn().unwrap();
    let waited = event.wait_with(HANDLE(child.as_raw_handle())).unwrap();
    assert_eq!(waited, Waited::AgentExited(7));
    let _ = child.wait();
}

#[test]
fn ready_wins_when_the_agent_ended_after_signalling() {
    let (event, _name) = ReadyEvent::create().unwrap();
    event.signal().unwrap();
    let mut child = Command::new("cmd").args(["/c", "exit", "0"]).spawn().unwrap();
    child.wait().unwrap();
    assert_eq!(event.wait_with(HANDLE(child.as_raw_handle())).unwrap(), Waited::Ready);
}

#[test]
fn a_second_creation_of_the_same_name_is_refused() {
    let (_first, name) = ReadyEvent::create().unwrap();
    assert!(ReadyEvent::create_named(&name, &crate::acl::Sid::current_user().unwrap().to_sddl().unwrap()).is_err());
}
