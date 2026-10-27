use super::*;
use crate::test_support::TempProfile;

fn session(sid: &str) -> String {
    format!("{}{sid}", super::super::session_task::TASK_PREFIX)
}

#[test]
fn nothing_is_owed_when_there_is_no_file() {
    let dir = TempProfile::new("pending-none");
    assert!(load(&dir.0.join("pending.txt")).unwrap().is_empty());
}

#[test]
fn what_was_stored_is_loaded_in_order() {
    let dir = TempProfile::new("pending-roundtrip");
    let path = dir.0.join("pending.txt");
    let owed = [session("S-1-5-21-1-2-3-1001"), session("S-1-5-21-1-2-3-1002")];
    store(&path, &owed).unwrap();
    assert_eq!(load(&path).unwrap(), owed);
}

#[test]
fn storing_replaces_what_was_there_and_leaves_no_temporary_file() {
    let dir = TempProfile::new("pending-replace");
    let path = dir.0.join("pending.txt");
    store(&path, &[session("a"), session("b")]).unwrap();
    store(&path, &[session("c")]).unwrap();
    assert_eq!(load(&path).unwrap(), [session("c")]);
    let left: Vec<_> = std::fs::read_dir(&dir.0)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .filter(|name| name.to_string_lossy().starts_with("pending"))
        .collect();
    assert_eq!(left, ["pending.txt"]);
}

#[test]
fn storing_nothing_removes_the_file_and_is_fine_without_one() {
    let dir = TempProfile::new("pending-clear");
    let path = dir.0.join("pending.txt");
    store(&path, &[]).unwrap();
    store(&path, &[session("a")]).unwrap();
    store(&path, &[]).unwrap();
    assert!(!path.exists());
    assert!(load(&path).unwrap().is_empty());
}

#[test]
fn a_line_that_is_not_a_session_task_name_is_not_owed() {
    // Only tasks of this program are ever enabled from the file, whatever it says.
    let dir = TempProfile::new("pending-foreign");
    let path = dir.0.join("pending.txt");
    let text = format!("{}\r\nMicrosoft\\Windows\\Defrag\r\n\r\n{}\n", session("a"), session("b"));
    std::fs::write(&path, text).unwrap();
    assert_eq!(load(&path).unwrap(), [session("a"), session("b")]);
}
