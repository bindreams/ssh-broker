//! Host tests for `provision::path_env`: the pure decisions about the system `PATH`.
use super::*;

const DIR: &str = r"C:\ProgramData\ssh-broker";

#[test]
fn path_with_directory_appends_once_and_ignores_case_and_a_trailing_backslash() {
    assert_eq!(
        with_directory(r"C:\Windows;C:\Windows\System32", DIR).as_deref(),
        Some(r"C:\Windows;C:\Windows\System32;C:\ProgramData\ssh-broker")
    );
    // A value that ends in a separator does not get a second one.
    assert_eq!(
        with_directory(r"C:\Windows;", DIR).as_deref(),
        Some(r"C:\Windows;C:\ProgramData\ssh-broker")
    );
    assert_eq!(with_directory("", DIR).as_deref(), Some(DIR));
    // A look-alike is not the directory.
    assert!(with_directory(r"C:\ProgramData\ssh-broker-old;C:\ProgramData", DIR).is_some());
    assert!(with_directory(r"C:\ProgramData\ssh-broker\bin", DIR).is_some());
}

#[test]
fn path_with_directory_leaves_a_value_that_already_has_it_unchanged() {
    for present in [
        r"C:\Windows;C:\ProgramData\ssh-broker;C:\x",
        r"C:\ProgramData\ssh-broker",
        r"c:\programdata\SSH-BROKER;C:\x",
        r"C:\Windows;C:\ProgramData\ssh-broker\",
        r"C:\Windows;C:\ProgramData\ssh-broker\\;C:\x",
        r#"C:\Windows;"C:\ProgramData\ssh-broker";C:\x"#,
        r"C:\Windows; C:\ProgramData\ssh-broker ;C:\x",
    ] {
        assert_eq!(with_directory(present, DIR), None, "{present}");
    }
    // The directory given with a trailing backslash is the same directory.
    assert_eq!(
        with_directory(r"C:\ProgramData\ssh-broker", r"C:\ProgramData\ssh-broker\"),
        None
    );
}

#[test]
fn a_variable_in_the_value_is_left_as_written_and_not_expanded() {
    let value = r"%SystemRoot%;%ProgramData%\ssh-broker";
    assert_eq!(
        with_directory(value, DIR).as_deref(),
        Some(r"%SystemRoot%;%ProgramData%\ssh-broker;C:\ProgramData\ssh-broker")
    );
}

#[test]
fn the_plan_keeps_the_stored_type_and_changes_nothing_it_cannot_judge() {
    let sz: Reading = Ok(Some(Stored::Sz(r"C:\Windows".into())));
    assert_eq!(
        plan(&sz, DIR),
        PathPlan::Write {
            value: format!(r"C:\Windows;{DIR}"),
            expand: false
        }
    );
    let expand: Reading = Ok(Some(Stored::ExpandSz(r"%SystemRoot%".into())));
    assert_eq!(
        plan(&expand, DIR),
        PathPlan::Write {
            value: format!(r"%SystemRoot%;{DIR}"),
            expand: true
        }
    );
    assert_eq!(
        plan(&Ok(Some(Stored::ExpandSz(format!("{DIR};%SystemRoot%")))), DIR),
        PathPlan::Present
    );
    for (reading, said) in [
        (Ok(Some(Stored::Other(7))), "type 7"),
        (Ok(None), "no Path value"),
        (Err("access is denied".to_owned()), "access is denied"),
    ] {
        match plan(&reading, DIR) {
            PathPlan::Refuse(why) => assert!(why.contains(said), "{why}"),
            other => panic!("{other:?}"),
        }
    }
}

#[test]
fn the_plan_refuses_a_value_the_environment_cannot_hold() {
    let long = format!("C:\\{}", "a".repeat(32767 - 3 - DIR.len()));
    match plan(&Ok(Some(Stored::Sz(long))), DIR) {
        PathPlan::Refuse(why) => assert!(why.contains("32767"), "{why}"),
        other => panic!("{other:?}"),
    }
    // One character shorter fits.
    let fits = format!("C:\\{}", "a".repeat(32767 - 4 - DIR.len()));
    assert!(matches!(plan(&Ok(Some(Stored::Sz(fits))), DIR), PathPlan::Write { .. }));
}

#[test]
fn the_path_row_passes_when_the_directory_is_on_the_path_and_says_what_to_do_when_not() {
    let on = row(&Ok(Some(Stored::ExpandSz(format!("%SystemRoot%;{DIR}")))), DIR);
    assert_eq!(on.name, "install directory on PATH");
    assert!(on.pass);
    assert_eq!(on.detail, format!("{DIR} is on the system PATH"));

    let off = row(&Ok(Some(Stored::Sz(r"C:\Windows".into()))), DIR);
    assert!(!off.pass);
    assert_eq!(
        off.detail,
        format!("{DIR} is not on the system PATH; run `ssh-broker apply`")
    );

    let unreadable = row(&Err("access is denied".into()), DIR);
    assert!(!unreadable.pass);
    assert!(
        unreadable
            .detail
            .contains("cannot read the system PATH: access is denied"),
        "{}",
        unreadable.detail
    );

    let strange = row(&Ok(Some(Stored::Other(7))), DIR);
    assert!(!strange.pass);
    assert!(strange.detail.contains("type 7"), "{}", strange.detail);
}
