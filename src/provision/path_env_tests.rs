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

/// An expansion that changes nothing: the length of the text itself.
fn unexpanded(text: &str) -> Result<usize, String> {
    Ok(text.encode_utf16().count())
}

#[test]
fn the_plan_keeps_the_stored_type_and_changes_nothing_it_cannot_judge() {
    let sz: Reading = Ok(Some(Stored::Sz(r"C:\Windows".into())));
    assert_eq!(
        plan(&sz, DIR, unexpanded),
        PathPlan::Write {
            value: format!(r"C:\Windows;{DIR}"),
            expand: false
        }
    );
    let expand: Reading = Ok(Some(Stored::ExpandSz(r"%SystemRoot%".into())));
    assert_eq!(
        plan(&expand, DIR, unexpanded),
        PathPlan::Write {
            value: format!(r"%SystemRoot%;{DIR}"),
            expand: true
        }
    );
    assert_eq!(
        plan(
            &Ok(Some(Stored::ExpandSz(format!("{DIR};%SystemRoot%")))),
            DIR,
            unexpanded
        ),
        PathPlan::Present
    );
    for (reading, said) in [
        (Ok(Some(Stored::Other(7))), "type 7"),
        (Ok(None), "no Path value"),
        (Err("access is denied".to_owned()), "access is denied"),
    ] {
        match plan(&reading, DIR, unexpanded) {
            PathPlan::Refuse(why) => assert!(why.contains(said), "{why}"),
            other => panic!("{other:?}"),
        }
    }
}

#[test]
fn the_plan_refuses_a_value_the_environment_cannot_hold() {
    let long = format!("C:\\{}", "a".repeat(32767 - 3 - DIR.len()));
    match plan(&Ok(Some(Stored::Sz(long))), DIR, unexpanded) {
        PathPlan::Refuse(why) => assert!(why.contains("32767"), "{why}"),
        other => panic!("{other:?}"),
    }
    // One character shorter fits.
    let fits = format!("C:\\{}", "a".repeat(32767 - 4 - DIR.len()));
    assert!(matches!(
        plan(&Ok(Some(Stored::Sz(fits))), DIR, unexpanded),
        PathPlan::Write { .. }
    ));
}

#[test]
fn an_expanding_value_is_measured_after_expansion_and_a_plain_one_as_stored() {
    let stored = Ok(Some(Stored::ExpandSz(r"%SystemRoot%;%LONG%".into())));
    // Short as stored, too long once `%LONG%` is expanded: the length is the expansion's.
    let measured = std::cell::RefCell::new(Vec::new());
    let plan_of = plan(&stored, DIR, |text| {
        measured.borrow_mut().push(text.to_owned());
        Ok(40000)
    });
    match plan_of {
        PathPlan::Refuse(why) => assert!(why.contains("32767") && why.contains("expanded"), "{why}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(*measured.borrow(), [format!(r"%SystemRoot%;%LONG%;{DIR}")]);
    // The same value that expands to a length that fits is written.
    assert!(matches!(
        plan(&stored, DIR, |_| Ok(32767)),
        PathPlan::Write { expand: true, .. }
    ));
    assert!(matches!(plan(&stored, DIR, |_| Ok(32768)), PathPlan::Refuse(_)));
    // An expansion that cannot be had refuses, with the cause.
    match plan(&stored, DIR, |_| Err("the environment is gone".into())) {
        PathPlan::Refuse(why) => assert!(why.contains("the environment is gone"), "{why}"),
        other => panic!("{other:?}"),
    }
    // A `REG_SZ` is never expanded.
    let plain = Ok(Some(Stored::Sz(r"%SystemRoot%".into())));
    assert!(matches!(
        plan(&plain, DIR, |_| panic!("a REG_SZ is not expanded")),
        PathPlan::Write { expand: false, .. }
    ));
    // A directory that is on the value already is not measured.
    let present = Ok(Some(Stored::ExpandSz(format!("%LONG%;{DIR}"))));
    assert_eq!(plan(&present, DIR, |_| panic!("nothing is written")), PathPlan::Present);
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
        format!("{DIR} is not on the system PATH; run `ssh-broker install`")
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

// the stored value =====

/// A registry string's data: UTF-16 little-endian, as stored.
fn data(units: &[u16]) -> Vec<u8> {
    units.iter().flat_map(|unit| unit.to_le_bytes()).collect()
}

fn units(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

#[test]
fn a_stored_string_is_decoded_with_or_without_its_terminators_and_keeps_its_type() {
    let text = r"C:\Windows;D:\Ünï";
    let bare = units(text);
    let one = [bare.clone(), vec![0]].concat();
    let two = [bare.clone(), vec![0, 0]].concat();
    for stored in [&bare, &one, &two] {
        assert_eq!(decode_string(&data(stored), false), Ok(Stored::Sz(text.into())));
        assert_eq!(decode_string(&data(stored), true), Ok(Stored::ExpandSz(text.into())));
    }
    assert_eq!(decode_string(&[], false), Ok(Stored::Sz(String::new())));
    assert_eq!(decode_string(&data(&[0]), true), Ok(Stored::ExpandSz(String::new())));
}

#[test]
fn a_stored_string_that_would_not_survive_a_write_back_is_refused_with_the_reason() {
    // An unpaired surrogate is not text: a lossy decode would write U+FFFD in its place.
    let unpaired = [units(r"C:\a;"), vec![0xD800], units(r";C:\b")].concat();
    let why = decode_string(&data(&unpaired), false).unwrap_err();
    assert!(why.contains("UTF-16"), "{why}");
    // Data after an embedded NUL would be cut off.
    let embedded = [units(r"C:\a;"), vec![0], units(r"C:\b"), vec![0]].concat();
    let why = decode_string(&data(&embedded), true).unwrap_err();
    assert!(why.contains("NUL"), "{why}");
    // Half a code unit.
    let mut odd = data(&units(r"C:\a"));
    odd.push(0x41);
    let why = decode_string(&odd, false).unwrap_err();
    assert!(why.contains("whole"), "{why}");
    // Each of them leaves the system PATH alone.
    assert!(matches!(
        plan(&decode_string(&data(&embedded), true).map(Some), DIR, unexpanded),
        PathPlan::Refuse(why) if why.contains("NUL")
    ));
}

#[test]
fn a_decoded_string_is_written_back_as_it_was_read() {
    for text in [r"C:\Windows;%SystemRoot%\System32;", "", r"D:\ü\𝄞;E:\x"] {
        let read = decode_string(&data(&[units(text), vec![0]].concat()), true).unwrap();
        let (Stored::Sz(back) | Stored::ExpandSz(back)) = read else {
            panic!("a string")
        };
        assert_eq!(back, text);
    }
}
