//! Unit tests for `console_prompt`: why the shim has no agent (no account, no console).
use super::*;
use crate::socket_loc::SocketLocationError;
use crate::test_support::TempProfile;
use crate::userdir::NoProfile;

fn some_location() -> anyhow::Result<SocketLocation> {
    let dir = std::path::PathBuf::from(r"C:\nowhere");
    Ok(SocketLocation {
        path: dir.join("agent.sock"),
        dir,
    })
}

fn refused() -> anyhow::Result<socket2::Socket> {
    Err(anyhow::anyhow!("a connect that failed for no OS reason"))
}

// absence: the shapes that are not OS codes -----

#[test]
fn absence_of_a_location_without_a_profile_is_no_profile_yet() {
    assert_eq!(absence(&refused(), &Err(NoProfile.into())), Absence::NoProfileYet);
}

#[test]
fn absence_of_a_too_long_path_is_other() {
    let too_long: anyhow::Error = SocketLocationError::TooLong {
        path: std::path::PathBuf::from(r"C:\very\long\agent.sock"),
        bytes: 120,
        max: 107,
    }
    .into();
    assert_eq!(absence(&refused(), &Err(too_long)), Absence::Other);
}

#[test]
fn absence_of_any_other_location_error_is_other() {
    assert_eq!(
        absence(&refused(), &Err(anyhow::anyhow!("the token could not be read"))),
        Absence::Other
    );
}

#[test]
fn absence_of_a_protocol_error_is_other() {
    assert_eq!(absence(&refused(), &some_location()), Absence::Other);
}

#[test]
fn absence_of_an_unobserved_os_code_is_other() {
    for code in [5, 10013, 10061 + 1000] {
        let denied: anyhow::Result<socket2::Socket> = Err(std::io::Error::from_raw_os_error(code).into());
        assert_eq!(absence(&denied, &some_location()), Absence::Other, "code {code}");
    }
}

// absence: the codes Windows returns, observed with real connects -----

/// The raw OS error a real `connect` to `path` fails with.
fn real_connect(path: &std::path::Path) -> anyhow::Result<socket2::Socket> {
    crate::afunix::connect(path)
}

fn code_of(result: &anyhow::Result<socket2::Socket>) -> String {
    match result {
        Ok(_) => "connected".to_string(),
        Err(e) => match e
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::raw_os_error)
        {
            Some(code) => format!("os error {code}"),
            None => format!("no OS code: {e:#}"),
        },
    }
}

#[test]
fn absence_of_a_connect_to_a_missing_folder_is_no_agent() {
    // The profile exists and its `AppData\Local` too, but no agent has made `ssh-broker` yet.
    let profile = TempProfile::new("ab-dir");
    let location = profile.location();
    assert!(!location.dir.exists());
    let connect = real_connect(&location.path);
    assert_eq!(
        absence(&connect, &Ok(location)),
        Absence::NoAgent,
        "a connect to a missing folder failed with {}",
        code_of(&connect)
    );
}

#[test]
fn absence_of_a_connect_to_a_missing_file_in_an_existing_folder_is_no_agent() {
    let profile = TempProfile::new("ab-file");
    let location = profile.location();
    std::fs::create_dir_all(&location.dir).unwrap();
    let connect = real_connect(&location.path);
    assert_eq!(
        absence(&connect, &Ok(location)),
        Absence::NoAgent,
        "a connect to a missing socket file failed with {}",
        code_of(&connect)
    );
}

/// What `logout` leaves behind: a socket file nobody listens on any more.
#[test]
fn absence_of_a_connect_to_a_stale_socket_file_is_no_agent() {
    let profile = TempProfile::new("ab-stale");
    let location = profile.location();
    crate::userdir::ensure_socket_dir(&location, &crate::acl::Sid::current_user().unwrap()).unwrap();
    drop(crate::afunix::Listener::bind(&location.path).unwrap());
    assert!(location.path.exists(), "the stale socket file is what is being tested");
    let connect = real_connect(&location.path);
    assert_eq!(
        absence(&connect, &Ok(location)),
        Absence::NoAgent,
        "a connect to a stale socket file failed with {}",
        code_of(&connect)
    );
}

// is_no_agent: the same codes, for a caller that has only the connect error -----

#[test]
fn only_the_observed_codes_for_nothing_listening_are_no_agent() {
    for code in [10050, 10061] {
        let error: anyhow::Error = std::io::Error::from_raw_os_error(code).into();
        assert!(is_no_agent(&error), "code {code}");
    }
    for code in [5, 10013, 10048] {
        let error: anyhow::Error = std::io::Error::from_raw_os_error(code).into();
        assert!(!is_no_agent(&error), "code {code}");
    }
    assert!(!is_no_agent(&anyhow::anyhow!("not an OS error")));
}
