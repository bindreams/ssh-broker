//! Unit tests for `winutil` (sibling-file style per project conventions).
use super::*;

/// A real OS error code must survive the conversion.
///
/// The regression this pins: reporting a fixed placeholder for every containment failure.
/// Two versions of this shipped — a hardcoded `ERROR_INVALID_HANDLE`, then an `E_FAIL` from a
/// `source()` walk that could not see through `#[error(transparent)]` — and neither was
/// detectable without asserting on the code itself.
#[test]
fn win_error_from_preserves_the_underlying_os_code() {
    const ERROR_ACCESS_DENIED: i32 = 5;
    let e = cosca::error::Error::from(std::io::Error::from_raw_os_error(ERROR_ACCESS_DENIED));
    let converted = win_error_from(&e, "assign the shell to a job object");
    assert_eq!(
        converted.code(),
        windows::core::HRESULT::from_win32(ERROR_ACCESS_DENIED as u32),
        "the real OS code must reach the log, not a placeholder"
    );
    assert!(
        converted.message().contains("assign the shell to a job object"),
        "the context must survive: {:?}",
        converted.message()
    );
}

/// A failure carrying no OS code still converts, rather than inventing one.
#[test]
fn win_error_from_falls_back_when_there_is_no_os_code() {
    let e = cosca::error::Error::Containment {
        detail: "job objects unavailable".into(),
    };
    let converted = win_error_from(&e, "contain");
    assert_eq!(converted.code(), windows::Win32::Foundation::E_FAIL);
    assert!(converted.message().contains("job objects unavailable"));
}

/// A variant that carries its OS error in a `source` field must be read too, not just `Io`.
#[test]
fn win_error_from_reads_os_codes_from_source_carrying_variants() {
    const ERROR_ACCESS_DENIED: i32 = 5;
    let e = cosca::error::Error::Unassessable {
        detail: "could not open the process".into(),
        source: Some(std::io::Error::from_raw_os_error(ERROR_ACCESS_DENIED)),
    };
    assert_eq!(
        win_error_from(&e, "assess").code(),
        windows::core::HRESULT::from_win32(ERROR_ACCESS_DENIED as u32)
    );
}

/// An `io::Error` built from an already-encoded HRESULT must survive unchanged; widening it a
/// second time would corrupt the code.
#[test]
fn win_error_from_does_not_re_encode_an_hresult() {
    let encoded = windows::core::HRESULT::from_win32(5).0; // 0x80070005, negative as i32
    let e = cosca::error::Error::from(std::io::Error::from_raw_os_error(encoded));
    assert_eq!(win_error_from(&e, "ctx").code(), windows::core::HRESULT(encoded));
}

/// The guard adds the flag to the thread's mode and puts back exactly what it read: a thread that already
/// had another bit set keeps it while the guard lives and after.
#[test]
fn the_message_box_guard_ors_the_thread_mode_and_restores_what_it_read() {
    use windows::Win32::System::Diagnostics::Debug::{
        GetThreadErrorMode, SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX, SetThreadErrorMode, THREAD_ERROR_MODE,
    };
    for already in [
        THREAD_ERROR_MODE(0),
        SEM_NOGPFAULTERRORBOX,
        SEM_FAILCRITICALERRORS,
        SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS,
    ] {
        // Each test runs on a thread of its own; this one's mode is set and read back here.
        unsafe { SetThreadErrorMode(already, None) }.unwrap();
        {
            let _guard = FailCriticalErrors::enter();
            assert_eq!(
                unsafe { GetThreadErrorMode() },
                already.0 | SEM_FAILCRITICALERRORS.0,
                "the mode inside the guard, from {already:?}"
            );
        }
        assert_eq!(unsafe { GetThreadErrorMode() }, already.0, "the mode after the guard");
    }
}

fn io_error(code: i32) -> windows::core::Error {
    std::io::Error::from_raw_os_error(code).into()
}

/// A start that failed in `CreateProcessW` is the program's fault unless the working directory is the
/// reason: then the shell is not blamed.
#[test]
fn a_failed_create_is_the_programs_unless_the_working_directory_is_not_one() {
    let dir = std::env::temp_dir();
    assert!(matches!(
        start_error_of_create(io_error(193), None),
        crate::shell::StartError::Program(_)
    ));
    assert!(matches!(
        start_error_of_create(io_error(193), Some(&dir)),
        crate::shell::StartError::Program(_)
    ));
    let missing = dir.join("ssh-broker-no-such-directory-for-a-test");
    let blamed = start_error_of_create(io_error(267), Some(&missing));
    assert!(matches!(blamed, crate::shell::StartError::Other(_)), "{blamed:?}");
    assert!(
        format!("{blamed}").contains("ssh-broker-no-such-directory-for-a-test"),
        "{blamed}"
    );
}

fn inherit_flag(handle: HANDLE) -> bool {
    use windows::Win32::Foundation::{GetHandleInformation, HANDLE_FLAG_INHERIT};
    let mut flags = 0u32;
    unsafe { GetHandleInformation(handle, &mut flags) }.unwrap();
    flags & HANDLE_FLAG_INHERIT.0 != 0
}

/// Only the read end is for a child; the agent's write end must never be inherited.
#[test]
fn a_hand_off_pipe_has_an_inheritable_read_end_and_a_private_write_end() {
    use std::os::windows::io::AsRawHandle;
    let pipe = Handoff::new(0).unwrap();
    assert!(inherit_flag(pipe.read().0));
    assert!(!inherit_flag(HANDLE(pipe.write.as_raw_handle())));
}

/// What was sent comes out of the read end, whole, and then the end of the stream.
#[test]
fn a_hand_off_pipe_delivers_what_is_sent_and_then_ends() {
    use std::io::Read;
    use std::os::windows::io::{BorrowedHandle, RawHandle};
    let pipe = Handoff::new(0).unwrap();
    // A second handle to the read end, as the child's inherited copy would be.
    let child_copy = unsafe { BorrowedHandle::borrow_raw(pipe.read().0.0 as RawHandle) }
        .try_clone_to_owned()
        .unwrap();
    let mut reader = std::fs::File::from(child_copy);
    // Far more than a pipe holds, so the send needs the reader to run.
    let bytes: Vec<u8> = (0..200_000u32).map(|n| (n % 251) as u8).collect();
    let read = std::thread::spawn(move || {
        let mut got = Vec::new();
        reader.read_to_end(&mut got).unwrap();
        got
    });
    pipe.send(&bytes).unwrap();
    assert_eq!(read.join().unwrap(), bytes);
}

/// With no reader left, the send fails instead of waiting for one.
#[test]
fn sending_into_a_hand_off_pipe_nobody_reads_fails() {
    let pipe = Handoff::new(0).unwrap();
    assert!(pipe.send(b"x").is_err());
}

/// A pipe made for its message holds all of it, so the send ends with the reader not reading: a
/// verb that is alive but slow to read cannot hold the agent's session thread.
#[test]
fn a_hand_off_pipe_made_for_its_message_takes_it_with_nobody_reading() {
    use std::io::Read;
    use std::os::windows::io::{BorrowedHandle, RawHandle};
    // Far more than the default buffer.
    let bytes: Vec<u8> = (0..200_000u32).map(|n| (n % 251) as u8).collect();
    let pipe = Handoff::new(bytes.len() as u32).unwrap();
    let child_copy = unsafe { BorrowedHandle::borrow_raw(pipe.read().0.0 as RawHandle) }
        .try_clone_to_owned()
        .unwrap();
    pipe.send(&bytes).unwrap();
    let mut got = Vec::new();
    std::fs::File::from(child_copy).read_to_end(&mut got).unwrap();
    assert_eq!(got, bytes);
}
