//! Unit tests for `winutil` (sibling-file style per project conventions).
use super::*;
use std::mem::offset_of;
use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_BAD_LENGTH, ERROR_INSUFFICIENT_BUFFER, WIN32_ERROR};

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
        start_error_of_create(io_error(193), None, false),
        crate::shell::StartError::Program(_)
    ));
    assert!(matches!(
        start_error_of_create(io_error(193), Some(&dir), false),
        crate::shell::StartError::Program(_)
    ));
    let missing = dir.join("ssh-broker-no-such-directory-for-a-test");
    let blamed = start_error_of_create(io_error(267), Some(&missing), false);
    assert!(matches!(blamed, crate::shell::StartError::Other(_)), "{blamed:?}");
    assert!(
        format!("{blamed}").contains("ssh-broker-no-such-directory-for-a-test"),
        "{blamed}"
    );
}

/// The shell is blamed for every failure of `CreateProcessW` except a machine out of memory, handles,
/// processes, quota or commit: the built-in would meet that too. For any other code (the image,
/// antivirus, a code policy, an unreadable disk or share, a bad handle, parameter or buffer that some
/// image-specific condition can also produce, a code nobody listed) the built-in is the only safe
/// answer, and a wrong "program" costs a warning while a wrong "other" locks the user out.
#[test]
fn a_failed_create_blames_the_program_unless_the_machine_is_out_of_a_resource() {
    let program = [
        1,    // ERROR_INVALID_FUNCTION (unlisted)
        2,    // ERROR_FILE_NOT_FOUND
        3,    // ERROR_PATH_NOT_FOUND
        5,    // ERROR_ACCESS_DENIED
        6,    // ERROR_INVALID_HANDLE
        11,   // ERROR_BAD_FORMAT
        21,   // ERROR_NOT_READY
        32,   // ERROR_SHARING_VIOLATION
        53,   // ERROR_BAD_NETPATH
        65,   // ERROR_NETWORK_ACCESS_DENIED
        87,   // ERROR_INVALID_PARAMETER
        122,  // ERROR_INSUFFICIENT_BUFFER
        123,  // ERROR_INVALID_NAME
        191,  // ERROR_INVALID_EXE_SIGNATURE
        192,  // ERROR_EXE_MARKED_INVALID
        193,  // ERROR_BAD_EXE_FORMAT
        206,  // ERROR_FILENAME_EXCED_RANGE (a program path over MAX_PATH)
        216,  // ERROR_EXE_MACHINE_TYPE_MISMATCH
        225,  // ERROR_VIRUS_INFECTED
        226,  // ERROR_VIRUS_DELETED
        577,  // ERROR_INVALID_IMAGE_HASH
        740,  // ERROR_ELEVATION_REQUIRED
        786,  // ERROR_ACCESS_DISABLED_NO_SAFER_UI_BY_POLICY
        1006, // ERROR_FILE_INVALID
        1117, // ERROR_IO_DEVICE
        1260, // ERROR_ACCESS_DISABLED_BY_POLICY
        1326, // ERROR_LOGON_FAILURE
        1392, // ERROR_FILE_CORRUPT
        1393, // ERROR_DISK_CORRUPT
        1920, // ERROR_CANT_ACCESS_FILE
        9999, // no such code
    ];
    let other = [
        4,    // ERROR_TOO_MANY_OPEN_FILES
        8,    // ERROR_NOT_ENOUGH_MEMORY
        14,   // ERROR_OUTOFMEMORY
        89,   // ERROR_NO_PROC_SLOTS
        567,  // ERROR_PAGEFILE_QUOTA_EXCEEDED
        1130, // ERROR_NOT_ENOUGH_SERVER_MEMORY
        1450, // ERROR_NO_SYSTEM_RESOURCES
        1451, // ERROR_NONPAGED_SYSTEM_RESOURCES
        1452, // ERROR_PAGED_SYSTEM_RESOURCES
        1453, // ERROR_WORKING_SET_QUOTA
        1454, // ERROR_PAGEFILE_QUOTA
        1455, // ERROR_COMMITMENT_LIMIT
        1816, // ERROR_NOT_ENOUGH_QUOTA
    ];
    for code in program {
        let blamed = start_error_of_create(io_error(code), None, false);
        assert!(
            matches!(blamed, crate::shell::StartError::Program(_)),
            "{code}: {blamed:?}"
        );
    }
    for code in other {
        let blamed = start_error_of_create(io_error(code), None, false);
        assert!(
            matches!(blamed, crate::shell::StartError::Other(_)),
            "{code}: {blamed:?}"
        );
    }
    // An error that is not a Win32 code says nothing against the program either.
    let blamed = start_error_of_create(
        windows::core::Error::from(windows::Win32::Foundation::E_FAIL),
        None,
        false,
    );
    assert!(matches!(blamed, crate::shell::StartError::Program(_)), "{blamed:?}");
}

/// `CreateProcessAsUserW` fails with `ERROR_PRIVILEGE_NOT_HELD` when the process lacks a privilege the call
/// needs with that token: the program is not at fault, and the built-in shell would meet it too. Without a
/// token the code is held against the program like any other.
#[test]
fn a_privilege_failure_with_a_token_is_not_the_programs() {
    const ERROR_PRIVILEGE_NOT_HELD: i32 = 1314;
    let blamed = start_error_of_create(io_error(ERROR_PRIVILEGE_NOT_HELD), None, true);
    assert!(matches!(blamed, crate::shell::StartError::Other(_)), "{blamed:?}");
    assert!(
        format!("{blamed:#}").contains("token"),
        "the token is named: {blamed:#}"
    );
    let blamed = start_error_of_create(io_error(ERROR_PRIVILEGE_NOT_HELD), None, false);
    assert!(matches!(blamed, crate::shell::StartError::Program(_)), "{blamed:?}");
    // Any other failure with a token is still judged as it is without one.
    let blamed = start_error_of_create(io_error(193), None, true);
    assert!(matches!(blamed, crate::shell::StartError::Program(_)), "{blamed:?}");
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

/// Every child the agent starts begins suspended with an extended startup block; the console choice adds
/// no window flag for a pseudoconsole (whose host shows none) and `CREATE_NO_WINDOW` for a command on pipes.
#[test]
fn a_child_started_without_a_pseudoconsole_gets_a_console_with_no_window() {
    use windows::Win32::System::Threading::{CREATE_NO_WINDOW, CREATE_SUSPENDED, EXTENDED_STARTUPINFO_PRESENT};
    let always = CREATE_SUSPENDED.0 | EXTENDED_STARTUPINFO_PRESENT.0;
    let pseudo = creation_flags(&ChildConsole::Pseudo(windows::Win32::System::Console::HPCON(1)));
    let none = creation_flags(&ChildConsole::NoWindow);
    assert_eq!(pseudo.0, always);
    assert_eq!(none.0, always | CREATE_NO_WINDOW.0);
}

#[test]
fn token_information_of_an_invalid_handle_carries_the_windows_error() {
    use windows::Win32::Security::TokenUser;
    let err = token_information(HANDLE::default(), TokenUser)
        .err()
        .expect("an invalid handle reads nothing");
    let os = err
        .downcast_ref::<windows::core::Error>()
        .expect("Windows' error is kept");
    assert_eq!(os.code(), windows::core::HRESULT::from_win32(6), "{err:#}"); // ERROR_INVALID_HANDLE
}

#[test]
fn token_information_of_a_handle_without_token_query_is_access_denied() {
    use windows::Win32::Security::{TOKEN_DUPLICATE, TokenUser};
    let mut token = HANDLE::default();
    // SAFETY: a valid out-pointer; the handle is closed by `OwnedHandle`.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE, &mut token) }.unwrap();
    let token = OwnedHandle(token);
    let err = token_information(token.0, TokenUser)
        .err()
        .expect("no TOKEN_QUERY reads nothing");
    let os = err
        .downcast_ref::<windows::core::Error>()
        .expect("Windows' error is kept");
    assert_eq!(os.code(), windows::core::HRESULT::from_win32(5), "{err:#}"); // ERROR_ACCESS_DENIED
}

#[test]
fn token_information_of_this_process_holds_a_header() {
    use windows::Win32::Security::{TOKEN_USER, TokenUser};
    let info = token_information(own_token().unwrap().0, TokenUser).unwrap();
    assert!(info.len >= size_of::<TOKEN_USER>(), "{}", info.len);
    // SAFETY: every bit pattern is a valid `TOKEN_USER` (a pointer and an integer).
    let user = unsafe { info.header::<TOKEN_USER>() }.unwrap();
    assert!(!user.User.Sid.0.is_null());
}

// Reading token information -----

#[test]
fn the_sids_in_this_process_token_lie_inside_the_returned_value() {
    use windows::Win32::Security::{
        SID_AND_ATTRIBUTES, TOKEN_GROUPS, TOKEN_MANDATORY_LABEL, TOKEN_USER, TokenGroups, TokenIntegrityLevel,
        TokenUser,
    };
    let token = own_token().unwrap();

    let info = token_information(token.0, TokenUser).unwrap();
    // SAFETY: every bit pattern is a valid `TOKEN_USER` (a pointer and an integer).
    let user = unsafe { info.header::<TOKEN_USER>() }.unwrap();
    assert!(info.sid(user.User.Sid).is_ok(), "TokenUser");

    let info = token_information(token.0, TokenIntegrityLevel).unwrap();
    // SAFETY: every bit pattern is a valid `TOKEN_MANDATORY_LABEL` (a pointer and an integer).
    let label = unsafe { info.header::<TOKEN_MANDATORY_LABEL>() }.unwrap();
    assert!(info.sid(label.Label.Sid).is_ok(), "TokenIntegrityLevel");

    let info = token_information(token.0, TokenGroups).unwrap();
    // SAFETY: the group count is a `u32`.
    let count = unsafe { info.header::<u32>() }.unwrap();
    assert!(count > 0, "a token has at least one group");
    // SAFETY: every bit pattern is a valid `SID_AND_ATTRIBUTES` (a pointer and an integer).
    let groups = unsafe { info.array::<SID_AND_ATTRIBUTES>(offset_of!(TOKEN_GROUPS, Groups), count as usize) }.unwrap();
    for (n, group) in groups.iter().enumerate() {
        assert!(info.sid(group.Sid).is_ok(), "TokenGroups[{n}]");
    }
}

/// A `TokenInformation` holding `bytes`. Data built this way must hold no pointers: the ones a real
/// read holds point into its own buffer, and a copy's would not.
fn from_bytes(bytes: &[u8]) -> TokenInformation {
    let mut storage = vec![0u64; bytes.len().div_ceil(size_of::<u64>())];
    // SAFETY: the storage holds at least `bytes.len()` bytes, and `u8` has no alignment to meet.
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), storage.as_mut_ptr().cast::<u8>(), bytes.len()) };
    TokenInformation {
        storage,
        len: bytes.len(),
    }
}

/// A buffer of a `u32` count, four bytes of padding, then the `u64`s `values`: the shape of a
/// `TOKEN_GROUPS`, with plain data in place of SIDs.
fn counted(count: u32, values: &[u64]) -> TokenInformation {
    let mut bytes = count.to_ne_bytes().to_vec();
    bytes.extend([0u8; 4]);
    for value in values {
        bytes.extend(value.to_ne_bytes());
    }
    from_bytes(&bytes)
}

#[test]
fn a_header_and_the_array_after_it_read_back() {
    let info = counted(2, &[7, 9]);
    assert_eq!(info.len, 24);
    // SAFETY: `u32` and `u64` accept every bit pattern.
    unsafe {
        assert_eq!(info.header::<u32>().unwrap(), 2);
        assert_eq!(info.array::<u64>(8, 2).unwrap(), [7, 9]);
        assert_eq!(info.array::<u64>(8, 0).unwrap(), [] as [u64; 0]);
    }
}

#[test]
fn a_buffer_shorter_than_the_header_is_an_error() {
    let info = from_bytes(&[1, 2, 3]);
    // SAFETY: `u32` accepts every bit pattern.
    let err = unsafe { info.header::<u32>() }.unwrap_err();
    assert!(err.to_string().contains("3 bytes"), "{err:#}");
}

#[test]
fn a_count_that_runs_past_the_buffer_is_an_error() {
    let info = counted(3, &[7, 9]);
    // SAFETY: `u64` accepts every bit pattern.
    let err = unsafe { info.array::<u64>(8, 3) }.unwrap_err();
    assert!(err.to_string().contains("24 bytes"), "{err:#}");
}

#[test]
fn a_count_whose_size_overflows_is_an_error() {
    let info = counted(2, &[7, 9]);
    // SAFETY: `u64` accepts every bit pattern.
    unsafe {
        assert!(info.array::<u64>(8, usize::MAX).is_err());
        assert!(info.array::<u64>(usize::MAX - 7, 1).is_err());
    }
}

#[test]
fn the_length_is_what_the_call_returned_not_the_rounded_storage() {
    // 12 bytes live in 16 bytes of storage; the 4 after them were never written.
    let info = from_bytes(&[0u8; 12]);
    assert_eq!(info.len, 12);
    // SAFETY: `u64` accepts every bit pattern.
    assert!(unsafe { info.array::<u64>(8, 1) }.is_err());
}

#[test]
fn an_offset_that_does_not_suit_the_element_is_an_error() {
    let info = counted(1, &[7]);
    // SAFETY: `u64` accepts every bit pattern.
    assert!(unsafe { info.array::<u64>(4, 1) }.is_err());
}

#[test]
fn a_fixed_size_class_reads_through_the_same_reader() {
    use windows::Win32::Security::{TOKEN_STATISTICS, TokenPrimary, TokenStatistics};
    let token = own_token().unwrap();
    let info = token_information(token.0, TokenStatistics).unwrap();
    assert_eq!(info.len, size_of::<TOKEN_STATISTICS>());
    // SAFETY: `TOKEN_STATISTICS` is plain data.
    let stats = unsafe { info.header::<TOKEN_STATISTICS>() }.unwrap();
    assert_eq!(stats.TokenType, TokenPrimary);
}

// Sizing and growing the read -----

/// What a fake read step does on one call.
enum Answer {
    /// Fails with `code`; reports `length` when it is `Some`, and leaves the length alone when not.
    Fail { code: WIN32_ERROR, length: Option<u32> },
    /// Succeeds, reporting `length` when it is `Some`, and writes `MARKER` into storage it is given.
    Done { length: Option<u32> },
}
use Answer::{Done, Fail};

const MARKER: u64 = 0x5eed;

/// Runs `read_information` with a step that answers from `answers`, one per call (a call past them
/// fails the test). Returns the outcome and the length each call was told. Every call must get new,
/// zeroed storage that holds the told length: a step that failed has dirtied the one before.
fn run(answers: &[Answer]) -> (anyhow::Result<TokenInformation>, Vec<u32>) {
    let mut told_by_call = Vec::new();
    let mut answers = answers.iter();
    let outcome = read_information(|storage, told, returned| {
        told_by_call.push(told);
        assert_eq!(storage.len(), (told as usize).div_ceil(8), "storage for {told} bytes");
        assert!(storage.iter().all(|&word| word == 0), "storage that was not new");
        let answer = answers.next().expect("the loop called the step again");
        let (outcome, length) = match answer {
            Fail { code, length } => (Err(win32(*code)), *length),
            Done { length } => (Ok(()), *length),
        };
        if let Some(first) = storage.first_mut() {
            *first = if outcome.is_ok() { MARKER } else { u64::MAX };
        }
        if let Some(length) = length {
            *returned = length;
        }
        outcome
    });
    (outcome, told_by_call)
}

fn win32(code: WIN32_ERROR) -> windows::core::Error {
    windows::core::HRESULT::from_win32(code.0).into()
}

fn code_of(err: &anyhow::Error) -> windows::core::HRESULT {
    err.downcast_ref::<windows::core::Error>()
        .expect("Windows' error is kept")
        .code()
}

#[test]
fn a_read_that_fits_the_probed_length_succeeds_at_once() {
    let (info, told) = run(&[
        Fail {
            code: ERROR_INSUFFICIENT_BUFFER,
            length: Some(16),
        },
        Done { length: None },
    ]);
    let info = info.unwrap();
    assert_eq!(told, [0, 16]);
    assert_eq!(info.len, 16);
    // SAFETY: `u64` accepts every bit pattern.
    assert_eq!(unsafe { info.header::<u64>() }.unwrap(), MARKER);
}

#[test]
fn a_read_that_returns_less_than_it_was_told_keeps_what_it_returned() {
    let (info, _) = run(&[
        Fail {
            code: ERROR_INSUFFICIENT_BUFFER,
            length: Some(16),
        },
        Done { length: Some(10) },
    ]);
    assert_eq!(info.unwrap().len, 10);
}

#[test]
fn a_probe_that_succeeds_with_a_length_is_read_from_that_length() {
    let (info, told) = run(&[Done { length: Some(16) }, Done { length: None }]);
    assert_eq!(info.unwrap().len, 16);
    assert_eq!(told, [0, 16]);
}

#[test]
fn a_probe_that_failed_with_another_error_and_set_a_length_is_read() {
    let (info, told) = run(&[
        Fail {
            code: ERROR_BAD_LENGTH,
            length: Some(16),
        },
        Done { length: None },
    ]);
    assert_eq!(info.unwrap().len, 16);
    assert_eq!(told, [0, 16]);
}

#[test]
fn a_probe_that_set_no_length_and_failed_is_that_error() {
    let (info, told) = run(&[Fail {
        code: ERROR_ACCESS_DENIED,
        length: None,
    }]);
    let err = info.err().expect("nothing to size the read by");
    assert_eq!(code_of(&err), windows::core::HRESULT::from_win32(ERROR_ACCESS_DENIED.0));
    assert!(format!("{err:#}").contains("size probe"), "{err:#}");
    assert_eq!(told, [0]);
}

#[test]
fn a_probe_that_set_no_length_and_succeeded_is_an_error() {
    let (info, told) = run(&[Done { length: None }]);
    let err = info.err().expect("nothing to size the read by");
    assert!(err.to_string().contains("no length"), "{err:#}");
    assert_eq!(told, [0]);
}

/// The token grew between the probe and the read: the read reports the length it needs, and is made
/// again with new storage of that size. Both codes Windows uses for it count.
#[test]
fn a_read_that_reports_a_larger_length_is_made_again_with_new_storage() {
    for code in [ERROR_INSUFFICIENT_BUFFER, ERROR_BAD_LENGTH] {
        let (info, told) = run(&[
            Fail {
                code: ERROR_INSUFFICIENT_BUFFER,
                length: Some(16),
            },
            Fail { code, length: Some(24) },
            Done { length: Some(24) },
        ]);
        let info = info.unwrap_or_else(|e| panic!("{code:?}: {e:#}"));
        assert_eq!(told, [0, 16, 24], "{code:?}");
        assert_eq!(info.len, 24, "{code:?}");
        // SAFETY: `u64` accepts every bit pattern.
        assert_eq!(unsafe { info.header::<u64>() }.unwrap(), MARKER, "{code:?}");
    }
}

#[test]
fn a_read_that_grows_again_is_made_again() {
    let (info, told) = run(&[
        Fail {
            code: ERROR_INSUFFICIENT_BUFFER,
            length: Some(16),
        },
        Fail {
            code: ERROR_INSUFFICIENT_BUFFER,
            length: Some(24),
        },
        Fail {
            code: ERROR_BAD_LENGTH,
            length: Some(40),
        },
        Done { length: Some(40) },
    ]);
    assert_eq!(info.unwrap().len, 40);
    assert_eq!(told, [0, 16, 24, 40]);
}

#[test]
fn a_read_that_fails_with_another_error_is_that_error_even_with_a_larger_length() {
    let (info, told) = run(&[
        Fail {
            code: ERROR_INSUFFICIENT_BUFFER,
            length: Some(16),
        },
        Fail {
            code: ERROR_ACCESS_DENIED,
            length: Some(100),
        },
    ]);
    let err = info.err().expect("access denied is not a size");
    assert_eq!(code_of(&err), windows::core::HRESULT::from_win32(ERROR_ACCESS_DENIED.0));
    assert_eq!(told, [0, 16]);
}

/// A failure that names no larger length is not a condition that clears by trying again.
#[test]
fn a_read_that_is_too_small_and_reports_no_larger_length_is_an_error() {
    for length in [None, Some(16), Some(8)] {
        let (info, told) = run(&[
            Fail {
                code: ERROR_INSUFFICIENT_BUFFER,
                length: Some(16),
            },
            Fail {
                code: ERROR_INSUFFICIENT_BUFFER,
                length,
            },
        ]);
        let err = info.err().expect("nothing to grow to");
        assert_eq!(
            code_of(&err),
            windows::core::HRESULT::from_win32(ERROR_INSUFFICIENT_BUFFER.0),
            "{length:?}"
        );
        assert_eq!(told, [0, 16], "{length:?}");
    }
}

#[test]
fn a_read_that_returns_more_than_it_was_told_is_an_error() {
    let (info, _) = run(&[
        Fail {
            code: ERROR_INSUFFICIENT_BUFFER,
            length: Some(16),
        },
        Done { length: Some(17) },
    ]);
    let err = info.err().expect("more bytes than the storage holds");
    assert!(err.to_string().contains("17 bytes"), "{err:#}");
}

// Following a pointer found in the data -----

/// Eight bytes of padding, then the SID `S-1-5-18` (a revision, a count of one, a six-byte authority
/// and one sub-authority): twenty bytes, the SID ending at the last.
fn with_a_sid() -> TokenInformation {
    let mut bytes = vec![0u8; 8];
    bytes.extend([1, 1, 0, 0, 0, 0, 0, 5]);
    bytes.extend(18u32.to_ne_bytes());
    from_bytes(&bytes)
}

/// The pointer `offset` bytes from the start of the data's buffer, which may lie outside it.
fn pointer_at(info: &TokenInformation, offset: isize) -> windows::Win32::Security::PSID {
    windows::Win32::Security::PSID(info.start().wrapping_offset(offset) as *mut core::ffi::c_void)
}

#[test]
fn a_sid_that_fits_inside_the_data_is_returned() {
    let info = with_a_sid();
    let sid = pointer_at(&info, 8);
    assert_eq!(info.sid(sid).unwrap(), sid);
}

#[test]
fn a_null_sid_is_an_error() {
    let info = with_a_sid();
    let err = info.sid(windows::Win32::Security::PSID::default()).unwrap_err();
    assert!(err.to_string().contains("null"), "{err:#}");
}

#[test]
fn a_sid_before_the_data_is_an_error() {
    let info = with_a_sid();
    assert!(info.sid(pointer_at(&info, -1)).is_err());
}

#[test]
fn a_sid_one_past_the_end_of_the_data_is_an_error() {
    let info = with_a_sid();
    assert!(info.sid(pointer_at(&info, info.len as isize)).is_err());
}

#[test]
fn a_sid_whose_header_runs_past_the_end_is_an_error() {
    // The data ends before the buffer does: the header at 16 fits the buffer but not the data.
    let info = with_a_sid();
    assert!(info.sid(pointer_at(&info, info.len as isize - 4)).is_err());
}

#[test]
fn a_sid_whose_sub_authorities_run_past_the_end_is_an_error() {
    // The header fits, but its count of one sub-authority needs four bytes more.
    let info = from_bytes(&[0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 5]);
    assert!(info.sid(pointer_at(&info, 8)).is_err());
}

#[test]
fn a_sid_with_no_sub_authority_is_returned() {
    // A header of eight bytes, ending at the last byte of the data.
    let info = from_bytes(&[0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 5]);
    let sid = pointer_at(&info, 8);
    assert_eq!(info.sid(sid).unwrap(), sid);
}

#[test]
fn a_sid_whose_sub_authorities_end_at_the_last_byte_is_returned() {
    // Two sub-authorities: the SID is 16 bytes, from 8 to the 24 the data holds.
    let mut bytes = vec![0u8; 8];
    bytes.extend([1, 2, 0, 0, 0, 0, 0, 5]);
    bytes.extend(21u32.to_ne_bytes());
    bytes.extend(544u32.to_ne_bytes());
    let info = from_bytes(&bytes);
    assert_eq!(info.len, 24);
    let sid = pointer_at(&info, 8);
    assert_eq!(info.sid(sid).unwrap(), sid);
}

#[test]
fn a_sid_claiming_the_most_sub_authorities_in_a_short_buffer_is_an_error() {
    // A count of 255 needs 1,028 bytes from the start of the SID; the data has 16.
    let info = from_bytes(&[0, 0, 0, 0, 0, 0, 0, 0, 1, 255, 0, 0, 0, 0, 0, 5]);
    let err = info.sid(pointer_at(&info, 8)).unwrap_err();
    assert!(err.to_string().contains("255 sub-authorities"), "{err:#}");
}

#[test]
fn a_sid_not_aligned_for_its_sub_authorities_is_an_error() {
    // The same SID as `with_a_sid`, one byte later: whole and inside the data, but a `u32` read of
    // its sub-authority would be misaligned.
    let mut bytes = vec![0u8; 9];
    bytes.extend([1, 1, 0, 0, 0, 0, 0, 5]);
    bytes.extend(18u32.to_ne_bytes());
    let info = from_bytes(&bytes);
    let err = info.sid(pointer_at(&info, 9)).unwrap_err();
    assert!(err.to_string().contains("aligned"), "{err:#}");
}

// Walking a token's groups -----

/// The group reader hands out each group of the token once, in the token's order, with the attributes the
/// token holds, and a SID that lies inside the token information it was read from.
#[test]
fn the_group_reader_visits_each_group_of_this_process_token_once() {
    use windows::Win32::Security::{SID_AND_ATTRIBUTES, TOKEN_GROUPS, TokenGroups};
    let token = own_token().unwrap();
    let info = token_information(token.0, TokenGroups).unwrap();
    // SAFETY: the group count is a `u32`.
    let count = unsafe { info.header::<u32>() }.unwrap();
    // SAFETY: every bit pattern is a valid `SID_AND_ATTRIBUTES` (a pointer and an integer).
    let expected: Vec<u32> =
        unsafe { info.array::<SID_AND_ATTRIBUTES>(offset_of!(TOKEN_GROUPS, Groups), count as usize) }
            .unwrap()
            .iter()
            .map(|group| group.Attributes)
            .collect();

    let mut seen = Vec::new();
    let found: Option<()> = find_group(token.0, |sid, attributes| {
        assert!(!sid.0.is_null());
        seen.push(attributes);
        Ok(None)
    })
    .unwrap();
    assert_eq!(found, None);
    assert_eq!(seen, expected);
}

/// The first group `pick` takes ends the walk, and what it returns is the result.
#[test]
fn the_group_reader_stops_at_the_group_that_is_picked() {
    let token = own_token().unwrap();
    let mut visited = 0;
    let found = find_group(token.0, |_, attributes| {
        visited += 1;
        Ok(Some(attributes))
    })
    .unwrap();
    assert!(found.is_some(), "a token has a group");
    assert_eq!(visited, 1);
}

/// An error from `pick` ends the walk and is the result.
#[test]
fn the_group_reader_returns_the_error_of_pick() {
    let token = own_token().unwrap();
    let error = find_group::<()>(token.0, |_, _| anyhow::bail!("not this one")).unwrap_err();
    assert!(error.to_string().contains("not this one"), "{error:#}");
}

// The inherit list -----

fn handle(value: isize) -> HANDLE {
    HANDLE(value as *mut core::ffi::c_void)
}

/// A handle named twice makes `CreateProcessW` fail (measured), and a terminal session's stdout and stderr can
/// be one console handle, so the list the call gets has each handle once, in the order given.
#[test]
fn the_inherit_list_names_each_handle_once() {
    let (h, other) = (handle(0x40), handle(0x44));
    assert_eq!(handle_list(&[h, h, other]), vec![h, other]);
    assert_eq!(handle_list(&[other, h, other, h]), vec![other, h]);
    assert!(handle_list(&[]).is_empty());
}

/// A standard handle a process does not have (null, or `INVALID_HANDLE_VALUE`) is not inherited: in the
/// list it would fail the call, where the start it replaces took the child without it.
#[test]
fn the_inherit_list_leaves_out_a_handle_that_is_not_one() {
    let h = handle(0x40);
    assert_eq!(handle_list(&[handle(0), h, handle(-1), h]), vec![h]);
}

// Starting a child -----

/// An inheritable handle: the write end of a pipe, and the read end kept by the caller.
fn pipe_with_inheritable_write_end() -> (OwnedHandle, OwnedHandle) {
    use windows::Win32::Foundation::HANDLE_FLAG_INHERIT;
    use windows::Win32::Foundation::SetHandleInformation;
    use windows::Win32::System::Pipes::CreatePipe;
    let (mut read, mut write) = (HANDLE::default(), HANDLE::default());
    // SAFETY: valid out-pointers; the handles are closed by `OwnedHandle`.
    unsafe { CreatePipe(&mut read, &mut write, None, 0) }.expect("make a pipe");
    let (read, write) = (OwnedHandle(read), OwnedHandle(write));
    // SAFETY: a handle this test owns.
    unsafe { SetHandleInformation(write.0, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT) }.expect("mark it inheritable");
    (read, write)
}

/// Start `cmd /c exit 0` suspended and end it: whether the call accepted what it was given.
fn starts(console: ChildConsole, std_handles: [HANDLE; 3], inherit: &[HANDLE]) -> Result<(), StartError> {
    use windows::Win32::System::Threading::TerminateProcess;
    // SAFETY: the handles are live and inheritable; the child is suspended and ended here.
    let (process, _thread) =
        unsafe { spawn_suspended("cmd.exe /c exit 0", None, console, std_handles, inherit, None) }?;
    // SAFETY: the suspended process just created.
    unsafe { TerminateProcess(process.0, 1) }.expect("end the suspended child");
    Ok(())
}

/// A terminal session's stdout and stderr can be one console handle. Named in the inherit list twice it fails
/// the call, so a start with the same handle for both starts.
#[test]
fn a_child_whose_stdout_and_stderr_are_one_handle_starts() {
    let (_read, write) = pipe_with_inheritable_write_end();
    let null = HANDLE::default();
    let h = write.0;
    starts(ChildConsole::NoWindow, [null, h, h], &[null, h, h]).expect("one handle for stdout and stderr");
    starts(ChildConsole::Parent, [null, h, h], &[null, h, h]).expect("the same on the parent's console");
}

/// The window policy of the parent's console adds no flag: the child shares the console this process has.
#[test]
fn a_child_on_the_parents_console_gets_no_window_flag() {
    use windows::Win32::System::Threading::{CREATE_SUSPENDED, EXTENDED_STARTUPINFO_PRESENT};
    assert_eq!(
        creation_flags(&ChildConsole::Parent).0,
        CREATE_SUSPENDED.0 | EXTENDED_STARTUPINFO_PRESENT.0
    );
}
