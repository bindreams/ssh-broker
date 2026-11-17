//! Unit tests for `winutil` (sibling-file style per project conventions).
use super::*;
use std::mem::offset_of;

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
        let blamed = start_error_of_create(io_error(code), None);
        assert!(
            matches!(blamed, crate::shell::StartError::Program(_)),
            "{code}: {blamed:?}"
        );
    }
    for code in other {
        let blamed = start_error_of_create(io_error(code), None);
        assert!(
            matches!(blamed, crate::shell::StartError::Other(_)),
            "{code}: {blamed:?}"
        );
    }
    // An error that is not a Win32 code says nothing against the program either.
    let blamed = start_error_of_create(windows::core::Error::from(windows::Win32::Foundation::E_FAIL), None);
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
    // SAFETY: a `TOKEN_USER` is a SID pointer and an integer.
    let user = unsafe { info.header::<TOKEN_USER>() }.unwrap();
    assert!(!user.User.Sid.0.is_null());
}

// Reading token information -----

/// The pointers Windows writes into token information are absolute: they point into the very bytes
/// the call filled, so the value must be read in place and never copied or moved afterwards.
#[test]
fn the_sids_in_this_process_token_lie_inside_the_returned_value() {
    use windows::Win32::Security::{
        SID_AND_ATTRIBUTES, TOKEN_GROUPS, TOKEN_MANDATORY_LABEL, TOKEN_USER, TokenGroups, TokenIntegrityLevel,
        TokenUser,
    };
    let token = own_token().unwrap();

    let info = token_information(token.0, TokenUser).unwrap();
    // SAFETY: a `TOKEN_USER` is a SID pointer and an integer.
    let user = unsafe { info.header::<TOKEN_USER>() }.unwrap();
    assert!(info.sid(user.User.Sid).is_ok(), "TokenUser");

    let info = token_information(token.0, TokenIntegrityLevel).unwrap();
    // SAFETY: a `TOKEN_MANDATORY_LABEL` is a SID pointer and an integer.
    let label = unsafe { info.header::<TOKEN_MANDATORY_LABEL>() }.unwrap();
    assert!(info.sid(label.Label.Sid).is_ok(), "TokenIntegrityLevel");

    let info = token_information(token.0, TokenGroups).unwrap();
    // SAFETY: the group count is a `u32`.
    let count = unsafe { info.header::<u32>() }.unwrap();
    assert!(count > 0, "a token has at least one group");
    // SAFETY: a `SID_AND_ATTRIBUTES` is a SID pointer and an integer.
    let groups = unsafe { info.array::<SID_AND_ATTRIBUTES>(offset_of!(TOKEN_GROUPS, Groups), count as usize) }.unwrap();
    assert!(info.sid(groups[0].Sid).is_ok(), "TokenGroups[0]");
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
    // The value is 20 bytes in 24 bytes of storage: the end of the data is not the end of the buffer,
    // and the header at 16 would fit in the buffer.
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
