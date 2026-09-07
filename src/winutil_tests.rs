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
