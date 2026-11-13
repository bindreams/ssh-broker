//! Tests for [`super::detach_with`] and [`super::std_handles_to_nul`]: no console is touched.

use std::cell::Cell;

use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_INVALID_HANDLE, HANDLE};
use windows::Win32::Storage::FileSystem::{FILE_TYPE_CHAR, GetFileType, ReadFile, WriteFile};
use windows::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, SetStdHandle,
};

use super::{DetachOutcome, detach_with, std_handles_to_nul};

/// What `detach_with` answers when the console count is `counted`, and whether it freed the console.
fn run(counted: windows::core::Result<u32>) -> (windows::core::Result<DetachOutcome>, bool) {
    let freed = Cell::new(false);
    let outcome = detach_with(
        || counted,
        || {
            freed.set(true);
            Ok(())
        },
    );
    (outcome, freed.get())
}

#[test]
fn an_agent_alone_on_its_console_frees_it() {
    let (outcome, freed) = run(Ok(1));
    assert_eq!(outcome.unwrap(), DetachOutcome::Detached);
    assert!(freed);
}

#[test]
fn an_agent_sharing_its_console_keeps_it() {
    for processes in [2, 3, u32::MAX] {
        let (outcome, freed) = run(Ok(processes));
        assert_eq!(outcome.unwrap(), DetachOutcome::Shared { processes });
        assert!(!freed, "{processes} processes use the console");
    }
}

#[test]
fn an_agent_without_a_console_has_nothing_to_free() {
    let (outcome, freed) = run(Err(ERROR_INVALID_HANDLE.into()));
    assert_eq!(outcome.unwrap(), DetachOutcome::NoConsole);
    assert!(!freed);
}

#[test]
fn a_count_that_fails_for_another_reason_is_an_error_and_frees_nothing() {
    let (outcome, freed) = run(Err(ERROR_ACCESS_DENIED.into()));
    assert_eq!(outcome.unwrap_err().code(), ERROR_ACCESS_DENIED.to_hresult());
    assert!(!freed);
}

#[test]
fn a_console_that_cannot_be_freed_is_an_error() {
    let outcome = detach_with(
        || Ok(1),
        || Err(windows::core::Error::from_hresult(windows::core::HRESULT(-1))),
    );
    assert!(outcome.is_err());
}

/// Puts the standard handles back, so the test leaves the process as it found it.
struct Saved([(windows::Win32::System::Console::STD_HANDLE, HANDLE); 3]);

impl Saved {
    fn take() -> Saved {
        Saved([STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE].map(|which| {
            // SAFETY: no pointers; this process's own standard handle.
            (which, unsafe { GetStdHandle(which) }.unwrap_or_default())
        }))
    }
}

impl Drop for Saved {
    fn drop(&mut self) {
        for (which, handle) in self.0 {
            // SAFETY: restores the value `GetStdHandle` gave.
            let _ = unsafe { SetStdHandle(which, handle) };
        }
    }
}

/// After the console is freed the old standard handles point at nothing, or at whatever reuses their
/// numbers: a later `eprintln!` must reach neither.
#[test]
fn std_handles_pointed_at_nul_swallow_writes_and_read_nothing() {
    let _saved = Saved::take();
    std_handles_to_nul().unwrap();

    for which in [STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        // SAFETY: no pointers; this process's own standard handle.
        let sink = unsafe { GetStdHandle(which) }.unwrap();
        // SAFETY: a valid handle.
        assert_eq!(
            unsafe { GetFileType(sink) },
            FILE_TYPE_CHAR,
            "NUL is a character device"
        );
        let mut written = 0u32;
        // SAFETY: the buffer and the out-pointer are valid for the call.
        unsafe { WriteFile(sink, Some(b"refused"), Some(&mut written), None) }.unwrap();
        assert_eq!(written, 7);
    }

    // SAFETY: as above.
    let source = unsafe { GetStdHandle(STD_INPUT_HANDLE) }.unwrap();
    let mut buffer = [0u8; 8];
    let mut read = 1u32;
    // SAFETY: the buffer and the out-pointer are valid for the call.
    unsafe { ReadFile(source, Some(&mut buffer), Some(&mut read), None) }.unwrap();
    assert_eq!(read, 0, "NUL is at its end");
}
