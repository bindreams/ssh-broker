//! Tests for [`super::detach_with`]: no console is touched.

use std::cell::Cell;
use std::num::NonZeroU32;

use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_INVALID_HANDLE};
use windows::core::HRESULT;

use super::{DetachOutcome, detach_with};

/// What `detach_with` answers when the console count is `counted`, and whether it freed the console.
fn run(counted: Result<NonZeroU32, u32>) -> (windows::core::Result<DetachOutcome>, bool) {
    let freed = Cell::new(false);
    let outcome = detach_with(counted, || {
        freed.set(true);
        Ok(None)
    });
    (outcome, freed.get())
}

fn count(processes: u32) -> Result<NonZeroU32, u32> {
    Ok(NonZeroU32::new(processes).unwrap())
}

#[test]
fn an_agent_alone_on_its_console_frees_it() {
    let (outcome, freed) = run(count(1));
    assert_eq!(
        outcome.unwrap(),
        DetachOutcome::Detached {
            std_handles_error: None
        }
    );
    assert!(freed);
}

#[test]
fn an_agent_sharing_its_console_keeps_it() {
    for processes in [2, 3, u32::MAX] {
        let (outcome, freed) = run(count(processes));
        assert_eq!(outcome.unwrap(), DetachOutcome::Shared { processes });
        assert!(!freed, "{processes} processes use the console");
    }
}

/// Whatever the reason the count is zero, the agent has no console to free; the reason is kept.
#[test]
fn a_count_of_zero_is_no_console_whatever_the_error_code() {
    for code in [ERROR_INVALID_HANDLE.0, ERROR_ACCESS_DENIED.0, 0] {
        let (outcome, freed) = run(Err(code));
        assert_eq!(outcome.unwrap(), DetachOutcome::NoConsole { error: code });
        assert!(!freed);
    }
}

#[test]
fn a_console_that_cannot_be_freed_is_an_error() {
    let outcome = detach_with(count(1), || Err(windows::core::Error::from_hresult(HRESULT(-1))));
    assert!(outcome.is_err());
}

/// The standard handles that could not be reset do not undo the detach: the outcome says so and keeps the code.
#[test]
fn standard_handles_that_could_not_be_reset_leave_the_agent_detached() {
    let outcome = detach_with(count(1), || Ok(Some(HRESULT(-2)))).unwrap();
    assert_eq!(
        outcome,
        DetachOutcome::Detached {
            std_handles_error: Some(HRESULT(-2))
        }
    );
}
