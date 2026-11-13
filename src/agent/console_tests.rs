//! Tests for [`super::detach_with`]: no console is touched.

use std::cell::Cell;

use super::{DetachOutcome, detach_with};

/// What `detach_with` answers for `count` processes on the console, and whether it freed it.
fn run(count: u32) -> (windows::core::Result<DetachOutcome>, bool) {
    let freed = Cell::new(false);
    let outcome = detach_with(
        || count,
        || {
            freed.set(true);
            Ok(())
        },
    );
    (outcome, freed.get())
}

#[test]
fn an_agent_alone_on_its_console_frees_it() {
    let (outcome, freed) = run(1);
    assert_eq!(outcome.unwrap(), DetachOutcome::Detached);
    assert!(freed);
}

#[test]
fn an_agent_sharing_its_console_keeps_it() {
    for processes in [2, 3, u32::MAX] {
        let (outcome, freed) = run(processes);
        assert_eq!(outcome.unwrap(), DetachOutcome::Shared { processes });
        assert!(!freed, "{processes} processes use the console");
    }
}

#[test]
fn an_agent_without_a_console_has_nothing_to_free() {
    let (outcome, freed) = run(0);
    assert_eq!(outcome.unwrap(), DetachOutcome::NoConsole);
    assert!(!freed);
}

#[test]
fn a_console_that_cannot_be_freed_is_an_error() {
    let outcome = detach_with(
        || 1,
        || Err(windows::core::Error::from_hresult(windows::core::HRESULT(-1))),
    );
    assert!(outcome.is_err());
}
