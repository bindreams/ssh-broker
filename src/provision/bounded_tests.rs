//! Host tests for the bounded wait. The `verify` path that uses it is `#[cfg(windows)]` with no
//! test module, which is precisely how an earlier check in this file's neighbourhood ended up
//! measurable only in production — so the logic lives here, where every platform runs it.
use super::await_bounded;
use std::time::Duration;

/// A value already waiting is returned, bound or no bound. Guards the obvious regression of a
/// bound that fires even when the answer is there.
#[test]
fn a_ready_value_is_returned() {
    let (tx, rx) = std::sync::mpsc::channel();
    tx.send(7).unwrap();
    assert_eq!(await_bounded(&rx, Some(Duration::from_secs(30))).unwrap(), 7);

    let (tx, rx) = std::sync::mpsc::channel();
    tx.send(9).unwrap();
    assert_eq!(await_bounded(&rx, None).unwrap(), 9);
}

/// Expiry must be an ERROR carrying the remedy, never a silent default — `verify` turns this into
/// a failed report row, and a row that read as passing would be the unverified assertion the
/// probe exists to replace.
///
/// This is deterministic, not a timing bet: nothing is ever sent on this channel, so no amount of
/// scheduling luck can deliver a value. The duration only decides how fast the test runs. The
/// sender is deliberately kept alive, or the channel would disconnect and take the other branch.
#[test]
fn expiry_reports_the_bound_and_how_to_raise_it() {
    let (_tx, rx) = std::sync::mpsc::channel::<u8>();
    let err = await_bounded(&rx, Some(Duration::from_millis(1)))
        .unwrap_err()
        .to_string();
    assert!(err.contains("no response within"), "{err}");
    assert!(
        err.contains("--probe-timeout"),
        "the error must name the flag that raises the bound: {err}"
    );
}

/// A worker that dies without reporting must surface as an error too. Returning a default here
/// would let a crashed probe read as a passing check.
#[test]
fn a_dead_worker_is_an_error_not_a_default() {
    let (tx, rx) = std::sync::mpsc::channel::<u8>();
    drop(tx);
    assert!(await_bounded(&rx, Some(Duration::from_secs(30))).is_err());

    let (tx, rx) = std::sync::mpsc::channel::<u8>();
    drop(tx);
    assert!(
        await_bounded(&rx, None).is_err(),
        "an unbounded wait must not hang on a dead sender"
    );
}
