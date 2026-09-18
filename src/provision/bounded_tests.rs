//! Host tests for the bounded wait. The `verify` path that uses it is `#[cfg(windows)]` with no
//! test module, which is precisely how an earlier check in this file's neighbourhood ended up
//! measurable only in production — so the logic lives here, where every platform runs it.
use super::{DEFAULT_PROBE_TIMEOUT, await_bounded, probe_timeout_from_args};
use std::time::Duration;

fn args(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| (*s).to_string()).collect()
}

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
    // Gate the PROPERTY, not the phrasing. The message must name the flag that raises the bound,
    // and must NOT blame the relay for delivering nothing: the agent demonstrably answered the
    // connect, so the honest report is that no OUTPUT arrived. An earlier version said "the relay
    // delivered nothing back", which pointed the operator at a transport that is not in the path.
    assert!(
        err.contains("--probe-timeout"),
        "the error must name the flag that raises the bound: {err}"
    );
    assert!(
        !err.contains("relay delivered nothing"),
        "expiry must not blame the relay — the agent accepted the connection: {err}"
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

/// `--probe-timeout 0` means WAIT INDEFINITELY. That contract is documented in three places
/// (README, CONTRIBUTING, this module) and is the escape hatch for debugging a genuine deadlock,
/// where a bound would hide the very hang being chased.
///
/// It exists as a test because the parser used to live in a `#[cfg(windows)]` module with no test
/// module at all: mutating `(secs != 0).then(...)` to `Some(...)` left the whole suite green on
/// both platforms while making `--probe-timeout 0` expire instantly and report a wedged agent.
#[test]
fn zero_means_wait_indefinitely() {
    assert_eq!(
        probe_timeout_from_args(&args(&["verify", "--probe-timeout", "0"])).unwrap(),
        None
    );
    assert_eq!(
        probe_timeout_from_args(&args(&["verify", "--probe-timeout=0"])).unwrap(),
        None
    );
}

/// Both spellings must work. `--probe-timeout=30` is what many operators type first, and the
/// earlier parser matched only the space-separated form — so the `=` form was silently ignored,
/// applied the default, and on the slow host the flag exists for produced a failure row blaming
/// the agent for what was merely a bound the operator thought they had raised.
#[test]
fn both_spellings_are_accepted_and_absence_means_the_default() {
    let five = Some(Duration::from_secs(5));
    assert_eq!(
        probe_timeout_from_args(&args(&["verify", "--probe-timeout", "5"])).unwrap(),
        five
    );
    assert_eq!(
        probe_timeout_from_args(&args(&["verify", "--probe-timeout=5"])).unwrap(),
        five
    );
    assert_eq!(
        probe_timeout_from_args(&args(&["verify"])).unwrap(),
        Some(DEFAULT_PROBE_TIMEOUT),
        "no flag must mean the default, not an unbounded wait"
    );
}

/// A present-but-unusable value must FAIL LOUDLY and name the flag, never fall back to the
/// default. Guessing would hand the operator who asked to wait indefinitely a 30s bound and a
/// diagnosis pointing at the agent instead of at their own command line.
#[test]
fn a_malformed_value_errors_and_names_the_flag() {
    for bad in [
        args(&["verify", "--probe-timeout", "abc"]),
        args(&["verify", "--probe-timeout", "-1"]),
        args(&["verify", "--probe-timeout="]),
        args(&["verify", "--probe-timeout"]), // flag last, no value follows
    ] {
        let err = probe_timeout_from_args(&bad).unwrap_err().to_string();
        assert!(err.contains("--probe-timeout"), "{bad:?} -> {err}");
    }
}
