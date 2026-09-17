//! A bounded wait for a result that crosses the SSH transport — the one place this crate
//! deliberately puts a clock on a wait, and why that is not the thing the no-sleep rule forbids.
//!
//! The rule bans synchronising with time: a sleep, or a poll loop with a numeric bound, standing
//! in for a real primitive between pieces of code we control. Its stated exception is awaiting an
//! external event that genuinely might never happen, where the bound is a failure surfaced to a
//! human. `verify`'s probe is exactly that case, and only that case:
//!
//! - The awaited thing is bytes crossing ssh client → sshd → shim → AF_UNIX socket → agent → pipe.
//!   Any link may drop them, and then they never arrive — there is no primitive to wait on, because
//!   the event may simply not occur.
//! - `verify` is an operator-run diagnostic with a human at the keyboard, so the bound is reported
//!   to that human ("no response within Ns") rather than used to sequence anything.
//!
//! It is emphatically NOT a licence for timeouts elsewhere. Everywhere the shim and agent
//! coordinate with each other they use real primitives — frame reads, EOF, process handles, job
//! objects — and an unbounded wait there is correct. If you are reaching for this module to make a
//! flaky wait pass, that is the bug.

use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::Duration;

/// Wait for `rx` to produce a value, giving up after `timeout` if one is given.
///
/// `None` waits indefinitely, which is what the rest of this crate does and what
/// `--probe-timeout 0` selects for someone debugging a slow box.
///
/// On expiry the sender is left running. That is deliberate: it is blocked on a socket that by
/// definition is not delivering, there is no way to interrupt it portably, and `verify` prints its
/// report and exits immediately afterwards — process teardown collects it. Leaking a blocked
/// thread in a short-lived CLI is a better trade than an unkillable wait with no report.
pub fn await_bounded<T>(rx: &Receiver<T>, timeout: Option<Duration>) -> anyhow::Result<T> {
    let Some(d) = timeout else {
        return rx
            .recv()
            .map_err(|_| anyhow::anyhow!("the probe worker stopped without reporting"));
    };
    // The `sleep-ok:` marker must sit on the SAME line as the call, because `no-sleep-sync` keys
    // per line. Bound to a `let` first rather than inlined into `match`: `cargo fmt` relocates a
    // trailing comment off a `match` scrutinee onto the next line, which silently un-suppressed
    // the hook once already. It keeps trailing comments on a statement.
    let received = rx.recv_timeout(d); // sleep-ok: bounded wait on an external event, see module doc
    match received {
        Ok(v) => Ok(v),
        Err(RecvTimeoutError::Timeout) => anyhow::bail!(
            "no response within {}s — the relay delivered nothing back. Raise the bound with \
             `--probe-timeout <seconds>` (0 waits indefinitely) if this host is merely slow",
            d.as_secs()
        ),
        Err(RecvTimeoutError::Disconnected) => {
            anyhow::bail!("the probe worker stopped without reporting")
        }
    }
}

#[cfg(test)]
#[path = "bounded_tests.rs"]
mod bounded_tests;
