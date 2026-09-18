//! `verify`'s bounded wait and the `--probe-timeout` flag that sizes it — the one place this crate
//! deliberately puts a clock on a wait, with the reason written down.
//!
//! The rule bans synchronising with time: a sleep, or a poll carrying a numeric bound, standing in
//! for a real primitive between pieces of code we control. The justification here is narrower than
//! "the network might swallow it", because **there is no network in this path**. `verify` runs on
//! this host and drives the agent over the AF_UNIX socket IN-PROCESS — no ssh client, no sshd, no
//! separate shim process. If the agent dies, the socket EOFs, the pump reports a closed peer, and
//! the probe fails with no clock involved at all.
//!
//! What the bound covers is the case with no such primitive: the agent ALIVE while its handler, or
//! the session-1 probe child, never produces output. A wedged LSASS blocking the child's DPAPI
//! round trip does that. So does a hung filesystem filter driver. So does a deadlock of our own.
//!
//! That last one is the uncomfortable part, and it is why this is confined to `verify`: most ways
//! this can hang are OUR bugs, and a clock over a bug is exactly what the rule exists to forbid. It
//! earns its place because `verify` is a one-shot operator diagnostic whose subject is a
//! possibly-sick machine — hanging is the worst way to report one, and it throws away the local
//! rows already gathered. `--probe-timeout 0` keeps the true unbounded hang for anyone debugging
//! such a deadlock. If you are reaching for this module to make a flaky wait pass, that is the bug.

use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::Duration;

/// The default bound. Deliberately generous: this exists to turn a wedge into a report, NOT to
/// police how fast a healthy host answers, and a bound tight enough to false-fail a loaded machine
/// would be worse than no bound at all.
pub const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_secs(30);

/// Parse `--probe-timeout` out of `args`; `0` selects an indefinite wait.
///
/// Accepts both `--probe-timeout 30` and `--probe-timeout=30`. The `=` spelling is what many
/// operators reach for first, and silently ignoring it would apply the default while the operator
/// believed otherwise — on exactly the slow host the flag exists for, that surfaces as a spurious
/// failure blaming the agent.
///
/// A present-but-unparseable value is an ERROR, never a quiet fallback to the default: someone who
/// asked to wait indefinitely and instead got 30 seconds would be handed a failure row with the
/// wrong diagnosis. (An earlier version of this defended guessing by citing `--user` as precedent;
/// that was wrong in both directions — `--user` has no value to parse, and when it resolves to
/// nothing `config::resolve_target_user` fails loudly and names the flag.)
///
/// Takes `args` as a parameter rather than reading `std::env::args()` so it is testable from any
/// host. Its only caller is `#[cfg(windows)]` with no test module, which is precisely how this
/// crate has previously shipped logic that nothing could reach.
pub fn probe_timeout_from_args(args: &[String]) -> anyhow::Result<Option<Duration>> {
    const FLAG: &str = "--probe-timeout";
    let mut raw: Option<&str> = None;
    for (i, a) in args.iter().enumerate() {
        if let Some(v) = a.strip_prefix("--probe-timeout=") {
            raw = Some(v);
            break;
        }
        if a == FLAG {
            let v = args
                .get(i + 1)
                .ok_or_else(|| anyhow::anyhow!("{FLAG} needs a value in seconds (0 waits indefinitely)"))?;
            raw = Some(v.as_str());
            break;
        }
    }
    let Some(raw) = raw else {
        return Ok(Some(DEFAULT_PROBE_TIMEOUT));
    };
    let secs: u64 = raw
        .parse()
        .map_err(|_| anyhow::anyhow!("{FLAG} wants whole seconds (0 waits indefinitely), not {raw:?}"))?;
    Ok((secs != 0).then(|| Duration::from_secs(secs)))
}

/// Wait for `rx` to produce a value, giving up after `timeout` if one is given.
///
/// `None` waits indefinitely — what the rest of this crate does, and what `--probe-timeout 0`
/// selects for someone debugging a genuine deadlock.
///
/// On expiry the sender is left running. That is deliberate: it is blocked inside the relay
/// conversation with no portable way to interrupt it, and `verify` prints its report and exits
/// immediately afterwards, so process teardown collects it. Leaking a blocked thread in a
/// short-lived diagnostic beats an unkillable wait that reports nothing.
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
    let received = rx.recv_timeout(d); // sleep-ok: bounded wait on a possibly-wedged peer, see module doc
    match received {
        Ok(v) => Ok(v),
        // Name what is actually known. The agent answered the connect, so the relay itself is not
        // the suspect — what has not happened is any output from the agent's handler or the
        // session-1 child it spawned.
        Err(RecvTimeoutError::Timeout) => anyhow::bail!(
            "the agent accepted the connection but the probe produced no output within {}s — the \
             agent or the session-1 child may be wedged. Raise the bound with \
             `--probe-timeout <seconds>`, or `--probe-timeout 0` to wait indefinitely",
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
