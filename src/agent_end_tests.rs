//! Tests that the end of the agent is decided by its real condition: every wait in the accept loop and
//! in the drain ends when that condition holds, and the bound is only the failure bound. Each test
//! that could hang for want of a wake has a failsafe that turns the hang into a failure.
use super::*;
use crate::afunix::AcceptError;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;

/// How long a test waits for a wake that never comes before it fails; never a proof that all is well.
const FAILSAFE: Duration = Duration::from_secs(5);

/// Runs `release` if `done` has not been sent to within the failsafe, and says so on the flag. A test
/// that expects its subject to finish by itself sends `done` and then asserts the flag is clear.
struct Failsafe {
    fired: Arc<AtomicBool>,
    done: mpsc::Sender<()>,
    thread: std::thread::JoinHandle<()>,
}

impl Failsafe {
    fn new(release: impl FnOnce() + Send + 'static) -> Failsafe {
        let fired = Arc::new(AtomicBool::new(false));
        let (done, finished) = mpsc::channel::<()>();
        let thread = std::thread::spawn({
            let fired = Arc::clone(&fired);
            move || {
                // A wake that never comes becomes a failure.
                let expired = finished.recv_timeout(FAILSAFE).is_err(); // sleep-ok: failure bound turned into a failed assertion
                if expired {
                    fired.store(true, Ordering::SeqCst);
                    release();
                }
            }
        });
        Failsafe { fired, done, thread }
    }

    /// Stop the failsafe; whether it had fired.
    fn finish(self) -> bool {
        let _ = self.done.send(());
        self.thread.join().unwrap();
        self.fired.load(Ordering::SeqCst)
    }
}

// the drain -----

#[test]
fn a_second_logout_that_registers_ends_the_drain_of_the_first_at_once() {
    // The first logout drains while the second is live and not yet a logout request. When the second
    // registers, the condition holds, and the drain must see it: its bound is an hour, so only a wake
    // can end it in time.
    let (events, on_event) = mpsc::channel();
    let connections = Connections::with_drain(Duration::from_secs(3600), move |_| {
        let _ = events.send("parked");
    });
    let first = connections.begin();
    let _first_logout = connections.begin_logout();
    let second = connections.begin();
    let failsafe = Failsafe::new({
        let connections = Arc::clone(&connections);
        // What an unrelated wake-up would do: the condition is true by then, so the drain ends.
        move || connections.wake()
    });
    let draining = std::thread::spawn({
        let connections = Arc::clone(&connections);
        move || connections.wait_until_only_logouts_live()
    });
    assert_eq!(on_event.recv().unwrap(), "parked");

    let _second_logout = connections.begin_logout();

    assert_eq!(draining.join().unwrap(), Drained::Complete);
    assert!(
        !failsafe.finish(),
        "the drain did not end when the second logout registered"
    );
    drop((first, second));
}

/// A drain parked on one connection that is not a `logout` request, which `mutation` then ends or gives
/// up. The condition holds from then on, and the drain must see it: its bound is an hour, so only a
/// wake can end it in time.
fn drain_ends_when(mutation: impl FnOnce(Live)) {
    let (events, on_event) = mpsc::channel();
    let connections = Connections::with_drain(Duration::from_secs(3600), move |_| {
        let _ = events.send("parked");
    });
    let _logout_connection = connections.begin();
    let _logout = connections.begin_logout();
    let other = connections.begin();
    let failsafe = Failsafe::new({
        let connections = Arc::clone(&connections);
        // What an unrelated wake-up would do: the condition is true by then, so the drain ends.
        move || connections.wake()
    });
    let draining = std::thread::spawn({
        let connections = Arc::clone(&connections);
        move || connections.wait_until_only_logouts_live()
    });
    assert_eq!(on_event.recv().unwrap(), "parked");

    mutation(other);

    assert_eq!(draining.join().unwrap(), Drained::Complete);
    assert!(!failsafe.finish(), "the drain did not end when the tally changed");
}

#[test]
fn a_connection_that_ends_ends_the_drain_at_once() {
    drain_ends_when(drop);
}

#[test]
fn a_connection_given_up_because_no_thread_could_be_started_ends_the_drain_at_once() {
    drain_ends_when(Live::abandon);
}

/// A drain parked on a connection that is not a `logout` request. `before` adds to the tally before
/// the drain parks; `mutation` then changes it without satisfying the drain, and returns the
/// connections it leaves live. The drain must re-judge after the change: the hook reports a park that
/// saw one more connection to wait for than the first park did (a spurious wake-up before the change
/// re-judges the old tally, so it cannot pass for the wake). Its bound is an hour, so only a wake can
/// make it. Then every connection ends and the drain completes.
fn drain_rejudges_when<T>(
    before: impl FnOnce(&Arc<Connections>) -> T,
    mutation: impl FnOnce(&Arc<Connections>, T) -> Vec<Live>,
) {
    let (events, on_event) = mpsc::channel();
    let connections = Connections::with_drain(Duration::from_secs(3600), move |waiting| {
        let _ = events.send(waiting);
    });
    let _logout_connection = connections.begin();
    let _logout = connections.begin_logout();
    let other = connections.begin();
    let added = before(&connections);
    let failsafe = Failsafe::new({
        let connections = Arc::clone(&connections);
        // The wake a skipped one would have been: it makes the drain re-judge, and `fired` says so.
        move || connections.wake()
    });
    let draining = std::thread::spawn({
        let connections = Arc::clone(&connections);
        move || connections.wait_until_only_logouts_live()
    });
    assert_eq!(on_event.recv().unwrap(), 1, "the drain parked on a different tally");

    let kept = mutation(&connections, added);

    // A park that still sees the old tally is a spurious wake-up before the change: it is not the wake.
    let judged = on_event.iter().find(|waiting| *waiting != 1);
    assert_eq!(judged, Some(2), "the drain did not re-judge the changed tally");
    assert!(!failsafe.finish(), "the drain re-judged only when the failsafe woke it");
    drop(other);
    drop(kept);
    assert_eq!(draining.join().unwrap(), Drained::Complete);
}

#[test]
fn a_connection_that_begins_wakes_the_drain_to_judge_again() {
    drain_rejudges_when(|_| (), |connections, ()| vec![connections.begin()]);
}

#[test]
fn a_logout_request_that_ends_while_other_connections_are_live_wakes_the_drain_to_judge_again() {
    drain_rejudges_when(
        |connections| (connections.begin(), connections.begin_logout()),
        |_, (live, request)| {
            drop(request);
            vec![live]
        },
    );
}

// the accept loop -----

/// The accept loop parked in `wait_for_an_end` while the end is decided. `accept` and `serve` make the
/// loop park; the only live connection is a `logout` request, so nothing ends by itself. The end is
/// decided from this thread, as a `logout` handler does, and must return, with the loop gone.
fn parked_loop_is_ended_by_the_end(
    accept: impl FnMut() -> Result<u32, AcceptError> + Send + 'static,
    serve: impl FnMut(u32, Live) -> Result<(), (u32, std::io::Error)> + Send + 'static,
) {
    let (events, on_event) = mpsc::channel();
    let connections = Connections::new();
    let _logout_connection = connections.begin();
    let _logout = connections.begin_logout();
    connections.listener_opened();
    let looped = Arc::new(AtomicBool::new(false));
    let failsafe = Failsafe::new({
        let connections = Arc::clone(&connections);
        // Closing the listener lets the end go on, so the test can say that the loop had not returned.
        move || connections.listener_closed()
    });
    let accepting = std::thread::spawn({
        let (connections, looped) = (Arc::clone(&connections), Arc::clone(&looped));
        move || {
            let end = serve_connections_with(
                Arc::clone(&connections),
                accept,
                serve,
                move || {
                    let _ = events.send(());
                },
                || connections.is_closing(),
            );
            looped.store(true, Ordering::SeqCst);
            connections.listener_closed();
            end
        }
    });
    on_event.recv().expect("the loop never parked");

    let drained = connections.settle(&|| {});

    let fired = failsafe.finish();
    assert!(
        looped.load(Ordering::SeqCst) && !fired,
        "the end was decided and the loop stayed parked"
    );
    assert_eq!(drained, Drained::Complete);
    let end = accepting.join().unwrap();
    assert!(end.downcast_ref::<Stopped>().is_some(), "{end:#}");
}

#[test]
fn a_loop_parked_for_lack_of_resources_returns_when_the_end_is_decided() {
    parked_loop_is_ended_by_the_end(
        || {
            Err(AcceptError::Exhausted {
                code: 10055,
                source: std::io::Error::from_raw_os_error(10055),
            })
        },
        |_conn, _live| panic!("nothing was accepted"),
    );
}

#[test]
fn a_loop_parked_for_lack_of_a_thread_returns_when_the_end_is_decided() {
    let mut accepted = 0;
    parked_loop_is_ended_by_the_end(
        move || {
            accepted += 1;
            Ok(accepted)
        },
        |conn, live| {
            live.abandon();
            Err((conn, std::io::Error::other("no thread")))
        },
    );
}

#[test]
fn a_loop_that_is_told_the_end_is_decided_before_it_parks_does_not_park() {
    // The flag is up when the shortage is found: the wait returns at once.
    let connections = Connections::new();
    let _logout_connection = connections.begin();
    let _logout = connections.begin_logout();
    connections.settle(&|| {});
    let before = connections.ended();
    assert!(
        connections.wait_for_an_end(before, || panic!("the loop parked although the end was decided")),
        "the loop is to read its flag and stop"
    );
}
