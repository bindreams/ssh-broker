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
                // sleep-ok: failsafe, a wake that never comes becomes a failure
                if finished.recv_timeout(FAILSAFE).is_err() {
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
    let connections = Connections::with_drain(Duration::from_secs(3600), move || {
        let _ = events.send("parked");
    });
    let first = connections.begin();
    let _first_logout = connections.begin_logout();
    let second = connections.begin();
    let failsafe = Failsafe::new({
        let connections = Arc::clone(&connections);
        // What an unrelated wake-up would do: the condition is true by then, so the drain ends.
        move || connections.ended.notify_all()
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
