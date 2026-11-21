//! Unit tests for the agent's answer to `logout`. In-process: no socket, no shell, no process ends.
use super::*;
use crate::afunix::{ConnRx, ConnTx, split};
use crate::agent::elevation::{HostedSession, Starts};
use crate::agent::{Drained, HeldListener};
use crate::protocol::{ElevationPolicy, ExitCode, FrameKind, FrameReader, Stream};
use crate::relay::{Outcome, TestSink, pump_decode, write_data};
use crate::test_support::ClosedStream;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;

/// The frames in `bytes`, with DATA payloads split into stream and text.
fn decode(bytes: &[u8]) -> (Vec<(u8, String)>, Option<i32>) {
    let mut fr = FrameReader::new();
    fr.push(bytes);
    let (mut data, mut exit) = (Vec::new(), None);
    while let Some(frame) = fr.next_frame().unwrap() {
        match frame.kind {
            FrameKind::Data => data.push((
                frame.payload[0],
                String::from_utf8(frame.payload[1..].to_vec()).unwrap(),
            )),
            FrameKind::Exit => exit = Some(ExitCode::decode(&frame.payload).unwrap().0),
            other => panic!("unexpected {other:?}"),
        }
    }
    (data, exit)
}

/// A client that has already closed.
struct Closed;

impl Read for Closed {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        Ok(0)
    }
}

impl LimitedRead for Closed {
    fn limit_reads(&mut self, _: Duration) {}
}

/// A client that stays connected until the test says it closes (a send, or dropping the sender).
/// A read that was not given a limit panics: it could wait for ever.
struct Gate {
    closed: mpsc::Receiver<()>,
    limit: Option<Duration>,
}

impl Gate {
    fn new(closed: mpsc::Receiver<()>) -> Gate {
        Gate { closed, limit: None }
    }
}

impl Read for Gate {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        let limit = self.limit.expect("a read of the logout client must have a limit");
        let got = self.closed.recv_timeout(limit); // sleep-ok: stands in for a socket's receive timeout
        match got {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => Ok(0),
            Err(mpsc::RecvTimeoutError::Timeout) => Err(std::io::ErrorKind::TimedOut.into()),
        }
    }
}

impl LimitedRead for Gate {
    fn limit_reads(&mut self, limit: Duration) {
        self.limit = Some(limit);
    }
}

/// A client that stays connected until the test drops the sender, whatever limit a read has: for a
/// test of something other than the bound. It says (on `reading`) each time a read begins.
struct Open {
    reading: mpsc::Sender<()>,
    closed: mpsc::Receiver<()>,
}

impl Read for Open {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        let _ = self.reading.send(());
        let _ = self.closed.recv();
        Ok(0)
    }
}

impl LimitedRead for Open {
    fn limit_reads(&mut self, _: Duration) {}
}

/// What `f` logged, and what it returned.
fn logged<T>(f: impl FnOnce() -> T) -> (String, T) {
    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Buf {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buf {
        type Writer = Buf;
        fn make_writer(&'a self) -> Buf {
            self.clone()
        }
    }
    let buf = Buf::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(buf.clone())
        .with_ansi(false)
        .finish();
    let result = tracing::subscriber::with_default(subscriber, f);
    let log = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    (log, result)
}

fn counting_killer(count: &Arc<AtomicUsize>) -> Killer {
    let count = Arc::clone(count);
    Arc::new(move || {
        count.fetch_add(1, Ordering::SeqCst);
    })
}

/// Reserve an id and register under it at once: what a session does, for a test of something else.
trait RegisterNow {
    fn register(&self, kill: Killer) -> Option<Registration<'_>>;
}

impl RegisterNow for Control {
    fn register(&self, kill: Killer) -> Option<Registration<'_>> {
        self.reserve().unwrap()?.register(kill)
    }
}

#[test]
fn desktop_agent_refuses_logout_and_keeps_serving() {
    let control = Control::new(false, Connections::new());
    let mut written = Vec::new();
    let ended = AtomicBool::new(false);
    let killed = Arc::new(AtomicUsize::new(0));
    let _session = control.register(counting_killer(&killed)).unwrap();

    handle_logout(&mut Closed, &mut written, &control, |_| {
        ended.store(true, Ordering::SeqCst)
    })
    .unwrap();

    let (data, exit) = decode(&written);
    assert_eq!(data.len(), 1);
    assert_eq!(data[0].0, Stream::Stderr as u8);
    assert!(data[0].1.contains("desktop session"), "{}", data[0].1);
    assert!(data[0].1.contains("signing out of Windows"), "{}", data[0].1);
    assert_eq!(exit, Some(2));
    assert!(!ended.load(Ordering::SeqCst), "a desktop agent keeps running");
    assert_eq!(killed.load(Ordering::SeqCst), 0, "and keeps its sessions");
    assert!(!control.is_ending(), "and keeps accepting");
    assert!(control.register(counting_killer(&killed)).is_some());
}

#[test]
fn background_agent_acknowledges_before_ending() {
    let control = Control::new(true, Connections::new());
    let events = Mutex::new(Vec::<&str>::new());
    struct Recorder<'a>(&'a Mutex<Vec<&'static str>>, Vec<u8>);
    impl Write for Recorder<'_> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.1.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.0.lock().unwrap().push("flushed");
            Ok(())
        }
    }
    let mut tx = Recorder(&events, Vec::new());
    handle_logout(&mut Closed, &mut tx, &control, |_| events.lock().unwrap().push("ended")).unwrap();

    assert_eq!(*events.lock().unwrap(), ["flushed", "ended"]);
    let (data, exit) = decode(&tx.1);
    assert_eq!(data, [(Stream::Stderr as u8, ENDING_REPLY.to_string())]);
    assert_eq!(exit, Some(0));
}

#[test]
fn background_agent_does_not_end_until_the_client_has_closed() {
    let control = Arc::new(Control::new(true, Connections::new()));
    let killed = Arc::new(AtomicUsize::new(0));
    let _session = control.register(counting_killer(&killed)).unwrap();
    let (close, closed) = mpsc::channel();
    let (replied, on_reply) = mpsc::channel();
    let (ended, on_end) = mpsc::channel();

    struct Tx(mpsc::Sender<()>);
    impl Write for Tx {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            let _ = self.0.send(());
            Ok(())
        }
    }

    let worker = {
        let control = Arc::clone(&control);
        std::thread::spawn(move || {
            handle_logout(&mut Gate::new(closed), &mut Tx(replied), &control, |_| {
                ended.send(()).unwrap()
            })
            .unwrap();
        })
    };
    // The reply is out and the client is still connected: nothing has been ended.
    on_reply.recv().unwrap();
    assert_eq!(killed.load(Ordering::SeqCst), 0);
    assert!(!control.is_ending());
    assert!(on_end.try_recv().is_err());

    close.send(()).unwrap();
    worker.join().unwrap();
    on_end.recv().unwrap();
    assert_eq!(
        killed.load(Ordering::SeqCst),
        1,
        "the session is ended once the client has closed"
    );
    assert!(control.is_ending());
}

#[test]
fn logout_ends_every_registered_session_once() {
    let control = Control::new(true, Connections::new());
    let killed = Arc::new(AtomicUsize::new(0));
    let sessions: Vec<_> = (0..3)
        .map(|_| control.register(counting_killer(&killed)).unwrap())
        .collect();
    handle_logout(&mut Closed, &mut Vec::new(), &control, |_| {}).unwrap();
    assert_eq!(killed.load(Ordering::SeqCst), 3);
    drop(sessions);
}

#[test]
fn a_finished_session_is_not_ended_by_a_later_logout() {
    let control = Control::new(true, Connections::new());
    let killed = Arc::new(AtomicUsize::new(0));
    drop(control.register(counting_killer(&killed)).unwrap());
    handle_logout(&mut Closed, &mut Vec::new(), &control, |_| {}).unwrap();
    assert_eq!(killed.load(Ordering::SeqCst), 0);
}

#[test]
fn a_session_that_starts_after_the_end_began_is_refused_registration() {
    let control = Control::new(true, Connections::new());
    handle_logout(&mut Closed, &mut Vec::new(), &control, |_| {}).unwrap();
    let killed = Arc::new(AtomicUsize::new(0));
    assert!(control.register(counting_killer(&killed)).is_none());
}

#[test]
fn the_process_ends_only_after_every_other_connection_has_finished() {
    // The drain says it is about to park, and only then does the other connection finish. A handler
    // that skipped the drain would report the end first.
    let (events, on_event) = mpsc::channel();
    let connections = Connections::observing_drain({
        let events = events.clone();
        move |_| {
            let _ = events.send("parked");
        }
    });
    let this_connection = connections.begin();
    let other = connections.begin();
    let control = Arc::new(Control::new(true, Arc::clone(&connections)));

    let worker = std::thread::spawn(move || {
        let _live = this_connection;
        handle_logout(&mut Closed, &mut Vec::new(), &control, |_| {
            let _ = events.send("ended");
        })
        .unwrap();
    });
    assert_eq!(
        on_event.recv().unwrap(),
        "parked",
        "the process ended before the other connection had finished"
    );
    drop(other);
    // The drain parks again at every spurious wake-up of its condition variable, so more than one
    // "parked" may be queued; the end is the first event that is not one.
    let next = std::iter::from_fn(|| on_event.recv().ok()).find(|event| *event != "parked");
    assert_eq!(next, Some("ended"));
    worker.join().unwrap();
}

#[test]
fn two_logouts_at_once_both_end_the_agent() {
    let connections = Connections::new();
    let control = Arc::new(Control::new(true, Arc::clone(&connections)));
    let ended = Arc::new(AtomicUsize::new(0));
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let live = connections.begin();
            let (control, ended) = (Arc::clone(&control), Arc::clone(&ended));
            std::thread::spawn(move || {
                let _live = live;
                handle_logout(&mut Closed, &mut Vec::new(), &control, |_| {
                    ended.fetch_add(1, Ordering::SeqCst);
                })
                .unwrap();
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(ended.load(Ordering::SeqCst), 2, "every logout ends the agent");
}

/// A control whose accept loop is the test: `woke` is told each time the loop is woken, and the wake
/// makes the loop return and close the listener, as a real one does. The listener is returned: the loop
/// holds it while the test does.
fn control_with_a_loop(
    connections: &Arc<Connections>,
    woke: impl Fn() + Send + Sync + 'static,
) -> (Control, Arc<HeldListener>) {
    let listener = HeldListener::open(connections, "agent.sock", move |listener| {
        woke();
        listener.close();
    });
    (Control::new(true, Arc::clone(connections)), listener)
}

#[test]
fn ending_wakes_the_accept_loop_once_however_many_logouts_ask() {
    let woken = Arc::new(AtomicUsize::new(0));
    let (control, _listener) = {
        let woken = Arc::clone(&woken);
        control_with_a_loop(&Connections::new(), move || {
            woken.fetch_add(1, Ordering::SeqCst);
        })
    };
    assert_eq!(
        woken.load(Ordering::SeqCst),
        0,
        "nothing wakes it before the end begins"
    );
    handle_logout(&mut Closed, &mut Vec::new(), &control, |_| {}).unwrap();
    assert_eq!(woken.load(Ordering::SeqCst), 1);
    handle_logout(&mut Closed, &mut Vec::new(), &control, |_| {}).unwrap();
    assert_eq!(woken.load(Ordering::SeqCst), 1, "it is already awake");
}

#[test]
fn the_accept_loop_is_woken_once_the_shells_are_ended_and_every_other_connection_has_finished() {
    // The listener answers logins with the refusal until the shells' last output is delivered; only
    // then is the loop told to stop.
    let (events, on_event) = mpsc::channel::<&'static str>();
    let connections = Connections::observing_drain({
        let events = events.clone();
        move |_| {
            let _ = events.send("parked");
        }
    });
    let (control, _listener) = control_with_a_loop(&connections, {
        let events = events.clone();
        move || {
            let _ = events.send("woken");
        }
    });
    let _session = control
        .register({
            let events = events.clone();
            Arc::new(move || {
                let _ = events.send("killed");
            })
        })
        .unwrap();
    let this_connection = connections.begin();
    let other = connections.begin();

    let mut seen = Vec::new();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let _live = this_connection;
            handle_logout(&mut Closed, &mut Vec::new(), &control, |_| {
                let _ = events.send("ended");
            })
            .unwrap();
        });
        let mut other = Some(other);
        loop {
            let event = on_event.recv().unwrap();
            seen.push(event);
            if event == "parked"
                && let Some(other) = other.take()
            {
                let _ = events.send("finished");
                drop(other);
            }
            if event == "ended" {
                break;
            }
        }
    });
    let steps: Vec<_> = seen.iter().filter(|event| **event != "parked").collect();
    assert_eq!(steps, [&"killed", &"finished", &"woken", &"ended"]);
}

#[test]
fn the_accept_loop_is_woken_after_the_flag_that_stops_it_is_up() {
    // A loop woken before the flag is raised would look, find nothing to stop for and accept again.
    let connections = Connections::new();
    let seen = Arc::new(Mutex::new(None));
    let (control, _listener) = control_with_a_loop(&connections, {
        let (connections, seen) = (Arc::clone(&connections), Arc::clone(&seen));
        move || *seen.lock().unwrap() = Some(connections.is_closing())
    });
    handle_logout(&mut Closed, &mut Vec::new(), &control, |_| {}).unwrap();
    assert_eq!(*seen.lock().unwrap(), Some(true));
}

/// [`crate::test_support::raw_socket_pair`] with both ends split: the server's halves, the client's
/// halves and the dir to remove.
fn socket_pair(tag: &str) -> ((ConnRx, ConnTx), (ConnRx, ConnTx), std::path::PathBuf) {
    let (server, client, dir) = crate::test_support::raw_socket_pair(tag);
    (split(server).unwrap(), split(client).unwrap(), dir)
}

#[test]
fn a_connection_that_arrives_while_ending_is_told_so_and_exits_255() {
    let ((mut srx, mut stx), (mut crx, mut ctx), dir) = socket_pair("refusal");
    // The client has sent its stdin EOF marker, as an exec shim always does, before it reads.
    write_data(&mut ctx, Stream::Stdin, b"").unwrap();
    let server = std::thread::spawn(move || refuse_while_ending(&mut srx, &mut stx, &Control::standalone()).unwrap());

    let mut sink = TestSink::default();
    let outcome = pump_decode(&mut crx, &mut FrameReader::new(), &mut sink).expect("the reply was lost");
    assert_eq!(outcome, Outcome::Exited(255));
    assert_eq!(sink.stderr, ENDING_REFUSAL.as_bytes());
    // The server is done only once the client has closed.
    drop((crx, ctx));
    server.join().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The agent's hand-back is the answer and nothing else: one `HandBack` frame with the cause, a FIN of the
/// write half, and then the agent waits for the client to close, as it does after a refusal.
#[test]
fn a_hand_back_is_one_frame_with_the_cause_then_a_fin_and_the_agent_waits_for_the_client() {
    /// The writes of the agent and the reads of its client wait, in the order they happened.
    type Events = Arc<Mutex<Vec<&'static str>>>;
    struct Server {
        sent: Vec<u8>,
        events: Events,
    }
    impl Write for Server {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.sent.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.events.lock().unwrap().push("flushed");
            Ok(())
        }
    }
    impl HalfClose for Server {
        fn shutdown_write(&self) -> anyhow::Result<()> {
            self.events.lock().unwrap().push("fin");
            Ok(())
        }
    }
    struct Client(Events);
    impl Read for Client {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().push("waited for the client");
            Ok(0)
        }
    }
    impl LimitedRead for Client {
        fn limit_reads(&mut self, _: Duration) {}
    }

    let events = Events::default();
    let mut server = Server {
        sent: Vec::new(),
        events: Arc::clone(&events),
    };
    hand_back(
        &mut Client(Arc::clone(&events)),
        &mut server,
        &Control::standalone(),
        "the token cannot be made",
    )
    .unwrap();

    // One frame, the answer, and nothing after it.
    let mut fr = FrameReader::new();
    fr.push(&server.sent);
    let frame = fr.next_frame().unwrap().expect("the answer was written");
    assert_eq!(frame.kind, FrameKind::HandBack);
    assert_eq!(frame.payload, b"the token cannot be made");
    assert!(
        fr.next_frame().unwrap().is_none() && fr.buffered_len() == 0,
        "bytes after the answer"
    );
    // Flushed, then the FIN, and only then the wait for the client to close.
    assert_eq!(*events.lock().unwrap(), ["flushed", "fin", "waited for the client"]);
}

/// A client that has gone cannot be told, which is not a fault.
#[test]
fn a_hand_back_to_a_client_that_has_gone_is_not_an_error() {
    hand_back(&mut Closed, &mut ClosedStream, &Control::standalone(), "why").unwrap();
}

/// An answer to a client that has gone (a Ctrl+C ended `elevate` while its command ran) is routine, whichever answer it
/// is: it is logged at debug and the handler ends cleanly. A write or a FIN that fails for another reason is still the
/// handler's error.
#[test]
fn an_answer_to_a_client_that_has_gone_is_not_an_error_and_any_other_failed_write_is() {
    use std::io::ErrorKind;
    /// A connection whose writes fail with `write` and whose FIN fails with `fin`, when they are set.
    struct Failing {
        write: Option<ErrorKind>,
        fin: Option<ErrorKind>,
    }
    impl Write for Failing {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.write.map_or(Ok(bytes.len()), |kind| Err(kind.into()))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.write.map_or(Ok(()), |kind| Err(kind.into()))
        }
    }
    impl HalfClose for Failing {
        fn shutdown_write(&self) -> anyhow::Result<()> {
            self.fin.map_or(Ok(()), |kind| Err(std::io::Error::from(kind).into()))
        }
    }
    let control = Control::standalone();
    // Both answers go through `answer_and_wait`: the first is a request's reply, the second a refused login's.
    let answer = |reply: bool, tx: &mut Failing| {
        if reply {
            reply_and_wait(&mut Closed, tx, &control, "", 0)
        } else {
            refuse_while_ending(&mut Closed, tx, &control)
        }
    };
    for (what, is_reply) in [("a reply", true), ("a refusal while ending", false)] {
        let answer = |tx: &mut Failing| answer(is_reply, tx);
        let gone = [
            ErrorKind::BrokenPipe,
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionAborted,
        ]
        .map(|kind| {
            (
                format!("a write that fails with {kind:?}"),
                Failing {
                    write: Some(kind),
                    fin: None,
                },
            )
        })
        .into_iter()
        .chain([(
            "a FIN that fails with BrokenPipe".to_owned(),
            Failing {
                write: None,
                fin: Some(ErrorKind::BrokenPipe),
            },
        )]);
        for (row, mut tx) in gone {
            let (log, result) = logged(|| answer(&mut tx));
            result.unwrap_or_else(|e| panic!("{what}, {row}: a client that has gone is not a fault: {e:#}"));
            assert!(!log.contains("WARN") && !log.contains("ERROR"), "{what}, {row}: {log}");
        }
        for mut tx in [
            Failing {
                write: Some(ErrorKind::PermissionDenied),
                fin: None,
            },
            Failing {
                write: None,
                fin: Some(ErrorKind::PermissionDenied),
            },
        ] {
            answer(&mut tx).expect_err(&format!("{what}: a failure for another reason is an error"));
        }
    }
}

#[test]
fn the_refusal_is_one_line_that_says_the_session_is_ending_and_to_reconnect() {
    assert_eq!(ENDING_REFUSAL.matches('\n').count(), 1);
    assert!(ENDING_REFUSAL.ends_with("\r\n"));
    assert!(ENDING_REFUSAL.contains("ending"), "{ENDING_REFUSAL}");
    assert!(ENDING_REFUSAL.contains("reconnect"), "{ENDING_REFUSAL}");
    // 255 is what ssh uses for a failed connection and what the shim uses for a dead agent; 1 would
    // look like the command's own failure (grep found nothing).
    assert_eq!(ENDING_REFUSED_EXIT_CODE, 255);
}

#[test]
fn the_refusal_arrives_although_the_client_keeps_sending_input() {
    // More than the socket buffers hold, so a server that has stopped reading cannot hide behind them.
    const AFTER_HANDSHAKE: usize = 8 * 1024 * 1024;
    let ((mut srx, mut stx), (mut crx, mut ctx), dir) = socket_pair("refusal-input");
    let client = std::thread::spawn(move || {
        let chunk = [b'x'; 32 * 1024];
        for _ in 0..AFTER_HANDSHAKE / chunk.len() {
            write_data(&mut ctx, Stream::Stdin, &chunk).expect("input after the handshake must still be read");
        }
        let mut sink = TestSink::default();
        let outcome = pump_decode(&mut crx, &mut FrameReader::new(), &mut sink).expect("the reply was lost");
        (outcome, sink.stderr)
    });
    refuse_while_ending(&mut srx, &mut stx, &Control::standalone()).unwrap();
    let (outcome, stderr) = client.join().unwrap();
    assert_eq!(outcome, Outcome::Exited(ENDING_REFUSED_EXIT_CODE));
    assert_eq!(stderr, ENDING_REFUSAL.as_bytes());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_session_that_registers_while_the_shells_are_being_ended_is_refused() {
    let slot: Arc<Mutex<Option<Arc<Control>>>> = Arc::new(Mutex::new(None));
    let control = Arc::new(Control::new(true, Connections::new()));
    *slot.lock().unwrap() = Some(Arc::clone(&control));
    let refused = Arc::new(AtomicBool::new(false));
    let _first = control
        .register({
            let (refused, slot) = (Arc::clone(&refused), Arc::clone(&slot));
            Arc::new(move || {
                let control = slot.lock().unwrap().clone().unwrap();
                let killed = Arc::new(AtomicUsize::new(0));
                refused.store(control.register(counting_killer(&killed)).is_none(), Ordering::SeqCst);
            })
        })
        .unwrap();

    handle_logout(&mut Closed, &mut Vec::new(), &control, |_| {}).unwrap();

    assert!(refused.load(Ordering::SeqCst));
    *slot.lock().unwrap() = None;
}

#[test]
fn a_logout_whose_client_is_gone_before_the_reply_still_ends_the_agent() {
    let control = Control::new(true, Connections::new());
    let killed = Arc::new(AtomicUsize::new(0));
    let _session = control.register(counting_killer(&killed)).unwrap();
    let ended = AtomicBool::new(false);

    handle_logout(&mut Closed, &mut ClosedStream, &control, |_| {
        ended.store(true, Ordering::SeqCst)
    })
    .unwrap();

    assert!(ended.load(Ordering::SeqCst), "every logout ends the agent");
    assert_eq!(killed.load(Ordering::SeqCst), 1);
}

// a login refused while the agent ends -----

#[test]
fn a_hand_back_whose_client_never_closes_is_let_go_after_the_bound_and_the_log_says_so() {
    let ((_srx, mut stx), (_crx, _ctx), dir) = socket_pair("hand-back-silent");
    let control = Control::new(true, Connections::with_drain_bound(SHORT_BOUND));
    let (_silent, closed) = mpsc::channel::<()>();

    let (log, result) = logged(|| hand_back(&mut Gate::new(closed), &mut stx, &control, "why"));

    result.unwrap();
    assert!(log.contains("had not closed its connection"), "{log}");
    assert!(log.contains("a handed-back login"), "{log}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_refused_login_whose_client_never_closes_is_let_go_after_the_bound_and_the_log_says_so() {
    let ((_srx, mut stx), (_crx, _ctx), dir) = socket_pair("refusal-silent");
    let control = Control::new(true, Connections::with_drain_bound(SHORT_BOUND));
    let (_silent, closed) = mpsc::channel::<()>();

    let (log, result) = logged(|| refuse_while_ending(&mut Gate::new(closed), &mut stx, &control));

    result.unwrap();
    assert!(log.contains("had not closed its connection"), "{log}");
    assert!(log.contains("refused"), "{log}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_refused_login_whose_client_closes_in_time_is_not_reported() {
    let ((_srx, mut stx), (_crx, _ctx), dir) = socket_pair("refusal-closes");
    let control = Control::new(true, Connections::new());

    let (log, result) = logged(|| refuse_while_ending(&mut Closed, &mut stx, &control));

    result.unwrap();
    assert!(!log.contains("had not closed"), "{log}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Run a refusal of a login whose client stays connected, on a thread of its own, as one live
/// connection of `connections`. Returns once the refusal is reading from the client (so the reply
/// and the FIN are out), with the means to close the client and to join the refusal.
fn refusal_awaiting_its_client(
    connections: &Arc<Connections>,
    tag: &str,
) -> (mpsc::Sender<()>, std::thread::JoinHandle<()>, std::path::PathBuf) {
    let ((server_rx, mut stx), client, dir) = socket_pair(tag);
    let control = Arc::new(Control::new(true, Arc::clone(connections)));
    let live = connections.begin();
    let (silent, closed) = mpsc::channel::<()>();
    let (reading, started) = mpsc::channel::<()>();
    let refusal = std::thread::spawn(move || {
        // The sockets stay open while the refusal runs.
        let _sockets = (server_rx, client);
        let _live = live;
        refuse_while_ending(&mut Open { reading, closed }, &mut stx, &control).unwrap();
    });
    started.recv().unwrap();
    (silent, refusal, dir)
}

#[test]
fn the_drain_does_not_complete_while_a_refused_client_is_still_connected() {
    // The client has input the refusal has not read, and the process ends when the drain returns:
    // closing with that unread resets the connection and loses the reply. The drain's bound is the
    // only thing that can end it while the client stays.
    let connections = Connections::with_drain_bound(SHORT_BOUND);
    let (silent, refusal, dir) = refusal_awaiting_its_client(&connections, "refusal-holds-drain");

    let drained = connections.wait_until_only_logouts_live();

    drop(silent);
    refusal.join().unwrap();
    assert_eq!(drained, Drained::Abandoned { still_live: 1 });
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_drain_completes_once_a_refused_client_has_closed() {
    // The client closes inside the drain's park, which is after the drain is waiting.
    let client: Arc<Mutex<Option<mpsc::Sender<()>>>> = Arc::default();
    let connections = Connections::observing_drain({
        let client = Arc::clone(&client);
        move |_| drop(client.lock().unwrap().take())
    });
    let (silent, refusal, dir) = refusal_awaiting_its_client(&connections, "refusal-ends-drain");
    *client.lock().unwrap() = Some(silent);

    let drained = connections.wait_until_only_logouts_live();

    // A drain that returned before the client closed must not leave the refusal waiting for ever.
    drop(client.lock().unwrap().take());
    refusal.join().unwrap();
    assert_eq!(drained, Drained::Complete);
    let _ = std::fs::remove_dir_all(&dir);
}

// a handler that never returns -----

/// The drain bound of these tests: the handler they hold never finishes, so the bound is what ends
/// the wait, and its length changes nothing about what is asserted.
const SHORT_BOUND: std::time::Duration = std::time::Duration::from_millis(10);

#[test]
fn a_logout_client_that_never_closes_does_not_keep_the_agent_alive_and_the_log_says_so() {
    let connections = Connections::with_drain_bound(SHORT_BOUND);
    let control = Control::new(true, connections);
    let killed = Arc::new(AtomicUsize::new(0));
    let _session = control.register(counting_killer(&killed)).unwrap();
    let ended = AtomicBool::new(false);
    // The sender stays alive and silent: the client is connected and says nothing.
    let (_silent, closed) = mpsc::channel::<()>();

    let (log, result) = logged(|| {
        handle_logout(&mut Gate::new(closed), &mut Vec::new(), &control, |_| {
            ended.store(true, Ordering::SeqCst)
        })
    });

    result.unwrap();
    assert!(ended.load(Ordering::SeqCst), "the logout ended the agent");
    assert_eq!(killed.load(Ordering::SeqCst), 1, "and its sessions");
    assert!(log.contains("had not closed its connection"), "{log}");
}

#[test]
fn a_logout_client_that_closes_in_time_is_not_reported() {
    let control = Control::new(true, Connections::new());
    let (close, closed) = mpsc::channel();
    close.send(()).unwrap();

    let (log, result) = logged(|| handle_logout(&mut Gate::new(closed), &mut Vec::new(), &control, |_| {}));

    result.unwrap();
    assert!(!log.contains("had not closed"), "{log}");
}

/// Run `f` on the server's read half while its client stays connected and says nothing. If `f`
/// blocks, the helper closes the client once the failsafe passes, so that `f` returns and the test
/// then fails instead of hanging. A bound that works ends `f` first and releases the helper.
fn against_a_silent_client<T>(tag: &str, f: impl FnOnce(&mut ConnRx) -> T) -> T {
    const FAILSAFE: Duration = Duration::from_secs(5);
    let ((mut srx, _stx), (crx, ctx), dir) = socket_pair(tag);
    let (done, finished) = mpsc::channel::<()>();
    let failsafe = std::thread::spawn(move || {
        let _ = finished.recv_timeout(FAILSAFE); // sleep-ok: failsafe, a hang becomes a failure
        let _ = ctx.shutdown_both();
        drop((crx, ctx));
    });
    let result = f(&mut srx);
    drop(done);
    failsafe.join().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    result
}

#[test]
fn a_read_limit_on_a_connection_ends_a_read_that_finds_nothing() {
    let result = against_a_silent_client("limited-read", |rx| {
        rx.limit_reads(SHORT_BOUND);
        rx.read(&mut [0u8; 8])
    });
    let err = result.expect_err("nothing was sent, and the client is still connected");
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut, "{err:?}");
}

/// Limits that are not whole milliseconds: the wait's poll takes whole milliseconds, and 0 would be no wait at all.
const LIMITS: [Duration; 6] = [
    Duration::from_micros(1),
    Duration::from_micros(500),
    Duration::from_micros(999),
    Duration::from_millis(1),
    Duration::from_micros(1500),
    Duration::from_nanos(1_000_001),
];

#[test]
fn a_read_limit_of_any_length_ends_a_read_that_finds_nothing() {
    for (i, limit) in LIMITS.into_iter().enumerate() {
        let result = against_a_silent_client(&format!("limited-read-{i}"), |rx| {
            rx.limit_reads(limit);
            rx.read(&mut [0u8; 8])
        });
        let err = result.expect_err(&format!("a limit of {limit:?} did not end the read"));
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut, "{limit:?}: {err:?}");
    }
}

#[test]
fn a_wait_for_a_client_that_never_closes_ends_whatever_the_bound() {
    // The loop skips the 1 us bound: it has passed before the wait issues a read, so that row would not
    // exercise the wait. `a_read_limit_of_any_length_*` pins that limit with a read.
    for (i, bound) in LIMITS.into_iter().enumerate().skip(1) {
        let waited = against_a_silent_client(&format!("wait-bound-{i}"), |rx| wait_for_close_within(rx, bound));
        assert_eq!(waited, Waited::Abandoned, "{bound:?}");
    }
}

#[test]
fn a_connection_with_a_read_limit_still_delivers_what_arrives_and_reports_the_close() {
    let ((mut srx, _stx), (crx, mut ctx), dir) = socket_pair("limited-read-data");
    srx.limit_reads(Duration::from_secs(30));
    ctx.write_all(b"hi").unwrap();
    let mut buf = [0u8; 8];
    assert_eq!(srx.read(&mut buf).unwrap(), 2);
    ctx.shutdown_write().unwrap();
    assert_eq!(wait_for_close_within(&mut srx, Duration::from_secs(30)), Waited::Closed);
    drop((crx, ctx));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_connection_handler_that_never_returns_does_not_keep_the_agent_alive() {
    let connections = Connections::with_drain_bound(SHORT_BOUND);
    let stuck = connections.begin();
    let this_connection = connections.begin();
    let control = Control::new(true, Arc::clone(&connections));
    let ended = AtomicBool::new(false);

    let _live = this_connection;
    handle_logout(&mut Closed, &mut Vec::new(), &control, |_| {
        ended.store(true, Ordering::SeqCst)
    })
    .unwrap();

    assert!(ended.load(Ordering::SeqCst), "the logout ended the agent");
    drop(stuck);
}

#[test]
fn a_logout_that_waited_in_vain_says_how_many_connections_it_left() {
    let connections = Connections::with_drain_bound(SHORT_BOUND);
    let _a = connections.begin();
    let _b = connections.begin();
    let _logout_connection = connections.begin();
    let _logout = connections.begin_logout();
    assert_eq!(
        connections.wait_until_only_logouts_live(),
        Drained::Abandoned { still_live: 2 }
    );
}

#[test]
fn a_drain_that_finishes_in_time_reports_complete() {
    let connections = Connections::with_drain_bound(SHORT_BOUND);
    let _logout_connection = connections.begin();
    let _logout = connections.begin_logout();
    assert_eq!(connections.wait_until_only_logouts_live(), Drained::Complete);
}

#[test]
fn a_connection_that_finishes_within_the_bound_is_waited_for() {
    // The bound is for what never finishes: a connection that does finish is awaited, however
    // long the bound.
    let connections = Connections::new();
    let other = connections.begin();
    let _logout_connection = connections.begin();
    let _logout = connections.begin_logout();
    let finisher = std::thread::spawn(move || drop(other));
    assert_eq!(connections.wait_until_only_logouts_live(), Drained::Complete);
    finisher.join().unwrap();
}

// Sessions' ids -----

#[test]
fn control_reserves_an_id_before_the_start_and_registration_ends_it() {
    let control = Control::new(true, Connections::new());
    let killed = Arc::new(AtomicUsize::new(0));
    let reservation = control
        .reserve()
        .unwrap()
        .expect("an agent that is not ending reserves");
    let id = *reservation.id();
    assert!(!control.is_registered(&id), "reserved is not running");

    let registration = reservation
        .register(counting_killer(&killed))
        .expect("an agent that is not ending registers");
    assert!(control.is_registered(&id));
    assert_eq!(
        SessionId::parse(&id.to_string()),
        Some(id),
        "the id is the one that goes into the environment"
    );

    drop(registration);
    assert!(!control.is_registered(&id), "the entry ends with the registration");
    handle_logout(&mut Closed, &mut Vec::new(), &control, |_| {}).unwrap();
    assert_eq!(killed.load(Ordering::SeqCst), 0, "an ended session is not ended again");
}

#[test]
fn a_registered_session_is_ended_by_the_id_it_was_given() {
    let control = Control::new(true, Connections::new());
    let killed = Arc::new(AtomicUsize::new(0));
    let reservation = control.reserve().unwrap().unwrap();
    let _registration = reservation.register(counting_killer(&killed)).unwrap();
    handle_logout(&mut Closed, &mut Vec::new(), &control, |_| {}).unwrap();
    assert_eq!(killed.load(Ordering::SeqCst), 1);
}

#[test]
fn reserve_is_refused_once_the_agent_is_ending() {
    let control = Control::new(true, Connections::new());
    handle_logout(&mut Closed, &mut Vec::new(), &control, |_| {}).unwrap();
    assert!(control.reserve().unwrap().is_none());
}

/// A session whose start is under way when the end begins is the one the registration refuses.
#[test]
fn a_reservation_made_before_the_end_began_is_refused_registration() {
    let control = Control::new(true, Connections::new());
    let killed = Arc::new(AtomicUsize::new(0));
    let reservation = control.reserve().unwrap().unwrap();
    let id = *reservation.id();
    handle_logout(&mut Closed, &mut Vec::new(), &control, |_| {}).unwrap();
    assert!(reservation.register(counting_killer(&killed)).is_none());
    assert!(!control.is_registered(&id));
}

#[test]
fn a_reservation_dropped_unregistered_leaves_no_entry() {
    let control = Control::new(true, Connections::new());
    let killed = Arc::new(AtomicUsize::new(0));
    // The reservation is dropped at the end of the statement: its session never started.
    let id = *control.reserve().unwrap().unwrap().id();
    assert!(!control.is_registered(&id));
    let _running = control.register(counting_killer(&killed)).unwrap();
    handle_logout(&mut Closed, &mut Vec::new(), &control, |_| {}).unwrap();
    assert_eq!(
        killed.load(Ordering::SeqCst),
        1,
        "only the session that started is ended; the reserved one left nothing to end"
    );
}

#[test]
fn two_reservations_never_share_an_id() {
    let control = Control::new(true, Connections::new());
    let killed = Arc::new(AtomicUsize::new(0));
    let a = control.reserve().unwrap().unwrap();
    let b = control.reserve().unwrap().unwrap();
    assert_ne!(a.id(), b.id());
    let (a_id, b_id) = (*a.id(), *b.id());
    let _a = a.register(counting_killer(&killed)).unwrap();
    let _b = b.register(counting_killer(&killed)).unwrap();
    assert!(control.is_registered(&a_id) && control.is_registered(&b_id));
}

/// A process that outlived its agent holds an id the next agent never gave out.
#[test]
fn an_id_from_another_agent_run_is_unknown_to_a_new_agent() {
    let (old, new) = (
        Control::new(true, Connections::new()),
        Control::new(true, Connections::new()),
    );
    let killed = Arc::new(AtomicUsize::new(0));
    let reservation = old.reserve().unwrap().unwrap();
    let id = *reservation.id();
    let _registration = reservation.register(counting_killer(&killed)).unwrap();
    assert!(old.is_registered(&id));
    assert!(!new.is_registered(&id), "a new agent does not know it");
    let fresh = new.reserve().unwrap().unwrap();
    assert_ne!(*fresh.id(), id, "and does not give it out again");
}

#[test]
fn reply_with_empty_text_writes_only_the_exit_frame() {
    let mut bytes = Vec::new();
    reply(&mut bytes, "", 7).unwrap();
    assert_eq!(decode(&bytes), (Vec::new(), Some(7)));

    let mut bytes = Vec::new();
    reply(&mut bytes, "said\r\n", 126).unwrap();
    assert_eq!(
        decode(&bytes),
        (vec![(Stream::Stderr as u8, "said\r\n".to_owned())], Some(126))
    );
}

// Sessions that can be elevated from -----

/// A session entry over a connection that goes nowhere: what `attach` is given.
fn a_hosted_session(policy: ElevationPolicy) -> Arc<HostedSession> {
    struct Nowhere;
    impl Write for Nowhere {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl HalfClose for Nowhere {
        fn shutdown_write(&self) -> anyhow::Result<()> {
            Ok(())
        }
    }
    let starts = Starts {
        pty: crate::conpty::PtySession::spawn,
        exec: crate::pipes::ExecChild::spawn,
    };
    Arc::new(HostedSession::new(
        policy,
        super::super::link::Link::new(Nowhere, true, (80, 24), None),
        starts,
    ))
}

/// `await_hosted` of `id` on a thread, which says on the returned channel that it is about to wait.
fn await_on_a_thread(
    control: &Arc<Control>,
    id: SessionId,
) -> (std::thread::JoinHandle<Option<Arc<HostedSession>>>, mpsc::Receiver<()>) {
    let (parked, on_parked) = mpsc::channel();
    let control = Arc::clone(control);
    let thread = std::thread::spawn(move || {
        control.await_hosted_observed(&id, || {
            let _ = parked.send(());
        })
    });
    (thread, on_parked)
}

#[test]
fn a_request_for_a_reserved_session_waits_for_its_link_and_then_runs() {
    let control = Arc::new(Control::new(true, Connections::new()));
    let reservation = control.reserve().unwrap().unwrap();
    let id = *reservation.id();
    let registration = reservation
        .register(counting_killer(&Arc::new(AtomicUsize::new(0))))
        .unwrap();

    let (waiter, on_parked) = await_on_a_thread(&control, id);
    on_parked.recv().expect("the request is waiting for the session's link");
    registration.attach(a_hosted_session(ElevationPolicy::AutoApprove));
    let hosted = waiter
        .join()
        .unwrap()
        .expect("the request goes on once the session is attached");
    assert_eq!(hosted.policy, ElevationPolicy::AutoApprove);
    assert!(hosted.link.has_terminal());
}

/// Before the session is registered it is only an id the agent has given out: a request for it waits as well.
#[test]
fn a_request_for_an_id_not_yet_registered_waits_for_the_registration_and_the_link() {
    let control = Arc::new(Control::new(true, Connections::new()));
    let reservation = control.reserve().unwrap().unwrap();
    let id = *reservation.id();
    let (waiter, on_parked) = await_on_a_thread(&control, id);
    on_parked.recv().unwrap();
    let registration = reservation
        .register(counting_killer(&Arc::new(AtomicUsize::new(0))))
        .unwrap();
    registration.attach(a_hosted_session(ElevationPolicy::Prompt));
    assert!(waiter.join().unwrap().is_some());
}

#[test]
fn a_request_waiting_for_a_session_whose_start_fails_is_released_by_the_reservation() {
    let control = Arc::new(Control::new(true, Connections::new()));
    let reservation = control.reserve().unwrap().unwrap();
    let (waiter, on_parked) = await_on_a_thread(&control, *reservation.id());
    on_parked.recv().unwrap();
    drop(reservation);
    assert!(waiter.join().unwrap().is_none(), "the session never started");
}

#[test]
fn a_request_waiting_for_a_session_that_ends_before_it_attaches_is_released_by_the_registration() {
    let control = Arc::new(Control::new(true, Connections::new()));
    let reservation = control.reserve().unwrap().unwrap();
    let id = *reservation.id();
    let registration = reservation
        .register(counting_killer(&Arc::new(AtomicUsize::new(0))))
        .unwrap();
    let (waiter, on_parked) = await_on_a_thread(&control, id);
    on_parked.recv().unwrap();
    drop(registration);
    assert!(waiter.join().unwrap().is_none(), "the session ended without a link");
}

#[test]
fn an_id_the_agent_did_not_give_out_is_not_waited_for_and_an_ended_session_is_gone() {
    let control = Arc::new(Control::new(true, Connections::new()));
    let stranger = *Control::new(true, Connections::new()).reserve().unwrap().unwrap().id();
    assert!(
        control
            .await_hosted_observed(&stranger, || panic!("an unknown id is not waited for"))
            .is_none()
    );

    let reservation = control.reserve().unwrap().unwrap();
    let id = *reservation.id();
    let registration = reservation
        .register(counting_killer(&Arc::new(AtomicUsize::new(0))))
        .unwrap();
    registration.attach(a_hosted_session(ElevationPolicy::Never));
    assert!(
        control
            .await_hosted_observed(&id, || panic!("an attached session is not waited for"))
            .is_some()
    );
    drop(registration);
    assert!(
        control
            .await_hosted_observed(&id, || panic!("an ended session is not waited for"))
            .is_none()
    );
}

#[test]
fn one_elevation_at_a_time_holds_a_slot_that_frees_when_it_is_dropped() {
    let hosted = a_hosted_session(ElevationPolicy::AutoApprove);
    let first = hosted.slot.try_take().expect("the first takes the slot");
    assert!(
        hosted.slot.try_take().is_none(),
        "a second is refused while the first holds it"
    );
    drop(first);
    assert!(hosted.slot.try_take().is_some(), "the slot is free again");
}

// The tally's listeners -----

/// Two accept loops (`agent.sock`, `request.sock`) hold listeners; the end waits for both to close.
#[test]
fn the_tally_waits_for_every_listener_to_close() {
    let (events, on_event) = mpsc::channel();
    let connections = Connections::observing_drain({
        let events = events.clone();
        move |_| {
            let _ = events.send("parked");
        }
    });
    let (woken, on_wake) = mpsc::channel();
    let open = |socket: &'static str| {
        let woken = woken.clone();
        HeldListener::open(&connections, socket, move |_| woken.send(socket).unwrap())
    };
    let (agent, request) = (open("agent.sock"), open("request.sock"));
    let ender = {
        let connections = Arc::clone(&connections);
        std::thread::spawn(move || {
            connections.settle();
            events.send("returned").unwrap();
        })
    };
    let mut loops = [on_wake.recv().unwrap(), on_wake.recv().unwrap()];
    loops.sort_unstable();
    assert_eq!(
        loops,
        ["agent.sock", "request.sock"],
        "each loop is woken, by the tally"
    );
    assert!(connections.is_closing(), "the flag is up when the loops are woken");
    // Nothing is live, so the drain does not park: the end parks once with both listeners open, and again each time
    // the tally changes while one is still held.
    assert_eq!(on_event.recv().unwrap(), "parked", "the end waits for the listeners");
    agent.close();
    assert_eq!(
        on_event.recv().unwrap(),
        "parked",
        "the end returned with the second listener still held"
    );
    request.close();
    // A wake the condition variable gives for nothing parks the end again, so a park may come first.
    let after = std::iter::from_fn(|| on_event.recv().ok()).find(|event| *event != "parked");
    assert_eq!(after, Some("returned"));
    assert!(!connections.listener_is_open());
    ender.join().unwrap();
}

/// One `logout`, whichever socket it came in on, wakes the loop of each socket, and the end completes once both
/// have returned.
#[test]
fn a_logout_wakes_the_loop_of_each_socket_and_ends_the_agent() {
    let connections = Connections::new();
    let (woken, on_wake) = mpsc::channel();
    let open = |socket: &'static str| {
        let woken = woken.clone();
        HeldListener::open(&connections, socket, move |listener| {
            woken.send(socket).unwrap();
            listener.close();
        })
    };
    let (_agent, _request) = (open("agent.sock"), open("request.sock"));
    let control = Control::new(true, Arc::clone(&connections));
    let ended = AtomicBool::new(false);

    handle_logout(&mut Closed, &mut Vec::new(), &control, |_| {
        ended.store(true, Ordering::SeqCst)
    })
    .unwrap();

    let mut loops: Vec<_> = on_wake.try_iter().collect();
    loops.sort_unstable();
    assert_eq!(loops, ["agent.sock", "request.sock"]);
    assert!(ended.load(Ordering::SeqCst), "the end completed");
    assert!(!connections.listener_is_open());
}

// How the end goes -----

/// How a background agent's end went when `logout` is handled on `control`: what the handler passed to `end_process`.
fn logout_ended(control: &Control) -> anyhow::Result<()> {
    let outcome = Mutex::new(None);
    handle_logout(&mut Closed, &mut Vec::new(), control, |ended| {
        *outcome.lock().unwrap() = Some(ended)
    })
    .unwrap();
    outcome.into_inner().unwrap().expect("the end was finished")
}

/// A `logout` served after a shortage decided the end (the connection the loop kept, or one accepted before the loop
/// read the flag) ends the agent as the failed end that the other threads end it as, whichever of them is first.
#[test]
fn a_logout_served_after_a_shortage_decided_the_end_ends_as_the_failed_end() {
    let connections = Connections::new();
    let control = Control::new(true, Arc::clone(&connections));
    assert!(connections.decide_end_if_idle(connections.ended(), &anyhow::anyhow!("accept failed with code 10055")));

    let end = logout_ended(&control).expect_err("the end is the failure that decided it");

    assert_eq!(crate::agent::exit_code_of(&end), 1);
    assert!(end.downcast_ref::<crate::agent::NothingLive>().is_some(), "{end:#}");
    assert!(format!("{end:#}").contains("accept failed with code 10055"), "{end:#}");
}

/// With no shortage recorded, a `logout` ends the agent cleanly.
#[test]
fn a_logout_with_no_shortage_recorded_ends_cleanly() {
    let control = Control::new(true, Connections::new());

    assert!(logout_ended(&control).is_ok());
}
