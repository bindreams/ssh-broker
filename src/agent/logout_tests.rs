//! Unit tests for the agent's answer to `logout`. In-process: no socket, no shell, no process ends.
use super::*;
use crate::afunix::{ConnRx, ConnTx, split};
use crate::agent::Drained;
use crate::protocol::{ExitCode, FrameKind, FrameReader, Stream};
use crate::relay::{Outcome, TestSink, pump_decode, write_data};
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
    fn limit_reads(&mut self, _: Duration) -> std::io::Result<()> {
        Ok(())
    }
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
    fn limit_reads(&mut self, limit: Duration) -> std::io::Result<()> {
        self.limit = Some(limit);
        Ok(())
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
    fn limit_reads(&mut self, _: Duration) -> std::io::Result<()> {
        Ok(())
    }
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

#[test]
fn desktop_agent_refuses_logout_and_keeps_serving() {
    let control = Control::new(false, Connections::new());
    let mut written = Vec::new();
    let ended = AtomicBool::new(false);
    let killed = Arc::new(AtomicUsize::new(0));
    let _session = control.register(counting_killer(&killed)).unwrap();

    handle_logout(&mut Closed, &mut written, &control, || {
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
    handle_logout(&mut Closed, &mut tx, &control, || events.lock().unwrap().push("ended")).unwrap();

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
            handle_logout(&mut Gate::new(closed), &mut Tx(replied), &control, || {
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
    handle_logout(&mut Closed, &mut Vec::new(), &control, || {}).unwrap();
    assert_eq!(killed.load(Ordering::SeqCst), 3);
    drop(sessions);
}

#[test]
fn a_finished_session_is_not_ended_by_a_later_logout() {
    let control = Control::new(true, Connections::new());
    let killed = Arc::new(AtomicUsize::new(0));
    drop(control.register(counting_killer(&killed)).unwrap());
    handle_logout(&mut Closed, &mut Vec::new(), &control, || {}).unwrap();
    assert_eq!(killed.load(Ordering::SeqCst), 0);
}

#[test]
fn a_session_that_starts_after_the_end_began_is_refused_registration() {
    let control = Control::new(true, Connections::new());
    handle_logout(&mut Closed, &mut Vec::new(), &control, || {}).unwrap();
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
        move || {
            let _ = events.send("parked");
        }
    });
    let this_connection = connections.begin();
    let other = connections.begin();
    let control = Arc::new(Control::new(true, Arc::clone(&connections)));

    let worker = std::thread::spawn(move || {
        let _live = this_connection;
        handle_logout(&mut Closed, &mut Vec::new(), &control, || {
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
                handle_logout(&mut Closed, &mut Vec::new(), &control, || {
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

#[test]
fn ending_wakes_the_accept_loop_once_however_many_logouts_ask() {
    let woken = Arc::new(AtomicUsize::new(0));
    let connections = Connections::new();
    let control = {
        let woken = Arc::clone(&woken);
        Control::new(true, connections).with_waker(move || {
            woken.fetch_add(1, Ordering::SeqCst);
        })
    };
    assert_eq!(
        woken.load(Ordering::SeqCst),
        0,
        "nothing wakes it before the end begins"
    );
    handle_logout(&mut Closed, &mut Vec::new(), &control, || {}).unwrap();
    assert_eq!(woken.load(Ordering::SeqCst), 1);
    handle_logout(&mut Closed, &mut Vec::new(), &control, || {}).unwrap();
    assert_eq!(woken.load(Ordering::SeqCst), 1, "it is already awake");
}

#[test]
fn the_accept_loop_is_woken_before_the_shells_are_ended() {
    // The listener should be gone, or going, by the time a user sees their shell end and logs in again.
    let events = Arc::new(Mutex::new(Vec::<&str>::new()));
    let control = {
        let events = Arc::clone(&events);
        Control::new(true, Connections::new()).with_waker(move || events.lock().unwrap().push("woken"))
    };
    let _session = control
        .register({
            let events = Arc::clone(&events);
            Arc::new(move || events.lock().unwrap().push("killed"))
        })
        .unwrap();
    handle_logout(&mut Closed, &mut Vec::new(), &control, || {}).unwrap();
    assert_eq!(*events.lock().unwrap(), ["woken", "killed"]);
}

#[test]
fn the_accept_loop_is_woken_after_the_flag_is_up() {
    // A loop woken before the flag is raised would look, find nothing to stop for and accept again.
    let seen = Arc::new(Mutex::new(None));
    let slot: Arc<Mutex<Option<Arc<Control>>>> = Arc::new(Mutex::new(None));
    let control = Arc::new(Control::new(true, Connections::new()).with_waker({
        let (seen, slot) = (Arc::clone(&seen), Arc::clone(&slot));
        move || {
            let control = slot.lock().unwrap().clone().unwrap();
            *seen.lock().unwrap() = Some(control.is_ending());
        }
    }));
    *slot.lock().unwrap() = Some(Arc::clone(&control));
    handle_logout(&mut Closed, &mut Vec::new(), &control, || {}).unwrap();
    assert_eq!(*seen.lock().unwrap(), Some(true));
    // Break the reference cycle.
    *slot.lock().unwrap() = None;
}

/// A connected AF_UNIX pair in a temp dir (no ACLs: these tests exercise the reply, not the security
/// boundary). Returns the server's halves, the client's halves and the dir to remove.
fn socket_pair(tag: &str) -> ((ConnRx, ConnTx), (ConnRx, ConnTx), std::path::PathBuf) {
    use socket2::{Domain, SockAddr, Socket, Type};
    let dir = std::env::temp_dir().join(format!("sb-logout-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("s");
    let listener = Socket::new(Domain::UNIX, Type::STREAM, None).unwrap();
    listener.bind(&SockAddr::unix(&path).unwrap()).unwrap();
    listener.listen(1).unwrap();
    let client = Socket::new(Domain::UNIX, Type::STREAM, None).unwrap();
    client.connect(&SockAddr::unix(&path).unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
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
fn a_login_that_registers_after_the_flag_is_up_but_before_the_shells_are_ended_is_refused() {
    // The window between raising the flag and ending the registered shells: a session that
    // registered in it would be neither ended with the rest nor refused.
    let refused = Arc::new(AtomicBool::new(false));
    let slot: Arc<Mutex<Option<Arc<Control>>>> = Arc::new(Mutex::new(None));
    let control = Arc::new(Control::new(true, Connections::new()).with_waker({
        let (refused, slot) = (Arc::clone(&refused), Arc::clone(&slot));
        move || {
            let control = slot.lock().unwrap().clone().unwrap();
            let killed = Arc::new(AtomicUsize::new(0));
            refused.store(control.register(counting_killer(&killed)).is_none(), Ordering::SeqCst);
        }
    }));
    *slot.lock().unwrap() = Some(Arc::clone(&control));
    let killed = Arc::new(AtomicUsize::new(0));
    let _before = control.register(counting_killer(&killed)).unwrap();

    handle_logout(&mut Closed, &mut Vec::new(), &control, || {}).unwrap();

    assert!(
        refused.load(Ordering::SeqCst),
        "a login that came after the flag was accepted"
    );
    assert_eq!(
        killed.load(Ordering::SeqCst),
        1,
        "a login that came before it is ended with the rest"
    );
    *slot.lock().unwrap() = None;
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

    handle_logout(&mut Closed, &mut Vec::new(), &control, || {}).unwrap();

    assert!(refused.load(Ordering::SeqCst));
    *slot.lock().unwrap() = None;
}

#[test]
fn a_logout_whose_client_is_gone_before_the_reply_still_ends_the_agent() {
    struct Gone;
    impl Write for Gone {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
    }
    let control = Control::new(true, Connections::new());
    let killed = Arc::new(AtomicUsize::new(0));
    let _session = control.register(counting_killer(&killed)).unwrap();
    let ended = AtomicBool::new(false);

    handle_logout(&mut Closed, &mut Gone, &control, || ended.store(true, Ordering::SeqCst)).unwrap();

    assert!(ended.load(Ordering::SeqCst), "every logout ends the agent");
    assert_eq!(killed.load(Ordering::SeqCst), 1);
}

// a login refused while the agent ends -----

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
        move || drop(client.lock().unwrap().take())
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

#[test]
fn a_wait_whose_limit_cannot_be_set_is_logged() {
    struct Unlimited;
    impl Read for Unlimited {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            panic!("a read without a limit");
        }
    }
    impl LimitedRead for Unlimited {
        fn limit_reads(&mut self, _: Duration) -> std::io::Result<()> {
            Err(std::io::Error::other("no such option"))
        }
    }

    let (log, waited) = logged(|| wait_for_close_within(&mut Unlimited, Duration::from_secs(30)));

    assert_eq!(waited, Waited::Closed);
    assert!(log.contains("could not limit"), "{log}");
    assert!(log.contains("no such option"), "{log}");
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
        handle_logout(&mut Gate::new(closed), &mut Vec::new(), &control, || {
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

    let (log, result) = logged(|| handle_logout(&mut Gate::new(closed), &mut Vec::new(), &control, || {}));

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
        rx.limit_reads(SHORT_BOUND).unwrap();
        rx.read(&mut [0u8; 8])
    });
    let err = result.expect_err("nothing was sent, and the client is still connected");
    assert!(
        matches!(
            err.kind(),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
        ),
        "{err:?}"
    );
}

/// Limits that are not whole milliseconds. The OS takes whole milliseconds and reads 0 as "no limit".
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
            rx.limit_reads(limit).unwrap();
            rx.read(&mut [0u8; 8])
        });
        let err = result.expect_err(&format!("a limit of {limit:?} did not end the read"));
        assert!(
            matches!(
                err.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            ),
            "{limit:?}: {err:?}"
        );
    }
}

#[test]
fn a_wait_for_a_client_that_never_closes_ends_whatever_the_bound() {
    // Not the 1 us limit: a bound that short has passed before the wait issues a read, so the row
    // would not exercise the limit. `a_read_limit_of_any_length_*` pins that limit with a read.
    for (i, bound) in LIMITS.into_iter().enumerate().skip(1) {
        let waited = against_a_silent_client(&format!("wait-bound-{i}"), |rx| wait_for_close_within(rx, bound));
        assert_eq!(waited, Waited::Abandoned, "{bound:?}");
    }
}

#[test]
fn a_connection_with_a_read_limit_still_delivers_what_arrives_and_reports_the_close() {
    let ((mut srx, _stx), (crx, mut ctx), dir) = socket_pair("limited-read-data");
    srx.limit_reads(Duration::from_secs(30)).unwrap();
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
    handle_logout(&mut Closed, &mut Vec::new(), &control, || {
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
