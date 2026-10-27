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

/// A client that stays connected until the test says it closes.
struct Gate(mpsc::Receiver<()>);

impl Read for Gate {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        let _ = self.0.recv();
        Ok(0)
    }
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
            handle_logout(&mut Gate(closed), &mut Tx(replied), &control, || {
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
    assert_eq!(on_event.recv().unwrap(), "ended");
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
    let server = std::thread::spawn(move || refuse_while_ending(&mut srx, &mut stx).unwrap());

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
    refuse_while_ending(&mut srx, &mut stx).unwrap();
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

// a handler that never returns -----

/// The drain bound of these tests: the handler they hold never finishes, so the bound is what ends
/// the wait, and its length changes nothing about what is asserted.
const SHORT_BOUND: std::time::Duration = std::time::Duration::from_millis(10);

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
