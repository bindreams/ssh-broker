//! Unit tests for the agent's answer to `logout`. In-process: no socket, no shell, no process ends.
use super::*;
use crate::protocol::{ExitCode, FrameKind, FrameReader, Stream};
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
    let connections = Connections::new();
    let this_connection = connections.begin();
    let other = connections.begin();
    let control = Arc::new(Control::new(true, Arc::clone(&connections)));
    let (ending, on_ending) = mpsc::channel();
    let _session = control
        .register(Arc::new(move || {
            let _ = ending.send(());
        }))
        .unwrap();
    let ended = Arc::new(AtomicBool::new(false));

    let worker = {
        let (control, ended) = (Arc::clone(&control), Arc::clone(&ended));
        std::thread::spawn(move || {
            let _live = this_connection;
            handle_logout(&mut Closed, &mut Vec::new(), &control, || {
                ended.store(true, Ordering::SeqCst)
            })
            .unwrap();
        })
    };
    // The session's shell has been ended; its connection is still relaying the last output.
    on_ending.recv().unwrap();
    assert!(!ended.load(Ordering::SeqCst), "the other connection has not finished");

    drop(other);
    worker.join().unwrap();
    assert!(ended.load(Ordering::SeqCst));
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

#[test]
fn a_connection_that_arrives_while_ending_is_told_so_and_gets_a_failing_exit_code() {
    let mut written = Vec::new();
    refuse_while_ending(&mut written).unwrap();
    let (data, exit) = decode(&written);
    assert_eq!(data, [(Stream::Stderr as u8, ENDING_REPLY.to_string())]);
    assert_eq!(exit, Some(ENDING_REFUSED_EXIT_CODE));
    assert_ne!(ENDING_REFUSED_EXIT_CODE, 0, "the login did not get a shell");
}
