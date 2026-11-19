//! Tests for the session's connection and whom it carries. In-memory transport and recording targets: no socket, no
//! agent. A wait is observed by the callback `deliver_observed` makes before it parks, never by a delay.
use super::super::test_wire::{Recorder, Wire};
use super::*;
use crate::protocol::{ConsentAnswer, ConsentRequest, ExitCode, FrameKind, Resize, Stream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;

/// A terminal link over `wire` of 80x24 whose session target is `session`.
fn terminal_link(wire: &Wire, session: &Arc<Recorder>) -> Arc<Link> {
    Link::new(
        wire.clone(),
        true,
        (80, 24),
        Some(Arc::clone(session) as Arc<dyn InputTarget>),
    )
}

/// Make `deliver_observed` of `link` park on a thread, and return once it has: the channel says it is about to wait.
fn deliver_parked(
    link: &Arc<Link>,
    carrier: Carrier,
    text: &'static str,
) -> (std::thread::JoinHandle<anyhow::Result<()>>, mpsc::Receiver<()>) {
    let (parked, on_parked) = mpsc::channel();
    let link = Arc::clone(link);
    let thread = std::thread::spawn(move || {
        link.deliver_observed(carrier, Stream::Pty, text.as_bytes(), || {
            let _ = parked.send(());
        })
    });
    (thread, on_parked)
}

/// Host `target` on `link`, with an end that does nothing: the link is not at its end.
fn host(link: &Link, target: ElevatedTarget) -> ElevatedGuard<'_> {
    link.host_elevated(target, Arc::new(|| {})).expect("hosted")
}

// Whose bytes the connection carries -----

#[test]
fn deliver_blocks_the_other_carrier_until_the_switch_back() {
    let (wire, session) = (Wire::default(), Arc::new(Recorder::default()));
    let link = terminal_link(&wire, &session);
    let guard = host(&link, Arc::new(Recorder::default()));

    let (blocked, on_parked) = deliver_parked(&link, Carrier::Session, "session");
    on_parked.recv().expect("the session's deliver is about to wait");
    assert!(
        wire.data().is_empty(),
        "nothing of the session was written while elevated"
    );

    drop(guard);
    blocked
        .join()
        .unwrap()
        .expect("the session's deliver went on after the switch back");
    assert_eq!(wire.data(), ["Psession"]);
}

#[test]
fn no_session_byte_is_written_while_elevated_and_none_of_the_elevated_after() {
    let (wire, session) = (Wire::default(), Arc::new(Recorder::default()));
    let link = terminal_link(&wire, &session);
    link.deliver(Carrier::Session, Stream::Pty, b"before").unwrap();

    let guard = host(&link, Arc::new(Recorder::default()));
    link.deliver(Carrier::Elevated, Stream::Pty, b"elevated").unwrap();
    let (session_waits, on_parked) = deliver_parked(&link, Carrier::Session, "held");
    on_parked.recv().unwrap();
    drop(guard);
    session_waits.join().unwrap().unwrap();

    let (late, on_late) = deliver_parked(&link, Carrier::Elevated, "late");
    on_late.recv().expect("an elevated byte after the switch back waits");
    link.deliver(Carrier::Session, Stream::Pty, b"after").unwrap();
    link.end();
    assert!(
        late.join().unwrap().is_err(),
        "the late elevated byte is refused at the end"
    );

    assert_eq!(wire.data(), ["Pbefore", "Pelevated", "Pheld", "Pafter"]);
}

/// Without a terminal nothing waits for a carrier: the streams are separate pipes, and a gate there could deadlock a
/// pipeline that waits on what it gates.
#[test]
fn without_a_terminal_no_carrier_waits() {
    let wire = Wire::default();
    let link = Link::new(wire.clone(), false, (0, 0), None);
    link.deliver(Carrier::Session, Stream::Stdout, b"session").unwrap();
    link.deliver(Carrier::Elevated, Stream::Stderr, b"elevated").unwrap();
    assert_eq!(wire.data(), ["Osession", "Eelevated"]);
}

#[test]
fn end_wakes_a_blocked_deliver_with_an_error() {
    let (wire, session) = (Wire::default(), Arc::new(Recorder::default()));
    let link = terminal_link(&wire, &session);
    let _guard = host(&link, Arc::new(Recorder::default()));
    let (blocked, on_parked) = deliver_parked(&link, Carrier::Session, "never");
    on_parked.recv().unwrap();

    link.end();
    let error = blocked.join().unwrap().expect_err("the session is over");
    assert!(format!("{error:#}").contains("ended"), "{error:#}");
    assert!(wire.data().is_empty());
    assert!(
        link.deliver(Carrier::Session, Stream::Pty, b"x").is_err(),
        "no wait is begun after the end"
    );
}

#[test]
fn send_exit_writes_the_code_and_closes_the_write_half() {
    let (wire, session) = (Wire::default(), Arc::new(Recorder::default()));
    let link = terminal_link(&wire, &session);
    link.send_exit(7);
    assert_eq!(wire.frames(), [(FrameKind::Exit, ExitCode(7).encode().to_vec())]);
    assert!(wire.closed.load(Ordering::SeqCst));
}

// Input and size -----

#[test]
fn input_and_resize_go_to_the_elevated_target_while_it_runs_and_back_after() {
    let (wire, session, elevated) = (
        Wire::default(),
        Arc::new(Recorder::default()),
        Arc::new(Recorder::default()),
    );
    let link = terminal_link(&wire, &session);
    link.route_input(b"a").unwrap();

    let guard = host(&link, elevated.clone());
    link.route_input(b"b").unwrap();
    link.resize(Resize { cols: 100, rows: 40 });
    assert_eq!(session.events(), ["input a"], "the session gets nothing while elevated");
    assert_eq!(elevated.events(), ["resize 80x24", "input b", "resize 100x40"]);

    drop(guard);
    link.route_input(b"c").unwrap();
    assert_eq!(
        session.events(),
        ["input a", "resize 100x40", "input c"],
        "the size changed meanwhile is applied to the session on the way back"
    );
    assert_eq!(elevated.events().len(), 3, "the elevated target gets nothing after");
}

/// The elevated command's input is closed while its pseudoconsole ends, before the guard drops: a key typed in that
/// window must not be the session's error, which would make the session's input pump drop every later key.
#[test]
fn an_input_error_of_the_elevated_target_is_not_the_sessions_and_the_session_gets_the_next_key() {
    let (wire, session) = (Wire::default(), Arc::new(Recorder::default()));
    let link = terminal_link(&wire, &session);
    let elevated = Arc::new(Recorder::failing());
    let guard = host(&link, elevated.clone());

    link.route_input(b"x")
        .expect("the command is ending: its error is not the caller's");
    assert_eq!(elevated.events(), ["resize 80x24", "input x"], "it was tried");
    assert_eq!(session.events(), Vec::<String>::new(), "the session got none of it");

    drop(guard);
    link.route_input(b"y").unwrap();
    assert_eq!(session.events(), ["resize 80x24", "input y"]);

    // The session's own target's error is still the caller's.
    let failing = Arc::new(Recorder::failing());
    let link = terminal_link(&Wire::default(), &failing);
    link.route_input(b"z")
        .expect_err("an error of the session's own input is returned");
}

/// The command has exited and its tree is reaped, but its screen is still up until its output is drained: the keys
/// typed meanwhile are the session's, and the session's echo of them waits for the screen like all its output.
#[test]
fn input_returns_to_the_session_before_the_screen_does() {
    let (wire, session, elevated) = (
        Wire::default(),
        Arc::new(Recorder::default()),
        Arc::new(Recorder::default()),
    );
    let link = terminal_link(&wire, &session);
    let guard = host(&link, elevated.clone());

    link.return_input();
    link.route_input(b"k").unwrap();
    link.resize(Resize { cols: 100, rows: 40 });
    assert_eq!(
        session.events(),
        ["input k", "resize 100x40"],
        "the keys and the size are the session's"
    );
    assert_eq!(
        elevated.events(),
        ["resize 80x24"],
        "the elevated target gets nothing after"
    );

    // The screen is still the command's: the session's echo waits, and the command's last output is written.
    let (echo, on_parked) = deliver_parked(&link, Carrier::Session, "echo");
    on_parked.recv().expect("the session's deliver waits for the screen");
    link.deliver(Carrier::Elevated, Stream::Pty, b"last").unwrap();
    assert_eq!(wire.data(), ["Plast"]);

    drop(guard);
    echo.join()
        .unwrap()
        .expect("the session's deliver went on after the switch back");
    assert_eq!(wire.data(), ["Plast", "Pecho"]);
}

#[test]
fn the_size_at_the_switch_is_applied_to_the_new_target() {
    let (wire, session, elevated) = (
        Wire::default(),
        Arc::new(Recorder::default()),
        Arc::new(Recorder::default()),
    );
    let link = terminal_link(&wire, &session);
    link.resize(Resize { cols: 120, rows: 30 });
    assert_eq!(session.events(), ["resize 120x30"]);

    let _guard = host(&link, elevated.clone());
    assert_eq!(elevated.events(), ["resize 120x30"]);
}

/// Resizing a pseudoconsole to the size it has makes it repaint its whole screen: that is how the session's screen
/// comes back after the command's.
#[test]
fn the_switch_back_gives_the_session_its_size_even_unchanged() {
    let (wire, session) = (Wire::default(), Arc::new(Recorder::default()));
    let link = terminal_link(&wire, &session);
    drop(host(&link, Arc::new(Recorder::default())));
    assert_eq!(session.events(), ["resize 80x24"]);
}

/// A link without a terminal has no screen to hand over: the session's `decide` refuses that request.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "without a terminal")]
fn hosting_a_command_on_a_link_without_a_terminal_is_a_bug() {
    let link = Link::new(Wire::default(), false, (0, 0), None);
    let _guard = host(&link, Arc::new(Recorder::default()));
}

/// The session's shell is gone: the command hosted now is ended, none is hosted after, and what is left of the
/// connection is the session's.
#[test]
fn after_end_hosting_nothing_is_hosted_and_a_command_that_asks_is_ended_at_once() {
    let (wire, session) = (Wire::default(), Arc::new(Recorder::default()));
    let link = terminal_link(&wire, &session);
    let ends = Arc::new(AtomicUsize::new(0));
    let (on_end, ended) = mpsc::channel();
    let counting = || -> Killer {
        let (ends, on_end) = (Arc::clone(&ends), on_end.clone());
        Arc::new(move || {
            ends.fetch_add(1, Ordering::SeqCst);
            let _ = on_end.send(());
        })
    };

    // A hosted command is ended once, and the guard's drop is still what switches back. `end_hosting` waits for that
    // drop, so it runs on a thread.
    let guard = link
        .host_elevated(Arc::new(Recorder::default()), counting())
        .expect("hosted");
    let ending = {
        let link = Arc::clone(&link);
        std::thread::spawn(move || link.end_hosting())
    };
    ended.recv().expect("the hosted command was ended");
    assert_eq!(ends.load(Ordering::SeqCst), 1, "the hosted command was ended");
    link.deliver(Carrier::Elevated, Stream::Pty, b"last words")
        .expect("the hosted command still has the screen until its guard drops");
    drop(guard);
    ending.join().unwrap();
    assert_eq!(ends.load(Ordering::SeqCst), 1, "the guard's drop ends nothing");

    // A command that asks now is refused hosting and ended at once.
    let late = link.host_elevated(Arc::new(Recorder::default()), counting());
    assert!(late.is_none(), "nothing is hosted after the session's end");
    assert_eq!(ends.load(Ordering::SeqCst), 2, "the command that asked was ended");

    link.deliver(Carrier::Session, Stream::Pty, b"session")
        .expect("a session deliver is written");
    link.deliver_observed(Carrier::Elevated, Stream::Pty, b"never", || {
        panic!("an elevated deliver waits after the session's shell is gone")
    })
    .expect_err("an elevated deliver fails");
    link.route_input(b"k").unwrap();
    assert_eq!(wire.data(), ["Plast words", "Psession"], "nothing else was written");
    assert_eq!(session.events().last().map(String::as_str), Some("input k"));
}

/// The session's end gives the connection to `send_exit` only once the command it hosted has given it back: its last
/// output is written before the session's `Exit`. The order is read off one channel the three parties send on: the
/// command's `end`, the guard's holder just before it drops the guard, and the thread that called `end_hosting`
/// just after the call.
#[test]
fn end_hosting_returns_only_when_the_hosted_command_has_given_the_connection_back() {
    let (wire, session) = (Wire::default(), Arc::new(Recorder::default()));
    let link = terminal_link(&wire, &session);
    let (events, order) = mpsc::channel::<&'static str>();
    let end: Killer = {
        let events = events.clone();
        Arc::new(move || {
            let _ = events.send("end");
        })
    };
    let guard = link.host_elevated(Arc::new(Recorder::default()), end).expect("hosted");

    let ending = {
        let (link, events) = (Arc::clone(&link), events.clone());
        std::thread::spawn(move || {
            link.end_hosting();
            let _ = events.send("returned");
        })
    };
    assert_eq!(order.recv().unwrap(), "end", "the hosted command was ended");

    // The command's teardown is still running: it writes its last words, then gives the connection back.
    link.deliver(Carrier::Elevated, Stream::Pty, b"last words")
        .expect("the hosted command still has the screen");
    let _ = events.send("released");
    drop(guard);
    ending.join().unwrap();

    assert_eq!(order.try_iter().collect::<Vec<_>>(), ["released", "returned"]);
    link.send_exit(0);
    assert_eq!(
        wire.frames().last().map(|(kind, _)| *kind),
        Some(FrameKind::Exit),
        "nothing is written after the Exit"
    );
    assert_eq!(wire.data(), ["Plast words"]);
}

#[test]
fn input_and_resize_are_routed_while_an_output_write_is_blocked() {
    let (wire, session) = (Wire::default(), Arc::new(Recorder::default()));
    let link = terminal_link(&wire, &session);
    let (gate, at_gate) = wire.hold_next_write();
    let writer = {
        let link = Arc::clone(&link);
        std::thread::spawn(move || link.deliver(Carrier::Session, Stream::Pty, b"stuck"))
    };
    at_gate.recv().expect("a deliver is inside the connection's write");

    // Both complete on this thread while the write is held: neither needs the connection.
    link.route_input(b"k").unwrap();
    link.resize(Resize { cols: 90, rows: 20 });
    assert_eq!(session.events(), ["input k", "resize 90x20"]);
    assert!(wire.data().is_empty(), "the write is still held");

    gate.release();
    writer.join().unwrap().unwrap();
    assert_eq!(wire.data(), ["Pstuck"]);
}

// The question -----

fn a_question() -> ConsentRequest {
    ConsentRequest {
        version: crate::protocol::PROTOCOL_VERSION,
        command: "cmd /c whoami".to_owned(),
        cwd: r"C:\Users\me".to_owned(),
    }
}

/// A question asked on a thread. The thread holds the question's hold on the screen after the answer, until the test
/// lets it go, so that what is true of the screen while the hold is on can be looked at.
struct Asked {
    /// The thread is about to wait for the answer.
    parked: mpsc::Receiver<()>,
    /// What `ask` returned.
    answer: mpsc::Receiver<Result<ConsentAnswer, Ended>>,
    release: mpsc::Sender<()>,
    thread: std::thread::JoinHandle<()>,
}

fn ask_on_a_thread(link: &Arc<Link>) -> Asked {
    let (parked, on_parked) = mpsc::channel();
    let (answered, answer) = mpsc::channel();
    let (release, released) = mpsc::channel::<()>();
    let link = Arc::clone(link);
    let thread = std::thread::spawn(move || {
        let outcome = link.ask_observed(&a_question(), || {
            let _ = parked.send(());
        });
        match outcome {
            Ok((given, hold)) => {
                let _ = answered.send(Ok(given));
                let _ = released.recv();
                drop(hold);
            }
            Err(ended) => {
                let _ = answered.send(Err(ended));
            }
        }
    });
    Asked {
        parked: on_parked,
        answer,
        release,
        thread,
    }
}

impl Asked {
    /// Let the thread drop its hold on the screen and end.
    fn finish(self) {
        let _ = self.release.send(());
        self.thread.join().unwrap();
    }
}

fn carrier(link: &Link) -> Carrier {
    locked(&link.state).carrier
}

#[test]
fn ask_writes_the_consent_frame_and_waits_for_the_answer_and_the_screen_is_the_questions_meanwhile() {
    for answer in [ConsentAnswer::Allow, ConsentAnswer::Refuse] {
        let (wire, session) = (Wire::default(), Arc::new(Recorder::default()));
        let link = terminal_link(&wire, &session);
        let asked = ask_on_a_thread(&link);
        asked.parked.recv().expect("the question is waiting for its answer");
        assert_eq!(
            wire.frames(),
            [(FrameKind::Consent, a_question().encode().unwrap())],
            "the question is the one frame written"
        );
        assert_eq!(carrier(&link), Carrier::Asking);
        assert!(asked.answer.try_recv().is_err(), "nothing answered yet");

        link.answer(answer);
        assert_eq!(asked.answer.recv().unwrap(), Ok(answer));
        assert_eq!(
            carrier(&link),
            Carrier::Asking,
            "the screen is the question's until its hold is let go"
        );
        asked.finish();
        assert_eq!(carrier(&link), Carrier::Session);
    }
}

/// The agent holds the session's output: a write for the session waits behind the question, and no output frame
/// follows the `Consent` frame until the answer is in.
#[test]
fn no_output_frame_follows_the_consent_frame_until_the_answer() {
    let (wire, session) = (Wire::default(), Arc::new(Recorder::default()));
    let link = terminal_link(&wire, &session);
    link.deliver(Carrier::Session, Stream::Pty, b"before").unwrap();
    let asked = ask_on_a_thread(&link);
    asked.parked.recv().unwrap();

    let (held, on_held) = deliver_parked(&link, Carrier::Session, "held");
    on_held.recv().expect("the session's output waits behind the question");
    let kinds: Vec<FrameKind> = wire.frames().iter().map(|(kind, _)| *kind).collect();
    assert_eq!(
        kinds,
        [FrameKind::Data, FrameKind::Consent],
        "nothing after the question"
    );

    link.answer(ConsentAnswer::Refuse);
    asked.answer.recv().unwrap().unwrap();
    asked.finish();
    held.join()
        .unwrap()
        .expect("the held output goes on once the question is over");
    let kinds: Vec<FrameKind> = wire.frames().iter().map(|(kind, _)| *kind).collect();
    assert_eq!(kinds, [FrameKind::Data, FrameKind::Consent, FrameKind::Data]);
    assert_eq!(wire.data(), ["Pbefore", "Pheld"]);
}

/// What is typed while the question is asked is neither the session's nor an answer: it is dropped. The size is
/// still the session's.
#[test]
fn input_typed_while_asking_is_discarded_and_the_size_is_not() {
    let (wire, session) = (Wire::default(), Arc::new(Recorder::default()));
    let link = terminal_link(&wire, &session);
    link.route_input(b"a").unwrap();
    let asked = ask_on_a_thread(&link);
    asked.parked.recv().unwrap();

    link.route_input(b"yes\r").expect("dropped, not an error");
    link.resize(Resize { cols: 100, rows: 40 });
    assert_eq!(
        session.events(),
        ["input a", "resize 100x40"],
        "no key reached the session"
    );

    link.answer(ConsentAnswer::Refuse);
    asked.answer.recv().unwrap().unwrap();
    asked.finish();
    link.route_input(b"c").unwrap();
    assert_eq!(
        session.events(),
        ["input a", "resize 100x40", "resize 100x40", "input c"],
        "the screen came back with the size, and keys are the session's again"
    );
}

/// Every return of the screen to the session gives the session's pseudoconsole its size, even unchanged: that is the
/// repaint of what the question's clear wiped.
#[test]
fn the_screen_goes_back_to_the_session_with_its_size_when_the_question_is_over() {
    let (wire, session) = (Wire::default(), Arc::new(Recorder::default()));
    let link = terminal_link(&wire, &session);
    let asked = ask_on_a_thread(&link);
    asked.parked.recv().unwrap();
    link.answer(ConsentAnswer::Refuse);
    asked.answer.recv().unwrap().unwrap();
    assert_eq!(session.events(), Vec::<String>::new(), "not before");
    asked.finish();
    assert_eq!(session.events(), ["resize 80x24"]);
}

/// An allowed `--terminal` command takes the screen straight from the question: the question's hold, let go
/// afterwards, gives nothing back, and the session is repainted once, when the command's own hold ends.
#[test]
fn a_command_hosted_while_the_question_holds_the_screen_takes_it_and_the_session_is_repainted_once() {
    let (wire, session, elevated) = (
        Wire::default(),
        Arc::new(Recorder::default()),
        Arc::new(Recorder::default()),
    );
    let link = terminal_link(&wire, &session);
    let asked = ask_on_a_thread(&link);
    asked.parked.recv().unwrap();
    link.answer(ConsentAnswer::Allow);
    asked.answer.recv().unwrap().unwrap();

    let guard = host(&link, elevated.clone());
    assert_eq!(carrier(&link), Carrier::Elevated);
    asked.finish();
    assert_eq!(
        carrier(&link),
        Carrier::Elevated,
        "the question's hold gave nothing back"
    );
    assert_eq!(session.events(), Vec::<String>::new(), "no repaint yet");

    drop(guard);
    assert_eq!(carrier(&link), Carrier::Session);
    assert_eq!(session.events(), ["resize 80x24"], "one repaint, at the command's end");
}

/// BINDING (the deputy, 2026-11-19): the session's shell going away ends a pending question at once.
#[test]
fn end_hosting_ends_a_pending_question_at_once() {
    let (wire, session) = (Wire::default(), Arc::new(Recorder::default()));
    let link = terminal_link(&wire, &session);
    let asked = ask_on_a_thread(&link);
    asked.parked.recv().unwrap();

    link.end_hosting();
    assert_eq!(asked.answer.recv().unwrap(), Err(Ended));
    asked.finish();
    // The session's own words can be written again, and nothing but the question was.
    link.deliver_observed(Carrier::Session, Stream::Pty, b"bye", || {
        panic!("the screen is still held by the question")
    })
    .unwrap();
    let kinds: Vec<FrameKind> = wire.frames().iter().map(|(kind, _)| *kind).collect();
    assert_eq!(kinds, [FrameKind::Consent, FrameKind::Data]);
}

#[test]
fn ask_on_a_link_whose_hosting_has_ended_or_that_has_ended_is_ended_at_once_and_writes_nothing() {
    for (what, end) in [
        ("hosting ended", (|link: &Link| link.end_hosting()) as fn(&Link)),
        ("ended", |link: &Link| link.end()),
    ] {
        let (wire, session) = (Wire::default(), Arc::new(Recorder::default()));
        let link = terminal_link(&wire, &session);
        end(&link);
        let asked = ask_on_a_thread(&link);
        assert_eq!(asked.answer.recv().unwrap(), Err(Ended), "{what}");
        assert!(asked.parked.try_recv().is_err(), "{what}: it never waited");
        asked.finish();
        assert!(wire.frames().is_empty(), "{what}: no question was put");
        assert_eq!(carrier(&link), Carrier::Session, "{what}");
    }
}

/// A connection that cannot be written is a client that has gone: the question is not put, and the screen is the
/// session's.
#[test]
fn a_connection_that_cannot_be_written_ends_the_question_and_gives_the_screen_back() {
    struct Broken;
    impl std::io::Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl HalfClose for Broken {
        fn shutdown_write(&self) -> anyhow::Result<()> {
            Ok(())
        }
    }
    let session = Arc::new(Recorder::default());
    let link = Link::new(
        Broken,
        true,
        (80, 24),
        Some(Arc::clone(&session) as Arc<dyn InputTarget>),
    );
    assert!(matches!(link.ask(&a_question()), Err(Ended)));
    assert_eq!(carrier(&link), Carrier::Session);
}

/// An answer that nobody asked for (the question was ended and the shim answered late) does not answer the next one.
#[test]
fn an_answer_with_no_question_is_dropped_and_does_not_answer_the_next_question() {
    let (wire, session) = (Wire::default(), Arc::new(Recorder::default()));
    let link = terminal_link(&wire, &session);
    link.answer(ConsentAnswer::Allow);
    let asked = ask_on_a_thread(&link);
    asked
        .parked
        .recv()
        .expect("the earlier answer did not answer it: it waits");
    link.answer(ConsentAnswer::Refuse);
    assert_eq!(asked.answer.recv().unwrap(), Ok(ConsentAnswer::Refuse));
    asked.finish();
}
