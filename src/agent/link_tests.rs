//! Tests for the session's connection and whom it carries. In-memory transport and recording targets: no socket, no
//! agent. A wait is observed by the callback `deliver_observed` makes before it parks, never by a delay.
use super::super::test_wire::{Recorder, Wire};
use super::*;
use crate::protocol::{
    ConsentAnswer, ConsentReply, ConsentRequest, ConsentWithdrawal, ExitCode, FrameKind, Resize, Stream,
};
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

const COMMAND: &str = "cmd /c whoami";
const CWD: &str = r"C:\Users\me";

/// The question the link puts, numbered `id`.
fn a_question(id: u32) -> ConsentRequest {
    ConsentRequest {
        version: crate::protocol::PROTOCOL_VERSION,
        id,
        command: COMMAND.to_owned(),
        cwd: CWD.to_owned(),
    }
}

fn reply(id: u32, answer: ConsentAnswer) -> ConsentReply {
    ConsentReply { id, answer }
}

/// The frame that withdraws the question numbered `id`.
fn withdrawn(id: u32) -> (FrameKind, Vec<u8>) {
    (FrameKind::ConsentWithdrawn, ConsentWithdrawal { id }.encode().unwrap())
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
    ask_for_on_a_thread(link, Arc::new(ClientGone::default()))
}

/// [`ask_on_a_thread`] for the request whose client is `gone`.
fn ask_for_on_a_thread(link: &Arc<Link>, gone: Arc<ClientGone>) -> Asked {
    let (parked, on_parked) = mpsc::channel();
    let (answered, answer) = mpsc::channel();
    let (release, released) = mpsc::channel::<()>();
    let link = Arc::clone(link);
    let thread = std::thread::spawn(move || {
        let outcome = link.ask_observed(COMMAND, CWD, &gone, || {
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
            [(FrameKind::Consent, a_question(1).encode().unwrap())],
            "the question is the one frame written"
        );
        assert_eq!(carrier(&link), Carrier::Asking);
        assert!(asked.answer.try_recv().is_err(), "nothing answered yet");

        link.answer(reply(1, answer));
        assert_eq!(asked.answer.recv().unwrap(), Ok(answer));
        assert_eq!(
            carrier(&link),
            Carrier::Asking,
            "the screen is the question's until its hold is let go"
        );
        asked.finish();
        assert_eq!(carrier(&link), Carrier::Session);
        assert_eq!(wire.frames().len(), 1, "an answered question is not withdrawn");
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

    link.answer(reply(1, ConsentAnswer::Refuse));
    asked.answer.recv().unwrap().unwrap();
    asked.finish();
    held.join()
        .unwrap()
        .expect("the held output goes on once the question is over");
    let kinds: Vec<FrameKind> = wire.frames().iter().map(|(kind, _)| *kind).collect();
    assert_eq!(kinds, [FrameKind::Data, FrameKind::Consent, FrameKind::Data]);
    assert_eq!(wire.data(), ["Pbefore", "Pheld"]);
}

/// The inputs a recording target was given, without its sizes.
fn inputs(target: &Recorder) -> Vec<String> {
    target
        .events()
        .into_iter()
        .filter(|event| event.starts_with("input "))
        .collect()
}

/// The shim relays nothing while it asks, so a key that reaches the agent before the answer was relayed before the
/// question existed: it is the session's, and goes to it at once, as at any other time.
#[test]
fn keys_before_the_answer_go_straight_to_the_session() {
    let (wire, session) = (Wire::default(), Arc::new(Recorder::default()));
    let link = terminal_link(&wire, &session);
    let asked = ask_on_a_thread(&link);
    asked.parked.recv().unwrap();

    link.route_input_observed(b"before", || panic!("waited before the answer"))
        .unwrap();
    link.resize(Resize { cols: 100, rows: 40 });
    assert_eq!(session.events(), ["input before", "resize 100x40"]);
    assert_eq!(carrier(&link), Carrier::Asking, "the question still holds the screen");

    link.answer(reply(1, ConsentAnswer::Refuse));
    asked.answer.recv().unwrap().unwrap();
    asked.finish();
}

/// The client's input is ordered after its answer: a key that arrives once the answer has waits, in the pump that
/// carries it, until the question's hold is let go, and then goes to the session.
#[test]
fn keys_after_the_answer_wait_for_the_hold_and_go_to_the_session_when_it_is_let_go() {
    for answer in [ConsentAnswer::Allow, ConsentAnswer::Refuse] {
        let (wire, session) = (Wire::default(), Arc::new(Recorder::default()));
        let link = terminal_link(&wire, &session);
        let asked = ask_on_a_thread(&link);
        asked.parked.recv().unwrap();
        link.answer(reply(1, answer));
        asked.answer.recv().unwrap().unwrap();

        let (waiting, on_waiting) = mpsc::channel();
        let pump = {
            let link = Arc::clone(&link);
            std::thread::spawn(move || {
                link.route_input_observed(b"dir", || {
                    let _ = waiting.send(());
                })
            })
        };
        on_waiting.recv().expect("the pump waits for the question's outcome");
        assert_eq!(
            inputs(&session),
            Vec::<String>::new(),
            "{answer:?}: nothing before the hold is let go"
        );

        asked.finish();
        pump.join().unwrap().unwrap();
        // The repaint's resize races the key, by design: only the inputs are compared.
        assert_eq!(inputs(&session), ["input dir"], "{answer:?}");
    }
}

/// An allowed `--terminal` command is what the keys after the answer are for: they wait for it, and go to it in
/// order, ahead of any later key. What came before the answer went to the session at once.
#[test]
fn keys_after_an_allow_wait_for_the_command_and_go_to_it_in_order() {
    let (wire, session, elevated) = (
        Wire::default(),
        Arc::new(Recorder::default()),
        Arc::new(Recorder::default()),
    );
    let link = terminal_link(&wire, &session);
    let asked = ask_on_a_thread(&link);
    asked.parked.recv().unwrap();

    link.route_input(b"before").unwrap();
    link.answer(reply(1, ConsentAnswer::Allow));
    asked.answer.recv().unwrap().unwrap();
    let (waiting, on_waiting) = mpsc::channel();
    let pump = {
        let link = Arc::clone(&link);
        std::thread::spawn(move || {
            link.route_input_observed(b"one", || {
                let _ = waiting.send(());
            })
            .unwrap();
            link.route_input(b"two")
        })
    };
    on_waiting.recv().expect("the pump waits for the command");
    assert_eq!(
        inputs(&session),
        ["input before"],
        "nothing of the later keys went to the session"
    );
    assert_eq!(
        inputs(&elevated),
        Vec::<String>::new(),
        "nor to a command not yet hosted"
    );

    let guard = host(&link, elevated.clone());
    pump.join().unwrap().unwrap();
    assert_eq!(inputs(&elevated), ["input one", "input two"]);
    assert_eq!(inputs(&session), ["input before"]);
    asked.finish();
    drop(guard);
}

/// Every return of the screen to the session gives the session's pseudoconsole its size, even unchanged: that is the
/// repaint of what the question's clear wiped.
#[test]
fn the_screen_goes_back_to_the_session_with_its_size_when_the_question_is_over() {
    let (wire, session) = (Wire::default(), Arc::new(Recorder::default()));
    let link = terminal_link(&wire, &session);
    let asked = ask_on_a_thread(&link);
    asked.parked.recv().unwrap();
    link.answer(reply(1, ConsentAnswer::Refuse));
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
    link.answer(reply(1, ConsentAnswer::Allow));
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
    assert_eq!(
        kinds,
        [FrameKind::Consent, FrameKind::ConsentWithdrawn, FrameKind::Data]
    );
    assert_eq!(wire.frames()[1], withdrawn(1), "it names the question");
}

/// A target that records which frames the connection had when the session was repainted (given its size).
struct FramesAtRepaint {
    wire: Wire,
    seen: std::sync::Mutex<Vec<Vec<FrameKind>>>,
}

impl InputTarget for FramesAtRepaint {
    fn input(&self, _bytes: &[u8]) -> anyhow::Result<()> {
        Ok(())
    }

    fn resize(&self, _cols: u16, _rows: u16) {
        let kinds = self.wire.frames().iter().map(|(kind, _)| *kind).collect();
        self.seen.lock().unwrap().push(kinds);
    }
}

/// Every way a question ends without an answer from the shim tells the shim, so that its question does not stay on
/// the console: the withdrawal, an empty frame, is written before the screen goes back to the session and repaints.
#[test]
fn a_question_that_ends_without_an_answer_is_withdrawn_before_the_screen_goes_back() {
    type Cause = fn(&Link, &ClientGone);
    let causes: [(&str, Cause); 3] = [
        ("the session's shell is gone", |link, _| link.end_hosting()),
        ("the session is over", |link, _| link.end()),
        ("the client has gone", |link, gone| link.client_gone(gone)),
    ];
    for (what, cause) in causes {
        let wire = Wire::default();
        let target = Arc::new(FramesAtRepaint {
            wire: wire.clone(),
            seen: Default::default(),
        });
        let link = Link::new(
            wire.clone(),
            true,
            (80, 24),
            Some(Arc::clone(&target) as Arc<dyn InputTarget>),
        );
        let gone = Arc::new(ClientGone::default());
        let asked = ask_for_on_a_thread(&link, Arc::clone(&gone));
        asked.parked.recv().expect("the question is waiting");

        cause(&link, &gone);
        assert_eq!(asked.answer.recv().unwrap(), Err(Ended), "{what}");
        asked.finish();
        assert_eq!(
            wire.frames(),
            [(FrameKind::Consent, a_question(1).encode().unwrap()), withdrawn(1),],
            "{what}"
        );
        assert_eq!(
            *target.seen.lock().unwrap(),
            [[FrameKind::Consent, FrameKind::ConsentWithdrawn]],
            "{what}: the repaint came after the withdrawal"
        );
    }
}

/// The client of the request the question is for hangs up: the question ends and the screen is the session's again; a
/// question for a client that has gone is not put.
#[test]
fn a_client_that_has_gone_ends_its_question_and_one_that_is_gone_is_not_asked() {
    let (wire, session) = (Wire::default(), Arc::new(Recorder::default()));
    let link = terminal_link(&wire, &session);
    let gone = Arc::new(ClientGone::default());
    let (parked, on_parked) = mpsc::channel();
    let asking = {
        let (link, gone) = (Arc::clone(&link), Arc::clone(&gone));
        std::thread::spawn(move || {
            let outcome = link.ask_observed(COMMAND, CWD, &gone, || {
                let _ = parked.send(());
            });
            outcome.map(|(answer, _hold)| answer)
        })
    };
    on_parked.recv().expect("the question is waiting");
    link.client_gone(&gone);
    assert_eq!(asking.join().unwrap(), Err(Ended));
    assert_eq!(carrier(&link), Carrier::Session, "the screen is the session's again");
    assert_eq!(
        wire.frames().len(),
        2,
        "only the question and its withdrawal were written"
    );

    assert!(matches!(link.ask(COMMAND, CWD, &gone), Err(Ended)));
    assert_eq!(
        wire.frames().len(),
        2,
        "no second question, and no withdrawal of it, for a client that is gone"
    );
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
    assert!(matches!(link.ask(COMMAND, CWD, &ClientGone::default()), Err(Ended)));
    assert_eq!(carrier(&link), Carrier::Session);
}

/// The session's own input target failed earlier (its pseudoconsole is closed): the input pump has stopped delivering
/// keys, and the question asked afterwards still gets its answer, and the pump still sees the client go.
#[test]
fn a_question_asked_after_the_sessions_input_failed_still_gets_its_answer() {
    use crate::protocol::{FrameReader, write_frame};
    use crate::relay::pump_until_peer_gone;

    struct Script<F>(F);
    impl<F: FnMut() -> Vec<u8>> std::io::Read for Script<F> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let bytes = (self.0)();
            buf[..bytes.len()].copy_from_slice(&bytes);
            Ok(bytes.len())
        }
    }

    let (wire, session) = (Wire::default(), Arc::new(Recorder::failing()));
    let link = terminal_link(&wire, &session);
    let mut sink = super::super::LinkInputSink {
        link: Arc::clone(&link),
    };
    let (mut step, mut asked, mut saw_eof) = (0, None, false);
    let script = Script(|| {
        step += 1;
        let mut bytes = Vec::new();
        match step {
            // A key: the session's target fails, and the sink with it.
            1 => crate::relay::write_data(&mut bytes, Stream::Pty, b"x").unwrap(),
            // The pump read again, so it saw the failure. Now the question is put and the shim answers it.
            2 => {
                let question = ask_on_a_thread(&link);
                question.parked.recv().expect("the question is waiting for its answer");
                write_frame(
                    &mut bytes,
                    FrameKind::ConsentAnswer,
                    &reply(1, ConsentAnswer::Allow).encode().unwrap(),
                )
                .unwrap();
                asked = Some(question);
            }
            _ => saw_eof = true,
        }
        bytes
    });
    pump_until_peer_gone(&mut { script }, &mut FrameReader::new(), &mut sink);

    assert!(
        saw_eof,
        "the pump went on reading after the failure, to the client's end"
    );
    let asked = asked.expect("the question was asked");
    assert_eq!(asked.answer.recv().unwrap(), Ok(ConsentAnswer::Allow));
    asked.finish();
}

/// The guard of a hosted command gives the connection back whoever carries it by then: what it set is cleared, so
/// that `end_hosting`, which waits for nothing to be hosted, returns.
#[test]
fn dropping_the_elevated_guard_clears_the_hosting_even_when_another_carries_the_connection() {
    let (wire, session) = (Wire::default(), Arc::new(Recorder::default()));
    let link = terminal_link(&wire, &session);
    let guard = host(&link, Arc::new(Recorder::default()));
    locked(&link.state).carrier = Carrier::Session;

    drop(guard);
    assert!(
        locked(&link.state).elevated.is_none(),
        "the guard cleared what it set; `end_hosting` would wait for ever"
    );
    link.end_hosting();
    assert_eq!(carrier(&link), Carrier::Session);
}

/// An answer that nobody asked for (the question was ended and the shim answered late) does not answer the next one.
#[test]
fn an_answer_with_no_question_is_dropped_and_does_not_answer_the_next_question() {
    let (wire, session) = (Wire::default(), Arc::new(Recorder::default()));
    let link = terminal_link(&wire, &session);
    link.answer(reply(1, ConsentAnswer::Allow));
    // A late answer cannot stall the pump: no question was open, so nothing waits for its outcome.
    link.route_input_observed(b"k", || panic!("a dropped answer made the pump wait"))
        .unwrap();
    assert_eq!(session.events(), ["input k"]);
    let asked = ask_on_a_thread(&link);
    asked
        .parked
        .recv()
        .expect("the earlier answer did not answer it: it waits");
    link.answer(reply(1, ConsentAnswer::Refuse));
    assert_eq!(asked.answer.recv().unwrap(), Ok(ConsentAnswer::Refuse));
    asked.finish();
}

/// An answer is for the question whose number it carries: one that was sent for a question that ended (its client
/// gone, the session's shell ending) and arrives after the next was asked is dropped, so it cannot allow a command
/// the person has not been shown.
#[test]
fn an_answer_to_an_earlier_question_is_dropped_and_the_new_question_still_waits() {
    let (wire, session) = (Wire::default(), Arc::new(Recorder::default()));
    let link = terminal_link(&wire, &session);
    let gone = Arc::new(ClientGone::default());
    let first = ask_for_on_a_thread(&link, Arc::clone(&gone));
    first.parked.recv().unwrap();
    link.client_gone(&gone);
    assert_eq!(first.answer.recv().unwrap(), Err(Ended));
    first.finish();

    let second = ask_on_a_thread(&link);
    second.parked.recv().unwrap();
    assert_eq!(
        wire.frames().last(),
        Some(&(FrameKind::Consent, a_question(2).encode().unwrap())),
        "the second question is numbered 2"
    );

    // The shim's answer to the first, which the shim had already begun to send.
    link.answer(reply(1, ConsentAnswer::Allow));
    assert!(
        second.answer.try_recv().is_err(),
        "the old answer did not answer the new question"
    );
    assert_eq!(carrier(&link), Carrier::Asking);

    link.answer(reply(2, ConsentAnswer::Refuse));
    assert_eq!(second.answer.recv().unwrap(), Ok(ConsentAnswer::Refuse));
    second.finish();
}
