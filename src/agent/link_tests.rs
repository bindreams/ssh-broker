//! Tests for the session's connection and whom it carries. In-memory transport and recording targets: no socket, no
//! agent. A wait is observed by the callback `deliver_observed` makes before it parks, never by a delay.
use super::super::test_wire::{Recorder, Wire};
use super::*;
use crate::protocol::{ExitCode, FrameKind, Resize, Stream};
use std::sync::atomic::Ordering;
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

// Whose bytes the connection carries -----

#[test]
fn deliver_blocks_the_other_carrier_until_the_switch_back() {
    let (wire, session) = (Wire::default(), Arc::new(Recorder::default()));
    let link = terminal_link(&wire, &session);
    let guard = link.host_elevated(Arc::new(Recorder::default()));

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

    let guard = link.host_elevated(Arc::new(Recorder::default()));
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
    let _guard = link.host_elevated(Arc::new(Recorder::default()));
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

    let guard = link.host_elevated(elevated.clone());
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

    let _guard = link.host_elevated(elevated.clone());
    assert_eq!(elevated.events(), ["resize 120x30"]);
}

/// Resizing a pseudoconsole to the size it has makes it repaint its whole screen: that is how the session's screen
/// comes back after the command's.
#[test]
fn the_switch_back_gives_the_session_its_size_even_unchanged() {
    let (wire, session) = (Wire::default(), Arc::new(Recorder::default()));
    let link = terminal_link(&wire, &session);
    drop(link.host_elevated(Arc::new(Recorder::default())));
    assert_eq!(session.events(), ["resize 80x24"]);
}

/// A link without a terminal has no screen to hand over: the session's `decide` refuses that request.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "without a terminal")]
fn hosting_a_command_on_a_link_without_a_terminal_is_a_bug() {
    let link = Link::new(Wire::default(), false, (0, 0), None);
    let _guard = link.host_elevated(Arc::new(Recorder::default()));
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
