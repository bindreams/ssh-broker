//! Tests for the request socket: what it answers, how it is served beside `agent.sock`, and how it is woken and
//! ended. Real sockets in a stand-in profile, which holds a plain folder at the level these tests run at.
use super::*;
use crate::acl::Sid;
use crate::afunix::{self, AcceptError, Listener};
use crate::agent::{Connections, Drained, Stopped};
use crate::protocol::{FrameKind, FrameReader, Handshake, Stream, write_frame};
use crate::relay::{Outcome, TestSink, pump_decode, write_data};
use crate::socket_loc::Integrity;
use crate::test_support::TempProfile;
use crate::userdir::{SocketDir, open_socket_dir};
use std::sync::Arc;
use std::sync::mpsc;

/// A plain folder in a stand-in profile, held, with a listener bound on its `request.sock`.
fn request_socket(tag: &str) -> (TempProfile, Arc<SocketDir>, Listener) {
    let profile = TempProfile::new(tag);
    let folder = Arc::new(open_socket_dir(&profile.location(), &Sid::current_user().unwrap()).unwrap());
    let listener = Listener::bind(&folder.location().request_path(), Integrity::Medium).unwrap();
    (profile, folder, listener)
}

/// Send `frames` to the request socket and return what the agent answers. The connection is closed when this
/// returns, which is what an agent that waits for its client to close waits for.
fn ask_raw(folder: &SocketDir, frames: impl FnOnce(&mut afunix::ConnTx)) -> (Outcome, TestSink) {
    let conn = folder.connect_request().unwrap();
    let (mut crx, mut ctx) = afunix::split(conn).unwrap();
    frames(&mut ctx);
    let mut sink = TestSink::default();
    let outcome = pump_decode(&mut crx, &mut FrameReader::new(), &mut sink).expect("the answer arrived");
    (outcome, sink)
}

fn send_handshake(hs: &Handshake) -> impl FnOnce(&mut afunix::ConnTx) + '_ {
    move |tx| write_frame(tx, FrameKind::Handshake, &hs.encode().unwrap()).unwrap()
}

fn logout_handshake() -> Handshake {
    Handshake {
        mode: Mode::Logout,
        ..Handshake::pty_default()
    }
}

/// What a client writes after it has connected.
type Frames = Box<dyn FnOnce(&mut afunix::ConnTx) + Send>;

fn stderr_of(sink: &TestSink) -> String {
    String::from_utf8_lossy(&sink.stderr).into_owned()
}

// What it answers -----

#[test]
fn the_request_socket_serves_logout_and_ends_a_background_agent() {
    let (_profile, folder, listener) = request_socket("rq-logout");
    let control = Control::new(true, Connections::new());
    let (ended, on_end) = mpsc::channel();
    let client = std::thread::spawn({
        let folder = Arc::clone(&folder);
        move || ask_raw(&folder, send_handshake(&logout_handshake()))
    });
    let conn = listener.accept().unwrap();
    handle(conn, &control, || ended.send(()).unwrap()).unwrap();

    let (outcome, sink) = client.join().unwrap();
    assert_eq!(outcome, Outcome::Exited(0));
    assert_eq!(stderr_of(&sink), logout::ENDING_REPLY, "the reply agent.sock gives");
    on_end.recv().expect("the background agent was ended");
    assert!(control.is_ending());
}

#[test]
fn the_request_socket_answers_a_desktop_agents_logout_as_agent_sock_does() {
    let (_profile, folder, listener) = request_socket("rq-desktop");
    let control = Control::new(false, Connections::new());
    let client = std::thread::spawn({
        let folder = Arc::clone(&folder);
        move || ask_raw(&folder, send_handshake(&logout_handshake()))
    });
    handle(listener.accept().unwrap(), &control, || {
        panic!("a desktop agent is not ended")
    })
    .unwrap();
    let (outcome, sink) = client.join().unwrap();
    assert_eq!(outcome, Outcome::Exited(logout::DESKTOP_EXIT_CODE));
    assert_eq!(stderr_of(&sink), logout::DESKTOP_REPLY);
    assert!(!control.is_ending());
}

#[test]
fn the_request_socket_refuses_a_session_handshake_with_a_sentence_and_starts_nothing() {
    for mode in [Mode::Pty, Mode::Exec] {
        let (_profile, folder, listener) = request_socket("rq-session");
        let control = Control::new(true, Connections::new());
        let hs = Handshake {
            mode,
            command: Some("cmd.exe /c echo SHOULD-NOT-RUN".into()),
            ..Handshake::pty_default()
        };
        let client = std::thread::spawn({
            let folder = Arc::clone(&folder);
            move || {
                ask_raw(&folder, |tx| {
                    send_handshake(&hs)(tx);
                    write_data(tx, Stream::Stdin, b"").unwrap();
                })
            }
        });
        let served = handle(listener.accept().unwrap(), &control, || {
            panic!("a session handshake ends nothing")
        });
        let (outcome, sink) = client.join().unwrap();

        assert!(served.is_err(), "{mode:?}: the refusal is for the log");
        assert_eq!(outcome, Outcome::Exited(logout::BAD_REQUEST_EXIT_CODE), "{mode:?}");
        assert_eq!(
            stderr_of(&sink),
            "ssh-broker: the agent could not serve the request: this socket takes requests only\r\n",
            "{mode:?}"
        );
        assert!(
            sink.stdout.is_empty() && sink.served == 0,
            "{mode:?}: no session was served"
        );
        assert!(!control.is_ending(), "{mode:?}: a refused request ends nothing");
    }
}

/// What a lower level can send is read as any connection's first frame is, and answered, not dropped.
#[test]
fn a_first_frame_that_is_no_handshake_is_answered_and_nothing_else_happens() {
    let oversize = [FrameKind::Handshake as u8, 0xff, 0xff, 0xff, 0xff];
    let old = Handshake {
        version: 4,
        ..logout_handshake()
    };
    let cases: [(&str, Frames, &str); 4] = [
        (
            "a data frame",
            Box::new(|tx| write_data(tx, Stream::Pty, b"oops").unwrap()),
            "first frame was not a handshake",
        ),
        (
            "a frame too large to read",
            Box::new(move |tx| {
                use std::io::Write;
                tx.write_all(&oversize).unwrap();
            }),
            "frame too large",
        ),
        (
            "bytes that are no handshake",
            Box::new(|tx| write_frame(tx, FrameKind::Handshake, &[0xff; 12]).unwrap()),
            "the agent could not read the request",
        ),
        (
            "a handshake of another version",
            Box::new(move |tx| send_handshake(&old)(tx)),
            "protocol version mismatch",
        ),
    ];
    for (what, frames, said) in cases {
        let (_profile, folder, listener) = request_socket("rq-garbage");
        let control = Control::new(true, Connections::new());
        let client = std::thread::spawn({
            let folder = Arc::clone(&folder);
            move || ask_raw(&folder, frames)
        });
        let served = handle(listener.accept().unwrap(), &control, || {
            panic!("{what} ended the agent")
        });
        let (outcome, sink) = client.join().unwrap();
        assert!(served.is_err(), "{what}");
        assert_eq!(outcome, Outcome::Exited(logout::BAD_REQUEST_EXIT_CODE), "{what}");
        assert!(stderr_of(&sink).contains(said), "{what}: {}", stderr_of(&sink));
        assert!(!control.is_ending(), "{what}");
    }
}

/// A connection that closes before a byte is not an error and gets no reply.
#[test]
fn a_client_that_leaves_without_a_byte_is_not_an_error() {
    let (_profile, folder, listener) = request_socket("rq-left");
    let control = Control::new(true, Connections::new());
    drop(folder.connect_request().unwrap());
    handle(listener.accept().unwrap(), &control, || panic!("nothing was asked")).unwrap();
}

// Served beside agent.sock -----

/// The request socket's own accept loop, over `listener`, with the end it was given wired as `agent` and
/// `request.sock` are in the agent. Its handler ends nothing but sends on `ended`, and says on `handling` that it
/// has a connection (which the loop has counted by then).
struct Serving {
    connections: Arc<Connections>,
    control: Arc<Control>,
    loop_thread: std::thread::JoinHandle<anyhow::Error>,
    ended: mpsc::Receiver<()>,
    handling: mpsc::Receiver<()>,
}

fn serve_on(folder: &Arc<SocketDir>, listener: Listener, connections: Arc<Connections>) -> Serving {
    let control = Arc::new(Control::new(true, Arc::clone(&connections)));
    let (ended, on_end) = mpsc::channel();
    let (handling, on_handling) = mpsc::channel();
    let loop_thread = std::thread::spawn({
        let (connections, control, folder) = (Arc::clone(&connections), Arc::clone(&control), Arc::clone(folder));
        move || {
            crate::agent::serve_listener(
                "request.sock",
                listener,
                Arc::new(move || folder.connect_request().map(drop)),
                &connections,
                |listener| {
                    crate::agent::accept_loop(
                        listener,
                        &connections,
                        &control,
                        || connections.is_closing(),
                        move |conn, control| {
                            // A test that has finished with this loop has dropped the receivers.
                            let _ = handling.send(());
                            let ended = ended.clone();
                            handle(conn, control, move || {
                                let _ = ended.send(());
                            })
                        },
                    )
                },
            )
        }
    });
    Serving {
        connections,
        control,
        loop_thread,
        ended: on_end,
        handling: on_handling,
    }
}

/// A logout typed in an unelevated session reaches the agent through the loop, which counts it as it counts a
/// session; the agent ends, and the end stops both the loop and the listener.
#[test]
fn a_logout_on_the_request_socket_ends_the_agent_and_its_loop() {
    let (_profile, folder, listener) = request_socket("rq-loop-logout");
    let serving = serve_on(&folder, listener, Connections::new());

    let (outcome, sink) = ask_raw(&folder, send_handshake(&logout_handshake()));
    assert_eq!(outcome, Outcome::Exited(0));
    assert_eq!(stderr_of(&sink), logout::ENDING_REPLY);

    serving.ended.recv().expect("the agent was ended by the request");
    let end = serving.loop_thread.join().unwrap();
    assert!(end.downcast_ref::<Stopped>().is_some(), "{end:#}");
    assert!(!serving.connections.listener_is_open(), "the listener is closed");
    assert!(serving.control.is_ending());
}

/// A connection that says nothing is live, and the end counts it among those it waits for, as for a session: a
/// drain whose bound passes reports it. (That a request connection that finishes is waited for is the tally's
/// own, for every connection: `a_request_connection_is_drained_like_a_session`.) The loop stops all the same.
#[test]
fn an_idle_connection_on_the_request_socket_is_counted_by_the_end() {
    let (_profile, folder, listener) = request_socket("rq-idle");
    let serving = serve_on(
        &folder,
        listener,
        Connections::with_drain_bound(std::time::Duration::from_millis(100)),
    );

    let idle = folder.connect_request().unwrap();
    serving
        .handling
        .recv()
        .expect("the loop gave the idle connection a handler");
    serving.control.end_all();
    assert_eq!(serving.control.settle(), Drained::Abandoned { still_live: 1 });
    let end = serving.loop_thread.join().unwrap();
    assert!(end.downcast_ref::<Stopped>().is_some(), "{end:#}");
    assert!(!serving.connections.listener_is_open());
    drop(idle);
}

/// A loop that fails leaves the agent as it was: the sessions' loop, the sessions and the decision to end are
/// not its to touch.
#[test]
fn a_request_listener_that_fails_does_not_end_the_sessions() {
    let connections = Connections::new();
    let control = Control::new(true, Arc::clone(&connections));
    let session = control.reserve().unwrap().unwrap();
    let killed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let session = session
        .register({
            let killed = Arc::clone(&killed);
            Arc::new(move || {
                killed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
        })
        .unwrap();

    let end = crate::agent::serve_listener("request.sock", (), Arc::new(|| Ok(())), &connections, |()| {
        anyhow::anyhow!("the listener failed")
    });

    assert_eq!(format!("{end:#}"), "the listener failed");
    assert!(!connections.listener_is_open(), "its listener is counted closed");
    assert!(!connections.is_closing(), "and it decided nothing");
    assert!(!control.is_ending());
    assert_eq!(
        killed.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "no session was touched"
    );
    assert!(control.reserve().unwrap().is_some(), "and sessions can still start");
    drop(session);
}

/// The request loop over an `accept` that fails with `accept`'s error, on a tally of its own with nothing live;
/// what the loop ended with.
fn request_loop_met(accept: impl FnMut() -> Result<socket2::Socket, AcceptError>) -> anyhow::Error {
    let connections = Connections::new();
    let control = Arc::new(Control::new(true, Arc::clone(&connections)));
    crate::agent::serve_listener("request.sock", (), Arc::new(|| Ok(())), &connections, |()| {
        crate::agent::accept_loop_with(
            accept,
            &connections,
            &control,
            || connections.is_closing(),
            |_conn, _control| Ok(()),
        )
    })
}

/// A shortage with no connection of the agent live ends the agent when the request loop meets it, as it does
/// when the loop of `agent.sock` does: nothing is live, so nothing is lost, and the next login starts an agent
/// with both sockets. Without that, the agent would serve `agent.sock` for the rest of its life with no request
/// socket, and every `logout` from an unelevated session would find nothing.
#[test]
fn a_shortage_with_nothing_live_ends_the_agent_whichever_socket_met_it() {
    let end = request_loop_met(|| {
        Err(AcceptError::Exhausted {
            code: 10055,
            source: std::io::Error::from_raw_os_error(10055),
        })
    });
    let mut ended = Vec::new();
    crate::agent::request_loop_ended(&end, |err| ended.push(format!("{err:#}")));
    assert_eq!(ended.len(), 1, "the agent was ended once: {end:#}");
    assert!(ended[0].contains("no connection of this agent is live"), "{}", ended[0]);
}

/// Anything else that stops the request loop leaves the agent and its sessions as they are.
#[test]
fn every_other_end_of_the_request_loop_leaves_the_agent_running() {
    let failed = request_loop_met(|| Err(AcceptError::Fatal(anyhow::anyhow!("the listener broke"))));
    let stopped = anyhow::Error::new(Stopped);
    for (what, end) in [("a listener that failed", failed), ("an end that was decided", stopped)] {
        crate::agent::request_loop_ended(&end, |err| panic!("{what} ended the agent: {err:#}"));
    }
}

// The wake -----

/// A connect that fails while its loop is open means the loop cannot be woken: the end stops waiting for it.
#[test]
fn a_request_loop_that_cannot_be_woken_does_not_hold_the_end_for_ever() {
    let connections = Connections::new();
    let control = Control::new(true, Arc::clone(&connections));
    // A loop that holds its listener and cannot be woken, and never returns.
    let _loop = connections.listener_opened("request.sock", Arc::new(|| Err(anyhow::anyhow!("no connection"))));
    let (log, drained) = crate::test_support::logged(|| control.settle());
    assert_eq!(drained, Drained::Complete);
    assert!(
        log.contains("could not wake the accept loop of request.sock: no connection"),
        "{log}"
    );
}

// Opening the folder -----

#[test]
fn only_an_agent_at_high_opens_the_plain_folder() {
    let profile = TempProfile::new("rq-medium");
    let result = crate::agent::open_request_folder(&profile.location_at(Integrity::Medium), |_| {
        panic!("an agent below High opens no plain folder")
    });
    assert!(result.is_none());
}

#[test]
fn a_plain_folder_that_cannot_be_opened_is_logged_and_the_agent_serves_without_it() {
    // A short tag: the elevated folder of the held location has the longer socket path.
    let profile = TempProfile::new("rf");
    let (log, none) = crate::test_support::logged(|| {
        crate::agent::open_request_folder(&profile.location_at(Integrity::High), |_| {
            Err(anyhow::anyhow!("the folder is owned by another account"))
        })
    });
    assert!(none.is_none());
    assert!(log.contains("the agent serves without a request socket"), "{log}");
    assert!(log.contains("the folder is owned by another account"), "{log}");
}

/// The plain folder is the held folder's profile's, not the one a second lookup of the token's would name.
#[test]
fn an_agent_at_high_opens_the_plain_folder_of_the_profile_it_holds() {
    let profile = TempProfile::new("op");
    let folder = crate::agent::open_request_folder(&profile.location_at(Integrity::High), |location| {
        open_socket_dir(location, &Sid::current_user().unwrap())
    })
    .expect("the folder opens");
    assert_eq!(folder.location(), &profile.location());
}

// Bound before the marker -----

/// The agent binds `request.sock` before it writes the serving marker, so that a login that wakes on the marker
/// finds both sockets; it starts serving it after.
#[test]
fn the_request_socket_exists_when_the_serving_marker_is_written() {
    let profile = TempProfile::new("rq-order");
    let folder = Arc::new(open_socket_dir(&profile.location(), &Sid::current_user().unwrap()).unwrap());
    let events = std::cell::RefCell::new(Vec::new());
    let end = crate::agent::run_on_with(
        folder.location(),
        |path| {
            events.borrow_mut().push("bind agent.sock");
            Listener::bind(path, Integrity::Medium)
        },
        || {
            events.borrow_mut().push("bind request.sock");
            crate::agent::bind_requests(&folder)
        },
        |location| {
            assert!(location.request_path().exists(), "request.sock is there at the marker");
            events.borrow_mut().push("mark");
            Ok(())
        },
        |_requests| events.borrow_mut().push("serve request.sock"),
        |_listener| {
            events.borrow_mut().push("accept");
            anyhow::anyhow!("stop")
        },
    )
    .unwrap_err();
    assert_eq!(end.to_string(), "stop");
    assert_eq!(
        *events.borrow(),
        [
            "bind agent.sock",
            "bind request.sock",
            "mark",
            "serve request.sock",
            "accept"
        ]
    );
}

/// A plain folder that is refused costs the request socket and nothing else.
#[test]
fn a_refused_plain_folder_leaves_the_agent_serving_its_sessions() {
    let profile = TempProfile::new("rq-none");
    let folder = Arc::new(open_socket_dir(&profile.location(), &Sid::current_user().unwrap()).unwrap());
    let events = std::cell::RefCell::new(Vec::new());
    let end = crate::agent::run_on_with(
        folder.location(),
        |path| Listener::bind(path, Integrity::Medium),
        || None::<()>,
        |_| {
            events.borrow_mut().push("mark");
            Ok(())
        },
        |()| events.borrow_mut().push("serve request.sock"),
        |_listener| {
            events.borrow_mut().push("accept");
            anyhow::anyhow!("stop")
        },
    )
    .unwrap_err();
    assert_eq!(end.to_string(), "stop");
    assert_eq!(*events.borrow(), ["mark", "accept"]);
    assert!(!folder.location().request_path().exists());
}
