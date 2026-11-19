//! Tests for a request to elevate on the request socket: a real session of the agent (a command on pipes, or a shell
//! in a pseudoconsole, as the agent's own handlers host them), a second connection that asks, and the elevated
//! command as a real process of this test. The starters record what they were given and then start the real thing.
//! Waits are on frames and on the end of what the test started, never on a delay.
use super::*;
use crate::afunix::{self, ConnRx, ConnTx};
use crate::agent::Hooks;
use crate::agent::link::Carrier;
use crate::conpty::PtySession;
use crate::offer::text;
use crate::pipes::ExecChild;
use crate::protocol::{
    ElevationPolicy, ElevationRequest, FrameKind, FrameReader, Handshake, Launch, PROTOCOL_VERSION, SESSION_VARIABLE,
    SessionId, Stream, read_one_frame, write_frame,
};
use crate::relay::{Outcome, TestSink, pump_decode};
use crate::socket_loc::StepDown;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// One command a starter was asked to start.
#[derive(Debug, Clone)]
struct Start {
    terminal: bool,
    line: String,
    /// It was given a token in place of the agent's own.
    token: bool,
    session: Option<String>,
    cwd: Option<PathBuf>,
}

/// The starters are plain function pointers, so they record into one list; the tests that read it run one at a time.
static STARTED: Mutex<Vec<Start>> = Mutex::new(Vec::new());
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    let guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    STARTED.lock().unwrap().clear();
    guard
}

fn session_of(env: &[(&str, &str)]) -> Option<String> {
    env.iter()
        .find(|(name, _)| *name == SESSION_VARIABLE)
        .map(|(_, value)| (*value).to_owned())
}

fn recording_hooks() -> Hooks {
    Hooks {
        make_unelevated: |_| Ok(StepDown::Own),
        start_exec: |line, cwd, token, env| {
            STARTED.lock().unwrap().push(Start {
                terminal: false,
                line: line.to_owned(),
                token: token.is_some(),
                session: session_of(env),
                cwd: cwd.map(std::path::Path::to_path_buf),
            });
            ExecChild::spawn(line, cwd, token, env)
        },
        start_pty: |line, cols, rows, cwd, read, token, env| {
            STARTED.lock().unwrap().push(Start {
                terminal: true,
                line: line.to_owned(),
                token: token.is_some(),
                session: session_of(env),
                cwd: cwd.map(std::path::Path::to_path_buf),
            });
            PtySession::spawn(line, cols, rows, cwd, read, token, env)
        },
        ..Hooks::production()
    }
}

fn started() -> Vec<Start> {
    STARTED.lock().unwrap().clone()
}

static PAIRS: AtomicUsize = AtomicUsize::new(0);

fn a_pair(tag: &str) -> (socket2::Socket, socket2::Socket, PathBuf) {
    let n = PAIRS.fetch_add(1, Ordering::SeqCst);
    crate::test_support::raw_socket_pair(&format!("{tag}-{n}"))
}

/// The client of a session the agent hosts: reads what the agent sends it, until the test has seen what it waits for.
struct Client {
    rx: ConnRx,
    tx: ConnTx,
    frames: FrameReader,
    /// What the session has sent so far, as text: terminal, stdout and stderr together.
    seen: String,
    exit: Option<i32>,
}

impl Client {
    /// Read frames until `seen` holds `needle`.
    fn read_until(&mut self, needle: &str) {
        while !self.seen.contains(needle) {
            let frame = read_one_frame(&mut self.rx, &mut self.frames).unwrap_or_else(|e| {
                panic!(
                    "the session ended before it showed {needle:?} ({e:#}); it showed {:?}",
                    self.seen
                )
            });
            match frame.kind {
                FrameKind::Data => self.seen.push_str(&String::from_utf8_lossy(&frame.payload[1..])),
                FrameKind::Exit => {
                    self.exit = Some(crate::protocol::ExitCode::decode(&frame.payload).unwrap().0);
                    panic!(
                        "the session exited before it showed {needle:?}; it showed {:?}",
                        self.seen
                    );
                }
                _ => {}
            }
        }
    }
}

/// A session the agent hosts, a command that waits for its input, with `policy`, and its id.
struct Hosting {
    control: Arc<Control>,
    id: SessionId,
    client: Client,
    handler: std::thread::JoinHandle<anyhow::Result<()>>,
}

fn host(tag: &str, mode: Mode, policy: ElevationPolicy) -> Hosting {
    let control = Arc::new(Control::standalone());
    let (server, client, _dir) = a_pair(tag);
    let handler = std::thread::spawn({
        let control = Arc::clone(&control);
        move || crate::agent::handle_connection_in(server, recording_hooks(), &control)
    });
    let (rx, mut tx) = afunix::split(client).unwrap();
    let hs = Handshake {
        mode,
        launch: Launch::Direct,
        command: Some("cmd.exe /d /c findstr x".to_owned()),
        elevation: Some(policy),
        ..Handshake::pty_default()
    };
    write_frame(&mut tx, FrameKind::Handshake, &hs.encode().unwrap()).unwrap();
    let mut client = Client {
        rx,
        tx,
        frames: FrameReader::new(),
        seen: String::new(),
        exit: None,
    };
    // The first frame is the answer: the session's process has started, and its id is the one it was given.
    let first = read_one_frame(&mut client.rx, &mut client.frames).expect("the agent's answer");
    assert_eq!(first.kind, FrameKind::Serving, "the session started");
    let id = {
        let started = started();
        let own = started.last().expect("the session's own start was recorded");
        SessionId::parse(own.session.as_deref().expect("the session was given its id")).unwrap()
    };
    Hosting {
        control,
        id,
        client,
        handler,
    }
}

impl Hosting {
    /// End the session as a client that goes away does, and wait for its handler.
    fn leave(self) {
        let Hosting { client, handler, .. } = self;
        drop(client);
        let _ = handler.join().unwrap();
    }
}

/// What a request was answered.
struct Reply {
    outcome: Outcome,
    stderr: String,
    handled: anyhow::Result<()>,
}

/// Ask on a connection of its own, as `elevate` does, on a thread: the answer is joined later.
fn ask(
    control: &Arc<Control>,
    tag: &str,
    frames: impl FnOnce(&mut ConnTx) + Send + 'static,
) -> std::thread::JoinHandle<Reply> {
    let (server, client, _dir) = a_pair(tag);
    let control = Arc::clone(control);
    let handler = std::thread::spawn(move || handle(server, &control, |_| panic!("a request ends nothing")));
    std::thread::spawn(move || {
        let (mut rx, mut tx) = afunix::split(client).unwrap();
        frames(&mut tx);
        let mut sink = TestSink::default();
        let outcome = pump_decode(&mut rx, &mut FrameReader::new(), &mut sink).expect("the answer arrived");
        drop((rx, tx));
        Reply {
            outcome,
            stderr: String::from_utf8_lossy(&sink.stderr).into_owned(),
            handled: handler.join().unwrap(),
        }
    })
}

fn request(id: &SessionId, command: &str, cwd: &str) -> ElevationRequest {
    ElevationRequest {
        version: PROTOCOL_VERSION,
        session: id.to_string(),
        command: command.to_owned(),
        cwd: cwd.to_owned(),
    }
}

fn send(request: ElevationRequest) -> impl FnOnce(&mut ConnTx) + Send + 'static {
    move |tx| write_frame(tx, FrameKind::Request, &request.encode().unwrap()).unwrap()
}

fn asked(hosting: &Hosting, tag: &str, request: ElevationRequest) -> Reply {
    ask(&hosting.control, tag, send(request)).join().unwrap()
}

/// The elevated starts: everything started after the session's own.
fn elevated_starts() -> Vec<Start> {
    started().split_off(1)
}

// What is refused -----

#[test]
fn an_unknown_or_unparseable_session_is_refused_not_hosted() {
    let _serial = serial();
    let control = Arc::new(Control::standalone());
    let stranger = *Control::standalone().reserve().unwrap().unwrap().id();
    for (what, session) in [
        ("an id this agent never gave out", stranger.to_string()),
        ("text that is no id", "not-a-session".to_owned()),
        ("nothing", String::new()),
    ] {
        let reply = ask(
            &control,
            "unknown",
            send(ElevationRequest {
                session,
                ..request(&stranger, "cmd.exe /c echo SHOULD-NOT-RUN", r"C:\")
            }),
        )
        .join()
        .unwrap();
        assert_eq!(reply.outcome, Outcome::Exited(126), "{what}");
        assert_eq!(reply.stderr, text::elevation_not_hosted(), "{what}");
    }
    assert!(started().is_empty(), "nothing was started");
}

#[test]
fn never_is_refused_and_starts_nothing() {
    let _serial = serial();
    let session = host("never", Mode::Exec, ElevationPolicy::Never);
    let reply = asked(
        &session,
        "never-ask",
        request(&session.id, "cmd.exe /c echo SHOULD-NOT-RUN", r"C:\"),
    );
    assert_eq!(reply.outcome, Outcome::Exited(126));
    assert_eq!(reply.stderr, text::elevation_never());
    assert!(elevated_starts().is_empty());
    session.leave();
}

#[test]
fn an_always_session_is_refused_already_elevated_and_starts_nothing() {
    let _serial = serial();
    let session = host("always", Mode::Exec, ElevationPolicy::Always);
    let reply = asked(
        &session,
        "always-ask",
        request(&session.id, "cmd.exe /c echo SHOULD-NOT-RUN", r"C:\"),
    );
    assert_eq!(reply.outcome, Outcome::Exited(126));
    assert_eq!(reply.stderr, text::elevation_already_elevated());
    assert!(elevated_starts().is_empty());
    session.leave();
}

#[test]
fn prompt_is_refused_with_the_next_units_sentence() {
    let _serial = serial();
    let session = host("prompt", Mode::Exec, ElevationPolicy::Prompt);
    let reply = asked(
        &session,
        "prompt-ask",
        request(&session.id, "cmd.exe /c echo SHOULD-NOT-RUN", r"C:\"),
    );
    assert_eq!(reply.outcome, Outcome::Exited(126));
    assert_eq!(reply.stderr, text::elevation_consent_not_built());
    assert!(elevated_starts().is_empty());
    session.leave();
}

#[test]
fn an_oversized_or_malformed_request_is_answered_with_a_sentence_and_does_not_reach_the_session() {
    let _serial = serial();
    let session = host("malformed", Mode::Exec, ElevationPolicy::AutoApprove);
    let units = crate::protocol::MAX_ELEVATION_UNITS;
    let cases = [
        ("an empty command", request(&session.id, "", r"C:\")),
        (
            "an oversized command",
            request(&session.id, &"a".repeat(units + 1), r"C:\"),
        ),
        (
            "an oversized directory",
            request(&session.id, "whoami", &"a".repeat(units + 1)),
        ),
        ("a NUL in the command", request(&session.id, "who\0ami", r"C:\")),
    ];
    for (what, request) in cases {
        let reply = asked(&session, "malformed-ask", request);
        assert_eq!(
            reply.outcome,
            Outcome::Exited(crate::agent::logout::BAD_REQUEST_EXIT_CODE),
            "{what}"
        );
        assert!(
            reply
                .stderr
                .starts_with("ssh-broker: the agent could not serve the request: "),
            "{what}: {}",
            reply.stderr
        );
        assert!(reply.handled.is_err(), "{what}: the refusal is for the log");
    }
    // Bytes that are no request, and a request of another version.
    let garbage = ask(&session.control, "garbage", |tx| {
        write_frame(tx, FrameKind::Request, &[0xff; 9]).unwrap()
    })
    .join()
    .unwrap();
    assert_eq!(
        garbage.outcome,
        Outcome::Exited(crate::agent::logout::BAD_REQUEST_EXIT_CODE)
    );
    let old = ElevationRequest {
        version: PROTOCOL_VERSION - 1,
        ..request(&session.id, "whoami", r"C:\")
    };
    let reply = ask(&session.control, "old", send(old)).join().unwrap();
    assert_eq!(
        reply.outcome,
        Outcome::Exited(crate::agent::logout::BAD_REQUEST_EXIT_CODE)
    );
    assert!(reply.stderr.contains("protocol version mismatch"), "{}", reply.stderr);
    assert!(elevated_starts().is_empty(), "none of them reached the session");
    session.leave();
}

#[test]
fn the_working_directory_must_be_an_existing_directory() {
    let _serial = serial();
    let session = host("cwd", Mode::Exec, ElevationPolicy::AutoApprove);
    let dir = std::env::temp_dir().join(format!("sb-elevate-cwd-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("a file");
    std::fs::write(&file, b"x").unwrap();

    for (what, cwd) in [
        ("a directory that is not there", dir.join("missing")),
        ("a file", file.clone()),
    ] {
        let reply = asked(
            &session,
            "cwd-bad",
            request(&session.id, "cmd.exe /c echo SHOULD-NOT-RUN", cwd.to_str().unwrap()),
        );
        assert_eq!(reply.outcome, Outcome::Exited(126), "{what}");
        assert!(
            reply
                .stderr
                .starts_with("ssh-broker: the command could not be started elevated: ")
                && reply.stderr.contains("is not an existing directory"),
            "{what}: {}",
            reply.stderr
        );
    }
    assert!(elevated_starts().is_empty(), "nothing started in either");

    let mut session = session;
    let reply = asked(
        &session,
        "cwd-ok",
        request(&session.id, "cmd.exe /d /c cd", dir.to_str().unwrap()),
    );
    assert_eq!(reply.outcome, Outcome::Exited(0), "{}", reply.stderr);
    session.client.read_until(dir.file_name().unwrap().to_str().unwrap());
    assert_eq!(elevated_starts()[0].cwd.as_deref(), Some(dir.as_path()));
    session.leave();
    let _ = std::fs::remove_dir_all(&dir);
}

// What is run -----

/// The elevated command's code is the reply's, its output goes to the client on its own streams with its stdin
/// closed, and it was given the agent's own token and the session's id.
#[test]
fn auto_approve_without_a_terminal_runs_the_command_on_pipes_with_stdin_closed_and_forwards_both_streams_and_the_code()
{
    let _serial = serial();
    let mut session = host("pipes", Mode::Exec, ElevationPolicy::AutoApprove);
    // `findstr x` ends at once only when its stdin is closed; then the command says its id on both streams.
    let command =
        "cmd.exe /d /c \"findstr x & echo out-%SSH_BROKER_SESSION%& echo err-%SSH_BROKER_SESSION% 1>&2 & exit /b 7\"";
    let reply = asked(&session, "pipes-ask", request(&session.id, command, ""));
    assert_eq!(reply.outcome, Outcome::Exited(7));
    assert_eq!(
        reply.stderr, "",
        "a command that ran says nothing of its own on the request connection"
    );
    assert!(reply.handled.is_ok(), "{:#}", reply.handled.unwrap_err());

    let id = session.id.to_string();
    session.client.read_until(&format!("out-{id}"));
    session.client.read_until(&format!("err-{id}"));
    let starts = elevated_starts();
    assert_eq!(starts.len(), 1, "{starts:?}");
    assert!(!starts[0].terminal && !starts[0].token, "{:?}", starts[0]);
    assert_eq!(starts[0].line, command, "the command line is started as it stands");
    assert_eq!(starts[0].session.as_deref(), Some(id.as_str()));
    session.leave();
}

/// With a terminal the connection carries the elevated command while it runs and is the session's again by the time
/// the reply is written.
#[test]
fn auto_approve_with_a_terminal_switches_the_connection_and_switches_back_before_the_reply() {
    let _serial = serial();
    let mut session = host("terminal", Mode::Pty, ElevationPolicy::AutoApprove);
    let command = "cmd.exe /d /c \"echo elevated-output& exit /b 3\"";
    let reply = asked(&session, "terminal-ask", request(&session.id, command, ""));
    assert_eq!(reply.outcome, Outcome::Exited(3));
    assert_eq!(reply.stderr, "");

    session.client.read_until("elevated-output");
    let starts = elevated_starts();
    assert_eq!(starts.len(), 1, "{starts:?}");
    assert!(starts[0].terminal && !starts[0].token, "{:?}", starts[0]);

    // The reply has been read, so the carrier is the session's: a write for it does not wait.
    let hosted = session
        .control
        .await_hosted(&session.id)
        .expect("the session is hosted");
    hosted
        .link()
        .deliver_observed(Carrier::Session, Stream::Pty, b"the-session-again", || {
            panic!("the connection was not the session's again when the reply came")
        })
        .unwrap();
    session.client.read_until("the-session-again");
    session.leave();
}

#[test]
fn a_second_elevation_while_one_runs_is_refused_and_the_slot_frees_when_it_ends_or_fails() {
    let _serial = serial();
    let mut session = host("slot", Mode::Exec, ElevationPolicy::AutoApprove);
    let id = session.id.to_string();
    // Says its id, which shows that the command holds the slot, and then runs until the session is left.
    let long = format!("cmd.exe /d /c \"echo running-{id}& ping -n 600 127.0.0.1 >nul\"");
    let first = ask(&session.control, "slot-first", send(request(&session.id, &long, "")));
    session.client.read_until(&format!("running-{id}"));

    let second = asked(
        &session,
        "slot-second",
        request(&session.id, "cmd.exe /c echo SHOULD-NOT-RUN", ""),
    );
    assert_eq!(second.outcome, Outcome::Exited(126));
    assert_eq!(second.stderr, text::elevation_in_progress());
    assert_eq!(elevated_starts().len(), 1, "the second did not start");

    // Leaving ends the session and, with it, the command that holds the slot.
    let Hosting {
        control,
        id: session_id,
        client,
        handler,
    } = session;
    drop(client);
    let _ = handler.join().unwrap();
    let first = first.join().unwrap();
    assert!(matches!(first.outcome, Outcome::Exited(_)), "{:?}", first.outcome);

    // A command that does not start frees the slot too, and so does one that ends.
    let mut again = host("slot-again", Mode::Exec, ElevationPolicy::AutoApprove);
    let nowhere = asked(
        &again,
        "slot-fails",
        request(&again.id, "no-such-program-for-elevate.exe", ""),
    );
    assert_eq!(nowhere.outcome, Outcome::Exited(126));
    let fine = asked(
        &again,
        "slot-ends",
        request(&again.id, "cmd.exe /d /c echo slot-free", ""),
    );
    assert_eq!(fine.outcome, Outcome::Exited(0), "{}", fine.stderr);
    again.client.read_until("slot-free");
    again.leave();
    let _ = (control, session_id);
}

#[test]
fn an_elevated_command_that_cannot_start_is_refused_with_the_cause_and_the_session_goes_on() {
    let _serial = serial();
    let mut session = host("nostart", Mode::Exec, ElevationPolicy::AutoApprove);
    let reply = asked(
        &session,
        "nostart-ask",
        request(&session.id, "no-such-program-for-elevate.exe", ""),
    );
    assert_eq!(reply.outcome, Outcome::Exited(126));
    assert!(
        reply
            .stderr
            .starts_with("ssh-broker: the command could not be started elevated: "),
        "{}",
        reply.stderr
    );
    assert!(reply.stderr.ends_with("\r\n"));

    // The session is untouched: it still serves a request and its own input.
    let fine = asked(
        &session,
        "nostart-after",
        request(&session.id, "cmd.exe /d /c echo still-serving", ""),
    );
    assert_eq!(fine.outcome, Outcome::Exited(0));
    session.client.read_until("still-serving");
    session.leave();
}

#[test]
fn a_session_that_ends_while_the_command_runs_reaps_it() {
    let _serial = serial();
    let mut session = host("reap", Mode::Exec, ElevationPolicy::AutoApprove);
    let id = session.id.to_string();
    let long = format!("cmd.exe /d /c \"echo running-{id}& ping -n 600 127.0.0.1 >nul\"");
    let pending = ask(&session.control, "reap-ask", send(request(&session.id, &long, "")));
    session.client.read_until(&format!("running-{id}"));

    // The session's own command ends (its stdin ends), and the elevated one is ended with it.
    crate::relay::write_data(&mut session.client.tx, Stream::Stdin, b"").unwrap();
    let reply = pending.join().unwrap();
    assert!(matches!(reply.outcome, Outcome::Exited(_)), "{:?}", reply.outcome);
    session.leave();
}
