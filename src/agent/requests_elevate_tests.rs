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
    ConsentAnswer, ConsentReply, ConsentRequest, ElevationPolicy, ElevationRequest, FrameKind, FrameReader, Handshake,
    Launch, PROTOCOL_VERSION, SESSION_VARIABLE, SessionId, Stream, read_one_frame, write_frame,
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
    /// Held so that the connection stays open: the session ends when its client closes it. What the shim sends: input,
    /// and the answer to a question.
    tx: ConnTx,
    frames: FrameReader,
    /// What the session has sent so far, as text: terminal, stdout and stderr together.
    seen: String,
    /// How many questions the session has asked it so far.
    questions: usize,
    /// The number of the last question it asked: what an answer carries.
    asked: u32,
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
                FrameKind::Consent => {
                    self.questions += 1;
                    self.asked = ConsentRequest::decode(&frame.payload)
                        .expect("a question that decodes")
                        .id;
                }
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

    /// Read frames until the agent asks its question, and return it.
    fn read_question(&mut self) -> ConsentRequest {
        loop {
            let frame = read_one_frame(&mut self.rx, &mut self.frames)
                .unwrap_or_else(|e| panic!("the session ended before it asked ({e:#}); it showed {:?}", self.seen));
            match frame.kind {
                FrameKind::Data => self.seen.push_str(&String::from_utf8_lossy(&frame.payload[1..])),
                FrameKind::Consent => {
                    self.questions += 1;
                    let question = ConsentRequest::decode(&frame.payload).expect("a question that decodes");
                    self.asked = question.id;
                    return question;
                }
                FrameKind::Exit => panic!("the session exited before it asked; it showed {:?}", self.seen),
                _ => {}
            }
        }
    }

    /// Answer the last question as the shim does.
    fn answer(&mut self, answer: ConsentAnswer) {
        let reply = ConsentReply { id: self.asked, answer };
        write_frame(&mut self.tx, FrameKind::ConsentAnswer, &reply.encode().unwrap()).unwrap();
    }

    /// Type `text` as the shim sends keys.
    fn type_text(&mut self, text: &str) {
        crate::relay::write_data(&mut self.tx, Stream::Pty, text.as_bytes()).unwrap();
    }

    /// Read frames until the session's `Exit`, which is kept in `exit`.
    fn read_to_exit(&mut self) {
        if self.exit.is_none() {
            self.exit = Some(read_until_exit(&mut self.rx, &mut self.frames).1);
        }
    }
}

/// Read frames from `rx` until an `Exit`: the kinds of the frames in the order they came, and the code.
fn read_until_exit(rx: &mut ConnRx, frames: &mut FrameReader) -> (Vec<FrameKind>, i32) {
    let mut kinds = Vec::new();
    loop {
        let frame = read_one_frame(rx, frames)
            .unwrap_or_else(|e| panic!("the connection ended before its exit code ({e:#}); frames: {kinds:?}"));
        kinds.push(frame.kind);
        if frame.kind == FrameKind::Exit {
            return (kinds, crate::protocol::ExitCode::decode(&frame.payload).unwrap().0);
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
    host_running(tag, mode, policy, "cmd.exe /d /c findstr x")
}

/// [`host`], with `command` as the session's own program.
fn host_running(tag: &str, mode: Mode, policy: ElevationPolicy, command: &str) -> Hosting {
    let control = Arc::new(Control::standalone());
    let (server, client, _dir) = a_pair(tag);
    let handler = std::thread::spawn({
        let control = Arc::clone(&control);
        move || crate::agent::handle_connection_in(afunix::Conn::new(server).unwrap(), recording_hooks(), &control)
    });
    let (rx, mut tx) = afunix::split(client).unwrap();
    let hs = Handshake {
        mode,
        launch: Launch::Direct,
        command: Some(command.to_owned()),
        elevation: Some(policy),
        ..Handshake::pty_default()
    };
    write_frame(&mut tx, FrameKind::Handshake, &hs.encode().unwrap()).unwrap();
    let mut client = Client {
        rx,
        tx,
        frames: FrameReader::new(),
        seen: String::new(),
        questions: 0,
        asked: 0,
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
    /// What the command wrote to its stdout (the request connection's, not the session's).
    stdout: String,
    stderr: String,
    /// How many answers `Serving` came: one when the command started, none for a refusal.
    served: usize,
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
    let handler = std::thread::spawn(move || {
        handle(afunix::Conn::new(server).unwrap(), &control, |_| {
            panic!("a request ends nothing")
        })
    });
    std::thread::spawn(move || {
        let (mut rx, mut tx) = afunix::split(client).unwrap();
        frames(&mut tx);
        let mut sink = TestSink::default();
        let outcome = pump_decode(&mut rx, &mut FrameReader::new(), &mut sink).expect("the answer arrived");
        drop((rx, tx));
        Reply {
            outcome,
            stdout: String::from_utf8_lossy(&sink.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&sink.stderr).into_owned(),
            served: sink.served,
            handled: handler.join().unwrap(),
        }
    })
}

/// A request in flight on a connection of its own, read as the test asks: for a command that has to be seen running
/// before the test goes on.
struct Pending {
    rx: ConnRx,
    tx: ConnTx,
    frames: FrameReader,
    stdout: String,
    handler: std::thread::JoinHandle<anyhow::Result<()>>,
}

/// Send `request` on a connection of its own and handle it on a thread.
fn open(control: &Arc<Control>, tag: &str, request: ElevationRequest) -> Pending {
    let (server, client, _dir) = a_pair(tag);
    let control = Arc::clone(control);
    let handler = std::thread::spawn(move || {
        handle(afunix::Conn::new(server).unwrap(), &control, |_| {
            panic!("a request ends nothing")
        })
    });
    let (rx, mut tx) = afunix::split(client).unwrap();
    write_frame(&mut tx, FrameKind::Request, &request.encode().unwrap()).unwrap();
    Pending {
        rx,
        tx,
        frames: FrameReader::new(),
        stdout: String::new(),
        handler,
    }
}

impl Pending {
    /// Read frames until the command's stdout holds `needle`. A frame is what is waited for, never the end of a
    /// stream.
    fn read_until(&mut self, needle: &str) {
        while !self.stdout.contains(needle) {
            let frame = read_one_frame(&mut self.rx, &mut self.frames).unwrap_or_else(|e| {
                panic!(
                    "the request ended before the command showed {needle:?} ({e:#}); it showed {:?}",
                    self.stdout
                )
            });
            match frame.kind {
                FrameKind::Data if frame.payload[0] == Stream::Stdout as u8 => {
                    self.stdout.push_str(&String::from_utf8_lossy(&frame.payload[1..]));
                }
                FrameKind::Exit => panic!(
                    "the command ended before it showed {needle:?}; it showed {:?}",
                    self.stdout
                ),
                _ => {}
            }
        }
    }

    /// Read frames until the command's `Exit`: the kinds of the frames in the order they came, and the code.
    fn read_to_exit(&mut self) -> (Vec<FrameKind>, i32) {
        read_until_exit(&mut self.rx, &mut self.frames)
    }

    /// The client goes away, as an `elevate` does that is ended: both halves close. Returns what the handler ended
    /// with, once it has ended: the command it was running is gone by then.
    fn hang_up(self) -> anyhow::Result<()> {
        let Pending { rx, tx, handler, .. } = self;
        drop((rx, tx));
        handler.join().unwrap()
    }
}

/// The line that runs the system's `cmd.exe` with `args`: a request names its program by an absolute path.
fn cmd(args: &str) -> String {
    let root = std::env::var("SystemRoot").expect("SystemRoot names the Windows directory");
    format!(r#""{root}\System32\cmd.exe" {args}"#)
}

/// An absolute path that holds no program.
const NO_SUCH_PROGRAM: &str = r"C:\no-such-folder-for-elevate\no-such-program.exe";

fn request(id: &SessionId, command: &str, cwd: &str) -> ElevationRequest {
    ElevationRequest {
        version: PROTOCOL_VERSION,
        session: id.to_string(),
        command: command.to_owned(),
        cwd: cwd.to_owned(),
        terminal: false,
    }
}

/// `elevate --terminal <command>`.
fn on_a_terminal(id: &SessionId, command: &str) -> ElevationRequest {
    ElevationRequest {
        terminal: true,
        ..request(id, command, "")
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
fn an_unknown_session_is_refused_not_hosted_and_an_unparseable_one_is_a_bad_request() {
    let _serial = serial();
    let control = Arc::new(Control::standalone());
    let stranger = *Control::standalone().reserve().unwrap().unwrap().id();
    let reply = ask(
        &control,
        "unknown",
        send(request(&stranger, &cmd("/c echo SHOULD-NOT-RUN"), r"C:\")),
    )
    .join()
    .unwrap();
    assert_eq!(reply.outcome, Outcome::Exited(126), "an id this agent never gave out");
    assert_eq!(reply.served, 0, "a refusal is not answered with `Serving`");
    assert_eq!(reply.stderr, text::elevation_not_hosted());

    // Only a foreign client sends one of these: `check` judges the request once, and it says which field.
    for (what, session) in [("text that is no id", "not-a-session"), ("nothing", "")] {
        let reply = ask(
            &control,
            "unparseable",
            send(ElevationRequest {
                session: session.to_owned(),
                ..request(&stranger, &cmd("/c echo SHOULD-NOT-RUN"), r"C:\")
            }),
        )
        .join()
        .unwrap();
        assert_eq!(
            reply.outcome,
            Outcome::Exited(crate::agent::logout::BAD_REQUEST_EXIT_CODE),
            "{what}"
        );
        assert!(
            reply.stderr.contains("the session is not a session id"),
            "{what}: {}",
            reply.stderr
        );
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
        request(&session.id, &cmd("/c echo SHOULD-NOT-RUN"), r"C:\"),
    );
    assert_eq!(reply.outcome, Outcome::Exited(126));
    assert_eq!(reply.served, 0);
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
        request(&session.id, &cmd("/c echo SHOULD-NOT-RUN"), r"C:\"),
    );
    assert_eq!(reply.outcome, Outcome::Exited(126));
    assert_eq!(reply.served, 0);
    assert_eq!(reply.stderr, text::elevation_already_elevated());
    assert!(elevated_starts().is_empty());
    session.leave();
}

// The question -----

/// The session speaks on its own connection: proof that the screen is the session's, since a write that has to wait
/// for it panics.
fn session_speaks(session: &mut Hosting, marker: &str) {
    let hosted = session
        .control
        .await_hosted(&session.id)
        .expect("the session is hosted");
    hosted
        .link
        .deliver_observed(Carrier::Session, Stream::Pty, marker.as_bytes(), || {
            panic!("the screen was not the session's")
        })
        .unwrap();
    session.client.read_until(marker);
}

#[test]
fn prompt_with_a_terminal_asks_and_yes_runs_the_command() {
    let _serial = serial();
    let mut session = host("prompt", Mode::Pty, ElevationPolicy::Prompt);
    let command = cmd("/d /c echo asked-and-run");
    let asking = ask(
        &session.control,
        "prompt-ask",
        send(request(&session.id, &command, r"C:\")),
    );
    let question = session.client.read_question();
    assert_eq!(
        (question.command.as_str(), question.cwd.as_str()),
        (command.as_str(), r"C:\")
    );
    assert!(elevated_starts().is_empty(), "nothing runs before the answer");

    session.client.answer(ConsentAnswer::Allow);
    let reply = asking.join().unwrap();
    assert_eq!(reply.outcome, Outcome::Exited(0), "{}", reply.stderr);
    assert_eq!(reply.served, 1);
    assert!(reply.stdout.contains("asked-and-run"), "{}", reply.stdout);
    assert_eq!(elevated_starts().len(), 1);
    // The screen was given back to the session before the command started.
    session_speaks(&mut session, "the-session-again");
    session.leave();
}

#[test]
fn the_question_shows_the_folder_the_command_runs_in_when_the_request_names_none() {
    let _serial = serial();
    let mut session = host("home", Mode::Pty, ElevationPolicy::Prompt);
    let asking = ask(
        &session.control,
        "home-ask",
        send(request(&session.id, &cmd("/d /c echo x"), "")),
    );
    let question = session.client.read_question();
    let home = home_dir().expect("a home directory in the test's own account");
    assert_eq!(question.cwd, home.display().to_string());
    session.client.answer(ConsentAnswer::Refuse);
    assert_eq!(asking.join().unwrap().outcome, Outcome::Exited(126));
    session.leave();
}

/// Every answer but `Allow` is a refusal that starts nothing and says so; the screen is the session's again before
/// the refusal is written.
#[test]
fn no_declines_and_starts_nothing() {
    let _serial = serial();
    let mut session = host("declined", Mode::Pty, ElevationPolicy::Prompt);
    let asking = ask(
        &session.control,
        "declined-ask",
        send(request(&session.id, &cmd("/c echo SHOULD-NOT-RUN"), r"C:\")),
    );
    session.client.read_question();
    session.client.answer(ConsentAnswer::Refuse);
    let reply = asking.join().unwrap();
    assert_eq!(reply.outcome, Outcome::Exited(126));
    assert_eq!(reply.served, 0);
    assert_eq!(reply.stderr, text::elevation_declined());
    assert!(elevated_starts().is_empty());
    session_speaks(&mut session, "the-session-again");
    session.leave();
}

#[test]
fn prompt_without_a_terminal_is_refused_naming_the_variable_and_sends_no_frame() {
    let _serial = serial();
    let mut session = host("noask", Mode::Exec, ElevationPolicy::Prompt);
    let reply = asked(
        &session,
        "noask-ask",
        request(&session.id, &cmd("/c echo SHOULD-NOT-RUN"), r"C:\"),
    );
    assert_eq!(reply.outcome, Outcome::Exited(126));
    assert_eq!(reply.served, 0);
    assert_eq!(reply.stderr, text::elevation_no_terminal());
    assert!(elevated_starts().is_empty());
    // The session's connection carried no question: what it carries next is the first thing it shows.
    session_speaks(&mut session, "the-session-again");
    assert_eq!(session.client.questions, 0);
    session.leave();
}

/// A request that cannot run is not asked about.
#[test]
fn a_working_directory_that_does_not_exist_is_refused_before_the_question() {
    let _serial = serial();
    let mut session = host("nodir", Mode::Pty, ElevationPolicy::Prompt);
    let missing = std::env::temp_dir().join(format!("sb-consent-missing-{}", std::process::id()));
    let reply = asked(
        &session,
        "nodir-ask",
        request(&session.id, &cmd("/c echo SHOULD-NOT-RUN"), missing.to_str().unwrap()),
    );
    assert_eq!(reply.outcome, Outcome::Exited(126));
    assert!(
        reply.stderr.contains("is not an existing directory"),
        "{}",
        reply.stderr
    );
    session_speaks(&mut session, "the-session-again");
    assert_eq!(session.client.questions, 0);
    session.leave();
}

/// The session's shell going away while the question is asked: nothing runs, and the request is told why.
#[test]
fn a_session_that_ends_while_asking_refuses_and_starts_nothing() {
    let _serial = serial();
    let mut session = host("endasking", Mode::Pty, ElevationPolicy::Prompt);
    let asking = ask(
        &session.control,
        "endasking-ask",
        send(request(&session.id, &cmd("/c echo SHOULD-NOT-RUN"), r"C:\")),
    );
    session.client.read_question();

    // The shell ends as `logout` ends it: the session's client stays connected, and nobody answers.
    session.control.end_all();
    let reply = asking.join().unwrap();
    assert_eq!(reply.outcome, Outcome::Exited(126));
    assert_eq!(reply.served, 0);
    assert_eq!(reply.stderr, text::elevation_session_ended());
    assert!(elevated_starts().is_empty());
    session.client.read_to_exit();
    assert!(session.client.exit.is_some(), "the session got its exit code");
    session.leave();
}

/// The client of the request exits while the question is on the screen: the question ends, nothing runs (a late `y`
/// answers nothing), and the session has its screen back.
#[test]
fn a_client_that_hangs_up_while_the_question_is_asked_ends_it_and_nothing_runs() {
    let _serial = serial();
    let mut session = host("goneasking", Mode::Pty, ElevationPolicy::Prompt);
    let pending = open(
        &session.control,
        "goneasking-ask",
        request(&session.id, &cmd("/c echo SHOULD-NOT-RUN"), r"C:\"),
    );
    session.client.read_question();

    // The handler returns once the question has ended; with the question still waiting it would not return.
    let _ = pending.hang_up();
    session_speaks(&mut session, "the-session-again");
    session.client.answer(ConsentAnswer::Allow);
    session_speaks(&mut session, "and-again");
    assert!(elevated_starts().is_empty(), "the late answer started nothing");
    session.leave();
}

/// The shim relays nothing while it asks, so a key that reaches the agent before the answer was relayed before the
/// question: it is the session's (the tail of a pasted block, say). The agent gives it to the session at once, ahead
/// of what is typed after.
#[test]
fn input_typed_while_asking_goes_to_the_session() {
    let _serial = serial();
    let mut session = host("typed", Mode::Pty, ElevationPolicy::Prompt);
    let asking = ask(
        &session.control,
        "typed-ask",
        send(request(&session.id, &cmd("/c echo SHOULD-NOT-RUN"), r"C:\")),
    );
    session.client.read_question();
    // Frames of one connection are handled in order: this reaches the session before the answer is read.
    session.client.type_text("xearly\r\n");
    session.client.answer(ConsentAnswer::Refuse);
    assert_eq!(asking.join().unwrap().outcome, Outcome::Exited(126));

    session.client.type_text("xlater\r\n");
    session.client.read_until("xlater");
    let seen = &session.client.seen;
    assert!(
        seen.find("xearly")
            .is_some_and(|early| early < seen.find("xlater").unwrap()),
        "the session saw {seen:?}"
    );
    session.leave();
}

#[test]
fn a_second_request_while_asking_is_refused_in_progress() {
    let _serial = serial();
    let mut session = host("second", Mode::Pty, ElevationPolicy::Prompt);
    let first = ask(
        &session.control,
        "second-first",
        send(request(&session.id, &cmd("/c echo SHOULD-NOT-RUN"), r"C:\")),
    );
    session.client.read_question();

    let second = asked(
        &session,
        "second-second",
        request(&session.id, &cmd("/c echo SHOULD-NOT-RUN"), r"C:\"),
    );
    assert_eq!(second.outcome, Outcome::Exited(126));
    assert_eq!(second.served, 0);
    assert_eq!(second.stderr, text::elevation_in_progress());

    session.client.answer(ConsentAnswer::Refuse);
    assert_eq!(first.join().unwrap().stderr, text::elevation_declined());
    assert_eq!(session.client.questions, 1, "the second was not asked");
    assert!(elevated_starts().is_empty());
    session.leave();
}

/// With `--terminal` the screen goes from the question straight to the command, whose output the session's
/// connection carries; and it is the session's again when the command ends.
#[test]
fn an_allowed_terminal_command_takes_the_screen_from_the_question() {
    let _serial = serial();
    let mut session = host("termask", Mode::Pty, ElevationPolicy::Prompt);
    let asking = ask(
        &session.control,
        "termask-ask",
        send(ElevationRequest {
            terminal: true,
            ..request(&session.id, &cmd("/d /c \"echo elevated-output& exit /b 3\""), r"C:\")
        }),
    );
    session.client.read_question();
    session.client.answer(ConsentAnswer::Allow);
    let reply = asking.join().unwrap();
    assert_eq!(reply.outcome, Outcome::Exited(3), "{}", reply.stderr);
    session.client.read_until("elevated-output");
    session_speaks(&mut session, "the-session-again");
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
            request(&session.id, &cmd("/c exit"), &"a".repeat(units + 1)),
        ),
        ("a NUL in the command", request(&session.id, "who\0ami", r"C:\")),
        (
            "a program that is not an absolute path",
            request(&session.id, "cmd.exe /c echo SHOULD-NOT-RUN", r"C:\"),
        ),
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
        assert_eq!(reply.served, 0, "{what}");
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
        ..request(&session.id, &cmd("/c exit"), r"C:\")
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
            request(&session.id, &cmd("/c echo SHOULD-NOT-RUN"), cwd.to_str().unwrap()),
        );
        assert_eq!(reply.outcome, Outcome::Exited(126), "{what}");
        assert_eq!(reply.served, 0, "{what}");
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

    let reply = asked(
        &session,
        "cwd-ok",
        request(&session.id, &cmd("/d /c cd"), dir.to_str().unwrap()),
    );
    assert_eq!(reply.outcome, Outcome::Exited(0), "{}", reply.stderr);
    assert!(
        reply.stdout.contains(dir.file_name().unwrap().to_str().unwrap()),
        "{}",
        reply.stdout
    );
    assert_eq!(elevated_starts()[0].cwd.as_deref(), Some(dir.as_path()));
    session.leave();
    let _ = std::fs::remove_dir_all(&dir);
}

// What is run -----

/// By default, in a session with a terminal or without: the elevated command's stdin is closed, its stdout and stderr
/// and its code go back on the request connection and not on the session's, and it was given the agent's own token
/// and the session's id.
#[test]
fn a_default_mode_command_runs_on_pipes_with_stdin_closed_and_its_streams_and_code_go_on_the_request_not_the_session() {
    for (what, mode) in [
        ("a session without a terminal", Mode::Exec),
        ("a session with a terminal", Mode::Pty),
    ] {
        let _serial = serial();
        let mut session = host("pipes", mode, ElevationPolicy::AutoApprove);
        // `findstr x` ends at once only when its stdin is closed; then the command says its id on both streams.
        let command = cmd(
            "/d /c \"findstr x & echo out-%SSH_BROKER_SESSION%& echo err-%SSH_BROKER_SESSION% 1>&2 & \
                       exit /b 7\"",
        );
        let reply = asked(&session, "pipes-ask", request(&session.id, &command, ""));
        let id = session.id.to_string();
        assert_eq!(reply.outcome, Outcome::Exited(7), "{what}");
        assert!(reply.stdout.contains(&format!("out-{id}")), "{what}: {}", reply.stdout);
        assert!(!reply.stdout.contains("err-"), "{what}: {}", reply.stdout);
        assert!(reply.stderr.contains(&format!("err-{id}")), "{what}: {}", reply.stderr);
        assert!(!reply.stderr.contains("out-"), "{what}: {}", reply.stderr);
        assert!(reply.handled.is_ok(), "{what}: {:#}", reply.handled.unwrap_err());

        // The session's own connection carried none of it: what it carries next is the first thing it shows.
        let hosted = session
            .control
            .await_hosted(&session.id)
            .expect("the session is hosted");
        hosted
            .link
            .deliver(Carrier::Session, Stream::Stdout, b"the-session-again")
            .unwrap();
        session.client.read_until("the-session-again");
        assert!(
            !session.client.seen.contains("out-") && !session.client.seen.contains("err-"),
            "{what}: the session showed {:?}",
            session.client.seen
        );

        let starts = elevated_starts();
        assert_eq!(starts.len(), 1, "{what}: {starts:?}");
        assert!(!starts[0].terminal && !starts[0].token, "{what}: {:?}", starts[0]);
        assert_eq!(
            starts[0].line, command,
            "{what}: the command line is started as it stands"
        );
        assert_eq!(starts[0].session.as_deref(), Some(id.as_str()));
        session.leave();
    }
}

/// `--terminal` in a session with a terminal: the connection carries the elevated command while it runs and is the
/// session's again by the time the reply is written.
#[test]
fn a_terminal_command_switches_the_connection_and_switches_back_before_the_reply() {
    let _serial = serial();
    let mut session = host("terminal", Mode::Pty, ElevationPolicy::AutoApprove);
    let command = cmd("/d /c \"echo elevated-output& exit /b 3\"");
    let reply = asked(&session, "terminal-ask", on_a_terminal(&session.id, &command));
    assert_eq!(reply.outcome, Outcome::Exited(3));
    assert_eq!(
        reply.stdout, "",
        "the request connection carries no output of a terminal command"
    );
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
        .link
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
    let session = host("slot", Mode::Exec, ElevationPolicy::AutoApprove);
    let id = session.id.to_string();
    // Says its id, which shows that the command holds the slot, and then runs until its request is hung up.
    let long = cmd(&format!("/d /c \"echo running-{id}& ping -n 600 127.0.0.1 >nul\""));
    let mut first = open(&session.control, "slot-first", request(&session.id, &long, ""));
    first.read_until(&format!("running-{id}"));

    let second = asked(
        &session,
        "slot-second",
        request(&session.id, &cmd("/c echo SHOULD-NOT-RUN"), ""),
    );
    assert_eq!(second.outcome, Outcome::Exited(126));
    assert_eq!(second.served, 0);
    assert_eq!(second.stderr, text::elevation_in_progress());
    assert_eq!(elevated_starts().len(), 1, "the second did not start");

    // The command ends with its request, and its slot is free again; so is the slot of a command that did not start,
    // and of one that ends by itself.
    let _ = first.hang_up();
    let nowhere = asked(&session, "slot-fails", request(&session.id, NO_SUCH_PROGRAM, ""));
    assert_eq!(nowhere.outcome, Outcome::Exited(126));
    assert_eq!(nowhere.served, 0, "a command that did not start is not served");
    assert!(
        nowhere
            .stderr
            .starts_with("ssh-broker: the command could not be started elevated: "),
        "the slot was free for a command that could not start: {}",
        nowhere.stderr
    );
    let fine = asked(
        &session,
        "slot-ends",
        request(&session.id, &cmd("/d /c echo slot-free"), ""),
    );
    assert_eq!(fine.outcome, Outcome::Exited(0), "{}", fine.stderr);
    assert!(fine.stdout.contains("slot-free"), "{}", fine.stdout);
    session.leave();
}

#[test]
fn an_elevated_command_that_cannot_start_is_refused_with_the_cause_and_the_session_goes_on() {
    let _serial = serial();
    let session = host("nostart", Mode::Exec, ElevationPolicy::AutoApprove);
    let reply = asked(&session, "nostart-ask", request(&session.id, NO_SUCH_PROGRAM, ""));
    assert_eq!(reply.outcome, Outcome::Exited(126));
    assert_eq!(reply.served, 0);
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
        request(&session.id, &cmd("/d /c echo still-serving"), ""),
    );
    assert_eq!(fine.outcome, Outcome::Exited(0));
    assert!(fine.stdout.contains("still-serving"), "{}", fine.stdout);
    session.leave();
}

/// The command lives as long as the request that asked for it: the `elevate` client is inside the session's tree, so
/// the session's end ends it, and its connection closing is what ends the command. Both with a terminal of its own
/// and without.
#[test]
fn the_request_connection_closing_ends_the_command() {
    for (what, mode, terminal) in [
        ("a default-mode command", Mode::Exec, false),
        ("a default-mode command of a session with a terminal", Mode::Pty, false),
        ("a command with a terminal", Mode::Pty, true),
    ] {
        let _serial = serial();
        let mut session = host("hangup", mode, ElevationPolicy::AutoApprove);
        let id = session.id.to_string();
        let long = cmd(&format!("/d /c \"echo running-{id}& ping -n 600 127.0.0.1 >nul\""));
        let ask = ElevationRequest {
            terminal,
            ..request(&session.id, &long, "")
        };
        let mut pending = open(&session.control, "hangup", ask);
        // The command runs: its output is on the request, or on the session's screen with `--terminal`.
        if terminal {
            session.client.read_until(&format!("running-{id}"));
        } else {
            pending.read_until(&format!("running-{id}"));
        }

        // The handler returns only once the command, which would run for ten minutes, has ended.
        let _ = pending.hang_up();
        assert_eq!(elevated_starts().len(), 1, "{what}");

        // The session goes on: the screen is the session's again, and the slot is free.
        let again = asked(
            &session,
            "hangup-again",
            request(&session.id, &cmd("/d /c echo went-on"), ""),
        );
        assert_eq!(again.outcome, Outcome::Exited(0), "{what}: {}", again.stderr);
        session.leave();
    }
}

/// The watch of the request, begun before the question, goes on for the command the person allowed: a client that
/// hangs up while that command runs ends it, with a terminal of its own and without.
#[test]
fn a_client_that_hangs_up_while_an_allowed_command_runs_ends_it() {
    for (what, terminal) in [("a default-mode command", false), ("a command with a terminal", true)] {
        let _serial = serial();
        let mut session = host("allowedhangup", Mode::Pty, ElevationPolicy::Prompt);
        let id = session.id.to_string();
        let long = cmd(&format!("/d /c \"echo running-{id}& ping -n 600 127.0.0.1 >nul\""));
        let ask = ElevationRequest {
            terminal,
            ..request(&session.id, &long, "")
        };
        let mut pending = open(&session.control, "allowedhangup", ask);
        session.client.read_question();
        session.client.answer(ConsentAnswer::Allow);
        if terminal {
            session.client.read_until(&format!("running-{id}"));
        } else {
            pending.read_until(&format!("running-{id}"));
        }

        // The handler returns only once the command, which would run for ten minutes, has ended.
        let _ = pending.hang_up();
        assert_eq!(elevated_starts().len(), 1, "{what}");
        session_speaks(&mut session, "the-session-again");
        session.leave();
    }
}

/// `--terminal` needs a terminal to give: a session without one is told so, and nothing starts.
#[test]
fn a_terminal_request_in_a_session_without_a_terminal_is_refused_and_starts_nothing() {
    let _serial = serial();
    let session = host("noterminal", Mode::Exec, ElevationPolicy::AutoApprove);
    let reply = asked(
        &session,
        "noterminal-ask",
        on_a_terminal(&session.id, &cmd("/c echo SHOULD-NOT-RUN")),
    );
    assert_eq!(reply.outcome, Outcome::Exited(126));
    assert_eq!(reply.served, 0);
    assert_eq!(reply.stderr, text::elevation_needs_a_terminal());
    assert!(elevated_starts().is_empty());
    session.leave();
}

// What the client is told -----

/// `Serving` is the first frame of an answer to a command that started, in both modes, and comes before any of its
/// output: with `--terminal` there is none on this connection.
#[test]
fn serving_comes_first_and_before_the_commands_output() {
    for (what, mode, terminal) in [
        ("a default-mode command", Mode::Exec, false),
        ("a command with a terminal", Mode::Pty, true),
    ] {
        let _serial = serial();
        let session = host("serving", mode, ElevationPolicy::AutoApprove);
        let ask = ElevationRequest {
            terminal,
            ..request(&session.id, &cmd("/d /c \"echo out-first& exit /b 5\""), "")
        };
        let mut pending = open(&session.control, "serving", ask);
        let (kinds, code) = pending.read_to_exit();
        assert_eq!(code, 5, "{what}");
        assert_eq!(kinds.first(), Some(&FrameKind::Serving), "{what}: {kinds:?}");
        assert_eq!(kinds.last(), Some(&FrameKind::Exit), "{what}: {kinds:?}");
        assert_eq!(
            kinds.iter().filter(|kind| **kind == FrameKind::Serving).count(),
            1,
            "{what}: {kinds:?}"
        );
        assert_eq!(
            kinds.contains(&FrameKind::Data),
            !terminal,
            "{what}: the output of a default-mode command is on this connection, a terminal command's is not: {kinds:?}"
        );
        let _ = pending.hang_up();
        session.leave();
    }
}

/// The slot is free once the command has ended, not when its client has closed: `elevate a` and then `elevate b`
/// must not meet "another elevation is in progress" because the first handler still waits for its client.
#[test]
fn the_slot_is_free_when_the_command_has_ended_while_its_client_is_still_connected() {
    let _serial = serial();
    let session = host("freed", Mode::Exec, ElevationPolicy::AutoApprove);
    let mut first = open(
        &session.control,
        "freed-first",
        request(&session.id, &cmd("/d /c echo ended-first"), ""),
    );
    let (_, code) = first.read_to_exit();
    assert_eq!(code, 0);

    // The first handler is waiting for its client to close: this test holds both halves open.
    let second = asked(
        &session,
        "freed-second",
        request(&session.id, &cmd("/d /c echo second"), ""),
    );
    assert_eq!(second.outcome, Outcome::Exited(0), "{}", second.stderr);
    assert_eq!(second.served, 1);
    assert!(second.stdout.contains("second"), "{}", second.stdout);
    let _ = first.hang_up();
    session.leave();
}

/// A `--terminal` command ends with the session whose screen it holds, whoever asked for it: its asker here is the
/// test, outside the session's job, and the command is silent, so no failed delivery could end it.
#[test]
fn a_sessions_end_ends_the_terminal_command_it_hosts_even_a_silent_one_and_the_session_gets_its_exit() {
    let _serial = serial();
    let mut session = host("sessionend", Mode::Pty, ElevationPolicy::AutoApprove);
    let id = session.id.to_string();
    // Says its id, then writes nothing, and would end by itself with 77 after twenty seconds.
    let long = cmd(&format!(
        "/d /c \"echo running-{id}& ping -n 20 127.0.0.1 >nul & exit /b 77\""
    ));
    let mut pending = open(&session.control, "sessionend", on_a_terminal(&session.id, &long));
    session.client.read_until(&format!("running-{id}"));

    // The shell ends as `logout` ends it: the session's client stays connected.
    session.control.end_all();

    let (kinds, code) = pending.read_to_exit();
    assert_eq!(kinds.first(), Some(&FrameKind::Serving), "{kinds:?}");
    assert_ne!(code, 77, "the command ran to its own end");
    session.client.read_to_exit();
    assert!(session.client.exit.is_some(), "the session got its exit code");
    let _ = pending.hang_up();
    session.leave();
}

/// The `None` of `Link::host_elevated` seen from a request: a command asked for after the session's shell has gone is
/// started, answered `Serving` and ended at once, as one hosted when the session ended is. The session's client stays
/// connected, so its handler is still there to be asked.
#[test]
fn a_terminal_command_asked_for_after_the_shell_has_gone_is_ended_at_once() {
    let _serial = serial();
    let mut session = host_running("late", Mode::Pty, ElevationPolicy::AutoApprove, &cmd("/d /c exit /b 0"));
    // The session's `Exit` is written after its shell is gone and nothing more can be hosted.
    session.client.read_to_exit();

    // Would end by itself with 77 after twenty seconds.
    let long = cmd("/d /c \"ping -n 20 127.0.0.1 >nul & exit /b 77\"");
    let mut pending = open(&session.control, "late-ask", on_a_terminal(&session.id, &long));
    let (kinds, code) = pending.read_to_exit();
    assert_eq!(kinds.first(), Some(&FrameKind::Serving), "{kinds:?}");
    assert_ne!(code, 77, "the command ran to its own end");
    assert_eq!(elevated_starts().len(), 1, "it was started");
    let _ = pending.hang_up();
    session.leave();
}
