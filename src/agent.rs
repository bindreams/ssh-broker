//! agent: resident in a user's interactive session (started by the logon task, once per
//! logon). Per AF_UNIX connection it hosts the shell — in a ConPTY for interactive (PTY)
//! sessions, or with redirected pipes for EXEC (`ssh host "cmd"`) — inheriting the session's
//! token (working DPAPI/profile + no RedirectionGuard) and relays it to the SSH-side shim.
//!
//! The socket is inside the user's own profile (see `socket_loc`), so an agent serves exactly
//! one account: the one whose token it runs under.

/// `agent` subcommand entrypoint. Windows-only: the agent must run in the user's interactive
/// session to confer RDP parity, or as a background session (`--background`).
pub fn run(args: crate::route::AgentArgs) -> anyhow::Result<()> {
    #[cfg(windows)]
    return start(args);

    #[cfg(not(windows))]
    {
        let _ = args;
        Err(anyhow::anyhow!(
            "the agent runs only on Windows (it hosts the shell in an interactive session)"
        ))
    }
}

/// The process exit code for an error [`run`] returned: a start refusal's own code (the record a
/// background agent leaves, see `agent_background`), else 1.
pub fn exit_code_of(err: &anyhow::Error) -> i32 {
    #[cfg(windows)]
    if let Some(refusal) = err.downcast_ref::<crate::agent_background::Refusal>() {
        return refusal.code();
    }
    let _ = err;
    1
}

mod ending;
pub use ending::{end_process, hold_until_end, keep_log};
#[cfg(windows)]
mod connections;
#[cfg(windows)]
mod logout;

#[cfg(windows)]
use crate::afunix::{self, AcceptError, ConnRx, ConnTx, Listener};
#[cfg(windows)]
use crate::agent_background::{Refusal, check_start, mark_listening};
#[cfg(windows)]
use crate::agent_lock::{SessionSlot, UserLock};
#[cfg(windows)]
use crate::conpty::{self, PtySession};
#[cfg(windows)]
use crate::hangup::{HangupWatcher, Waker};
#[cfg(windows)]
use crate::pipes::ExecChild;
#[cfg(windows)]
use crate::protocol::{ExitCode, FrameKind, FrameReader, Handshake, Mode, Resize, Stream, read_one_frame, write_frame};
#[cfg(windows)]
use crate::relay::{FrameSink, pump_until_peer_gone, write_data};
#[cfg(windows)]
use crate::route::{AgentArgs, BackgroundArgs};
#[cfg(windows)]
use crate::socket_loc::SocketLocation;
#[cfg(windows)]
use crate::winutil::OwnedHandle;
#[cfg(windows)]
use connections::{Connections, Drained, Live};
#[cfg(windows)]
use logout::Control;
#[cfg(windows)]
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::sync::mpsc::TrySendError;
#[cfg(windows)]
use std::sync::{Arc, Condvar, Mutex};

/// Everything between "the task started us" and "serve": check where we are, make the user's
/// private folder, and become the one agent that serves this user.
#[cfg(windows)]
fn start(args: AgentArgs) -> anyhow::Result<()> {
    let current_sid = crate::acl::Sid::current_user()?.to_sddl()?;
    let background = args.background.is_some();
    start_with(
        args.background.as_ref(),
        crate::provision::probe::current_session_id(),
        &current_sid,
        crate::userdir::current_socket_location,
        |logs| crate::filelog::init_in(logs, "agent.log"),
        |location, session| serve(location, session, background),
    )
}

/// [`start`] with its inputs as parameters, so a test can pick the session and see what runs.
///
/// `background` is `Some` for `agent --background`. The refusals before the log opens leave their
/// exit code as the only record (see [`Refusal`]).
#[cfg(windows)]
fn start_with(
    background: Option<&BackgroundArgs>,
    session: u32,
    current_sid: &str,
    locate: impl FnOnce() -> anyhow::Result<SocketLocation>,
    init_log: impl FnOnce(&Path) -> anyhow::Result<tracing_appender::non_blocking::WorkerGuard>,
    serve: impl FnOnce(&SocketLocation, u32) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    check_start(background, session, current_sid)?;
    let refused = |refusal: Refusal, cause: anyhow::Error| anyhow::Error::new(refusal).context(format!("{cause:#}"));
    let location = locate().map_err(|e| refused(Refusal::NoSocketLocation, e))?;
    let user = crate::acl::Sid::current_user()?;
    crate::userdir::ensure_socket_dir(&location, &user).map_err(|e| refused(Refusal::SocketFolderRefused, e))?;
    // Held to the end of the process and flushed by `end_process`, from whichever thread ends it:
    // dropping the guard stops the writer and later lines are lost. Until the log opens an error goes
    // to stderr, which a logon task discards; a hand-run agent shows it.
    if let Some(log) = keep_log_or_report(init_log(&location.logs_dir()), &mut std::io::stderr()) {
        keep_log(log);
    }
    let result = serve(&location, session);
    if let Err(e) = &result {
        tracing::error!("the agent stopped: {e:#}");
    }
    result
}

/// Keep the log if it opened. If not, say why on `stderr` and go on: serving does not need a log.
#[cfg(windows)]
fn keep_log_or_report(
    log: anyhow::Result<tracing_appender::non_blocking::WorkerGuard>,
    stderr: &mut dyn std::io::Write,
) -> Option<tracing_appender::non_blocking::WorkerGuard> {
    match log {
        Ok(guard) => Some(guard),
        Err(e) => {
            let _ = writeln!(stderr, "ssh-broker agent: serving without a log: {e:#}");
            None
        }
    }
}

/// Become the one agent that serves this user, then serve.
#[cfg(windows)]
fn serve(location: &SocketLocation, session: u32, background: bool) -> anyhow::Result<()> {
    serve_in(location, session, |location| run_on(location, background))
}

/// [`serve`] with the serving as a parameter, so a test can see that what the agent holds goes to
/// [`hold_until_end`].
#[cfg(windows)]
fn serve_in(
    location: &SocketLocation,
    session: u32,
    run: impl FnOnce(&SocketLocation) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    serve_with(
        location,
        session,
        |path| {
            // One serving agent per user. A second session of the same user waits instead of
            // leaving: the serving agent dies with its session, and this user may still be logged
            // on here.
            UserLock::acquire(path, || {
                tracing::info!("waiting for the agent of another session of this user to end");
            })
        },
        run,
        hold_until_end,
    )
}

/// [`serve`] with the user lock, the serving and the keeping as parameters, so a test can see the
/// order.
///
/// The slot and the lock are handed to `hold` when serving is over, whatever it returned, and not
/// dropped: the process ends right after, and a successor that took the lock before then would start
/// while this agent is still ending. The system releases both with the process.
#[cfg(windows)]
fn serve_with(
    location: &SocketLocation,
    session: u32,
    user_lock: impl FnOnce(&Path) -> anyhow::Result<UserLock>,
    run: impl FnOnce(&SocketLocation) -> anyhow::Result<()>,
    hold: impl FnOnce(Box<dyn std::any::Any + Send>),
) -> anyhow::Result<()> {
    // One agent per session: `apply` and the boot self-heal start one per logged-on session
    // every time they run, and the logon task starts one per logon. This comes first, because the
    // user lock may be held for as long as another session lives.
    let Some(slot) = SessionSlot::try_acquire(&location.sessions_lock_path(), session)? else {
        tracing::info!("another agent already runs in this session; exiting");
        return Ok(());
    };
    let lock = user_lock(&location.lock_path())?;
    let result = run(location);
    hold(Box::new((slot, lock)));
    result
}

/// Bind the hardened socket and serve connections, one handler thread each. The caller holds
/// the user's lock, so no other agent of this user binds meanwhile.
#[cfg(windows)]
fn run_on(location: &SocketLocation, background: bool) -> anyhow::Result<()> {
    let connections = Connections::new();
    // Closing the listener wakes the blocked `accept` with a connection of its own; the loop then sees
    // the flag. A wake that fails is reported to the connections, which stop waiting for the loop.
    let socket = location.path.clone();
    let waking = Arc::clone(&connections);
    let control = Arc::new(Control::new(background, Arc::clone(&connections)).with_waker(move || {
        let socket = socket.clone();
        wake_without_blocking(&waking, move || afunix::connect(&socket).map(drop))
    }));
    run_on_with(location, Listener::bind, mark_listening, |listener| {
        serve_until_drained(listener, &connections, &control)
    })
    .or_else(|err| match err.downcast_ref::<Stopped>() {
        Some(Stopped) => Ok(()),
        None => Err(err),
    })
}

/// Serve `listener` until the agent has decided to end, then return the error that stopped the loop.
///
/// The one loop keeps accepting through the drain: a login that comes while the agent drains gets the
/// ending refusal at once, where a closed socket would have left its shim waiting for an agent it
/// takes to be starting, for as long as the drain lasts. It stops when the drain has finished
/// ([`Connections::settle`]), after counting the connection it was accepting, and the listener is
/// closed here, before the drain judges again.
#[cfg(windows)]
fn serve_until_drained(listener: Listener, connections: &Arc<Connections>, control: &Arc<Control>) -> anyhow::Error {
    serve_until_drained_in(
        listener,
        connections,
        || control.is_ending(),
        |listener| accept_loop(listener, connections, control, || connections.is_closing()),
    )
}

/// [`serve_until_drained`] with the accepting as a parameter, so a test can see that the listener is
/// closed before the end is judged. `ending` says whether the agent has begun to end, which makes a
/// failed loop wait for the drain as a stopped one does.
#[cfg(windows)]
fn serve_until_drained_in<L>(
    listener: L,
    connections: &Connections,
    ending: impl FnOnce() -> bool,
    accept: impl FnOnce(&L) -> anyhow::Error,
) -> anyhow::Error {
    connections.listener_opened();
    let end = accept(&listener);
    drop(listener);
    connections.listener_closed();
    finish_stopped(end, connections, ending())
}

/// [`serve_connections_with`] over `listener`, handing each connection to a thread of its own.
#[cfg(windows)]
fn accept_loop(
    listener: &Listener,
    connections: &Arc<Connections>,
    control: &Arc<Control>,
    stopping: impl Fn() -> bool,
) -> anyhow::Error {
    accept_loop_with(|| listener.accept(), connections, control, stopping)
}

/// [`accept_loop`] over an `accept` the caller supplies, so a test can stop the loop between a
/// connection's `accept` and its count.
#[cfg(windows)]
fn accept_loop_with(
    mut accept: impl FnMut() -> Result<socket2::Socket, AcceptError>,
    connections: &Arc<Connections>,
    control: &Arc<Control>,
    stopping: impl Fn() -> bool,
) -> anyhow::Error {
    serve_connections_with(
        Arc::clone(connections),
        move || match accept() {
            Ok(conn) => Ok(Arrived::Usable(conn)),
            Err(AcceptError::Refused { socket, cause }) => Ok(Arrived::Refused(socket, cause)),
            Err(e) => Err(e),
        },
        |arrived, live| {
            let control = Arc::clone(control);
            hand_to_thread(
                arrived,
                live,
                |work| std::thread::Builder::new().spawn(work).map(drop),
                move |arrived| match arrived {
                    Arrived::Usable(conn) => {
                        if let Err(e) = serve_connection(conn, Hooks::production(), &control) {
                            tracing::warn!("connection handler error: {e:?}");
                        }
                    }
                    Arrived::Refused(conn, cause) => {
                        let failure =
                            logout::fail_socket(conn, &control, "the agent could not use the connection", cause);
                        tracing::warn!("refused a connection: {failure:#}");
                    }
                },
            )
        },
        || {},
        stopping,
    )
}

/// What the accept loop took: a connection to serve, or one the agent must not serve and answers.
#[cfg(windows)]
enum Arrived {
    Usable(socket2::Socket),
    Refused(socket2::Socket, anyhow::Error),
}

/// Run `wake` on a thread of its own, so that the caller never waits for it. The wake is a connect
/// to the agent's own listener, and a connect to a listener whose queue is full may wait for room in
/// it; the caller may be the `logout` handler. A wake that has to wait wakes nothing that needs
/// waking: the queue is full only if the accept loop is not blocked in `accept`, and a loop that is
/// not blocked reads the flag before its next `accept`.
///
/// A wake that fails, or a thread that cannot be started, is reported to `connections` (see
/// [`Connections::wake_failed`]).
#[cfg(windows)]
fn wake_without_blocking(connections: &Arc<Connections>, wake: impl FnOnce() -> anyhow::Result<()> + Send + 'static) {
    let on_thread = Arc::clone(connections);
    let started = std::thread::Builder::new().spawn(move || {
        if let Err(e) = wake() {
            on_thread.wake_failed(&format!("{e:#}"));
        }
    });
    if let Err(e) = started {
        connections.wake_failed(&format!("no thread for it: {e}"));
    }
}

/// The accept loop stopped because the end is decided (see [`serve_connections_with`]).
#[cfg(windows)]
#[derive(Debug, thiserror::Error)]
#[error("the agent stopped accepting connections because its session is ending")]
struct Stopped;

/// After the loop returned `end`: if it stopped on purpose, or the agent is ending and the loop failed,
/// wait until the end is decided (see [`Connections::settle`]) and return `end` either way. The agent's
/// process ends when this returns.
#[cfg(windows)]
fn finish_stopped(end: anyhow::Error, connections: &Connections, ending: bool) -> anyhow::Error {
    if ending || end.downcast_ref::<Stopped>().is_some() {
        // The listener is closed, so there is nothing to wake.
        connections.settle(&|| {});
    }
    end
}

/// [`run_on`] with its steps as parameters, so a test can see their order: bind, then mark, then
/// accept. The marker comes after `bind` returns, which includes `listen`, so a shim that wakes
/// on it can connect.
#[cfg(windows)]
fn run_on_with<L>(
    location: &SocketLocation,
    bind: impl FnOnce(&Path) -> anyhow::Result<L>,
    mark: impl FnOnce(&SocketLocation) -> std::io::Result<()>,
    accept_loop: impl FnOnce(L) -> anyhow::Error,
) -> anyhow::Result<()> {
    let listener = bind(&location.path)?;
    mark(location).map_err(|e| anyhow::Error::new(e).context("write the serving marker"))?;
    Err(accept_loop(listener))
}

/// Run `handle` on a thread started by `spawn`, which owns `conn` and `live`. The connection ends
/// after `handle` returns and `conn` is closed: that is when its descriptors are free again.
///
/// If the thread cannot be started, `conn` is handed back with the error and `live` is given up
/// without counting an end: the connection never ran, so it frees nothing for [`serve_connections`] to
/// wait for. The caller keeps the connection: dropping it would close it without a byte.
#[cfg(windows)]
fn hand_to_thread<C: Send + 'static>(
    conn: C,
    live: Live,
    spawn: impl FnOnce(Box<dyn FnOnce() + Send>) -> std::io::Result<()>,
    handle: impl FnOnce(C) + Send + 'static,
) -> Result<(), NotServed<C>> {
    // The thread takes the connection from here, so a failed start leaves it with the caller.
    let (give, take) = std::sync::mpsc::channel::<(C, Live)>();
    let work = Box::new(move || {
        if let Ok((conn, live)) = take.recv() {
            let _live = live;
            handle(conn);
        }
    });
    match spawn(work) {
        Ok(()) => {
            // A send fails only if the thread has gone without running, which drops the pair.
            let _ = give.send((conn, live));
            Ok(())
        }
        Err(e) => {
            live.abandon();
            Err((conn, e))
        }
    }
}

/// A connection no thread could be started for, and why.
#[cfg(windows)]
type NotServed<C> = (C, std::io::Error);

/// Accept connections and hand each to `serve`, with the guard that says when it ends, until the
/// listener breaks; returns that error.
///
/// A connection that is lost (reset while queued, or one that cannot be set up) is logged and
/// dropped: it must not end service for every session of the user. An interrupted `accept` is
/// called again. A shortage of descriptors or buffers, and a `serve` that could not start a thread
/// for its connection (it returns the connection and the error, having given up its `Live`), is
/// waited out: the loop blocks until one of this agent's own connections ends, which is the only thing
/// that can free any of those, and then accepts again, or serves the same connection again if it was
/// kept. With no live connection nothing can, and the shortage is fatal.
#[cfg(all(windows, test))]
fn serve_connections<C>(
    accept: impl FnMut() -> Result<C, AcceptError>,
    serve: impl FnMut(C, Live) -> Result<(), NotServed<C>>,
) -> anyhow::Error {
    serve_connections_observed(accept, serve, || {})
}

/// [`serve_connections`], calling `blocking` each time the loop is about to block waiting for a
/// connection to end (see [`Connections::wait_for_an_end`] for what that guarantees).
#[cfg(all(windows, test))]
fn serve_connections_observed<C>(
    accept: impl FnMut() -> Result<C, AcceptError>,
    serve: impl FnMut(C, Live) -> Result<(), NotServed<C>>,
    blocking: impl FnMut(),
) -> anyhow::Error {
    serve_connections_with(Connections::new(), accept, serve, blocking, || false)
}

/// [`serve_connections_observed`] over a tally the caller also holds, so that a connection can wait
/// for the others to finish (`logout`).
///
/// `stopping` is asked before every `accept`; once it says so the loop returns [`Stopped`]. The
/// party that makes it true must also make a blocked `accept` return (a connection of its own).
#[cfg(windows)]
fn serve_connections_with<C>(
    connections: Arc<Connections>,
    mut accept: impl FnMut() -> Result<C, AcceptError>,
    mut serve: impl FnMut(C, Live) -> Result<(), NotServed<C>>,
    mut blocking: impl FnMut(),
    stopping: impl Fn() -> bool,
) -> anyhow::Error {
    // A connection that no thread could be started for. The agent does not close it without a byte
    // (its client would take that for an agent that is going away): it serves it once a connection
    // has ended, unless the end is decided first.
    let mut kept = None;
    loop {
        if stopping() {
            // The end is decided while a connection waits for a thread. It is served once more, which
            // gets it the ending refusal (see `handle_connection_in`) and counts it, so the drain waits
            // for the refusal. If there is still no thread, its client sees the agent end.
            if let Some(conn) = kept.take()
                && let Err((_, e)) = serve(conn, connections.begin())
            {
                tracing::warn!("no thread to refuse a connection with ({e}); closing it as the agent ends");
            }
            return anyhow::Error::new(Stopped);
        }
        // Read before the attempt: a connection that ends while it fails is then not missed.
        let ended_before = connections.ended();
        let next = match kept.take() {
            Some(conn) => Ok(conn),
            None => accept(),
        };
        let shortage = match next {
            Ok(conn) => match serve(conn, connections.begin()) {
                Ok(()) => continue,
                Err((conn, e)) => {
                    tracing::warn!("no thread for a connection ({e}); waiting for a connection to end");
                    kept = Some(conn);
                    anyhow::Error::new(e).context("could not start a thread for a connection")
                }
            },
            Err(AcceptError::Connection(e)) => {
                tracing::warn!("dropped a connection: {e:#}");
                continue;
            }
            // The caller's `accept` turns a refused connection into a `C` it can answer (see
            // `accept_loop_with`); one that gets here would be closed without a byte.
            Err(AcceptError::Refused { cause, .. }) => {
                debug_assert!(false, "a refused connection reached the loop: {cause:#}");
                tracing::error!("dropped a refused connection, which should have been answered: {cause:#}");
                continue;
            }
            Err(AcceptError::Interrupted(_)) => continue,
            Err(AcceptError::Exhausted { code, source }) => {
                tracing::warn!(
                    "accept failed for lack of resources (code {code}); waiting for a connection to end: {source}"
                );
                anyhow::Error::new(source).context(format!("accept failed with code {code}"))
            }
            Err(AcceptError::Fatal(e)) => return e.context("the listener failed"),
        };
        if !connections.wait_for_an_end(ended_before, &mut blocking) {
            return shortage.context("no connection of this agent is live to free a resource");
        }
    }
}

/// Default shell when the handshake carries no command (config-driven shell is Phase 7).
#[cfg(windows)]
fn default_shell() -> String {
    "pwsh.exe -NoLogo".to_string()
}

/// The home directory of the account the agent runs as: its token's profile. The environment is
/// not consulted, because it belongs to whoever started the process. `None` (logged) if there is
/// no such directory.
#[cfg(windows)]
fn home_dir() -> Option<PathBuf> {
    match find_home(crate::userdir::current_profile_dir()) {
        Ok(home) => Some(home),
        Err(why) => {
            tracing::warn!("no home directory to start the child in: {why}");
            None
        }
    }
}

/// `profile` as a home directory, or why it is not one.
#[cfg(windows)]
fn find_home(profile: anyhow::Result<PathBuf>) -> Result<PathBuf, String> {
    let profile = profile.map_err(|e| format!("{e:#}"))?;
    if profile.is_dir() {
        Ok(profile)
    } else {
        Err(format!(
            "the profile directory {} is not a directory",
            profile.display()
        ))
    }
}

/// The working directory to start the child in: the handshake's explicit `cwd` if any, else the
/// user's home directory. This mirrors what a normal SSH login does — sshd's `do_child()` runs
/// `chdir(pw->pw_dir)` to the user's home before exec'ing the shell — so `ssh host` lands you in
/// your home, not wherever the agent task happened to start (`C:\Windows\System32`).
pub fn child_cwd(handshake_cwd: &str, home: Option<std::path::PathBuf>) -> Option<std::path::PathBuf> {
    if handshake_cwd.is_empty() {
        home
    } else {
        Some(std::path::PathBuf::from(handshake_cwd))
    }
}

/// Read the handshake, then dispatch to the PTY or EXEC relay.
#[cfg(all(windows, test))]
fn handle_connection(conn: socket2::Socket) -> anyhow::Result<()> {
    handle_connection_with(conn, Hooks::production())
}

/// [`handle_connection`] with hooks, for a connection that no accept loop owns: it is a desktop
/// agent's, which `logout` does not end.
#[cfg(all(windows, test))]
fn handle_connection_with(conn: socket2::Socket, hooks: Hooks) -> anyhow::Result<()> {
    handle_connection_in(conn, hooks, &Control::standalone())
}

/// What a session runs with: the hooks a test can replace, and the agent's shared control.
#[cfg(windows)]
struct Env<'a> {
    hooks: Hooks,
    control: &'a Control,
}

/// How a session obtains its [`HangupWatcher`]; a parameter so a test can force a failure.
#[cfg(windows)]
type WatchFactory = fn(&ConnTx) -> std::io::Result<(HangupWatcher, Waker)>;

/// How a session starts its shell in a pseudoconsole (`command`, `cols`, `rows`, `cwd`); a parameter
/// so a test can force a failure without starting a process.
#[cfg(windows)]
type PtyStarter = fn(&str, u16, u16, Option<&Path>) -> anyhow::Result<PtySession>;

/// How a session starts its command on pipes (`command`, `cwd`); a parameter like [`PtyStarter`].
#[cfg(windows)]
type ExecStarter = fn(&str, Option<&Path>) -> anyhow::Result<ExecChild>;

/// How a connection is split into halves; a parameter so a test can force a failure.
#[cfg(windows)]
type Splitter = fn(socket2::Socket) -> Result<(ConnRx, ConnTx), (afunix::Whole, anyhow::Error)>;

/// What a test can replace or observe in a session; production uses [`Hooks::production`].
#[cfg(windows)]
struct Hooks {
    make_watcher: WatchFactory,
    start_pty: PtyStarter,
    start_exec: ExecStarter,
    split: Splitter,
    parked: ParkSignal,
    /// Called once the session's shell is started and before it is registered, the window in which
    /// the agent can begin to end.
    after_spawn: Box<dyn Fn() + Send + Sync>,
    /// Told what a PTY session does that no result shows, for a test that has to say where a hang is.
    observe: Box<dyn Fn(Observed) + Send + Sync>,
}

/// What a PTY session reports to [`Hooks::observe`]; only tests read the fields.
#[cfg(windows)]
#[cfg_attr(not(test), allow(dead_code))]
enum Observed {
    /// The shell has started. `output` is the read end of the pseudoconsole's output pipe and
    /// `process` the shell's process handle; both are valid until the session is dropped, which is
    /// after a refused login has reported [`Observed::RefusedConsoleClosed`].
    ShellStarted { output: isize, process: isize },
    /// A refused login has closed its pseudoconsole after reading `bytes` of its output.
    RefusedConsoleClosed { bytes: usize },
}

#[cfg(windows)]
impl Hooks {
    fn production() -> Self {
        Self {
            make_watcher: HangupWatcher::new,
            start_pty: |command, cols, rows, cwd| Ok(PtySession::spawn(command, cols, rows, cwd)?),
            start_exec: |command, cwd| Ok(ExecChild::spawn(command, cwd)?),
            split: afunix::try_split,
            parked: ParkSignal::default(),
            after_spawn: Box::new(|| {}),
            observe: Box::new(|_| {}),
        }
    }
}

/// [`handle_connection_in`] for a thread of its own: if the thread panics, the connection is answered
/// with the failure reply before it closes (see [`logout::PanicReply`]).
#[cfg(windows)]
fn serve_connection(conn: socket2::Socket, hooks: Hooks, control: &Control) -> anyhow::Result<()> {
    let _answer_a_panic = logout::PanicReply::new(&conn, control);
    handle_connection_in(conn, hooks, control)
}

/// Serve one connection. The agent never closes a connection without a byte while it is alive: a
/// connection it cannot set up, read or carry out is answered with a frame the shim prints (see
/// [`logout::fail_connection`]), and the error comes back for the log. A client that leaves before
/// it sends anything has nothing to be told, and is not an error.
#[cfg(windows)]
fn handle_connection_in(conn: socket2::Socket, hooks: Hooks, control: &Control) -> anyhow::Result<()> {
    let (mut rx, mut tx) = match (hooks.split)(conn) {
        Ok(halves) => halves,
        Err((whole, cause)) => {
            let (mut rx, mut tx) = (&whole, &whole);
            return Err(logout::fail_connection(
                &mut rx,
                &mut tx,
                control,
                "the agent could not set up the connection",
                cause,
                logout::FAILED_EXIT_CODE,
            ));
        }
    };
    let mut fr = FrameReader::new();
    let hs = match read_handshake(&mut rx, &mut fr) {
        Ok(Some(hs)) => hs,
        Ok(None) => return Ok(()),
        Err(cause) => {
            return Err(logout::fail_connection(
                &mut rx,
                &mut tx,
                control,
                "the agent could not read the request",
                cause,
                logout::BAD_REQUEST_EXIT_CODE,
            ));
        }
    };
    if hs.mode == Mode::Logout {
        return logout::handle_logout(&mut rx, &mut tx, control, || {
            tracing::info!("the background session has ended");
            end_process(0)
        });
    }
    // Before a shell is started for nothing; the registration below is what decides.
    if control.is_ending() {
        return logout::refuse_while_ending(&mut rx, &mut tx, control);
    }
    let command = hs.command.clone().unwrap_or_else(default_shell);
    let cwd_buf = child_cwd(&hs.cwd, home_dir());
    let cwd = cwd_buf.as_deref();
    match hs.mode {
        Mode::Pty => handle_pty(rx, fr, tx, &command, (hs.cols, hs.rows), cwd, Env { hooks, control }),
        Mode::Exec => handle_exec(rx, fr, tx, &command, cwd, Env { hooks, control }),
        Mode::Logout => unreachable!("answered above"),
    }
}

/// The handshake that opens a connection. `None` if the client closed the connection before it sent
/// a byte: the wake that ends the accept loop does, and a client that gave up does; neither is a fault.
#[cfg(windows)]
fn read_handshake(rx: &mut impl std::io::Read, fr: &mut FrameReader) -> anyhow::Result<Option<Handshake>> {
    struct Counted<'a, R> {
        inner: &'a mut R,
        any: bool,
    }
    impl<R: std::io::Read> std::io::Read for Counted<'_, R> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.inner.read(buf)?;
            self.any |= n > 0;
            Ok(n)
        }
    }
    let mut rx = Counted { inner: rx, any: false };
    let frame = match read_one_frame(&mut rx, fr) {
        Ok(frame) => frame,
        Err(e) if !rx.any => {
            tracing::debug!("a client left without sending a request: {e:#}");
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    anyhow::ensure!(frame.kind == FrameKind::Handshake, "first frame was not a handshake");
    Ok(Some(Handshake::decode(&frame.payload)?))
}

#[cfg(test)]
#[path = "agent_cwd_tests.rs"]
mod agent_cwd_tests;

#[cfg(all(windows, test))]
#[path = "agent_start_tests.rs"]
mod agent_start_tests;

#[cfg(all(windows, test))]
#[path = "agent_program_path_tests.rs"]
mod agent_program_path_tests;

#[cfg(all(windows, test))]
#[path = "agent_end_tests.rs"]
mod agent_end_tests;

#[cfg(all(windows, test))]
#[path = "agent_reply_tests.rs"]
mod agent_reply_tests;

// ── PTY relay ────────────────────────────────────────────────────────────────────────

/// Interactive PTY relay: spawn the shell in a ConPTY and bridge it with three threads and
/// an ordered, race-free teardown (criterion 2).
#[cfg(windows)]
fn handle_pty(
    mut rx: ConnRx,
    mut fr: FrameReader,
    mut tx: ConnTx,
    command: &str,
    (cols, rows): (u16, u16),
    cwd: Option<&Path>,
    env: Env<'_>,
) -> anyhow::Result<()> {
    let Env { hooks, control } = env;
    let mut session = match (hooks.start_pty)(command, cols, rows, cwd) {
        Ok(session) => session,
        Err(cause) => {
            return Err(logout::fail_connection(
                &mut rx,
                &mut tx,
                control,
                "the agent could not start the shell",
                cause,
                logout::FAILED_EXIT_CODE,
            ));
        }
    };
    (hooks.observe)(Observed::ShellStarted {
        output: session.out_read_raw(),
        process: session.process_raw(),
    });
    (hooks.after_spawn)();
    let job = session.job();
    let Some(_registration) = register_session(control, &job) else {
        return refuse_unserved_pty(session, &mut rx, &mut tx, control, &*hooks.observe);
    };
    // Before `tx` moves into the shared mutex.
    let hangup = start_hangup_watch(&tx, &job, hooks.make_watcher);

    let out_raw = session.out_read_raw();
    let in_raw = session.in_write_raw();
    // HPCON shared behind a mutex: the input thread resizes under the lock; teardown takes
    // it (→ None) and closes it under the lock, so resize can never touch a closed HPCON.
    let hpc_cell = Arc::new(Mutex::new(Some(session.take_hpc_raw())));
    let tx_arc = Arc::new(Mutex::new(tx));

    // Output pump: ConPTY output -> DATA(Pty). It deliberately does NOT emit EXIT.
    // `read_handle` returns 0 for a read *error* as well as for EOF, so this thread cannot
    // tell "the shell finished" from "the pipe broke" — emitting the code from here raced the
    // waiter that produces it, and a failed session could report EXIT(0).
    let out_thread = {
        let tx = Arc::clone(&tx_arc);
        let job = Arc::clone(&job);
        std::thread::spawn(move || {
            let mut buf = [0u8; 32 * 1024];
            let mut delivering = true;
            loop {
                let n = conpty::read_handle(out_raw, &mut buf);
                if n == 0 {
                    break; // pseudoconsole closed (teardown) -> drained to EOF
                }
                if !delivering {
                    continue; // draining, see below
                }
                let ok = {
                    let mut g = tx.lock().unwrap();
                    write_data(&mut *g, Stream::Pty, &buf[..n]).is_ok()
                };
                if !ok {
                    // The socket is gone. Reap, but keep READING: this thread is the only
                    // reader of the pseudoconsole's output pipe, and `ClosePseudoConsole`
                    // below flushes conhost's pending output through it. Abandoning the pipe
                    // here lets it fill, and teardown then blocks inside the close.
                    reap_tree(&job);
                    delivering = false;
                }
            }
        })
    };

    let in_thread = {
        let hpc_cell = Arc::clone(&hpc_cell);
        let job = Arc::clone(&job);
        std::thread::spawn(move || {
            let mut sink = PtyInputSink {
                writer: HandleWriter::spawn(in_raw, None, hooks.parked),
                hpc_cell,
            };
            pump_until_peer_gone(&mut rx, &mut fr, &mut sink);
            if let Some(w) = teardown_warning(reap_tree(&job)) {
                tracing::error!("{w}");
            }
            // Dropping the sink joins the writer thread, which may be parked writing to the
            // pseudoconsole's input pipe. The reap does NOT release that: conhost holds the
            // read end and is not a member of the job. `ClosePseudoConsole` in the waiter
            // below is what releases it, which is why this drop must not be moved ahead of it.
            drop(sink);
        })
    };

    // Waiter + ordered teardown. Do NOT `?` on wait(): even if it errors we must still tear
    // down (close the HPCON, join the threads) before returning, or the threads would
    // outlive `session` and touch closed handles, and the (forgotten) HPCON would leak.
    let wait_result = session.wait();
    if let Some(w) = teardown_warning(reap_tree(&job)) {
        tracing::error!("{w}");
    }
    let code = *wait_result.as_ref().unwrap_or(&1);
    {
        // Close the pseudoconsole while HOLDING the lock, so a concurrent resize cannot
        // copy the raw HPCON out and then race this close (use-after-close).
        let mut hpc = hpc_cell.lock().unwrap();
        if let Some(raw) = hpc.take() {
            conpty::close_pty_raw(raw); // → flushes conhost, then output pipe EOF → out_thread ends
        }
    }
    let _ = out_thread.join();
    {
        // The shell is gone and the output is drained, so the code is final and nothing else
        // can still be writing frames.
        let mut g = tx_arc.lock().unwrap();
        // FIN the write half only: the input pump keeps reading until the client closes, so for a
        // conforming client the socket never closes with unread input, which would reset it and
        // lose the EXIT frame.
        send_exit(&mut *g, code);
    }
    if let Some(hangup) = hangup {
        hangup.finish();
    }
    let _ = in_thread.join();
    // Threads joined; `session` now drops and closes the process/thread + pipe handles.
    wait_result?;
    Ok(())
}

/// The write half of a connection, which can be closed on its own.
#[cfg(windows)]
trait HalfClose: std::io::Write {
    /// Send FIN on the write half.
    fn shutdown_write(&self) -> anyhow::Result<()>;
}

#[cfg(windows)]
impl HalfClose for ConnTx {
    fn shutdown_write(&self) -> anyhow::Result<()> {
        ConnTx::shutdown_write(self)
    }
}

#[cfg(windows)]
impl HalfClose for &afunix::Whole {
    fn shutdown_write(&self) -> anyhow::Result<()> {
        afunix::Whole::shutdown_write(self)
    }
}

/// Send the shell's exit code and FIN the write half. A client that has gone loses the code, which
/// is routine and logged at debug; any other failure loses it too and is logged as a warning.
#[cfg(windows)]
fn send_exit(tx: &mut impl HalfClose, code: i32) {
    let write = write_frame(tx, FrameKind::Exit, &ExitCode(code).encode());
    let close = tx.shutdown_write();
    for (what, result) in [("send the exit code", write), ("close the write half", close)] {
        if let Err(e) = result {
            if crate::shim::peer_gone(&e).is_some() {
                tracing::debug!("the client is gone; could not {what} (exit code {code}): {e:#}");
            } else {
                tracing::warn!("could not {what} (exit code {code}): {e:#}");
            }
        }
    }
}

/// Answer a login whose shell has been ended before it was served with the refusal. The pseudoconsole
/// is closed first, with its output read as the regular teardown reads it: the shell has been running
/// since `spawn`, and closing flushes whatever it wrote into a pipe that nothing else reads.
#[cfg(windows)]
fn refuse_unserved_pty(
    mut session: PtySession,
    rx: &mut ConnRx,
    tx: &mut ConnTx,
    control: &Control,
    observe: &(dyn Fn(Observed) + Send + Sync),
) -> anyhow::Result<()> {
    let out_raw = session.out_read_raw();
    let hpc = session.take_hpc_raw();
    let mut buf = [0u8; 32 * 1024];
    let mut bytes = 0usize;
    let drained = close_while_draining(
        || {
            let n = conpty::read_handle(out_raw, &mut buf);
            bytes += n;
            n
        },
        || conpty::close_pty_raw(hpc),
    );
    if let Err(e) = drained {
        // Closing without a reader could block for ever; the pseudoconsole is left to the process's end.
        tracing::warn!("could not read the output of a refused shell; its pseudoconsole stays open: {e}");
    }
    observe(Observed::RefusedConsoleClosed { bytes });
    drop(session); // the pipe ends go after the reader has finished with them
    logout::refuse_while_ending(rx, tx, control)
}

/// Run `close`, which flushes into a pipe `read_chunk` reads (it returns 0 at the end), with a
/// reader on a thread of its own, and return once both are done. If the reader cannot be started,
/// `close` is not run, because it may block for ever on a pipe nobody reads, and the error says why.
#[cfg(windows)]
fn close_while_draining(mut read_chunk: impl FnMut() -> usize + Send, close: impl FnOnce()) -> std::io::Result<()> {
    std::thread::scope(|scope| {
        std::thread::Builder::new().spawn_scoped(scope, || while read_chunk() > 0 {})?;
        close();
        Ok(())
    })
}

/// Record the session so that `logout` can end its shell tree. `None` means the agent is already
/// ending: the tree is ended here, at once, and the caller answers the login with the refusal
/// instead of relaying a shell that is gone.
#[cfg(windows)]
fn register_session<'a>(control: &'a Control, job: &Arc<cosca::Job>) -> Option<logout::Registration<'a>> {
    let kill_job = Arc::clone(job);
    let registration = control.register(Arc::new(move || {
        reap_tree(&kill_job);
    }));
    if registration.is_none() {
        reap_tree(job);
    }
    registration
}

/// Routes decoded input frames into the pseudoconsole.
#[cfg(windows)]
struct PtyInputSink {
    writer: HandleWriter,
    hpc_cell: Arc<Mutex<Option<isize>>>,
}

#[cfg(windows)]
impl FrameSink for PtyInputSink {
    fn on_data(&mut self, _stream: Stream, bytes: &[u8]) -> anyhow::Result<()> {
        // PTY input arrives pre-encoded (win32-input-mode); hand it straight to ConPTY#2.
        self.writer.write(bytes)
    }
    fn on_resize(&mut self, r: Resize) -> anyhow::Result<()> {
        // Hold the lock across the OS call (bound guard, not a temporary) so teardown
        // cannot close the HPCON mid-resize.
        let hpc = self.hpc_cell.lock().unwrap();
        if let Some(raw) = *hpc {
            let _ = conpty::resize_pty(raw, r.cols, r.rows);
        }
        Ok(())
    }
}

// ── EXEC relay ───────────────────────────────────────────────────────────────────────

/// Non-interactive EXEC relay (`ssh host "cmd"`): spawn the child with redirected pipes,
/// relay stdout/stderr as SEPARATE streams, feed stdin, and propagate the exit code.
#[cfg(windows)]
fn handle_exec(
    mut rx: ConnRx,
    mut fr: FrameReader,
    mut tx: ConnTx,
    command: &str,
    cwd: Option<&Path>,
    env: Env<'_>,
) -> anyhow::Result<()> {
    let Env { hooks, control } = env;
    let mut child = match (hooks.start_exec)(command, cwd) {
        Ok(child) => child,
        Err(cause) => {
            return Err(logout::fail_connection(
                &mut rx,
                &mut tx,
                control,
                "the agent could not start the command",
                cause,
                logout::FAILED_EXIT_CODE,
            ));
        }
    };
    (hooks.after_spawn)();
    let job = child.job();
    let Some(_registration) = register_session(control, &job) else {
        return logout::refuse_while_ending(&mut rx, &mut tx, control);
    };
    // Before `tx` moves into the shared mutex.
    let hangup = start_hangup_watch(&tx, &job, hooks.make_watcher);
    let out_raw = child.stdout_read_raw();
    let err_raw = child.stderr_read_raw();
    let stdin_owned = child.take_stdin_write();
    let stdin_raw = stdin_owned.as_ref().map_or(0, |h| h.raw());
    // stdout, stderr, and the EXIT frame all share tx → serialize with a mutex.
    let tx_arc = Arc::new(Mutex::new(tx));

    let t_out = spawn_stream_pump(out_raw, Stream::Stdout, Arc::clone(&tx_arc), Arc::clone(&job));
    let t_err = spawn_stream_pump(err_raw, Stream::Stderr, Arc::clone(&tx_arc), Arc::clone(&job));

    // stdin pump owns the child's stdin-write handle. A half-close mid-session (empty
    // DATA(Stdin) marker) closes only the child's stdin so a reader like sort/findstr
    // finishes; a FULL socket close means the SSH side is gone, so after the pump returns we
    // kill the child unconditionally. Without this, a silent, stdin-ignoring command that
    // sleeps indefinitely would never exit, and the output pumps — blocked in read with
    // nothing to write — would never detect the dead socket, hanging the waiter.
    let t_in = {
        let job = Arc::clone(&job);
        std::thread::spawn(move || {
            let mut sink = ExecInputSink {
                writer: HandleWriter::spawn(stdin_raw, stdin_owned, hooks.parked),
            };
            pump_until_peer_gone(&mut rx, &mut fr, &mut sink);
            // Reap first: dropping the sink joins the writer thread, which may be parked
            // writing to the child's stdin. Here the reap does release it — `ExecChild::spawn`
            // drops the parent's copy of the read end, so the dead child was the only holder.
            if let Some(w) = teardown_warning(reap_tree(&job)) {
                tracing::error!("{w}");
            }
            drop(sink); // also closes the child's stdin if the EOF marker never arrived
        })
    };

    let wait_result = child.wait();
    // The command is gone, so the session is over. Reaping now takes its descendants with it
    // and closes the pipes, which is what lets the output pumps below be joined at all.
    if let Some(w) = teardown_warning(reap_tree(&job)) {
        tracing::error!("{w}");
    }
    let code = *wait_result.as_ref().unwrap_or(&1);
    let _ = t_out.join();
    let _ = t_err.join();
    {
        let mut g = tx_arc.lock().unwrap();
        // FIN the write half only: the stdin pump keeps reading until the client closes, so for a
        // conforming client the socket never closes with unread input, which would reset it and
        // lose the EXIT frame.
        send_exit(&mut *g, code);
    }
    if let Some(hangup) = hangup {
        hangup.finish();
    }
    let _ = t_in.join();
    wait_result?;
    Ok(())
}

/// The hangup watcher's thread and the means to end it.
#[cfg(windows)]
struct HangupGuard {
    waker: Waker,
    thread: std::thread::JoinHandle<()>,
}

/// Start the third detector, for the one case the other two cannot see: a command that is silent
/// (no output pump ever fails a write) while the input pump is parked in the bounded queue
/// (nothing reads the socket). It watches the socket without reading it and reaps on a hangup.
///
/// `None` if the watcher cannot be created. A failure here must not cost the user a session; it
/// only loses the hangup protection.
#[cfg(windows)]
fn start_hangup_watch(tx: &ConnTx, job: &Arc<cosca::Job>, make_watcher: WatchFactory) -> Option<HangupGuard> {
    let (hangup, waker) = match make_watcher(tx) {
        Ok(pair) => pair,
        Err(e) => {
            tracing::warn!("could not create the hangup watcher; a silent command will outlive its client: {e}");
            return None;
        }
    };
    let job = Arc::clone(job);
    let thread = std::thread::spawn(move || {
        // The wait also ends after a normal teardown.
        end_of_watch(hangup.wait(), || {
            if let Some(w) = teardown_warning(reap_tree(&job)) {
                tracing::error!("{w}");
            }
        });
    });
    Some(HangupGuard { waker, thread })
}

/// What the end of a hangup watcher's wait means. `Ok` is a hangup or a teardown wake, so the
/// command is reaped; `Err` is the poll failing, which says nothing about the peer.
#[cfg(windows)]
fn end_of_watch(waited: std::io::Result<()>, reap: impl FnOnce()) {
    match waited {
        Ok(()) => reap(),
        Err(e) => tracing::warn!("the hangup watcher failed; a silent command will outlive its client: {e}"),
    }
}

#[cfg(windows)]
impl HangupGuard {
    /// End the watch once the session has been shut down.
    fn finish(self) {
        let Self { waker, thread } = self;
        // Wake explicitly: the shutdown alone does not wake the watcher's poll (see hangup).
        match waker.wake() {
            Ok(()) => {
                let _ = thread.join();
            }
            // Dropping the waker closes the wake channel, which normally ends the watcher. If the
            // channel itself failed it may not, and a join could block until the peer's FIN. The
            // thread holds only a socket duplicate and the job, so detaching it is safe.
            Err(e) => tracing::error!("could not wake the hangup watcher; leaving it to end on its own: {e}"),
        }
    }
}

/// Pump one child output stream (stdout/stderr) into `DATA(stream)` frames on the shared
/// connection. On EOF the child is exiting; on a write failure the SSH side is gone, so
/// kill the child to unblock the waiter.
#[cfg(windows)]
fn spawn_stream_pump(
    raw: isize,
    stream: Stream,
    tx: Arc<Mutex<ConnTx>>,
    job: std::sync::Arc<cosca::Job>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut buf = [0u8; 32 * 1024];
        let mut delivering = true;
        loop {
            let n = conpty::read_handle(raw, &mut buf);
            if n == 0 {
                break; // child's stream closed (exiting)
            }
            if !delivering {
                continue; // draining so the pipe cannot fill and stall the writer
            }
            let ok = {
                let mut g = tx.lock().unwrap();
                write_data(&mut *g, stream, &buf[..n]).is_ok()
            };
            if !ok {
                // The socket is gone. This is an independent detector, not a redundant
                // one: the input pump's queue is bounded, so a command that ignores its stdin
                // can still park that pump in a send and blind it to the socket.
                reap_tree(&job);
                delivering = false;
            }
        }
    })
}

/// Routes decoded input frames into the EXEC child's stdin. Owns the stdin-write handle so
/// it can close it on the stdin-EOF marker (below) or when the pump thread ends.
#[cfg(windows)]
struct ExecInputSink {
    writer: HandleWriter,
}

#[cfg(windows)]
impl FrameSink for ExecInputSink {
    fn on_data(&mut self, _stream: Stream, bytes: &[u8]) -> anyhow::Result<()> {
        if bytes.is_empty() {
            // The shim's stdin-EOF marker: close the child's stdin so a reader like
            // sort/findstr finishes, WITHOUT tearing down the connection — stdout, stderr and
            // EXIT still flow. A full socket close is the separate disconnect signal.
            self.writer.close();
            Ok(())
        } else {
            self.writer.write(bytes)
        }
    }

    // on_resize: default no-op (EXEC has no pseudoconsole).
}

/// Writes to a blocking handle from a thread of its own.
///
/// The frame reader must never park in a sink. `pump_decode` dispatches inline, and a pipe
/// write blocks as soon as the pipe fills and the child stops reading it — so a reader parked
/// there has stopped watching the socket, and a disconnect becomes invisible. If the command
/// also produces no output, nothing is left that can notice, and the session hangs for the
/// lifetime of the agent. Moving the write off this thread is what sshd gets from a select
/// loop over non-blocking descriptors.
///
/// The queue is bounded. Unbounded buffering makes an ordinary `cat big-file | ssh host cmd`
/// into unbounded growth in a resident agent that is shared with the user's other sessions, so
/// the cap is what keeps one session from taking down the rest. Once it is full the reader
/// does park in the send — the socket then applies the same backpressure sshd gets from its
/// channel window — and the output pumps and the hangup watcher are what still see a disconnect.
#[cfg(windows)]
struct HandleWriter {
    tx: Option<std::sync::mpsc::SyncSender<Option<Vec<u8>>>>,
    thread: Option<std::thread::JoinHandle<()>>,
    parked: ParkSignal,
}

/// Raised when a [`HandleWriter`] finds its queue full, i.e. when its caller is about to park in
/// the send. Lets a test wait for that state instead of guessing when it arrives.
#[cfg(windows)]
#[derive(Clone, Default)]
pub struct ParkSignal(Arc<(Mutex<bool>, Condvar)>);

#[cfg(windows)]
impl ParkSignal {
    fn raise(&self) {
        let (raised, condvar) = &*self.0;
        *raised.lock().unwrap() = true;
        condvar.notify_all();
    }

    /// Block until raised.
    pub fn wait(&self) {
        let (raised, condvar) = &*self.0;
        let mut guard = raised.lock().unwrap();
        while !*guard {
            guard = condvar.wait(guard).unwrap();
        }
    }
}

#[cfg(windows)]
impl HandleWriter {
    /// `owned` is the handle to close on the stdin-EOF marker; the PTY path passes `None`
    /// because the pseudoconsole's input handle belongs to the session.
    fn spawn(raw: isize, owned: Option<OwnedHandle>, parked: ParkSignal) -> Self {
        // Frames are at most `protocol::MAX_FRAME`, but the shim sends 32 KiB chunks, so
        // this is well under a megabyte in practice.
        let (tx, rx) = std::sync::mpsc::sync_channel::<Option<Vec<u8>>>(16);
        let thread = std::thread::spawn(move || {
            let _owned = owned; // dropped on the way out, closing the child's stdin
            for msg in rx {
                match msg {
                    Some(bytes) if conpty::write_all_handle(raw, &bytes) => {}
                    _ => break, // the write failed, or the peer signalled stdin-EOF
                }
            }
        });
        Self {
            tx: Some(tx),
            thread: Some(thread),
            parked,
        }
    }

    /// Queue bytes. Fails only once the writer thread has stopped, which is a genuine
    /// [`crate::relay::PumpError::Sink`]: local, and no evidence about the peer.
    fn write(&self, bytes: &[u8]) -> anyhow::Result<()> {
        let Some(tx) = &self.tx else {
            return Ok(()); // stdin already closed by the marker; further input is discarded
        };
        let stopped = || anyhow::anyhow!("the handle writer stopped");
        match tx.try_send(Some(bytes.to_vec())) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(msg)) => {
                self.parked.raise();
                tx.send(msg).map_err(|_| stopped())
            }
            Err(TrySendError::Disconnected(_)) => Err(stopped()),
        }
    }

    /// Close the underlying handle without ending the session.
    fn close(&mut self) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(None);
        }
    }
}

#[cfg(windows)]
impl Drop for HandleWriter {
    fn drop(&mut self) {
        self.tx = None; // end the channel so the thread finishes
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// The warning teardown owes an operator when a failed reap means the joins can block.
///
/// Pure so the decision is testable; the caller does the logging. Proceeding with the join is
/// deliberate — detaching would let those threads read handles the session is about to close —
/// but it must not be silent, or the agent looks wedged for no stated reason.
#[cfg(windows)]
fn teardown_warning(reaped: bool) -> Option<&'static str> {
    (!reaped).then_some(
        "the process tree survived teardown; joining the output pumps will block until whatever still holds the session's pipes exits",
    )
}

/// Reap the child and everything it spawned. Idempotent.
///
/// This is what Windows OpenSSH does, measured rather than assumed: it ends the session when
/// the direct child exits, does not wait for a descendant holding the pipe, and terminates the
/// descendant tree — including one whose stdout was redirected to a file and never touched the
/// session's pipe. There is no `nohup` equivalent on that platform, so preserving descendants
/// would be a divergence from the shell this replaces, not parity with it. (Unix OpenSSH does
/// the opposite: it waits for pipe EOF, which is why `nohup cmd >/dev/null 2>&1 &` exists.)
///
/// Reaping is also what unblocks teardown: killing the tree closes the pipes, so an output pump
/// parked in `ReadFile` on a handle a descendant was holding returns instead of hanging the
/// handler thread forever in a resident agent.
#[cfg(windows)]
fn reap_tree(job: &cosca::Job) -> bool {
    match job.kill_tree() {
        Ok(()) => true,
        Err(e) => {
            tracing::warn!("tearing down the process tree failed: {e}");
            false
        }
    }
}

#[cfg(all(windows, test))]
#[path = "agent_tests.rs"]
mod agent_tests;
