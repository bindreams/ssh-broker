//! agent: resident in a user's interactive session (started by the logon task, once per
//! logon). Per AF_UNIX connection it hosts the shell — in a ConPTY for interactive (PTY)
//! sessions, or with redirected pipes for EXEC (`ssh host "cmd"`) — inheriting the session's
//! token (working DPAPI/profile + no RedirectionGuard) and relays it to the SSH-side shim.
//!
//! The socket is inside the user's own profile (see `socket_loc`), so an agent serves exactly
//! one account: the one whose token it runs under.
//!
//! The agent frees the console the logon task gives it, so it shows no window; what that asks of
//! every child it starts is in `console`.

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

/// End the process because the agent failed with `err`, as `main` does when [`run`] returns it: report it where
/// an operator's console or redirect may show it (after the console is freed it is dropped, and the exit code is
/// the record) and exit with [`exit_code_of`]. A thread other than the one that ran the agent ends it through here
/// when it meets a failure that no part of the agent can serve through.
pub fn end_on_error(err: &anyhow::Error) -> ! {
    eprintln!("ssh-broker agent: {err:#}");
    end_process(exit_code_of(err))
}

mod ending;
pub use ending::{end_process, hold_until_end, keep_log};
#[cfg(windows)]
mod connections;
#[cfg(windows)]
mod console;
#[cfg(windows)]
mod elevation;
#[cfg(windows)]
mod launch;
#[cfg(windows)]
mod link;
#[cfg(windows)]
mod logout;
#[cfg(windows)]
mod requests;
#[cfg(windows)]
mod session;
#[cfg(all(windows, test))]
mod test_wire;
#[cfg(windows)]
mod verb;

#[cfg(windows)]
use crate::afunix::{AcceptError, Conn, ConnRx, ConnTx, Listener};
#[cfg(windows)]
use crate::agent_background::{Refusal, check_start, mark_listening};
#[cfg(windows)]
use crate::agent_lock::{SessionSlot, UserLock};
#[cfg(windows)]
use crate::conpty::{self, PtySession};
#[cfg(windows)]
use crate::hangup::{HangupWatcher, Waker};
#[cfg(windows)]
use crate::offer::text;
#[cfg(windows)]
use crate::pipes::ExecChild;
#[cfg(windows)]
use crate::protocol::{
    ElevationPolicy, ExitCode, Frame, FrameKind, FrameReader, Handshake, Mode, Resize, SESSION_VARIABLE, Stream,
    read_one_frame, write_frame,
};
#[cfg(windows)]
use crate::relay::{FrameSink, pump_until_peer_gone, write_data, write_serving};
#[cfg(windows)]
use crate::route::{AgentArgs, BackgroundArgs};
#[cfg(windows)]
use crate::shell::StartError;
#[cfg(windows)]
use crate::socket_loc::{Integrity, REQUEST_SOCKET_FILE_NAME, SOCKET_FILE_NAME, SocketLocation, StepDown};
#[cfg(windows)]
use crate::userdir::SocketDir;
#[cfg(windows)]
use crate::winutil::{OwnedHandle, UnelevatedToken};
#[cfg(all(windows, test))]
use connections::HeldListener;
#[cfg(windows)]
use connections::{Connections, Drained, Live, WakeConnect};
#[cfg(windows)]
use elevation::{HostedSession, Starts};
#[cfg(windows)]
use link::{Carrier, InputTarget, Link};
#[cfg(windows)]
use logout::{Control, Reservation};
#[cfg(windows)]
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::sync::mpsc::TrySendError;
#[cfg(windows)]
use std::sync::{Arc, Condvar, Mutex, PoisonError};

/// Everything between "the task started us" and "serve": check where we are, make the user's
/// private folder, and become the one agent that serves this user.
#[cfg(windows)]
fn start(args: AgentArgs) -> anyhow::Result<()> {
    // First, to keep the console window open as briefly as possible. The log is not open yet, so the
    // outcome is reported once serving begins.
    let console = console::detach_if_alone();
    let current_sid = crate::acl::Sid::current_user()?.to_sddl()?;
    let background = args.background.is_some();
    start_with(
        args.background.as_ref(),
        crate::provision::probe::current_session_id(),
        &current_sid,
        crate::account::elevation,
        &mut std::io::stderr(),
        reset_inherited_start_state,
        crate::userdir::current_socket_location,
        |logs| crate::filelog::init_in(logs, "agent.log"),
        |location, session| {
            match console {
                Ok(outcome) => {
                    tracing::info!("console: {outcome:?}");
                    if let console::DetachOutcome::Detached {
                        std_handles_error: Some(e),
                    } = outcome
                    {
                        tracing::warn!(
                            "could not set the standard handles to null: {}",
                            windows::core::Error::from(e)
                        );
                    }
                }
                Err(e) => tracing::warn!("could not detach from the console: {e}"),
            }
            serve(location, session, background)
        },
    )
}

/// Clear the "ignore Ctrl+C" setting that the secondary-logon call of the prompt path sets on its child;
/// every shell and command in every session would inherit it. The same on every start route. Best
/// effort: a failure is reported by [`start_with`].
#[cfg(windows)]
fn reset_inherited_start_state() -> windows::core::Result<()> {
    use windows::Win32::System::Console::SetConsoleCtrlHandler;
    // SAFETY: no pointers; this process's own setting.
    unsafe { SetConsoleCtrlHandler(None, false) }
}

/// [`start`] with its inputs as parameters, so a test can pick the session and see what runs.
///
/// `background` is `Some` for `agent --background`; `elevation` reads the agent's own token's. The
/// refusals before the log opens leave their exit code as the only record (see [`Refusal`]). `reset`
/// runs first, then `elevation`, before any check; a failure of `reset` goes to `stderr` at once, and to
/// the log once it opens.
#[cfg(windows)]
#[allow(clippy::too_many_arguments)] // every input is a seam a test fills
fn start_with(
    background: Option<&BackgroundArgs>,
    session: u32,
    current_sid: &str,
    elevation: impl FnOnce() -> anyhow::Result<crate::account::Elevation>,
    stderr: &mut dyn std::io::Write,
    reset: impl FnOnce() -> windows::core::Result<()>,
    locate: impl FnOnce() -> anyhow::Result<SocketLocation>,
    init_log: impl FnOnce(&crate::acl::DirHandle) -> anyhow::Result<tracing_appender::non_blocking::WorkerGuard>,
    serve: impl FnOnce(&Arc<SocketDir>, u32) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let reset_failure = reset()
        .err()
        .map(|e| format!("could not clear the inherited ignore of Ctrl+C: {e}"));
    if let Some(message) = &reset_failure {
        let _ = writeln!(stderr, "ssh-broker agent: {message}");
    }
    let refused = |refusal: Refusal, cause: anyhow::Error| anyhow::Error::new(refusal).context(format!("{cause:#}"));
    let elevation = elevation().map_err(|e| refused(Refusal::ElevationUnreadable, e))?;
    check_start(background, session, current_sid, elevation)?;
    let location = locate().map_err(|e| refused(Refusal::NoSocketLocation, e))?;
    let user = crate::acl::Sid::current_user()?;
    // Held to the end of the process: the folders it keeps cannot be renamed or removed meanwhile, so
    // the paths the agent binds and is woken at name them. Shared with the waker, which connects
    // through it.
    let folder = Arc::new(
        crate::userdir::open_socket_dir(&location, &user).map_err(|e| refused(Refusal::SocketFolderRefused, e))?,
    );
    // Held to the end of the process and flushed by `end_process`, from whichever thread ends it:
    // dropping the guard stops the writer and later lines are lost. Until the log opens an error goes
    // to stderr, which a logon task discards; a hand-run agent shows it.
    let log = match &folder.logs {
        Ok(logs) => init_log(logs),
        Err(e) => Err(anyhow::anyhow!("{e:#}")),
    };
    if let Some(log) = keep_log_or_report(log, stderr) {
        keep_log(log);
        if let Some(message) = &reset_failure {
            tracing::warn!("{message}");
        }
    }
    let result = serve(&folder, session);
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
fn serve(folder: &Arc<SocketDir>, session: u32, background: bool) -> anyhow::Result<()> {
    serve_in(folder, session, |folder| run_on(folder, background))
}

/// [`serve`] with the serving as a parameter, so a test can see that what the agent holds goes to
/// [`hold_until_end`].
#[cfg(windows)]
fn serve_in(
    folder: &Arc<SocketDir>,
    session: u32,
    run: impl FnOnce(&Arc<SocketDir>) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    serve_with(
        folder.location(),
        session,
        |path| {
            // One serving agent per user. A second session of the same user waits instead of
            // leaving: the serving agent dies with its session, and this user may still be logged
            // on here.
            UserLock::acquire(path, || {
                tracing::info!("waiting for the agent of another session of this user to end");
            })
        },
        |_| run(folder),
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
    // One agent per session: `apply` starts one per logged-on session every time it runs, and the
    // logon task starts one per logon. This comes first, because the user lock may be held for as
    // long as another session lives.
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
///
/// An agent at High also keeps `request.sock` in the plain folder, which the processes of its account below High
/// can reach (see [`requests`]). Without it the agent serves its sessions all the same, and `logout` from an
/// unelevated process reports which case it is (see [`crate::logout`]).
#[cfg(windows)]
fn run_on(folder: &Arc<SocketDir>, background: bool) -> anyhow::Result<()> {
    let connections = Connections::new();
    let integrity = folder.location().integrity();
    // Held to the end of the function so the plain folder cannot be renamed or removed.
    let plain = open_request_folder(folder.location(), |location| {
        crate::userdir::open_socket_dir(location, &crate::acl::Sid::current_user()?)
    });
    let control = Arc::new(Control::new(background, Arc::clone(&connections)));
    let agent_folder = Arc::clone(folder);
    run_on_with(
        folder.location(),
        |path| Listener::bind(path, integrity),
        || plain.as_ref().and_then(bind_requests),
        mark_listening,
        |(listener, connect)| serve_requests(listener, connect, &connections, &control),
        |listener| {
            serve_until_drained(
                listener,
                Arc::new(move || agent_folder.connect().map(drop)),
                &connections,
                &control,
            )
        },
    )
    .or_else(|end| run_ended(end, &connections))
}

/// How [`run_on`] ends, given `end`, how the loop of `agent.sock` ended: a loop that stopped because the end was
/// decided ends as that end was settled ([`settled_end`]); any other stop is its own failure.
#[cfg(windows)]
fn run_ended(end: anyhow::Error, connections: &Connections) -> anyhow::Result<()> {
    match end.downcast_ref::<Stopped>() {
        Some(Stopped) => settled_end(connections),
        None => Err(end),
    }
}

/// How an end that is decided and settled ([`Connections::settle`]) goes, from the tally's record and nowhere else:
/// a clean end, unless what decided it was a shortage that no connection was live to cure
/// ([`Connections::fatal_cause`]), on whichever loop: then it is that failure. Every thread that ends the agent with
/// an end that was decided (the main thread through [`run_ended`], the request socket's loop, a `logout`) takes its end
/// from here, so the process has the same exit code whichever of them ends it first. The one end that was not decided
/// is a loop of `agent.sock` that failed on its own ([`run_ended`]): that is the loop's failure, whatever the record.
#[cfg(windows)]
fn settled_end(connections: &Connections) -> anyhow::Result<()> {
    match connections.fatal_cause() {
        None => Ok(()),
        Some(cause) => Err(anyhow::Error::msg(cause).context(NothingLive)),
    }
}

/// End the process as `outcome` ([`settled_end`]) says: a clean end is logged, a failed one is logged and then
/// reported ([`end_on_error`]). A background agent has no stderr, so the log is where the cause is kept; the main
/// path logs it as well when it is the thread that ends the process, so it can be said twice.
#[cfg(windows)]
fn finish_settled(outcome: anyhow::Result<()>) -> ! {
    match outcome {
        Ok(()) => {
            tracing::info!("the background session has ended");
            end_process(0)
        }
        Err(e) => {
            tracing::error!("the agent stopped: {e:#}");
            end_on_error(&e)
        }
    }
}

/// The plain folder in which an agent that holds `held` keeps its request socket: only an agent at High has one.
/// It is the plain folder of the profile `held` is in, so the two cannot name different profiles. A folder that
/// cannot be opened is logged, and the agent serves without it.
#[cfg(windows)]
fn open_request_folder(
    held: &SocketLocation,
    open: impl FnOnce(&SocketLocation) -> anyhow::Result<SocketDir>,
) -> Option<Arc<SocketDir>> {
    if held.integrity() != Integrity::High {
        return None;
    }
    let plain = crate::socket_loc::for_profile(held.profile_dir(), Integrity::Medium).map_err(anyhow::Error::from);
    match plain.and_then(|location| open(&location)) {
        Ok(folder) => Some(Arc::new(folder)),
        Err(e) => {
            tracing::warn!("the agent serves without a request socket: the plain folder is unusable: {e:#}");
            None
        }
    }
}

/// Bind `request.sock` in the plain folder `plain`, with the connect that wakes its loop. A failure is logged,
/// and the agent serves without it.
#[cfg(windows)]
fn bind_requests(plain: &Arc<SocketDir>) -> Option<(Listener, WakeConnect)> {
    let path = plain.location().request_path();
    match Listener::bind(&path, plain.location().integrity()) {
        Ok(listener) => {
            let plain = Arc::clone(plain);
            Some((listener, Arc::new(move || plain.connect_request().map(drop))))
        }
        Err(e) => {
            tracing::warn!(
                "the agent serves without a request socket: it could not bind {}: {e:#}",
                path.display()
            );
            None
        }
    }
}

/// Serve `listener` (`request.sock`) on a thread of its own, beside the loop of `agent.sock` and counted in the
/// same tally. `connect` wakes its loop. If no thread can be started the agent serves without it, and says so.
#[cfg(windows)]
fn serve_requests(listener: Listener, connect: WakeConnect, connections: &Arc<Connections>, control: &Arc<Control>) {
    let (connections, control) = (Arc::clone(connections), Arc::clone(control));
    let spawned = std::thread::Builder::new()
        .name("request-socket".into())
        .spawn(move || {
            let end = serve_listener(REQUEST_SOCKET_FILE_NAME, listener, connect, &connections, |listener| {
                accept_loop(
                    listener,
                    &connections,
                    &control,
                    || connections.is_closing(),
                    requests::serve,
                )
            });
            request_loop_ended(&end, &connections, |outcome| finish_settled(outcome));
        });
    if let Err(e) = spawned {
        tracing::warn!("the agent serves without a request socket: no thread for it: {e}");
    }
}

/// How the request socket's loop ended (`end`). Any stop leaves the sessions as they are, except a shortage with no
/// connection live ([`NothingLive`]): the loop has decided the end, so settle it ([`Connections::settle`]) and end
/// the process via `end_agent`, with how that end went ([`settled_end`]). The main thread, woken by that settle, and
/// a `logout` served meanwhile take their ends from the same record, so the exit code is the same whichever thread
/// ends the process first. Serving on without the request socket would leave unelevated `logout`s nothing to ask.
/// This logs the cause when the loop ends; the thread that ends the process reports it as well, so it can be said
/// twice.
#[cfg(windows)]
fn request_loop_ended(end: &anyhow::Error, connections: &Arc<Connections>, end_agent: impl FnOnce(anyhow::Result<()>)) {
    if end.downcast_ref::<Stopped>().is_some() {
        tracing::debug!("the request socket is closed: the agent is ending");
    } else if end.downcast_ref::<NothingLive>().is_some() {
        debug_assert!(
            connections.is_closing(),
            "the shortage with nothing live is returned only once the end is decided"
        );
        tracing::error!("the request socket met a shortage with no connection live; ending the agent: {end:#}");
        connections.settle();
        end_agent(settled_end(connections));
    } else {
        tracing::error!("the request socket stopped; the agent serves its sessions without it: {end:#}");
    }
}

/// Serve `listener` of `socket` to its end: register it with the tally together with `wake`, run `accept` over
/// it, count it closed, and only then close it. The registration comes before the loop's first look at whether
/// the end is decided (see [`Connections::listener_opened`]). Returns the error that stopped the loop.
///
/// The loop has returned when it is counted closed, so a wake that is still on its way is for a loop the tally no
/// longer holds, and its failure, if the listener has closed by then, is not reported.
#[cfg(windows)]
fn serve_listener<L>(
    socket: &'static str,
    listener: L,
    wake: WakeConnect,
    connections: &Arc<Connections>,
    accept: impl FnOnce(&L) -> anyhow::Error,
) -> anyhow::Error {
    let open = connections.listener_opened(socket, wake);
    let end = accept(&listener);
    drop(open);
    drop(listener);
    end
}

/// Serve `listener` until the agent has decided to end, then return the error that stopped the loop.
///
/// The one loop keeps accepting through the drain: a login that comes while the agent drains gets the
/// ending refusal at once, where a closed socket would have left its shim waiting for an agent it
/// takes to be starting, for as long as the drain lasts. It stops when the drain has finished
/// ([`Connections::settle`]), after counting the connection it was accepting, and the listener is
/// closed here, before the drain judges again. `wake` is the connect that makes the loop return from `accept`.
#[cfg(windows)]
fn serve_until_drained(
    listener: Listener,
    wake: WakeConnect,
    connections: &Arc<Connections>,
    control: &Arc<Control>,
) -> anyhow::Error {
    serve_until_drained_in(
        listener,
        wake,
        connections,
        || control.is_ending(),
        |listener| {
            accept_loop(
                listener,
                connections,
                control,
                || connections.is_closing(),
                |conn, control| serve_connection(conn, Hooks::production(), control),
            )
        },
    )
}

/// [`serve_until_drained`] with the accepting as a parameter, so a test can see that the listener is
/// closed before the end is judged. `ending` says whether the agent has begun to end, which makes a
/// failed loop wait for the drain as a stopped one does.
#[cfg(windows)]
fn serve_until_drained_in<L>(
    listener: L,
    wake: WakeConnect,
    connections: &Arc<Connections>,
    ending: impl FnOnce() -> bool,
    accept: impl FnOnce(&L) -> anyhow::Error,
) -> anyhow::Error {
    let end = serve_listener(SOCKET_FILE_NAME, listener, wake, connections, accept);
    finish_stopped(end, connections, ending())
}

/// [`serve_connections_with`] over `listener`, handing each connection to a thread of its own.
#[cfg(windows)]
fn accept_loop(
    listener: &Listener,
    connections: &Arc<Connections>,
    control: &Arc<Control>,
    stopping: impl Fn() -> bool,
    handler: impl Fn(socket2::Socket, &Control) -> anyhow::Result<()> + Send + Sync + 'static,
) -> anyhow::Error {
    accept_loop_with(|| listener.accept(), connections, control, stopping, handler)
}

/// [`accept_loop`] over an `accept` the caller supplies, so a test can stop the loop between a
/// connection's `accept` and its count. `handler` serves each connection on its thread: a session's
/// ([`serve_connection`]) on `agent.sock`, a request's ([`requests::serve`]) on `request.sock`.
#[cfg(windows)]
fn accept_loop_with(
    mut accept: impl FnMut() -> Result<socket2::Socket, AcceptError>,
    connections: &Arc<Connections>,
    control: &Arc<Control>,
    stopping: impl Fn() -> bool,
    handler: impl Fn(socket2::Socket, &Control) -> anyhow::Result<()> + Send + Sync + 'static,
) -> anyhow::Error {
    let handler = Arc::new(handler);
    serve_connections_with(
        Arc::clone(connections),
        move || match accept() {
            Ok(conn) => Ok(Arrived::Usable(conn)),
            Err(AcceptError::Refused { socket, cause }) => Ok(Arrived::Refused(socket, cause)),
            Err(e) => Err(e),
        },
        |arrived, live| {
            let control = Arc::clone(control);
            let handler = Arc::clone(&handler);
            hand_to_thread(
                arrived,
                live,
                |work| std::thread::Builder::new().spawn(work).map(drop),
                move |arrived| match arrived {
                    Arrived::Usable(conn) => {
                        if let Err(e) = handler(conn, &control) {
                            tracing::warn!("connection handler error: {e:?}");
                        }
                    }
                    Arrived::Refused(sock, cause) => match logout::admit(sock) {
                        Ok(conn) => {
                            let failure =
                                logout::fail_socket(conn, &control, "the agent could not use the connection", cause);
                            tracing::warn!("refused a connection: {failure:#}");
                        }
                        Err(e) => tracing::warn!("refused a connection that could not be answered: {e:#}; {cause:#}"),
                    },
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

/// The accept loop stopped because the end is decided (see [`serve_connections_with`]).
#[cfg(windows)]
#[derive(Debug, thiserror::Error)]
#[error("the agent stopped accepting connections because its session is ending")]
struct Stopped;

/// The context of a shortage that met no live connection: the loop has already decided the end (see
/// [`serve_connections_with`]); the caller settles it and ends the process.
#[cfg(windows)]
#[derive(Debug, thiserror::Error)]
#[error("no connection of this agent is live to free a resource")]
struct NothingLive;

/// After the loop returned `end`: if it stopped on purpose, or the agent is ending and the loop failed,
/// wait until the end is decided (see [`Connections::settle`]) and return `end` either way. The agent's
/// process ends when this returns. The tally wakes whichever other loop is still in `accept`.
#[cfg(windows)]
fn finish_stopped(end: anyhow::Error, connections: &Arc<Connections>, ending: bool) -> anyhow::Error {
    if ending || end.downcast_ref::<Stopped>().is_some() {
        connections.settle();
    }
    end
}

/// [`run_on`] with its steps as parameters, so a test can see their order: bind `agent.sock`, bind `request.sock`
/// (`bind_requests`, which says nothing when the agent keeps none), then mark, then serve the request socket,
/// then accept. The marker comes after both binds return, which include `listen`, so a shim that wakes on it
/// finds both sockets and can connect.
#[cfg(windows)]
fn run_on_with<L, Q>(
    location: &SocketLocation,
    bind: impl FnOnce(&Path) -> anyhow::Result<L>,
    bind_requests: impl FnOnce() -> Option<Q>,
    mark: impl FnOnce(&SocketLocation) -> std::io::Result<()>,
    serve_requests: impl FnOnce(Q),
    accept_loop: impl FnOnce(L) -> anyhow::Error,
) -> anyhow::Result<()> {
    let listener = bind(location.path())?;
    let requests = bind_requests();
    mark(location).map_err(|e| anyhow::Error::new(e).context("write the serving marker"))?;
    if let Some(requests) = requests {
        serve_requests(requests);
    }
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
/// kept. With no live connection nothing can, and the shortage is fatal: the loop decides the end
/// (see [`serve_connections_with`]).
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
///
/// A shortage that meets no live connection decides the end here, in one step under the tally's lock
/// ([`Connections::decide_end_if_idle`]), while the loop still holds the connection it kept: that connection is
/// served once more, as when `stopping` says so, and the loop returns the shortage with [`NothingLive`] as its
/// context, and the tally keeps the cause for the main thread ([`run_ended`]). If a connection became live or ended
/// meanwhile (it may have freed what the loop lacks) the end stays undecided and the loop goes round again, with
/// the kept connection still held. Both loops of the agent get the rule from here.
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
            refuse_kept(kept.take(), &connections, &mut serve);
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
        if !connections.wait_for_an_end(ended_before, &mut blocking)
            && connections.decide_end_if_idle(ended_before, &shortage)
        {
            refuse_kept(kept.take(), &connections, &mut serve);
            return shortage.context(NothingLive);
        }
    }
}

/// Serve the connection `kept` for want of a thread once more, now that the end is decided (see
/// [`serve_connections_with`]): it is counted, so the drain waits for its refusal. With no thread for that either,
/// its client sees the agent end.
#[cfg(windows)]
fn refuse_kept<C>(
    kept: Option<C>,
    connections: &Arc<Connections>,
    serve: &mut impl FnMut(C, Live) -> Result<(), NotServed<C>>,
) {
    if let Some(conn) = kept
        && let Err((_, e)) = serve(conn, connections.begin())
    {
        tracing::warn!("no thread to refuse a connection with ({e}); closing it as the agent ends");
    }
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
    handle_connection_in(Conn::new(conn)?, hooks, &Control::standalone())
}

/// What a session runs with: the hooks a test can replace, the agent's shared control, the token its
/// shell runs with in place of the agent's, if the login did not ask for an elevated session and the agent is
/// elevated, the id its environment carries, and what its login asked of elevation (which `ssh-broker elevate` in it
/// is judged by).
#[cfg(windows)]
struct Env<'a> {
    hooks: Hooks,
    control: &'a Control,
    unelevated: Option<UnelevatedToken>,
    reservation: Reservation<'a>,
    policy: ElevationPolicy,
}

/// How a session obtains its [`HangupWatcher`], given a share of its connection; a parameter so a test can
/// force a failure.
#[cfg(windows)]
type WatchFactory = fn(Conn) -> std::io::Result<(HangupWatcher, Waker)>;

/// How a session starts its shell in a pseudoconsole (`command`, `cols`, `rows`, `cwd`, and the one
/// handle besides the pseudoconsole's that the shell inherits, if any, the token the shell runs
/// with in place of the agent's, if any, and the variables put over its environment); a parameter so a
/// test can force a failure without starting a process.
#[cfg(windows)]
type PtyStarter = fn(
    &str,
    u16,
    u16,
    Option<&Path>,
    Option<&OwnedHandle>,
    Option<&UnelevatedToken>,
    &[(&str, &str)],
) -> Result<PtySession, StartError>;

/// How a session starts its command on pipes (`command`, `cwd`, the token it runs with in place of
/// the agent's, if any, and the variables put over its environment); a parameter like [`PtyStarter`].
#[cfg(windows)]
type ExecStarter = fn(&str, Option<&Path>, Option<&UnelevatedToken>, &[(&str, &str)]) -> Result<ExecChild, StartError>;

/// How a session gets what its shell runs with, given what the login asked of elevation: the stepped-down token,
/// the agent's own, or a refusal (see [`crate::account::step_down`]); a parameter so a test can force a failure.
#[cfg(windows)]
type UnelevatedMaker = fn(Option<ElevationPolicy>) -> anyhow::Result<StepDown<UnelevatedToken>>;

/// What a test can replace or observe in a session; production uses [`Hooks::production`].
#[cfg(windows)]
struct Hooks {
    make_watcher: WatchFactory,
    make_unelevated: UnelevatedMaker,
    start_pty: PtyStarter,
    start_exec: ExecStarter,
    /// What the shell configuration is resolved against: the machine, in production.
    shell_host: Box<dyn crate::shell::Host + Send + Sync>,
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
    /// after a login that was not served has reported [`Observed::UnservedConsoleClosed`].
    ShellStarted { output: isize, process: isize },
    /// A login that was started and not served has closed its pseudoconsole after reading `bytes` of
    /// its output.
    UnservedConsoleClosed { bytes: usize },
}

#[cfg(windows)]
impl Hooks {
    fn production() -> Self {
        Self {
            make_watcher: HangupWatcher::new,
            make_unelevated: UnelevatedToken::for_policy,
            start_pty: PtySession::spawn,
            start_exec: ExecChild::spawn,
            shell_host: Box::new(crate::shell::WindowsHost),
            parked: ParkSignal::default(),
            after_spawn: Box::new(|| {}),
            observe: Box::new(|_| {}),
        }
    }
}

/// [`handle_connection_in`] for a thread of its own: if the thread panics, the connection is answered
/// with the failure reply before it closes (see [`logout::PanicReply`]).
#[cfg(windows)]
fn serve_connection(sock: socket2::Socket, hooks: Hooks, control: &Control) -> anyhow::Result<()> {
    let conn = logout::admit(sock)?;
    let _answer_a_panic = logout::PanicReply::new(conn.clone(), control);
    handle_connection_in(conn, hooks, control)
}

/// Serve one connection. The agent never closes a connection without a byte while it is alive: a
/// connection it cannot read or carry out is answered with a frame the shim prints (see
/// [`logout::fail_connection`]), and the error comes back for the log. A client that leaves before
/// it sends anything has nothing to be told, and is not an error.
///
/// The one exception is a socket that [`Conn::new`] cannot make non-blocking and non-inheritable: it is
/// closed unanswered, which the shim handles as a close without a byte.
#[cfg(windows)]
fn handle_connection_in(conn: Conn, hooks: Hooks, control: &Control) -> anyhow::Result<()> {
    let Some(Opened {
        mut rx,
        fr,
        mut tx,
        first: hs,
    }) = read_request(conn, control)?
    else {
        return Ok(());
    };
    if hs.mode == Mode::Logout {
        return logout::handle_logout(&mut rx, &mut tx, control, |outcome| finish_settled(outcome));
    }
    // Before a shell is started for nothing; the registration below is what decides.
    if control.is_ending() {
        return logout::refuse_while_ending(&mut rx, &mut tx, control);
    }
    // Decided before the shell's configuration is read: a handed-back login's shell is the shim's to plan
    // (see `crate::account::step_down`).
    let unelevated = match (hooks.make_unelevated)(hs.elevation) {
        Ok(StepDown::Token(token)) => Some(token),
        Ok(StepDown::Own) => None,
        // The agent hosts no session it could not step down: the shim runs it, in either mode.
        Ok(StepDown::Fallback(cause)) => {
            tracing::warn!("the agent could not prepare an unelevated session, so it hands the session back: {cause}");
            return logout::hand_back(&mut rx, &mut tx, control, &cause);
        }
        Ok(StepDown::Refused) => {
            return Err(logout::fail_connection(
                &mut rx,
                &mut tx,
                control,
                text::ALWAYS_BELOW_HIGH_WHAT,
                anyhow::anyhow!(text::ALWAYS_BELOW_HIGH_CAUSE),
                logout::FAILED_EXIT_CODE,
            ));
        }
        Err(cause) => {
            return Err(logout::fail_connection(
                &mut rx,
                &mut tx,
                control,
                text::unelevated_unavailable_what(hs.elevation),
                cause,
                logout::FAILED_EXIT_CODE,
            ));
        }
    };
    let launched = match launch::launch_line(&hs, &*hooks.shell_host) {
        Ok(launched) => launched,
        Err(launch::Refusal::BadRequest(cause)) => {
            return Err(logout::fail_connection(
                &mut rx,
                &mut tx,
                control,
                "the agent could not read the request",
                cause,
                logout::BAD_REQUEST_EXIT_CODE,
            ));
        }
        Err(launch::Refusal::Failed(cause)) => {
            return Err(logout::fail_connection(
                &mut rx,
                &mut tx,
                control,
                "the agent could not prepare the shell",
                cause,
                logout::FAILED_EXIT_CODE,
            ));
        }
    };
    // The session's id, before its program starts: its environment carries it. The agent that began to
    // end meanwhile refuses the login as it does at the top.
    let reservation = match control.reserve() {
        Ok(Some(reservation)) => reservation,
        Ok(None) => return logout::refuse_while_ending(&mut rx, &mut tx, control),
        Err(cause) => {
            return Err(logout::fail_connection(
                &mut rx,
                &mut tx,
                control,
                "the agent could not give the session an id",
                cause,
                logout::FAILED_EXIT_CODE,
            ));
        }
    };
    // The answer `Serving` is written by the handler, once the session's process has started.
    let cwd_buf = child_cwd(&hs.cwd, home_dir());
    let cwd = cwd_buf.as_deref();
    let env = Env {
        hooks,
        control,
        unelevated,
        reservation,
        policy: hs.elevation.unwrap_or(ElevationPolicy::DEFAULT),
    };
    match hs.mode {
        Mode::Pty => handle_pty(rx, fr, tx, &launched, (hs.cols, hs.rows), cwd, env),
        Mode::Exec => handle_exec(rx, fr, tx, &launched, cwd, env),
        Mode::Logout => unreachable!("answered above"),
    }
}

/// A connection split into halves, with what opens it (a [`Handshake`] on every socket; the request socket also
/// takes a request, see [`requests`]).
#[cfg(windows)]
struct Opened<T = Handshake> {
    rx: ConnRx,
    /// The reader that read the first frame, with anything it read past it.
    fr: FrameReader,
    tx: ConnTx,
    first: T,
}

/// Split a connection and read the handshake that opens it: the start of every connection, whichever socket it
/// came on. `None` if the client left before it sent a byte. An `Err` has been answered already (see
/// [`logout::fail_connection`]) and is for the log.
#[cfg(windows)]
fn read_request(conn: Conn, control: &Control) -> anyhow::Result<Option<Opened>> {
    read_opening(conn, control, decode_handshake)
}

/// The handshake `frame` is, if it is one.
#[cfg(windows)]
fn decode_handshake(frame: Frame) -> anyhow::Result<Handshake> {
    anyhow::ensure!(frame.kind == FrameKind::Handshake, "first frame was not a handshake");
    Handshake::decode(&frame.payload)
}

/// [`read_request`] for a socket whose first frame may be more than a handshake: `decode` reads it from the frame,
/// and its error is answered as an unreadable request is.
#[cfg(windows)]
fn read_opening<T>(
    conn: Conn,
    control: &Control,
    decode: impl FnOnce(Frame) -> anyhow::Result<T>,
) -> anyhow::Result<Option<Opened<T>>> {
    let (mut rx, mut tx) = conn.split();
    let mut fr = FrameReader::new();
    match read_first_frame(&mut rx, &mut fr).and_then(|frame| frame.map(decode).transpose()) {
        Ok(Some(first)) => Ok(Some(Opened { rx, fr, tx, first })),
        Ok(None) => Ok(None),
        Err(cause) => Err(logout::fail_connection(
            &mut rx,
            &mut tx,
            control,
            "the agent could not read the request",
            cause,
            logout::BAD_REQUEST_EXIT_CODE,
        )),
    }
}

/// Show the warning for a shell that could not be used: the first data of the session, on the
/// terminal for a PTY and on stderr for a command. `launch::start` has logged it.
#[cfg(windows)]
fn show_notice(tx: &mut ConnTx, mode: Mode, text: &str) {
    let (stream, bytes) = launch::notice_frame(mode, text);
    // A client that has gone is found by the relay, which owns that case.
    if let Err(e) = write_data(tx, stream, &bytes) {
        tracing::debug!("could not show the shell warning: {e:#}");
    }
}

/// Write the answer `Serving` (see [`FrameKind`]) once the session's process has started, before any of its
/// output. A write that fails is logged and returned, and the caller ends the session: a client that
/// was not answered forwards no input to it.
#[cfg(windows)]
fn answer_serving(tx: &mut ConnTx) -> anyhow::Result<()> {
    write_serving(tx).inspect_err(|e| {
        if crate::shim::peer_gone(e).is_some() {
            tracing::debug!("the client is gone; could not send the answer: {e:#}");
        } else {
            tracing::warn!("could not send the answer: {e:#}");
        }
    })
}

/// Show the warnings of a start, in order, as the first data of a session that was started or ahead of the
/// failure reply of one that was not.
#[cfg(windows)]
fn show_notices(tx: &mut ConnTx, mode: Mode, texts: &[String]) {
    for text in texts {
        show_notice(tx, mode, text);
    }
}

/// Warn that the session's shell ended with the loader's "DLL not found" status, as the last data of
/// the session: before the exit code, after everything the shell wrote. Nothing for any other code.
#[cfg(windows)]
fn show_exit_notice(link: &Link, mode: Mode, shell: Option<&crate::shell::ConfiguredShell>, code: i32) {
    if let Some(text) = shell.and_then(|shell| shell.exit_notice(code)) {
        tracing::warn!("{text}");
        let (stream, bytes) = launch::notice_frame(mode, &text);
        // A client that has gone is found by the relay, which owns that case.
        if let Err(e) = link.deliver(Carrier::Session, stream, &bytes) {
            tracing::debug!("could not show the shell warning: {e:#}");
        }
    }
}

/// The frame that opens a connection. `None` if the client closed the connection before it sent
/// a byte: the wake that ends the accept loop does, and a client that gave up does; neither is a fault.
#[cfg(windows)]
fn read_first_frame(rx: &mut impl std::io::Read, fr: &mut FrameReader) -> anyhow::Result<Option<Frame>> {
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
    Ok(Some(frame))
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

/// This program's path, looked up once for all the agent's sessions: the hidden `console-fallback`
/// verb is started from it. `None` (with one warning) when it cannot be found, and then the warning of
/// a terminal session goes out ahead of the shell.
#[cfg(windows)]
fn broker_exe() -> Option<&'static Path> {
    static EXE: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();
    EXE.get_or_init(|| {
        std::env::current_exe()
            .inspect_err(|e| {
                tracing::warn!("cannot find this program, so a shell warning goes out ahead of the terminal: {e}")
            })
            .ok()
    })
    .as_deref()
}

/// Interactive PTY relay: spawn the shell in a ConPTY and bridge it with three threads and
/// an ordered, race-free teardown (criterion 2).
#[cfg(windows)]
fn handle_pty(
    mut rx: ConnRx,
    mut fr: FrameReader,
    mut tx: ConnTx,
    launched: &launch::Launched<'_>,
    (cols, rows): (u16, u16),
    cwd: Option<&Path>,
    env: Env<'_>,
) -> anyhow::Result<()> {
    let Env {
        hooks,
        control,
        unelevated,
        reservation,
        policy,
    } = env;
    let id = reservation.id().to_string();
    let session_env = [(SESSION_VARIABLE, id.as_str())];
    // The warning for a shell that could not be used is printed by `console-fallback` inside the
    // pseudoconsole, which clears the screen after anything written ahead of it. Without this
    // program's path it goes out here, before the output threads exist: after `Serving`.
    let mut notices = Vec::new();
    let started = launch::start(
        &*hooks.shell_host,
        launched,
        broker_exe(),
        |spawn| match spawn {
            launch::Spawn::Line(line) => {
                (hooks.start_pty)(line, cols, rows, cwd, None, unelevated.as_ref(), &session_env)
            }
            launch::Spawn::Verb {
                exe,
                notice,
                line,
                login,
            } => verb::start(exe, notice, line, login, |verb_line, read| {
                (hooks.start_pty)(
                    verb_line,
                    cols,
                    rows,
                    cwd,
                    Some(read),
                    unelevated.as_ref(),
                    &session_env,
                )
            }),
        },
        |text| notices.push(text.to_owned()),
    );
    let (mut session, configured) = match started {
        Ok(started) => started,
        Err(cause) => {
            show_notices(&mut tx, Mode::Pty, &notices);
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
    let Some(registration) = register_session(reservation, &job) else {
        tracing::debug!("the agent is ending; the shell warnings of a refused login are not shown: {notices:?}");
        close_unserved_pty(session, &*hooks.observe);
        return logout::refuse_while_ending(&mut rx, &mut tx, control);
    };
    if answer_serving(&mut tx).is_err() {
        // The login was started and cannot be served: end it as a refused one is ended.
        if let Some(w) = teardown_warning(reap_tree(&job)) {
            tracing::error!("{w}");
        }
        close_unserved_pty(session, &*hooks.observe);
        return Ok(());
    }
    show_notices(&mut tx, Mode::Pty, &notices);
    // Before `tx` moves into the link.
    let watcher = prepare_hangup_watch(&tx, hooks.make_watcher);

    let out_raw = session.out_read_raw();
    let target = Arc::new(PtyTarget::new(&mut session, hooks.parked));
    let link = Link::new(tx, true, (cols, rows), Some(target.clone()));
    let starts = Starts {
        pty: hooks.start_pty,
        exec: hooks.start_exec,
    };
    registration.attach(Arc::new(HostedSession::new(policy, Arc::clone(&link), starts)));
    let hangup = start_hangup_watch(watcher, &job);

    // Output pump: ConPTY output -> DATA(Pty). It deliberately does NOT emit EXIT.
    // `read_handle` returns 0 for a read *error* as well as for EOF, so this thread cannot
    // tell "the shell finished" from "the pipe broke" — emitting the code from here raced the
    // waiter that produces it, and a failed session could report EXIT(0).
    let out_thread = {
        let job = Arc::clone(&job);
        spawn_stream_pump(out_raw, Stream::Pty, Arc::clone(&link), Carrier::Session, move || {
            reap_tree(&job);
        })
    };

    let in_thread = {
        let link = Arc::clone(&link);
        let job = Arc::clone(&job);
        std::thread::spawn(move || {
            let mut sink = LinkInputSink {
                link: Arc::clone(&link),
            };
            pump_until_peer_gone(&mut rx, &mut fr, &mut sink);
            if let Some(w) = teardown_warning(reap_tree(&job)) {
                tracing::error!("{w}");
            }
        })
    };

    // Do NOT `?` on the end: even when the wait fails the pseudoconsole is closed and the threads joined (see
    // `end_pty`) before this returns, or they would outlive `session` and touch closed handles.
    let ended = end_pty(session, &target, out_thread, || link.end_hosting());
    let code = *ended.as_ref().unwrap_or(&1);
    // The shell is gone and the output is drained, so the code is final and nothing else can still be writing
    // frames. The connection is the session's again by now, if `ssh-broker elevate --terminal` had it: the output
    // pump above could not end before, and `end_hosting` inside `end_pty` ended the command that held it, whoever
    // asked for it (see `elevation::run_hosted`).
    show_exit_notice(&link, Mode::Pty, configured.as_ref(), code);
    // FIN the write half only: the input pump keeps reading until the client closes, so for a
    // conforming client the socket never closes with unread input, which would reset it and
    // lose the EXIT frame.
    link.send_exit(code);
    link.end();
    if let Some(hangup) = hangup {
        hangup.finish();
    }
    let _ = in_thread.join();
    ended?;
    Ok(())
}

/// The end of a session in a pseudoconsole, `session`'s or an elevated command's: wait for its process, reap its
/// tree, run `after_reap`, close the pseudoconsole (which flushes conhost and ends the output) and join the writer of
/// `target`, join the output `pump`, and close what `session` holds. Returns the process's exit code, or why it
/// could not be read: the teardown is done either way.
///
/// `after_reap` is whatever else must end with this process, and it runs before the close, not only before the join:
/// the close can wait on a pump that is parked and not reading, and the pump of a session's shell waits for the
/// elevated command that holds its screen (`Link::end_hosting`).
#[cfg(windows)]
fn end_pty(
    session: PtySession,
    target: &PtyTarget,
    pump: std::thread::JoinHandle<()>,
    after_reap: impl FnOnce(),
) -> anyhow::Result<i32> {
    let waited = session.wait();
    if let Some(w) = teardown_warning(reap_tree(&session.job())) {
        tracing::error!("{w}");
    }
    after_reap();
    target.close();
    let _ = pump.join();
    // The writer is joined and the pump is, so nothing reads or writes the handles `session` closes.
    drop(session);
    Ok(waited?)
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

/// The write half a [`link::Link`] owns.
#[cfg(windows)]
impl HalfClose for Box<dyn HalfClose + Send> {
    fn shutdown_write(&self) -> anyhow::Result<()> {
        (**self).shutdown_write()
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

/// Close the pseudoconsole of a login whose shell has been ended before it was served, with its output
/// read as the regular teardown reads it: the shell has been running since `spawn`, and closing flushes
/// whatever it wrote into a pipe that nothing else reads.
#[cfg(windows)]
fn close_unserved_pty(mut session: PtySession, observe: &(dyn Fn(Observed) + Send + Sync)) {
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
        tracing::warn!("could not read the output of an unserved shell; its pseudoconsole stays open: {e}");
    }
    observe(Observed::UnservedConsoleClosed { bytes });
    drop(session); // the pipe ends go after the reader has finished with them
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
fn register_session<'a>(reservation: Reservation<'a>, job: &Arc<cosca::Job>) -> Option<logout::Registration<'a>> {
    let kill_job = Arc::clone(job);
    let registration = reservation.register(Arc::new(move || {
        reap_tree(&kill_job);
    }));
    if registration.is_none() {
        reap_tree(job);
    }
    registration
}

/// A pseudoconsole's input: the session's own, or an elevated command's (see `elevation`).
#[cfg(windows)]
struct PtyTarget {
    /// `None` once [`PtyTarget::close`] has joined the writer.
    writer: Mutex<Option<HandleWriter>>,
    /// The pseudoconsole, shared behind a mutex: a resize holds the lock across its OS call and teardown takes the
    /// handle (`None`) and closes it under the lock, so a resize can never touch a closed one.
    hpc: Mutex<Option<isize>>,
}

#[cfg(windows)]
impl PtyTarget {
    /// The target of `session`'s pseudoconsole: it takes the pseudoconsole and the write end of its input, which
    /// [`PtyTarget::close`] gives back to the system.
    fn new(session: &mut PtySession, parked: ParkSignal) -> Self {
        PtyTarget {
            writer: Mutex::new(Some(HandleWriter::spawn(session.in_write_raw(), None, parked))),
            hpc: Mutex::new(Some(session.take_hpc_raw())),
        }
    }

    /// Close the pseudoconsole, which flushes conhost and ends the output, then stop and join the writer thread. The
    /// writer may be parked writing to the pseudoconsole's input pipe, which the reap of the tree does NOT release
    /// (conhost holds the read end and is not a member of the job): the close does, so the join comes after it, and
    /// before the pipe's handles are closed with the session. Input after it is discarded. The writer holds a raw
    /// handle that its owner closes, so it must not outlive the owner, and a share of this target can: a request
    /// that is still being answered holds one.
    fn close(&self) {
        {
            // Under the lock, so that a concurrent resize cannot copy the handle out and then race this close.
            let mut hpc = self.hpc.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(raw) = hpc.take() {
                conpty::close_pty_raw(raw);
            }
        }
        let writer = self.writer.lock().unwrap_or_else(PoisonError::into_inner).take();
        drop(writer);
    }
}

#[cfg(windows)]
impl InputTarget for PtyTarget {
    fn input(&self, bytes: &[u8]) -> anyhow::Result<()> {
        // PTY input arrives pre-encoded (win32-input-mode); hand it straight to ConPTY#2.
        match &*self.writer.lock().unwrap_or_else(PoisonError::into_inner) {
            Some(writer) => writer.write(bytes),
            None => Ok(()),
        }
    }

    fn resize(&self, cols: u16, rows: u16) {
        // Hold the lock across the OS call (bound guard, not a temporary) so teardown
        // cannot close the HPCON mid-resize.
        let hpc = self.hpc.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(raw) = *hpc {
            let _ = conpty::resize_pty(raw, cols, rows);
        }
    }
}

/// Routes decoded input frames of a session with a terminal to whoever the link says gets them.
#[cfg(windows)]
struct LinkInputSink {
    link: Arc<Link>,
}

#[cfg(windows)]
impl FrameSink for LinkInputSink {
    fn on_data(&mut self, _stream: Stream, bytes: &[u8]) -> anyhow::Result<()> {
        self.link.route_input(bytes)
    }
    fn on_resize(&mut self, r: Resize) -> anyhow::Result<()> {
        self.link.resize(r);
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
    launched: &launch::Launched<'_>,
    cwd: Option<&Path>,
    env: Env<'_>,
) -> anyhow::Result<()> {
    let Env {
        hooks,
        control,
        unelevated,
        reservation,
        policy,
    } = env;
    let id = reservation.id().to_string();
    let session_env = [(SESSION_VARIABLE, id.as_str())];
    // The warning for a shell that could not be used goes out after `Serving`.
    let mut notices = Vec::new();
    let started = launch::start(
        &*hooks.shell_host,
        launched,
        None,
        |spawn| match spawn {
            launch::Spawn::Line(line) => (hooks.start_exec)(line, cwd, unelevated.as_ref(), &session_env),
            launch::Spawn::Verb { .. } => Err(StartError::Other(anyhow::anyhow!(
                "a session without a pseudoconsole is given no verb"
            ))),
        },
        |text| notices.push(text.to_owned()),
    );
    let (mut child, configured) = match started {
        Ok(started) => started,
        Err(cause) => {
            show_notices(&mut tx, Mode::Exec, &notices);
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
    let Some(registration) = register_session(reservation, &job) else {
        tracing::debug!("the agent is ending; the shell warnings of a refused login are not shown: {notices:?}");
        return logout::refuse_while_ending(&mut rx, &mut tx, control);
    };
    if answer_serving(&mut tx).is_err() {
        // The command was started and cannot be served: end it.
        if let Some(w) = teardown_warning(reap_tree(&job)) {
            tracing::error!("{w}");
        }
        return Ok(());
    }
    show_notices(&mut tx, Mode::Exec, &notices);
    // Before `tx` moves into the link.
    let watcher = prepare_hangup_watch(&tx, hooks.make_watcher);
    let out_raw = child.stdout_read_raw();
    let err_raw = child.stderr_read_raw();
    let stdin_owned = child.take_stdin_write();
    let stdin_raw = stdin_owned.as_ref().map_or(0, |h| h.raw());
    // stdout, stderr, and the EXIT frame all share the connection → the link serialises the writes. Without a
    // terminal the link gates nothing, and the session's input goes to its stdin by this function's own sink.
    let link = Link::new(tx, false, (0, 0), None);
    let starts = Starts {
        pty: hooks.start_pty,
        exec: hooks.start_exec,
    };
    registration.attach(Arc::new(HostedSession::new(policy, Arc::clone(&link), starts)));
    let hangup = start_hangup_watch(watcher, &job);

    let reaping = || {
        let job = Arc::clone(&job);
        move || {
            reap_tree(&job);
        }
    };
    let t_out = spawn_stream_pump(out_raw, Stream::Stdout, Arc::clone(&link), Carrier::Session, reaping());
    let t_err = spawn_stream_pump(err_raw, Stream::Stderr, Arc::clone(&link), Carrier::Session, reaping());

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
    show_exit_notice(&link, Mode::Exec, configured.as_ref(), code);
    // FIN the write half only: the stdin pump keeps reading until the client closes, so for a
    // conforming client the socket never closes with unread input, which would reset it and
    // lose the EXIT frame.
    link.send_exit(code);
    link.end();
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
///
/// In two steps, because the watcher is made from the connection's write half, which then moves into the session's
/// [`Link`].
#[cfg(windows)]
fn prepare_hangup_watch(tx: &ConnTx, make_watcher: WatchFactory) -> Option<(HangupWatcher, Waker)> {
    match make_watcher(tx.conn().clone()) {
        Ok(pair) => Some(pair),
        Err(e) => {
            tracing::warn!("could not create the hangup watcher; a silent command will outlive its client: {e}");
            None
        }
    }
}

/// Start the watch [`prepare_hangup_watch`] made.
#[cfg(windows)]
fn start_hangup_watch(watcher: Option<(HangupWatcher, Waker)>, job: &Arc<cosca::Job>) -> Option<HangupGuard> {
    let (hangup, waker) = watcher?;
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
            // thread holds only a share of the connection and the job, so detaching it is safe.
            Err(e) => tracing::error!("could not wake the hangup watcher; leaving it to end on its own: {e}"),
        }
    }
}

/// Pump one output stream (a terminal's, or stdout/stderr) of a process into `DATA(stream)` frames on the session's
/// connection, as `carrier`'s. On EOF the process is exiting; on a write failure the SSH side is gone (or the link
/// has ended), so `gone` is called (a session's pump ends its tree) and the pump goes on reading without
/// delivering: it is the only reader of the pipe, and a pipe nobody reads fills and stalls the writer.
///
/// An elevated command's pumps are this one: a `--terminal` command's writes through the session's link with another
/// carrier, and a default-mode command's through a link of the request's own connection, which has no terminal.
#[cfg(windows)]
fn spawn_stream_pump(
    raw: isize,
    stream: Stream,
    link: Arc<Link>,
    carrier: Carrier,
    gone: impl Fn() + Send + 'static,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut buf = [0u8; 32 * 1024];
        let mut delivering = true;
        loop {
            let n = conpty::read_handle(raw, &mut buf);
            if n == 0 {
                break; // stream closed (exiting, or the pseudoconsole closed by teardown and drained to EOF)
            }
            if !delivering {
                continue; // draining, see above
            }
            if link.deliver(carrier, stream, &buf[..n]).is_err() {
                // The socket is gone. This is an independent detector, not a redundant
                // one: the input pump's queue is bounded, so a command that ignores its stdin
                // can still park that pump in a send and blind it to the socket. And keep READING: for a
                // pseudoconsole, `ClosePseudoConsole` flushes conhost's pending output through the pipe, and
                // abandoning it here lets it fill, and teardown then blocks inside the close.
                gone();
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
