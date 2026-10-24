//! agent: resident in a user's interactive session (started by the logon task, once per
//! logon). Per AF_UNIX connection it hosts the shell — in a ConPTY for interactive (PTY)
//! sessions, or with redirected pipes for EXEC (`ssh host "cmd"`) — inheriting the session's
//! token (working DPAPI/profile + no RedirectionGuard) and relays it to the SSH-side shim.
//!
//! The socket is inside the user's own profile (see `socket_loc`), so an agent serves exactly
//! one account: the one whose token it runs under.

/// `agent` subcommand entrypoint. Windows-only: the agent must run in the user's interactive
/// session to confer RDP parity.
pub fn run() -> anyhow::Result<()> {
    #[cfg(windows)]
    return start();

    #[cfg(not(windows))]
    return Err(anyhow::anyhow!(
        "the agent runs only on Windows (it hosts the shell in an interactive session)"
    ));
}

#[cfg(windows)]
use crate::afunix::{self, AcceptError, ConnRx, ConnTx, Listener};
#[cfg(windows)]
use crate::agent_lock::{SessionSlot, UserLock, session_allows_agent};
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
use crate::socket_loc::SocketLocation;
#[cfg(windows)]
use crate::winutil::OwnedHandle;
#[cfg(windows)]
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::sync::mpsc::TrySendError;
#[cfg(windows)]
use std::sync::{Arc, Condvar, Mutex};

/// Everything between "the task started us" and "serve": check where we are, make the user's
/// private folder, and become the one agent that serves this user.
#[cfg(windows)]
fn start() -> anyhow::Result<()> {
    start_with(
        crate::provision::probe::current_session_id(),
        crate::userdir::current_socket_location,
        |logs| crate::filelog::init_in(logs, "agent.log"),
        serve,
    )
}

/// [`start`] with its inputs as parameters, so a test can pick the session and see what runs.
#[cfg(windows)]
fn start_with(
    session: u32,
    locate: impl FnOnce() -> anyhow::Result<SocketLocation>,
    init_log: impl FnOnce(&Path) -> anyhow::Result<tracing_appender::non_blocking::WorkerGuard>,
    serve: impl FnOnce(&SocketLocation, u32) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        session_allows_agent(session),
        "the agent will not run in session 0: a shell hosted there has the limited environment this tool \
         exists to avoid. It belongs in the user's interactive session; the logon task starts it there"
    );
    let location = locate()?;
    let user = crate::acl::Sid::current_user()?;
    crate::userdir::ensure_socket_dir(&location, &user)?;
    // Held to the end: dropping the guard stops the writer and later lines are lost. Until the
    // log opens an error goes to stderr, which a logon task discards; a hand-run agent shows it.
    let _log = keep_log_or_report(init_log(&location.logs_dir()), &mut std::io::stderr());
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
fn serve(location: &SocketLocation, session: u32) -> anyhow::Result<()> {
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
        run_on,
    )
}

/// [`serve`] with the user lock and the serving as parameters, so a test can see the order.
#[cfg(windows)]
fn serve_with(
    location: &SocketLocation,
    session: u32,
    user_lock: impl FnOnce(&Path) -> anyhow::Result<UserLock>,
    run: impl FnOnce(&SocketLocation) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    // One agent per session: `apply` and the boot self-heal start one per logged-on session
    // every time they run, and the logon task starts one per logon. This comes first, because the
    // user lock may be held for as long as another session lives.
    let Some(_slot) = SessionSlot::try_acquire(&location.sessions_lock_path(), session)? else {
        tracing::info!("another agent already runs in this session; exiting");
        return Ok(());
    };
    let _lock = user_lock(&location.lock_path())?;
    run(location)
}

/// Bind the hardened socket and serve connections, one handler thread each. The caller holds
/// the user's lock, so no other agent of this user binds meanwhile.
#[cfg(windows)]
fn run_on(location: &SocketLocation) -> anyhow::Result<()> {
    let listener = Listener::bind(&location.path)?;
    Err(serve_connections(
        || listener.accept(),
        |conn, live| {
            std::thread::spawn(move || {
                // Ends with the thread, after the connection is closed: that is when its
                // descriptors are free again.
                let _live = live;
                if let Err(e) = handle_connection(conn) {
                    tracing::warn!("connection handler error: {e:?}");
                }
            });
        },
    ))
}

/// The connections this agent is serving, so that a shortage of descriptors can wait for one to end.
#[cfg(windows)]
struct Connections {
    tally: Mutex<Tally>,
    ended: Condvar,
}

#[cfg(windows)]
struct Tally {
    live: usize,
    /// How many connections have ever ended: a counter, so "one ended since I looked" is a
    /// comparison and not a guess at what changed.
    ended: u64,
}

/// A live connection. Dropping it, on any exit from the handler including a panic, ends it.
#[cfg(windows)]
struct Live(Arc<Connections>);

#[cfg(windows)]
impl Connections {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            tally: Mutex::new(Tally { live: 0, ended: 0 }),
            ended: Condvar::new(),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Tally> {
        self.tally.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn begin(self: &Arc<Self>) -> Live {
        self.lock().live += 1;
        Live(Arc::clone(self))
    }

    /// How many connections have ended so far.
    fn ended(&self) -> u64 {
        self.lock().ended
    }

    /// Return once more than `since` connections have ended (`true`), or at once with `false` if
    /// none is live and none has ended since: then nothing is left that could end.
    fn wait_for_an_end(&self, since: u64) -> bool {
        let mut tally = self.lock();
        loop {
            if tally.ended > since {
                return true;
            }
            if tally.live == 0 {
                return false;
            }
            tally = self
                .ended
                .wait(tally)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
}

#[cfg(windows)]
impl Drop for Live {
    fn drop(&mut self) {
        let mut tally = self.0.lock();
        tally.live -= 1;
        tally.ended += 1;
        self.0.ended.notify_all();
    }
}

/// Accept connections and hand each to `serve`, with the guard that says when it ends, until the
/// listener breaks; returns that error.
///
/// A connection that is lost (reset while queued, or one that cannot be set up) is logged and
/// dropped: it must not end service for every session of the user. An interrupted `accept` is
/// called again. A shortage of descriptors or buffers is waited out: the loop blocks until one of
/// this agent's own connections ends, which is the only thing that can free either, and then tries
/// again. With no live connection nothing can, and the shortage is fatal.
#[cfg(windows)]
fn serve_connections<C>(
    mut accept: impl FnMut() -> Result<C, AcceptError>,
    mut serve: impl FnMut(C, Live),
) -> anyhow::Error {
    let connections = Connections::new();
    loop {
        // Read before the attempt: a connection that ends while it fails is then not missed.
        let ended_before = connections.ended();
        match accept() {
            Ok(conn) => serve(conn, connections.begin()),
            Err(AcceptError::Connection(e)) => tracing::warn!("dropped a connection: {e:#}"),
            Err(AcceptError::Interrupted(_)) => {}
            Err(AcceptError::Exhausted { code, source }) => {
                tracing::warn!(
                    "accept failed for lack of resources (code {code}); waiting for a connection to end: {source}"
                );
                if !connections.wait_for_an_end(ended_before) {
                    return anyhow::Error::new(source).context(format!(
                        "accept failed with code {code} and no connection of this agent is live to free a resource"
                    ));
                }
            }
            Err(AcceptError::Fatal(e)) => return e.context("the listener failed"),
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
#[cfg(windows)]
fn handle_connection(conn: socket2::Socket) -> anyhow::Result<()> {
    handle_connection_with(conn, Hooks::production())
}

/// How a session obtains its [`HangupWatcher`]; a parameter so a test can force a failure.
#[cfg(windows)]
type WatchFactory = fn(&ConnTx) -> std::io::Result<(HangupWatcher, Waker)>;

/// What a test can replace or observe in a session; production uses [`Hooks::production`].
#[cfg(windows)]
struct Hooks {
    make_watcher: WatchFactory,
    parked: ParkSignal,
}

#[cfg(windows)]
impl Hooks {
    fn production() -> Self {
        Self {
            make_watcher: HangupWatcher::new,
            parked: ParkSignal::default(),
        }
    }
}

#[cfg(windows)]
fn handle_connection_with(conn: socket2::Socket, hooks: Hooks) -> anyhow::Result<()> {
    let (mut rx, tx) = afunix::split(conn)?;
    let mut fr = FrameReader::new();
    let frame = read_one_frame(&mut rx, &mut fr)?;
    anyhow::ensure!(frame.kind == FrameKind::Handshake, "first frame was not a handshake");
    let hs = Handshake::decode(&frame.payload)?;
    let command = hs.command.clone().unwrap_or_else(default_shell);
    let cwd_buf = child_cwd(&hs.cwd, home_dir());
    let cwd = cwd_buf.as_deref();
    match hs.mode {
        Mode::Pty => handle_pty(rx, fr, tx, &command, (hs.cols, hs.rows), cwd, hooks),
        Mode::Exec => handle_exec(rx, fr, tx, &command, cwd, hooks),
    }
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

// ── PTY relay ────────────────────────────────────────────────────────────────────────

/// Interactive PTY relay: spawn the shell in a ConPTY and bridge it with three threads and
/// an ordered, race-free teardown (criterion 2).
#[cfg(windows)]
fn handle_pty(
    mut rx: ConnRx,
    mut fr: FrameReader,
    tx: ConnTx,
    command: &str,
    (cols, rows): (u16, u16),
    cwd: Option<&Path>,
    hooks: Hooks,
) -> anyhow::Result<()> {
    let mut session = PtySession::spawn(command, cols, rows, cwd)?;
    let job = session.job();
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
        let _ = write_frame(&mut *g, FrameKind::Exit, &ExitCode(code).encode());
        // FIN the write half only: the input pump keeps reading until the client closes, so for a
        // conforming client the socket never closes with unread input, which would reset it and
        // lose the EXIT frame.
        let _ = g.shutdown_write();
    }
    if let Some(hangup) = hangup {
        hangup.finish();
    }
    let _ = in_thread.join();
    // Threads joined; `session` now drops and closes the process/thread + pipe handles.
    wait_result?;
    Ok(())
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
    tx: ConnTx,
    command: &str,
    cwd: Option<&Path>,
    hooks: Hooks,
) -> anyhow::Result<()> {
    let mut child = ExecChild::spawn(command, cwd)?;
    let job = child.job();
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
        let _ = write_frame(&mut *g, FrameKind::Exit, &ExitCode(code).encode());
        // FIN the write half only: the stdin pump keeps reading until the client closes, so for a
        // conforming client the socket never closes with unread input, which would reset it and
        // lose the EXIT frame.
        let _ = g.shutdown_write();
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
