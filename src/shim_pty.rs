//! shim_pty: the Windows interactive PTY path of the shim + the `run()` wiring.
//!
//! Windows-only: it drives the real ssh-shellhost console. `run_on` connects to the agent,
//! decides fail-open, and dispatches; `run_pty` puts the console into raw VT mode (RAII
//! restore), spawns ONE `ReadConsoleInputW` worker that re-encodes keys/mouse/resize toward
//! the agent, and pumps the agent's filtered output to stdout on the main thread.
//!
//! Teardown model (mirrors `agent::handle_pty`'s discipline, inverted): MAIN owns `rx`, the
//! `ConsoleModes` RAII guard, and the worker's `JoinHandle`; it runs `pump_decode` (the
//! deterministic completion signal) and coordinates teardown. The worker owns `tx` (the sole
//! frame producer post-handshake) and runs the un-cancellable `ReadConsoleInputW` loop. On
//! EXIT, MAIN sets a `stopping` flag, wakes the parked read by injecting a benign console
//! record (`WriteConsoleInputW` — reliable for console reads where `CancelSynchronousIo` is
//! not), JOINS the worker, then the guard restores modes AFTER the join — so the worker can
//! never read with a half-restored mode (the use-after-close hazard).

use crate::cmdline::{Encoding, Exec, RawExec, resolve_exec};
use crate::console_modes::ConsoleModes;
use crate::protocol::{FrameKind, FrameReader, Handshake, Launch, Stream, write_frame};
use crate::relay::{FrameSink, write_data};
use crate::shim::{
    Fallback, MouseModeSniffer, PROTOCOL_VIOLATION_CODE, Pumped, Started, XtwinopsFilter, closed_twice_message,
    decide_fallback, fail_open, is_blank_command, make_handshake, peer_gone, pump_exec, pump_heard, size_to_resize,
    start_exec_input,
};
use crate::shim_offer::{Absent, Prompting, Rescue, Rescued};
use crate::socket_loc::SocketLocation;
use crate::{afunix, conpty, vtinput};
use socket2::Socket;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Console::{
    CONSOLE_SCREEN_BUFFER_INFO, GetConsoleScreenBufferInfo, GetStdHandle, INPUT_RECORD, ReadConsoleInputW,
    STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, WriteConsoleInputW,
};

// INPUT_RECORD.EventType values (processthreadsapi/consoleapi). windows-rs 0.62 does not
// export them as usable typed consts, so name them with their documented `u16` values.
const EVT_KEY: u16 = 0x0001;
const EVT_MOUSE: u16 = 0x0002;
const EVT_WINDOW_BUFFER_SIZE: u16 = 0x0004;
const EVT_FOCUS: u16 = 0x0010;

// ── run() wiring + fail-open ───────────────────────────────────────────────────────

/// Windows shim entrypoint. Connect to the agent; on a completed relay exit with the child's
/// code. On agent-unreachable, no-console, or ANY pre-spawn setup error, fail open to a local
/// shell — never let an error reach `main()` (which would exit 1 and print to the terminal,
/// corrupting an interactive PTY). The log guard is flushed before every `process::exit`,
/// since `process::exit` runs no destructors and the log is the only PTY-mode diagnostic.
///
/// A `-c` session resolves its command first, once the log is open: `detect` says how sshd
/// encoded it (see [`resolve_exec`]), and a blank command ends the run there, exit 0.
pub fn run_on(exec: Option<RawExec>, detect: impl FnOnce() -> Encoding) -> anyhow::Result<()> {
    // A log that cannot be set up never stops the shim. The cause is kept, to be said where the
    // shim already explains a fallback to the user.
    let (log, log_failure) = match crate::filelog::init_for_current_user("shim.log") {
        Ok(guard) => (Some(guard), None),
        Err(e) => (None, Some(format!("{e:#}"))),
    };
    let exec = exec.map(|exec| resolve_exec(exec, detect));
    if exec.as_ref().is_some_and(|exec| is_blank_command(&exec.command)) {
        drop(log); // flush: `process::exit` runs no destructors
        std::process::exit(0)
    }

    // EVERY command relays. There is deliberately no local route for file transfers.
    //
    // Routing them locally required deciding, from a string the CLIENT chose, whether a command
    // was a transfer — and that decision is not reliably derivable: sshd rewrites commands before
    // `DefaultShell` sees them, and its config serialisation differs from Windows' own quoting.
    // The justification for routing was that relaying would corrupt a binary stream; that turned
    // out to be untrue — `exec_relay_is_byte_clean_*` covers the framing in both directions, and
    // `verify`'s probe covers a real child, real pipes and a real socket in both directions too.
    // What remains is a throughput difference, which does not earn a classifier.
    match try_relay(
        &exec,
        crate::userdir::current_socket_location,
        log_failure.as_deref(),
        std::io::stdin(),
        &mut Prompting,
    ) {
        Ok(Some(code)) => {
            drop(log); // flush the appender before process::exit
            // Bypass main()'s Result→0/1 collapse; the i32→u32 cast is bit-preserving.
            std::process::exit(code)
        }
        Ok(None) => {} // fail-open reason (unreachable / no console) already logged
        Err(e) => {
            // A pre-spawn setup failure: the agent ran nothing, so re-running locally is
            // safe and far better than dying with an error to the user's terminal.
            tracing::warn!("shim relay setup failed: {e:?}; falling back to a local shell");
        }
    }
    // Fail open: the session runs here, through the shell the agent would have started and with the command
    // packed the same way (`shim::fail_open`), in a job so the child dies with the session
    // (`run_local_passthrough`). The log guard stays alive until the exit: dropping it stops the
    // `tracing-appender` worker, whose lossy writer then discards every later line.
    let code = fail_open(
        &crate::shell::WindowsHost,
        &exec,
        &mut std::io::stderr(),
        run_local_passthrough,
    );
    drop(log); // flush: `process::exit` runs no destructors
    // Bypass main()'s Result→0/1 collapse; the i32→u32 cast is bit-preserving.
    std::process::exit(code)
}

/// Attempt the relay. `Ok(Some(code))` = a relay completed (PTY or EXEC). `Ok(None)` = the
/// shim should fail open (agent unreachable, or no interactive console). Any `Err` is a
/// pre-spawn setup failure (connect/split/handshake/console) — the agent spawned nothing, so
/// the caller can safely fail open without a double-execution or an orphaned shell.
///
/// `locate` says where the socket is. `run_on` passes [`crate::userdir::current_socket_location`],
/// the profile of the account this process runs as and no other; it is a parameter so a test can
/// pin that this function connects only to what it is given. `log_failure` is why the shim has no
/// log, if it has none (see [`try_relay_at`]). `stdin` is what an EXEC session forwards to the
/// child (the process's own stdin in `run_on`).
fn try_relay(
    exec: &Option<Exec>,
    locate: impl FnOnce() -> anyhow::Result<SocketLocation>,
    log_failure: Option<&str>,
    stdin: impl std::io::Read + Send + 'static,
    rescue: &mut dyn Rescue,
) -> anyhow::Result<Option<i32>> {
    try_relay_at(locate(), exec, &mut std::io::stderr(), log_failure, stdin, rescue)
}

/// The phrase `tests/fail_open_windows.rs` greps for; every fail-open message begins with it.
/// `reason` is why the agent cannot be reached, when the shim knows and the user can act on it.
fn unavailable_message(reason: Option<&dyn std::fmt::Display>) -> String {
    match reason {
        Some(reason) => format!("ssh-broker: agent unavailable — falling back to a local shell ({reason})"),
        None => "ssh-broker: agent unavailable — falling back to a local shell".to_string(),
    }
}

/// [`try_relay`] for a given socket location (or the reason there is none), writing a user
/// message to `stderr` where one is safe.
///
/// `log_failure`, why there is no log, is added to the message of a fallback for a command: the
/// log is where that fallback's reason would otherwise go, and it is gone. Nothing is written for
/// it on the relay path, where stderr belongs to the command, nor in PTY mode, where a write
/// could corrupt the stream. A location that cannot be resolved already prints its own cause,
/// which is the cause of the missing log too.
fn try_relay_at(
    location: anyhow::Result<SocketLocation>,
    exec: &Option<Exec>,
    stderr: &mut dyn std::io::Write,
    log_failure: Option<&str>,
    stdin: impl std::io::Read + Send + 'static,
    rescue: &mut dyn Rescue,
) -> anyhow::Result<Option<i32>> {
    try_relay_with(
        location,
        exec,
        stderr,
        log_failure,
        stdin,
        rescue,
        &mut relay_interactive,
    )
}

/// What an interactive attempt came to.
enum Interactive {
    /// The relay ran; see [`Pumped`].
    Pumped(Pumped),
    /// There is no console to relay: fail open.
    NoConsole,
}

/// The interactive relay ([`relay_interactive`]): the connection, a console a rescue left raw, and the
/// command of a session that has a terminal.
type InteractiveRelay<'a> = dyn FnMut(Socket, Option<ConsoleModes>, Option<&str>) -> anyhow::Result<Interactive> + 'a;

/// [`try_relay_at`] with the interactive relay as a parameter, so that a test can stand in for the
/// console. `interactive` gets the command of a session that has a terminal (`ssh -t host cmd`),
/// which it sends in the handshake.
fn try_relay_with(
    location: anyhow::Result<SocketLocation>,
    exec: &Option<Exec>,
    stderr: &mut dyn std::io::Write,
    log_failure: Option<&str>,
    stdin: impl std::io::Read + Send + 'static,
    rescue: &mut dyn Rescue,
    interactive: &mut InteractiveRelay<'_>,
) -> anyhow::Result<Option<i32>> {
    if let Some(exec) = exec.as_ref().filter(|exec| !exec.terminal) {
        return match connect_or_rescue(&location, true, stderr, log_failure, rescue)? {
            Connected::Agent { socket, .. } => relay_exec(socket, &exec.command, stdin, stderr),
            Connected::Done(code) => Ok(code),
        };
    }
    // A command with a terminal goes round the same loop as a login, except that it is never sent
    // again: the agent may have started it before it ended the connection.
    let command = exec.as_ref().map(|exec| exec.command.as_str());
    // An interactive session whose connection the agent ends before it says anything goes round again:
    // the agent is ending, because an agent that follows the protocol closes a connection without a
    // byte only while its listener closes. The next connect then finds no listener or an agent that
    // answers. A second close without a byte from a connect that succeeded, right after the first,
    // breaks the protocol, and the session ends there. A connect that fails in between (and the rescue
    // that follows it) starts the count again: that agent is gone.
    let mut closed_before = false;
    loop {
        let (conn, rescued_modes) = match connect_or_rescue(&location, command.is_some(), stderr, log_failure, rescue)?
        {
            Connected::Agent { socket, modes, rescued } => {
                closed_before &= !rescued;
                (socket, modes)
            }
            Connected::Done(code) => return Ok(code),
        };
        match interactive(conn, rescued_modes, command)? {
            Interactive::Pumped(pumped) if pumped.no_answer() => {
                if command.is_some() {
                    let _ = writeln!(stderr, "{AGENT_ENDED_UNANSWERED}");
                    return Ok(Some(255));
                }
                if closed_before {
                    let path = location.as_ref().ok().map(|location| location.path.as_path());
                    let message = closed_twice_message(path);
                    tracing::error!("{message}");
                    let _ = writeln!(stderr, "{message}");
                    return Ok(Some(PROTOCOL_VIOLATION_CODE));
                }
                closed_before = true;
                tracing::warn!("the agent ended the connection before it answered; connecting again");
            }
            Interactive::Pumped(pumped) => return Ok(Some(pumped.code())),
            Interactive::NoConsole => return Ok(None),
        }
    }
}

/// What [`connect_or_rescue`] came to.
enum Connected {
    /// A connection to the agent, with the console a rescue left raw. `rescued`: the connect found no
    /// agent and the rescue made this connection.
    Agent {
        socket: Socket,
        modes: Option<ConsoleModes>,
        rescued: bool,
    },
    /// There is none: what [`try_relay_with`] returns instead.
    Done(Option<i32>),
}

/// A connection to the agent, or what [`try_relay_with`] returns instead when there is none.
///
/// A user with no agent may be offered a session (or told how to get one). What the rescue does not
/// use, the fail-open handles exactly as it did before.
fn connect_or_rescue(
    location: &anyhow::Result<SocketLocation>,
    is_command: bool,
    stderr: &mut dyn std::io::Write,
    log_failure: Option<&str>,
    rescue: &mut dyn Rescue,
) -> anyhow::Result<Connected> {
    let connection = match location {
        Ok(location) => afunix::connect(&location.path),
        // The cause is shown by the fail-open below; this only says there was nothing to connect to.
        Err(e) => Err(anyhow::anyhow!("{e:#}")),
    };
    let connection: anyhow::Result<Socket> = match connection {
        Ok(socket) => {
            return Ok(Connected::Agent {
                socket,
                modes: None,
                rescued: false,
            });
        }
        Err(e) => Err(e),
    };
    let absent = Absent {
        exec: is_command,
        location,
        connect: &connection,
    };
    Ok(match rescue.rescue(&absent, stderr) {
        Rescued::Connected { socket, modes } => Connected::Agent {
            socket,
            modes,
            rescued: true,
        },
        Rescued::Gone => Connected::Done(Some(255)),
        Rescued::Plain => Connected::Done(fail_open_reason(
            location,
            &connection,
            is_command,
            stderr,
            log_failure,
        )?),
    })
}

/// Relay an EXEC session over `conn`, once. The agent may have started the command before it ended a
/// connection without a byte, and an agent that answers next could run it again, so the command is
/// neither sent again nor run anywhere else.
fn relay_exec(
    conn: Socket,
    cmd: &str,
    stdin: impl std::io::Read + Send + 'static,
    stderr: &mut dyn std::io::Write,
) -> anyhow::Result<Option<i32>> {
    let (rx, tx) = afunix::split(conn)?;
    let hs = make_handshake(&Some(cmd.to_owned()), false, Launch::Shell, term(), 80, 24); // EXEC ignores cols/rows
    // Held until the session is over: the agent takes a close for a disconnect.
    let pumped = match start_exec_input(tx, &hs, stdin)? {
        Started::Ready(_keep_open) => pump_exec(rx, std::io::stdout(), std::io::stderr()),
        Started::Closed(e) => Pumped::closed(e),
    };
    if pumped.no_answer() {
        let _ = writeln!(stderr, "{AGENT_ENDED_UNANSWERED}");
        return Ok(Some(255));
    }
    Ok(Some(pumped.code()))
}

/// Relay an interactive session over `conn`. A real console is required to capture input. No
/// handshake has been sent yet, so a missing console fails open without orphaning an agent shell. A
/// prompt that signed the user on hands over the raw console it was using. `command` is the command of
/// a session that has a terminal: the agent runs it in the pseudoconsole, as OpenSSH runs it under a
/// pty.
fn relay_interactive(
    conn: Socket,
    rescued_modes: Option<ConsoleModes>,
    command: Option<&str>,
) -> anyhow::Result<Interactive> {
    let (rx, tx) = afunix::split(conn)?;
    let modes = match rescued_modes {
        Some(modes) => modes,
        None => ConsoleModes::enter()?,
    };
    if !modes.is_console {
        drop(modes); // restore is a no-op when !is_console
        tracing::warn!("no interactive console (redirected stdio) — local shell");
        return Ok(Interactive::NoConsole);
    }
    let (cols, rows) = console_size(modes.stdout);
    let hs = make_handshake(&command.map(str::to_owned), true, Launch::Shell, term(), cols, rows);
    Ok(Interactive::Pumped(run_pty(modes, rx, FrameReader::new(), tx, &hs)?))
}

/// What an EXEC session says when the agent ended the connection before it answered.
const AGENT_ENDED_UNANSWERED: &str =
    "ssh-broker: the agent ended before it answered; the command may or may not have run";

/// The message of a fail-open, for a location that cannot be used or a connect that failed.
/// Always `Ok(None)`: the caller falls back to a local shell.
fn fail_open_reason(
    location: &anyhow::Result<SocketLocation>,
    connection: &anyhow::Result<socket2::Socket>,
    is_command: bool,
    stderr: &mut dyn std::io::Write,
    log_failure: Option<&str>,
) -> anyhow::Result<Option<i32>> {
    let location = match location {
        Ok(location) => location,
        Err(e) => {
            // No profile, or a profile path too long for a socket: the cause is the user's own
            // setup and nothing but this line will tell them. Nothing is relayed and the console
            // is untouched, so a line on stderr is safe even for an interactive session.
            let reason = format!("{e:#}");
            tracing::warn!("{}", unavailable_message(Some(&reason)));
            let _ = writeln!(stderr, "{}", unavailable_message(Some(&reason)));
            return Ok(None);
        }
    };
    let path = &location.path;
    if decide_fallback(connection.is_err()) == Fallback::LocalShellWithWarning {
        let msg = unavailable_message(None);
        tracing::warn!("{msg} (path={path:?}, err={:?})", connection.as_ref().err());
        // EXEC has a clean stderr channel; in PTY mode a stderr write would corrupt the
        // terminal stream, so there the warning goes only to the log file.
        if is_command {
            match log_failure {
                Some(why) => {
                    let _ = writeln!(stderr, "{msg} (the shim has no log: {why})");
                }
                None => {
                    let _ = writeln!(stderr, "{msg}");
                }
            }
        }
    }
    Ok(None)
}

/// `$TERM` from the SSH environment, defaulting to a sane 256-colour terminal.
fn term() -> String {
    std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".into())
}

/// Run `command_line` locally (in the session sshd launched us in), inheriting our stdio directly,
/// and return its exit code.
///
/// It deliberately RETURNS the code rather than calling `process::exit` itself. Exiting here forced
/// the caller to drop the log guard before this ran, which shut the appender down and silently
/// discarded every diagnostic logged afterwards — including the one explaining a failed fallback.
/// Returning leaves the caller owning both the exit and the flush that must precede it.
///
/// This is the fail-open path for every session. The line is already the shell's: `shim::fail_open`
/// built it with the same planner the agent uses, so the command reaches the shell packed as it
/// would have been under the agent. The child writes raw to sshd's pipes, exactly as the original
/// DefaultShell did, and it is spawned through [`spawn_contained`], so it dies with the session.
fn run_local_passthrough(command_line: &str) -> anyhow::Result<i32> {
    use windows::Win32::Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation};
    use windows::Win32::System::Console::STD_ERROR_HANDLE;
    use windows::Win32::System::Threading::{GetExitCodeProcess, INFINITE, WaitForSingleObject};
    unsafe {
        let stdin = GetStdHandle(STD_INPUT_HANDLE)?;
        let stdout = GetStdHandle(STD_OUTPUT_HANDLE)?;
        let stderr = GetStdHandle(STD_ERROR_HANDLE)?;
        // STARTF_USESTDHANDLES only passes handles the child can inherit; make sure they are.
        for h in [stdin, stdout, stderr] {
            let _ = SetHandleInformation(h, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT);
        }
        // `_job` must outlive the wait: `cosca::Job` sets KILL_ON_JOB_CLOSE, so dropping it early
        // would terminate the very child we are waiting on.
        let (process, _job) = spawn_contained(command_line, Some([stdin, stdout, stderr]))?;
        WaitForSingleObject(process.0, INFINITE);
        let mut code = 0u32;
        if GetExitCodeProcess(process.0, &mut code).is_err() {
            // A failed query must not read as SUCCESS. `code` is still 0 here, so returning it
            // would be indistinguishable from the command having succeeded — the exact confusion
            // `shim::map_outcome` exists to prevent. Reporting it as an error routes it to the
            // caller's 255, this crate's "the broker failed" code, which is what the relay reports
            // for the same class of failure. Erroring rather than exiting here is also what lets
            // the caller LOG it: exiting inside this function is why that diagnostic was lost.
            anyhow::bail!("GetExitCodeProcess failed for the fail-open child");
        }
        Ok(code as i32)
    }
}

/// `console-fallback`: the notice and the line `file` holds (see [`crate::fallback_file`]), the
/// notice printed on this console, then the line started on it, in a job like every local child
/// ([`spawn_contained`]). Returns the exit code of the line, or 255, this crate's code for a
/// broker-side failure, when the file cannot be used or the line cannot be started.
///
/// The agent starts this verb as the fallback shell of a terminal session instead of the shell, so
/// that the notice is written inside the pseudoconsole, after the clear that opens it. The verb
/// stays in the agent's job, so the shell is a descendant of the agent that dies with the session.
pub fn console_fallback(file: &std::path::Path) -> i32 {
    use std::io::Write;
    let (notice, command_line) = match read_fallback_file(file) {
        Ok(read) => read,
        Err(error) => {
            eprintln!("ssh-broker: could not read the fallback shell from its file: {error:#}");
            return 255;
        }
    };
    let mut out = std::io::stdout();
    let notice_line = format!("{notice}\r\n");
    let _ = out.write_all(notice_line.as_bytes()).and_then(|()| out.flush());
    match run_local_passthrough(&command_line) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("ssh-broker: could not start the shell: {error:#}");
            255
        }
    }
}

/// The notice and the line in `file`, which must be in this account's private folder (from the
/// token) and private to it. The file is removed.
fn read_fallback_file(file: &std::path::Path) -> anyhow::Result<(String, String)> {
    let dir = crate::userdir::current_socket_location()?.dir;
    let user = crate::acl::Sid::current_user()?;
    crate::fallback_file::take(file, &dir, |f| crate::acl::verify_file_acl(f, &user))
}

/// Spawn `command` suspended and contain it in a job object before it runs a single instruction.
///
/// This exists as its own function so the containment is *testable* in isolation. `run_on` still
/// ends in `process::exit` (so nothing in-process can observe its wiring — that is gated end to
/// end by `tests/fail_open_windows.rs`), but the spawn itself can be asserted against here.
///
/// Containment is the point. A child spawned here must die with the session exactly as a relayed
/// one does (`pipes.rs`, `conpty.rs` both contain theirs) — otherwise reaching the fail-open path
/// would be a way to leave a process running after disconnect, and the README promises the
/// opposite. `CREATE_SUSPENDED` is load-bearing: assignment has to win the race against the child
/// spawning anything, or a descendant is born outside the job. `contain_and_resume` kills rather
/// than resumes if assignment fails, so a failure here never yields an uncontained process.
///
/// The caller MUST keep the returned `Job` alive for as long as the child should live.
///
/// # Safety
/// Any handles named in `stdio` must be valid and inheritable.
unsafe fn spawn_contained(
    command: &str,
    stdio: Option<[windows::Win32::Foundation::HANDLE; 3]>,
) -> anyhow::Result<(crate::winutil::OwnedHandle, cosca::Job)> {
    use anyhow::Context;
    use windows::Win32::System::Threading::{
        CREATE_SUSPENDED, CreateProcessW, PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW,
    };
    use windows::core::PWSTR;

    let mut si = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    if let Some([i, o, e]) = stdio {
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = i;
        si.hStdOutput = o;
        si.hStdError = e;
    }
    let mut cmd: Vec<u16> = crate::shim::spawn_line(command)
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut pi = PROCESS_INFORMATION::default();
    unsafe {
        CreateProcessW(
            None,
            Some(PWSTR(cmd.as_mut_ptr())),
            None,
            None,
            stdio.is_some(), // inherit → the child gets sshd's stdio directly (binary-clean)
            CREATE_SUSPENDED,
            None,
            None,
            &si,
            &mut pi,
        )
        .with_context(|| format!("spawn the fail-open local command: {command}"))?;
        let process = crate::winutil::OwnedHandle(pi.hProcess);
        let thread = crate::winutil::OwnedHandle(pi.hThread);
        let job = crate::winutil::contain_and_resume(process.0, thread.0, "shim fail-open")?;
        Ok((process, job))
    }
}

// ── PTY relay ──────────────────────────────────────────────────────────────────────

/// Relay an interactive PTY session. Owns `modes` so the console is restored (the guard's
/// Drop) BEFORE this returns — `run_on` then `process::exit`s, which would skip Drop, so the
/// restore must happen here on the normal return path.
fn run_pty(
    modes: ConsoleModes,
    mut rx: afunix::ConnRx,
    mut fr: FrameReader,
    mut tx: afunix::ConnTx,
    hs: &Handshake,
) -> anyhow::Result<Pumped> {
    let stdin_raw = modes.stdin.0 as isize;
    let stdout_raw = modes.stdout.0 as isize;

    // Handshake first (MAIN owns tx until the worker spawn consumes it), so the agent has
    // spawned + sized the shell before the first keystroke/resize frame arrives.
    if let Err(e) = write_frame(&mut tx, FrameKind::Handshake, &hs.encode()?) {
        return if peer_gone(&e).is_some() {
            Ok(Pumped::closed(e))
        } else {
            Err(e)
        };
    }

    let gate = Arc::new(MouseGate::default());
    let stopping = Arc::new(AtomicBool::new(false));

    let worker = {
        let gate = Arc::clone(&gate);
        let stopping = Arc::clone(&stopping);
        std::thread::spawn(move || input_worker(stdin_raw, stdout_raw, tx, gate, stopping))
    };

    // MAIN: pump agent output → sniff/filter → console stdout. Capture the result WITHOUT `?`
    // so teardown always runs (mirrors agent.rs's deferred wait_result handling).
    let mut sink = StdoutSink {
        out: stdout_raw,
        filter: XtwinopsFilter::new(),
        sniffer: MouseModeSniffer::new(),
        gate,
    };
    let pumped = pump_heard(&mut rx, &mut fr, &mut sink);

    // Ordered teardown: stop, wake the parked ReadConsoleInputW, join. Console modes are
    // restored by `modes` dropping at scope end — AFTER the join, so the worker is provably
    // done before the restore.
    stopping.store(true, Ordering::Relaxed);
    wake_console_input(stdin_raw);
    let _ = worker.join();

    drop(modes); // explicit: restore console modes before we return into run_on's process::exit
    Ok(pumped)
}

/// Routes the agent's output to the real console: observe mouse-mode changes (publishing the
/// gate), strip XTWINOPS, then write the raw VT bytes straight to the console handle (the
/// proven short-write loop, not buffered Rust stdout).
struct StdoutSink {
    out: isize,
    filter: XtwinopsFilter,
    sniffer: MouseModeSniffer,
    gate: Arc<MouseGate>,
}

impl FrameSink for StdoutSink {
    fn on_data(&mut self, _stream: Stream, bytes: &[u8]) -> anyhow::Result<()> {
        self.sniffer.observe(bytes);
        // The AND (tracking && SGR) is computed here on the single writer, so the worker
        // reads one self-consistent flag rather than two it would have to combine.
        self.gate.forward.store(self.sniffer.forward_mouse(), Ordering::Relaxed);
        self.gate.focus.store(self.sniffer.focus_on(), Ordering::Relaxed);
        let filtered = self.filter.filter(bytes);
        anyhow::ensure!(
            conpty::write_all_handle(self.out, &filtered),
            "failed to write relayed output to the console"
        );
        Ok(())
    }
    // on_resize: no-op — RESIZE flows shim→agent only.
}

/// Shared input gate: MAIN (the output sink) publishes whether the brokered shell wants SGR
/// mouse events (`forward`) and focus in/out reports (`focus`); the input worker reads them.
/// Each is an independent scalar, so atomics (not a mutex) suffice with no compound invariant
/// to tear.
#[derive(Default)]
struct MouseGate {
    forward: AtomicBool,
    focus: AtomicBool,
}

/// The single input thread: owns `tx`, reads `ReadConsoleInputW`, re-encodes keys/mouse and
/// re-queries the window size on resize. On any exit it FINs the socket so the agent (and the
/// MAIN pump) observe the disconnect.
fn input_worker(
    stdin_raw: isize,
    stdout_raw: isize,
    mut tx: afunix::ConnTx,
    gate: Arc<MouseGate>,
    stopping: Arc<AtomicBool>,
) {
    unsafe { input_loop(stdin_raw, stdout_raw, &mut tx, &gate, &stopping) };
    // FIN: in the disconnect-first case this makes the agent kill the brokered shell and
    // unblocks MAIN's pump; in the EXIT case it ends the agent's drain, which keeps reading
    // until the client closes.
    let _ = tx.shutdown_both();
}

/// # Safety
/// `stdin_raw`/`stdout_raw` must be the live console handles set up by `ConsoleModes::enter`,
/// valid for the duration of the call (guaranteed: MAIN joins this thread before the guard
/// drops).
unsafe fn input_loop(
    stdin_raw: isize,
    stdout_raw: isize,
    tx: &mut afunix::ConnTx,
    gate: &MouseGate,
    stopping: &AtomicBool,
) {
    let stdin = HANDLE(stdin_raw as *mut core::ffi::c_void);
    let stdout = HANDLE(stdout_raw as *mut core::ffi::c_void);
    let mut enc = vtinput::MouseEncoder::default();
    let mut recs: [INPUT_RECORD; 64] = unsafe { std::mem::zeroed() };
    loop {
        if stopping.load(Ordering::Relaxed) {
            return;
        }
        let mut n = 0u32;
        if unsafe { ReadConsoleInputW(stdin, &mut recs, &mut n) }.is_err() {
            return; // console input closed (SSH side gone)
        }
        // The wake record (or a real one) returns the read; re-check before processing so the
        // teardown signal is honored without forwarding the synthetic record.
        if stopping.load(Ordering::Relaxed) {
            return;
        }
        for rec in &recs[..n as usize] {
            match rec.EventType {
                EVT_KEY => {
                    let k = unsafe { rec.Event.KeyEvent };
                    let ke = vtinput::KeyEvent {
                        virtual_key_code: k.wVirtualKeyCode,
                        virtual_scan_code: k.wVirtualScanCode,
                        unicode_char: unsafe { k.uChar.UnicodeChar },
                        key_down: k.bKeyDown.as_bool(),
                        control_key_state: k.dwControlKeyState,
                        repeat_count: k.wRepeatCount,
                    };
                    if write_data(tx, Stream::Pty, &vtinput::encode_key_event(&ke)).is_err() {
                        return;
                    }
                }
                EVT_WINDOW_BUFFER_SIZE => {
                    // The record carries only the scrollback buffer size; the agent needs the
                    // visible window, so re-query it.
                    let (cols, rows) = console_size(stdout);
                    let r = size_to_resize(cols, rows);
                    if write_frame(tx, FrameKind::Resize, &r.encode()).is_err() {
                        return;
                    }
                }
                EVT_MOUSE => {
                    let m = unsafe { rec.Event.MouseEvent };
                    let mev = vtinput::MouseEvent {
                        x: m.dwMousePosition.X,
                        y: m.dwMousePosition.Y,
                        button_state: m.dwButtonState,
                        control_key_state: m.dwControlKeyState,
                        event_flags: m.dwEventFlags,
                    };
                    if gate.forward.load(Ordering::Relaxed) {
                        let sgr = enc.encode_sgr(&mev);
                        if !sgr.is_empty() && write_data(tx, Stream::Pty, &sgr).is_err() {
                            return;
                        }
                    } else {
                        // Forwarding off: keep the encoder's view clean so a later enable
                        // starts fresh (no unmatched release for a button held across the
                        // enable boundary).
                        enc.reset();
                    }
                }
                // Forward focus in/out as `CSI I`/`CSI O`, but ONLY when the shell enabled
                // ?1004 — else focus-naive programs would see stray `ESC[I`/`ESC[O`. A focus
                // record arriving while the gate is closed falls through to the `_` arm. The
                // teardown wake record (also a FOCUS) never reaches here: the worker returns
                // on the post-read `stopping` re-check above, before this loop.
                EVT_FOCUS if gate.focus.load(Ordering::Relaxed) => {
                    let focused = unsafe { rec.Event.FocusEvent }.bSetFocus.as_bool();
                    let seq: &[u8] = if focused { b"\x1b[I" } else { b"\x1b[O" };
                    if write_data(tx, Stream::Pty, seq).is_err() {
                        return;
                    }
                }
                _ => {} // MENU: ignored (internal)
            }
        }
    }
}

/// Wake a parked `ReadConsoleInputW` by injecting one benign FOCUS record. The worker, having
/// observed `stopping`, returns without forwarding it. More reliable for console reads than
/// `CancelSynchronousIo` (which may not cancel a parked console wait).
fn wake_console_input(stdin_raw: isize) {
    unsafe {
        let stdin = HANDLE(stdin_raw as *mut core::ffi::c_void);
        let mut rec: INPUT_RECORD = std::mem::zeroed();
        rec.EventType = EVT_FOCUS;
        let mut written = 0u32;
        let _ = WriteConsoleInputW(stdin, std::slice::from_ref(&rec), &mut written);
    }
}

/// Current visible window size (cols, rows) from the console, or an 80×24 default if the
/// query fails (e.g. a redirected handle).
fn console_size(stdout: HANDLE) -> (u16, u16) {
    unsafe {
        let mut sbi = CONSOLE_SCREEN_BUFFER_INFO::default();
        if GetConsoleScreenBufferInfo(stdout, &mut sbi).is_ok() {
            let w = sbi.srWindow;
            vtinput::win_size(w.Left, w.Top, w.Right, w.Bottom)
        } else {
            (80, 24)
        }
    }
}

#[cfg(test)]
#[path = "shim_pty_tests.rs"]
mod shim_pty_tests;
