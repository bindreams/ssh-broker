//! elevate: `ssh-broker elevate <command>`, the client side. Runs one command elevated, from a session that is not.
//!
//! The unelevated session is a convenience and a consent step, like an ordinary prompt beside "Run as
//! administrator"; it is not a security boundary, and nothing here claims one. The command is started by the
//! agent, which holds the account's elevated token, and only when the session's login allowed it (see
//! `agent::elevation`); this side only asks.
//!
//! What it does depends on where it runs ([`course`]): a process at High runs the command itself, in place; a
//! process below High sends one request to the agent on `request.sock` ([`elevate_on`]), and the agent hosts the
//! command and answers as it answers a session: a refusal, or `Serving` and then the command's output and its exit
//! code. A shell that is not under ssh-broker, whatever its level, is refused: the session id
//! ([`SESSION_VARIABLE`]) is how the agent knows which session asks.
//!
//! The line that runs is the one that was typed after `elevate` ([`program_line`]), as written, with its program
//! found the way the session finds it. `elevate` exits with the command's own exit code, with
//! [`REFUSED_EXIT_CODE`] when the command did not run, and with [`UNKNOWN_END_EXIT_CODE`] when it cannot tell how
//! the command ended, each after a line that says why.

use std::ffi::OsStr;
use std::io::{Read, Write};
use std::path::Path;

use crate::cmdline::split_program;
use crate::console_prompt::is_no_agent;
use crate::offer::text;
use crate::protocol::{
    ElevationRequest, FrameKind, FrameReader, PROTOCOL_VERSION, SESSION_VARIABLE, SessionId, Stream,
};
use crate::relay::{FrameSink, Outcome};
use crate::request::{Asked, ReplySink, send_request};
use crate::shell::{self, Host};
use crate::shim::pump_heard;
use crate::socket_loc::Integrity;

/// What `elevate` exits with when the command was not run: a refusal of the agent's or of this process's own.
/// 126, as a shell says "found, but could not run"; the command's own codes are the other exit codes.
pub const REFUSED_EXIT_CODE: i32 = 126;

/// What `elevate` exits with when it cannot tell how the command ended: the agent ended before it answered, its
/// answer could not be read, or the command's end could not be read. 255, as `ssh` says for a connection that
/// failed.
pub const UNKNOWN_END_EXIT_CODE: i32 = 255;

/// Where the command runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Course {
    /// This process is at High: start the command here, asking nobody.
    InPlace,
    /// This process is below High: ask the agent.
    ViaAgent,
}

/// Why the command was not run, before or without the agent's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// No valid [`SESSION_VARIABLE`], or no agent that serves requests: this shell is not hosted by ssh-broker.
    NotHosted,
    /// The plain folder holds an `agent.sock` and no `request.sock`: the account's agent runs below High.
    NeedsHighAgent,
    /// Anything else this process could not do, with the cause.
    CannotStart(String),
}

impl Refused {
    /// The line to show: the same sentences the agent's refusals are.
    pub fn text(&self) -> String {
        match self {
            Refused::NotHosted => text::elevation_not_hosted(),
            Refused::NeedsHighAgent => text::elevation_needs_high_agent(),
            Refused::CannotStart(cause) => text::elevation_cannot_start(cause),
        }
    }

    /// Every refusal exits with [`REFUSED_EXIT_CODE`].
    pub fn exit_code(&self) -> i32 {
        REFUSED_EXIT_CODE
    }
}

/// How asking the agent to run the command went, as the frames it sent say: not by the codes of its refusals, which
/// are nothing a script can tell from the command's own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElevateOutcome {
    /// `Serving`, then the command's exit code: the command ran and this is how it ended.
    Ran(i32),
    /// The command did not run: an answer that ends without `Serving` (the agent's sentence is already printed), or a
    /// request that could not be sent (its sentence is printed too).
    NotRun,
    /// The connection ended before the agent's first byte. The command is not sent again: the agent may have started
    /// it.
    Unanswered,
    /// Bytes came that were neither a refusal nor the start of a command, or a refusal that was cut: whether the
    /// command ran is not known. The cause.
    Unreadable(String),
    /// `Serving` came and the command's exit code did not: the command ran, and its end could not be read. The cause.
    EndUnread(String),
}

impl ElevateOutcome {
    /// What `elevate` exits with: the command's own code, [`REFUSED_EXIT_CODE`] when it did not run and
    /// [`UNKNOWN_END_EXIT_CODE`] when how it ended is not known.
    pub fn exit_code(&self) -> i32 {
        match self {
            ElevateOutcome::Ran(code) => *code,
            ElevateOutcome::NotRun => REFUSED_EXIT_CODE,
            ElevateOutcome::Unanswered | ElevateOutcome::Unreadable(_) | ElevateOutcome::EndUnread(_) => {
                UNKNOWN_END_EXIT_CODE
            }
        }
    }

    /// The line `elevate` says of its own, for the outcomes the agent's frames did not already explain.
    pub fn sentence(&self) -> Option<String> {
        match self {
            ElevateOutcome::Ran(_) | ElevateOutcome::NotRun => None,
            ElevateOutcome::Unanswered => Some(format!("{}\r\n", text::agent_ended_unanswered())),
            ElevateOutcome::Unreadable(cause) => Some(text::elevation_answer_unreadable(cause)),
            ElevateOutcome::EndUnread(cause) => Some(text::elevation_end_unread(cause)),
        }
    }
}

/// The session `session` (the value of [`SESSION_VARIABLE`], if set) names and where the command runs for a
/// process at `integrity`. The order is fixed: a shell that is not hosted is refused at any level, High included,
/// and only then does High run in place.
pub fn course(session: Option<&OsStr>, integrity: Integrity) -> Result<(SessionId, Course), Refused> {
    let id = session
        .and_then(OsStr::to_str)
        .and_then(SessionId::parse)
        .ok_or(Refused::NotHosted)?;
    let course = match integrity {
        Integrity::High => Course::InPlace,
        Integrity::Medium => Course::ViaAgent,
    };
    Ok((id, course))
}

/// Whether the plain folder holds what a request needs, given whether it holds a `request.sock` and an
/// `agent.sock`: a request socket is asked. An `agent.sock` alone is the agent of an account that runs below High,
/// which keeps no request socket, and neither is no agent at all.
pub fn requestable(request_sock: bool, agent_sock: bool) -> Result<(), Refused> {
    match (request_sock, agent_sock) {
        (true, _) => Ok(()),
        (false, true) => Err(Refused::NeedsHighAgent),
        (false, false) => Err(Refused::NotHosted),
    }
}

/// The line `line` (what was typed after `elevate`, as written) with its program found the way the session finds
/// it: `"<absolute path>"` and then the rest of the line exactly as typed. A program with a `\`, `/` or `:` is a
/// path, made absolute against this process's working directory (the system's rule, `C:x` and `\x` included); a
/// bare one is searched on `PATH` only, as the shell does, with `.exe` added when it has no extension. Neither the
/// current directory nor this program's own is searched for a bare name.
///
/// A program that only the shell finds (`dir`) or that `PATHEXT` completes (`npm` for `npm.cmd`) is refused and
/// nothing runs: name the file (`npm.cmd`), or run it through the shell (`cmd /c dir`).
pub fn program_line(host: &dyn Host, line: &str) -> Result<String, Refused> {
    let (program, rest) = split_program(line);
    let cannot = |reason: &dyn std::fmt::Display| Refused::CannotStart(format!("{program}: {reason}"));
    let named = if program.contains(['\\', '/', ':']) {
        let absolute = std::path::absolute(program).map_err(|e| cannot(&e))?;
        absolute
            .to_str()
            .map(str::to_owned)
            .ok_or_else(|| cannot(&"the path is not valid Unicode"))?
    } else {
        program.to_owned()
    };
    let found = shell::resolve_program(host, &named).map_err(|reason| cannot(&reason))?;
    let found = found.to_str().ok_or_else(|| cannot(&"the path is not valid Unicode"))?;
    // A path cannot hold `"`, so the quoted token is always one program name.
    Ok(format!("\"{found}\"{rest}"))
}

/// The request that runs `line` (see [`program_line`]) in `cwd` for session `id`, on a screen of its own when
/// `terminal`.
pub fn request_for(id: &SessionId, terminal: bool, line: &str, cwd: &str) -> ElevationRequest {
    ElevationRequest {
        version: PROTOCOL_VERSION,
        session: id.to_string(),
        command: line.to_owned(),
        cwd: cwd.to_owned(),
        terminal,
    }
}

/// The reply of a request, which is answered as a session is: a refusal, or `Serving` and then the command's
/// streams. Remembers whether `Serving` came.
struct Answer<'a> {
    reply: ReplySink<'a>,
    served: bool,
}

impl FrameSink for Answer<'_> {
    fn on_serving(&mut self) -> anyhow::Result<()> {
        self.served = true;
        Ok(())
    }

    fn on_data(&mut self, stream: Stream, bytes: &[u8]) -> anyhow::Result<()> {
        self.reply.on_data(stream, bytes)
    }
}

/// Send `request` over a connected transport and relay the reply: the command's stdout to `out` and its stderr (or a
/// refusal's text) to `err`. What the frames say decides the outcome ([`ElevateOutcome`]), and the outcome decides
/// the code. The transport is borrowed, not consumed: the caller keeps it open until it has the outcome, as the
/// agent waits for the client to close before it is done with the connection.
pub fn elevate_on<R: Read, W: Write>(
    rx: &mut R,
    tx: &mut W,
    out: &mut dyn Write,
    err: &mut dyn Write,
    request: &ElevationRequest,
) -> ElevateOutcome {
    if let Err(asked) = send_request(
        tx,
        err,
        FrameKind::Request,
        request.encode(),
        "ask the agent to run the command elevated",
    ) {
        return match asked {
            Asked::Unanswered => ElevateOutcome::Unanswered,
            Asked::Code(_) => ElevateOutcome::NotRun,
        };
    }
    let mut answer = Answer {
        reply: ReplySink { out, err },
        served: false,
    };
    let pumped = pump_heard(rx, &mut FrameReader::new(), &mut answer);
    if pumped.no_answer() {
        return ElevateOutcome::Unanswered;
    }
    match (pumped.outcome, answer.served) {
        (Ok(Outcome::Exited(code)), true) => ElevateOutcome::Ran(code),
        (Ok(Outcome::Exited(_)), false) => ElevateOutcome::NotRun,
        (Ok(Outcome::PeerClosed), true) => {
            ElevateOutcome::EndUnread("the agent closed the connection before it sent an exit code".to_owned())
        }
        (Ok(Outcome::PeerClosed), false) => {
            ElevateOutcome::Unreadable("the agent closed the connection in the middle of its answer".to_owned())
        }
        (Ok(Outcome::HandedBack(cause)), _) => ElevateOutcome::Unreadable(format!(
            "the agent handed the request back, which it never does: {cause}"
        )),
        (Err(e), true) => ElevateOutcome::EndUnread(e.to_string()),
        (Err(e), false) => ElevateOutcome::Unreadable(e.to_string()),
    }
}

/// Connect once with `connect` and ask ([`elevate_on`]). A command is never sent again: a connection that ends
/// without a byte may be an agent that ran it, so there is no second try. No agent to connect to is
/// [`Refused::NotHosted`]; any other failure to connect is a [`Refused::CannotStart`].
pub fn elevate_over<R: Read, W: Write>(
    connect: impl FnOnce() -> anyhow::Result<(R, W)>,
    out: &mut dyn Write,
    err: &mut dyn Write,
    request: &ElevationRequest,
) -> Result<ElevateOutcome, Refused> {
    let (mut rx, mut tx) = connect().map_err(|e| {
        if is_no_agent(&e) {
            Refused::NotHosted
        } else {
            Refused::CannotStart(format!("could not reach your session's agent: {e:#}"))
        }
    })?;
    Ok(elevate_on(&mut rx, &mut tx, out, err, request))
}

/// `ssh-broker elevate [--terminal] <command> [arguments]`; `command` is the text after the verb and the flag, as
/// typed. Never returns: it exits with the command's code, or with [`REFUSED_EXIT_CODE`] when the command was not
/// run and [`UNKNOWN_END_EXIT_CODE`] when how it ended is not known.
pub fn run(terminal: bool, command: &str) -> ! {
    let outcome = start(terminal, command);
    let code = match outcome {
        Ok(code) => code,
        Err(refused) => {
            let _ = std::io::stderr().write_all(refused.text().as_bytes());
            refused.exit_code()
        }
    };
    std::process::exit(code)
}

/// The command's exit code, run in place or by the agent, or why it was not run.
fn start(terminal: bool, command: &str) -> Result<i32, Refused> {
    let integrity = crate::account::integrity()
        .map_err(|e| Refused::CannotStart(text::elevation_unreadable_clause(&format!("{e:#}"))))?;
    let session = std::env::var_os(SESSION_VARIABLE);
    let (id, course) = course(session.as_deref(), integrity)?;
    let line = program_line(&shell::WindowsHost, command)?;
    match course {
        Course::InPlace => run_in_place(&line),
        Course::ViaAgent => via_agent(&id, terminal, &line),
    }
}

/// Start `line` (see [`program_line`]) as a child of this process, on its console, and wait for it. A process at
/// High has the console to give, so `--terminal` changes nothing here. While the child runs, Ctrl+C and Ctrl+Break
/// are the child's, which shares the console, and not this process's: it ends when the child does, with its code.
fn run_in_place(line: &str) -> Result<i32, Refused> {
    use std::os::windows::process::CommandExt;
    let (program, rest) = split_program(line);
    let mut command = std::process::Command::new(program);
    let rest = rest.trim_start_matches([' ', '\t']);
    if !rest.trim().is_empty() {
        command.raw_arg(rest);
    }
    crate::shim_pty::ignore_ctrl_c();
    let status = command
        .status()
        .map_err(|e| Refused::CannotStart(format!("{program}: {e}")))?;
    Ok(status.code().unwrap_or(1))
}

/// Ask the agent to run `line` (see [`program_line`]), in this process's working directory, and exit as its answer
/// says ([`ElevateOutcome`]). The command's output is printed here, to this process's stdout and stderr.
///
/// The request socket is the one of the plain folder, asked first when it is there (see [`requestable`]).
fn via_agent(id: &SessionId, terminal: bool, line: &str) -> Result<i32, Refused> {
    let cwd = std::env::current_dir().map_err(|e| Refused::CannotStart(format!("the working directory: {e}")))?;
    let cwd = cwd
        .to_str()
        .ok_or_else(|| Refused::CannotStart(format!("the working directory {} is not valid Unicode", cwd.display())))?;
    let request = request_for(id, terminal, line, cwd);

    let folder = match crate::userdir::inspect_current_socket_dir() {
        Ok(folder) => folder,
        Err(e) if e.is::<crate::userdir::NoProfile>() => return Err(Refused::NotHosted),
        Err(e) => return Err(Refused::CannotStart(format!("{e:#}"))),
    };
    let location = folder.location();
    let request_sock = match location.checked_request_path() {
        Ok(path) => held(&path)?,
        // No agent at High can exist for a profile this long.
        Err(_) => false,
    };
    requestable(request_sock, held(location.path())?)?;

    let mut stderr = std::io::stderr();
    let outcome = elevate_over(
        || crate::afunix::split(folder.connect_request()?),
        &mut std::io::stdout(),
        &mut stderr,
        &request,
    )?;
    if let Some(sentence) = outcome.sentence() {
        let _ = stderr.write_all(sentence.as_bytes());
    }
    Ok(outcome.exit_code())
}

/// Whether something is at `path`, a socket included, which is looked at and not followed.
fn held(path: &Path) -> Result<bool, Refused> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(Refused::CannotStart(format!(
            "{:#}",
            anyhow::Error::new(e).context(format!("look at {}", path.display()))
        ))),
    }
}

#[cfg(test)]
#[path = "elevate_tests.rs"]
mod elevate_tests;
