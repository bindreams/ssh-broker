//! elevate: `ssh-broker elevate <command>`, the client side. Runs one command elevated, from a session that is not.
//!
//! The unelevated session is a convenience and a consent step, like an ordinary prompt beside "Run as
//! administrator"; it is not a security boundary, and nothing here claims one. The command is started by the
//! agent, which holds the account's elevated token, and only when the session's login allowed it (see
//! `agent::elevation`); this side only asks.
//!
//! What it does depends on where it runs ([`course`]): a process at High runs the command itself, in place; a
//! process below High sends one request to the agent on `request.sock` ([`elevate_on`]), and the agent hosts the
//! command and answers with its exit code or a refusal. A shell that is not under ssh-broker, whatever its level,
//! is refused: the session id ([`SESSION_VARIABLE`]) is how the agent knows which session asks.

use std::ffi::OsStr;
use std::io::{Read, Write};
use std::path::Path;

use crate::cmdline::join_args;
use crate::console_prompt::is_no_agent;
use crate::offer::text;
use crate::protocol::{ElevationRequest, FrameKind, PROTOCOL_VERSION, SESSION_VARIABLE, SessionId};
use crate::request::{Asked, ask_at, ask_with};
use crate::socket_loc::Integrity;

/// What `elevate` exits with when the command was not run: a refusal of the agent's or of this process's own.
/// 126, as a shell says "found, but could not run"; the command's own codes are the other exit codes.
pub const REFUSED_EXIT_CODE: i32 = 126;

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

/// The request that runs `args` (the command and its arguments, as typed) in `cwd` for session `id`.
pub fn request_for(id: &SessionId, args: &[String], cwd: &str) -> ElevationRequest {
    ElevationRequest {
        version: PROTOCOL_VERSION,
        session: id.to_string(),
        command: join_args(args),
        cwd: cwd.to_owned(),
    }
}

/// Send `request` over a connected transport and relay the reply to `err`: text, then the code that is this
/// process's. The transport is borrowed, not consumed: the caller keeps it open until the process exits, as the
/// agent waits for the client to close before it is done with the connection.
pub fn elevate_on<R: Read, W: Write>(rx: &mut R, tx: &mut W, err: &mut dyn Write, request: &ElevationRequest) -> Asked {
    ask_with(
        rx,
        tx,
        err,
        FrameKind::Request,
        request.encode(),
        "ask the agent to run the command elevated",
    )
}

/// `ssh-broker elevate <command> [arguments]`. Never returns: it exits with the command's code, or
/// [`REFUSED_EXIT_CODE`] when the command was not run.
pub fn run(args: &[String]) -> ! {
    let outcome = start(args);
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
fn start(args: &[String]) -> Result<i32, Refused> {
    let integrity = crate::account::integrity()
        .map_err(|e| Refused::CannotStart(text::elevation_unreadable_clause(&format!("{e:#}"))))?;
    let session = std::env::var_os(SESSION_VARIABLE);
    let (id, course) = course(session.as_deref(), integrity)?;
    match course {
        Course::InPlace => run_in_place(args),
        Course::ViaAgent => via_agent(&id, args),
    }
}

/// Start the command as a child of this process, on its console, and wait for it.
fn run_in_place(args: &[String]) -> Result<i32, Refused> {
    let (program, rest) = args
        .split_first()
        .ok_or_else(|| Refused::CannotStart("no command was given".to_owned()))?;
    let status = std::process::Command::new(program)
        .args(rest)
        .status()
        .map_err(|e| Refused::CannotStart(format!("{program}: {e}")))?;
    Ok(status.code().unwrap_or(1))
}

/// Ask the agent to run `args`, in this process's working directory, and exit with its answer.
///
/// The request socket is the one of the plain folder, asked first when it is there (see [`requestable`]).
fn via_agent(id: &SessionId, args: &[String]) -> Result<i32, Refused> {
    let cwd = std::env::current_dir().map_err(|e| Refused::CannotStart(format!("the working directory: {e}")))?;
    let cwd = cwd
        .to_str()
        .ok_or_else(|| Refused::CannotStart(format!("the working directory {} is not valid Unicode", cwd.display())))?;
    let request = request_for(id, args, cwd);
    request.check().map_err(|e| Refused::CannotStart(format!("{e:#}")))?;

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

    // The socket was there a moment ago: one that is gone now, or left by an agent that ended, is the same
    // refusal as no socket, and it exits as a refusal does.
    let gone = std::cell::Cell::new(false);
    let connect = || crate::afunix::split(folder.connect_request()?);
    let no_session = |e: &anyhow::Error| {
        let none = is_no_agent(e);
        gone.set(none);
        none
    };
    let no_session_line = Refused::NotHosted.text();
    let code = ask_at(
        connect,
        |rx, tx, err| elevate_on(rx, tx, err, &request),
        no_session,
        no_session_line.trim_end(),
        &mut std::io::stderr(),
        |code| code,
    );
    Ok(if gone.get() { REFUSED_EXIT_CODE } else { code })
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
