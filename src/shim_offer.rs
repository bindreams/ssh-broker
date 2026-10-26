//! shim_offer: what the shim does when a user has no reachable agent.
//!
//! `plan` decides, from facts and without touching anything, whether to say nothing, print the
//! one-line notice of a session without a terminal, or run the offer at the console. The offer is
//! `offer::offer` over the real console (`ConsolePrompt`); when it starts a background session,
//! this waits, on real primitives and without a timeout, until the agent's socket answers.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Context;
use socket2::Socket;
use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
use windows::Win32::Storage::FileSystem::{
    FILE_NOTIFY_CHANGE_FILE_NAME, FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_CHANGE_SIZE, FindCloseChangeNotification,
    FindFirstChangeNotificationW, FindNextChangeNotification,
};
use windows::Win32::System::Threading::{INFINITE, WaitForMultipleObjects};
use windows::core::PCWSTR;

use crate::account::{self, LocalAccount};
use crate::console_modes::ConsoleModes;
use crate::console_prompt::{ConsolePrompt, absence, console_available};
use crate::logon::{self, StartedAgent};
use crate::offer::{
    Absence, AccountKind, Disconnected, OfferIo, Offered, SessionKind, StartFailure, non_interactive_notice, offer,
    text,
};
use crate::password_entry::{Password, Step};
use crate::ready::{ReadyEvent, Waited};
use crate::socket_loc::SocketLocation;
use crate::{afunix, provision};

// plan -----

/// What the shim does about a missing agent, before anything is touched.
#[derive(Debug, PartialEq, Eq)]
pub enum Plan {
    /// Today's behaviour, unchanged.
    Nothing,
    /// A session without a terminal: one stderr line naming `ssh -t` and `auto-login on`.
    Notice { user: String },
    /// A terminal and no command: run the offer.
    Offer { account: LocalAccount, absence: Absence },
}

/// Decide. `exec` is whether the session carries a command; `console` whether stdin and stdout are a
/// console. A command, or no console, is a session without a terminal: it never prompts.
///
/// `Absence::Other` (an agent that exists but cannot be reached, a path that is too long, ...) keeps
/// today's message alone, because the notice's first sentence would be false for it. A non-local
/// account is not told to run a command it cannot use.
pub fn plan(exec: bool, console: bool, absence: Absence, account: Option<LocalAccount>) -> Plan {
    let Some(account) = account else {
        return Plan::Nothing;
    };
    if absence == Absence::Other {
        return Plan::Nothing;
    }
    if !exec && console {
        return Plan::Offer { account, absence };
    }
    match account.kind {
        AccountKind::Local => Plan::Notice { user: account.name },
        AccountKind::NotLocal => Plan::Nothing,
    }
}

// wait_until_serving -----

/// What woke the wait for a starting agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Woke {
    /// The folder changed (the agent's `serving` marker, or anything else in it).
    Changed,
    /// The agent process ended with this exit code.
    AgentExited(u32),
}

/// How the wait ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Served<C> {
    Connected(C),
    /// The agent ended and nothing else serves.
    Ended {
        code: u32,
    },
}

/// Connect, and while that is refused wait for the folder to change or the agent to end.
///
/// The watch is armed by the caller before the first `connect`. After a wake it is re-armed **before**
/// the next connect, so a change between the wake and that connect is seen by the connect or by the
/// re-armed watch. A connect in the window between the socket file's creation and `listen()` is
/// refused, and the marker the agent writes after `listen()` is the change that wakes the shim again:
/// nothing is inferred from the file's creation.
///
/// When the agent has ended, connect once more: the loser of a start race exits 0 while another agent
/// serves, and an agent that left non-zero can still have a serving peer.
pub fn wait_until_serving<C>(
    mut connect: impl FnMut() -> Option<C>,
    mut wait: impl FnMut() -> anyhow::Result<Woke>,
    mut rearm: impl FnMut() -> anyhow::Result<()>,
) -> anyhow::Result<Served<C>> {
    loop {
        if let Some(connected) = connect() {
            return Ok(Served::Connected(connected));
        }
        match wait()? {
            Woke::Changed => rearm()?,
            Woke::AgentExited(code) => {
                return Ok(match connect() {
                    Some(connected) => Served::Connected(connected),
                    None => Served::Ended { code },
                });
            }
        }
    }
}

/// A directory-change watch on the socket folder: file names, size, last write.
struct DirWatch(HANDLE);

impl DirWatch {
    fn arm(dir: &Path) -> anyhow::Result<DirWatch> {
        use std::os::windows::ffi::OsStrExt;
        let dir_w: Vec<u16> = dir.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
        // SAFETY: a NUL-terminated path; the handle is closed on drop.
        unsafe {
            FindFirstChangeNotificationW(
                PCWSTR(dir_w.as_ptr()),
                false,
                FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE,
            )
        }
        .map(DirWatch)
        .with_context(|| format!("watch {}", dir.display()))
    }

    fn rearm(&self) -> anyhow::Result<()> {
        // SAFETY: a valid watch handle.
        unsafe { FindNextChangeNotification(self.0) }.context("re-arm the folder watch")
    }
}

impl Drop for DirWatch {
    fn drop(&mut self) {
        // SAFETY: the handle from `arm`.
        let _ = unsafe { FindCloseChangeNotification(self.0) };
    }
}

// the shim's hook -----

/// A shim that found no agent, as the rescue sees it.
pub(crate) struct Absent<'a> {
    /// The session carries a command.
    pub exec: bool,
    pub location: &'a anyhow::Result<SocketLocation>,
    pub connect: &'a anyhow::Result<Socket>,
}

/// How the shim goes on.
pub(crate) enum Rescued {
    /// A session now serves: relay into it. `modes` is the raw console the prompt used, to be
    /// reused by the interactive relay.
    Connected {
        socket: Socket,
        modes: Option<ConsoleModes>,
    },
    /// Carry on with today's fail-open.
    Plain,
    /// The input is gone: end the shim without running anything.
    Gone,
}

/// What the shim does about a missing agent. A trait so the tests of the shim's wiring do not open a
/// prompt on whatever console runs them.
pub(crate) trait Rescue {
    fn rescue(&mut self, absent: &Absent<'_>, stderr: &mut dyn Write) -> Rescued;
}

/// The shim of today: no prompt, no notice. For the tests of the shim's wiring.
#[cfg(test)]
pub(crate) struct NoRescue;

#[cfg(test)]
impl Rescue for NoRescue {
    fn rescue(&mut self, _absent: &Absent<'_>, _stderr: &mut dyn Write) -> Rescued {
        Rescued::Plain
    }
}

/// The real thing: the notice on stderr, or the prompt at the console.
pub(crate) struct Prompting;

impl Rescue for Prompting {
    fn rescue(&mut self, absent: &Absent<'_>, stderr: &mut dyn Write) -> Rescued {
        let account = match account::current_account() {
            Ok(account) => Some(account),
            Err(e) => {
                tracing::warn!("cannot tell who this is, so no session is offered: {e:#}");
                None
            }
        };
        let kind_of_absence = absence(absent.connect, absent.location);
        let console = !absent.exec && console_available();
        match plan(absent.exec, console, kind_of_absence, account) {
            Plan::Nothing => Rescued::Plain,
            Plan::Notice { user } => {
                let exe = provision::canonical_exe();
                let _ = writeln!(stderr, "{}", non_interactive_notice(&user, &exe.to_string_lossy()));
                Rescued::Plain
            }
            Plan::Offer { account, absence } => run_offer(account, absence),
        }
    }
}

/// A started background session, until its socket answers.
struct Started {
    ready: ReadyEvent,
    agent: StartedAgent,
}

/// The console and the logon, as `offer` drives them.
struct LiveIo {
    prompt: ConsolePrompt,
    account: LocalAccount,
    exe: PathBuf,
    started: Option<Started>,
}

impl OfferIo for LiveIo {
    fn write(&mut self, text: &str) {
        self.prompt.write_text(text);
    }

    fn read_password(&mut self) -> Result<Step, Disconnected> {
        self.prompt.read_step()
    }

    fn start_session(&mut self, password: &Password) -> Result<(), StartFailure> {
        let (ready, name) = ReadyEvent::create().map_err(|e| StartFailure::Internal {
            reason: format!("{e:#}"),
        })?;
        match logon::start_background_agent(&self.account, password, &self.exe, &name) {
            Ok(agent) => {
                self.started = Some(Started { ready, agent });
                Ok(())
            }
            Err(failure) => Err(StartFailure::Windows { reason: failure.reason }),
        }
    }
}

fn run_offer(account: LocalAccount, kind_of_absence: Absence) -> Rescued {
    let prompt = match ConsolePrompt::enter() {
        Ok(Some(prompt)) => prompt,
        Ok(None) => return Rescued::Plain,
        Err(e) => {
            tracing::warn!("could not take the console for a password prompt: {e:#}");
            return Rescued::Plain;
        }
    };
    let mut io = LiveIo {
        prompt,
        account: account.clone(),
        exe: provision::canonical_exe(),
        started: None,
    };
    match offer(SessionKind::Pty, account.kind, kind_of_absence, &account.name, &mut io) {
        Offered::Gone => Rescued::Gone,
        Offered::Plain => Rescued::Plain,
        Offered::Started => {
            let LiveIo {
                mut prompt, started, ..
            } = io;
            let Some(started) = started else {
                debug_assert!(false, "a started offer holds its agent");
                return Rescued::Plain;
            };
            match settle(started) {
                Ok(socket) => Rescued::Connected {
                    socket,
                    modes: Some(prompt.into_modes()),
                },
                Err(line) => {
                    prompt.write_text(&line);
                    prompt.write_text(text::COST_LINE);
                    Rescued::Plain
                }
            }
        }
    }
}

/// Wait until the agent just started serves and return the connection, or the line that says why
/// it will not. Every wait here is on the agent itself: its ready event, its process, and the
/// folder it writes into.
fn settle(started: Started) -> Result<Socket, String> {
    let Started { ready, agent } = started;
    let logs = || {
        crate::userdir::current_socket_location()
            .map(|location| location.logs_dir())
            .unwrap_or_default()
    };
    // 1. The agent's socket folder exists, or the agent ended first.
    match ready.wait_with(agent.process.0) {
        Ok(Waited::Ready) => {}
        Ok(Waited::AgentExited(code)) => return Err(text::agent_ended(code, &logs())),
        Err(e) => return Err(text::start_failed(&format!("{e:#}"))),
    }
    // 2. The profile exists now: look for the socket again, from this process's own token.
    let location = crate::userdir::current_socket_location().map_err(|e| text::start_failed(&format!("{e:#}")))?;
    // 3 and 4.
    let watch = DirWatch::arm(&location.dir).map_err(|e| text::start_failed(&format!("{e:#}")))?;
    let served = wait_until_serving(
        || afunix::connect(&location.path).ok(),
        || {
            let handles = [watch.0, agent.process.0];
            // SAFETY: both handles are valid for the call.
            let woke = unsafe { WaitForMultipleObjects(&handles, false, INFINITE) };
            if woke == WAIT_OBJECT_0 {
                return Ok(Woke::Changed);
            }
            if woke.0 == WAIT_OBJECT_0.0 + 1 {
                let mut code = 0u32;
                // SAFETY: a valid process handle and out-pointer.
                unsafe { windows::Win32::System::Threading::GetExitCodeProcess(agent.process.0, &mut code) }
                    .context("read the agent's exit code")?;
                return Ok(Woke::AgentExited(code));
            }
            anyhow::bail!("waiting for the agent's socket failed: {woke:?}")
        },
        || watch.rearm(),
    )
    .map_err(|e| text::start_failed(&format!("{e:#}")))?;
    match served {
        Served::Connected(socket) => Ok(socket),
        Served::Ended { code } => Err(text::agent_ended(code, &location.logs_dir())),
    }
}

#[cfg(test)]
#[path = "shim_offer_tests.rs"]
mod shim_offer_tests;
