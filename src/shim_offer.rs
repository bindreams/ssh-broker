//! shim_offer: what the shim does when a user has no reachable agent.
//!
//! `plan` decides, from facts and without touching anything, whether to say nothing, print the
//! one-line notice of a session without a terminal, or run the offer at the console. The offer is
//! `offer::offer` over the real console (`ConsolePrompt`); when it starts a background session,
//! this waits, on real primitives and without a timeout, until the agent's socket answers.

use std::cell::RefCell;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Context;
use socket2::Socket;
use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
use windows::Win32::System::Threading::{GetExitCodeProcess, INFINITE, WaitForMultipleObjects};

use crate::account::{self, LocalAccount};
use crate::acl::Sid;
use crate::console_modes::ConsoleModes;
use crate::console_prompt::{ConsolePrompt, absence, console_available};
use crate::logon::{self, StartedAgent};
use crate::offer::{
    Absence, AccountKind, Disconnected, OfferIo, Offered, SessionKind, StartFailure, non_interactive_notice, offer,
    text,
};
use crate::password_entry::{Password, Step};
use crate::provision::procwait;
use crate::socket_loc::SocketLocation;
use crate::socket_watch::SocketWatch;
use crate::{afunix, provision, starting_agent};

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
    /// The holder of the user's lock, or an agent process, ended; its exit code is not known.
    Gone,
}

/// How the wait ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Served<C> {
    Connected(C),
    /// The agent ended and nothing else serves.
    Ended {
        code: u32,
    },
    /// The agent that held the user's lock ended and nothing else serves.
    Gone,
}

/// Connect, and while that is refused wait for the folder to change or the agent to end.
///
/// The watch is armed by the caller before the first `connect`. After a wake it is re-armed **before**
/// the next connect, so a change between the wake and that connect is seen by the connect or by the
/// re-armed watch. A connect in the window between the socket file's creation and `listen()` is
/// refused, and the marker the agent writes after `listen()` is the change that wakes the shim again:
/// nothing is inferred from the file's creation.
///
/// When the agent has ended (or, for an agent this process did not start, its lock was released),
/// connect once more: the loser of a start race exits 0 while another agent
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
            Woke::Gone => {
                return Ok(match connect() {
                    Some(connected) => Served::Connected(connected),
                    None => Served::Gone,
                });
            }
        }
    }
}

/// What `wait_while_starting` found out.
#[derive(Debug, PartialEq, Eq)]
pub enum Starting<C> {
    /// No agent exists, and none was seen starting.
    No,
    /// An agent was starting and now serves.
    Served(C),
    /// An agent was starting and ended without any agent serving.
    Gone,
}

/// Connect; while that is refused and an agent exists, wait for the folder to change or for an
/// agent to end. `look` says whether an agent exists: one that holds the user's lock, or a running
/// agent process of the user (which may not have taken the lock yet).
///
/// The watch is armed by the caller before the first `connect`, and re-armed after every folder
/// change before the next `connect`, as in [`wait_until_serving`]. When an agent ends (`Woke::Gone`),
/// the loop connects once more and looks again: another agent may remain, and the wait goes on
/// until none does. Refused with nobody there is `No` when no agent was ever seen, `Gone` when one was.
pub fn wait_while_starting<C>(
    mut connect: impl FnMut() -> Option<C>,
    mut look: impl FnMut() -> anyhow::Result<bool>,
    mut wait: impl FnMut() -> anyhow::Result<Woke>,
    mut rearm: impl FnMut() -> anyhow::Result<()>,
) -> anyhow::Result<Starting<C>> {
    let mut seen = false;
    loop {
        if let Some(connected) = connect() {
            return Ok(Starting::Served(connected));
        }
        if !look()? {
            return Ok(if seen { Starting::Gone } else { Starting::No });
        }
        seen = true;
        match wait()? {
            Woke::Changed => rearm()?,
            Woke::AgentExited(_) | Woke::Gone => {}
        }
    }
}

/// Wait until the agent process `agent` ends or `watch` fires, whichever is first.
fn wait_for_change_or_exit(watch: &SocketWatch, agent: HANDLE) -> anyhow::Result<Woke> {
    let handles = [watch.handle(), agent];
    // SAFETY: both handles are valid for the call.
    let woke = unsafe { WaitForMultipleObjects(&handles, false, INFINITE) };
    if woke == WAIT_OBJECT_0 {
        return Ok(Woke::Changed);
    }
    if woke.0 == WAIT_OBJECT_0.0 + 1 {
        let mut code = 0u32;
        // SAFETY: a valid process handle and out-pointer.
        unsafe { GetExitCodeProcess(agent, &mut code) }.context("read the agent's exit code")?;
        return Ok(Woke::AgentExited(code));
    }
    anyhow::bail!("waiting for the agent's socket failed: {woke:?}")
}

/// Wait, on real primitives and with no time limit, until the agent process `agent` has made a
/// connection possible: `connect` is tried on the socket's location each time the folder (or, before
/// a first logon, the profile list) changes. The location is found from the shim's own token as soon
/// as the profile exists. See [`wait_until_serving`] for the order of arming and connecting.
pub fn wait_for_agent<C>(
    watch: SocketWatch,
    agent: HANDLE,
    mut connect: impl FnMut(&SocketLocation) -> Option<C>,
) -> anyhow::Result<Served<C>> {
    let watch = RefCell::new(watch);
    wait_until_serving(
        || {
            let watch = watch.borrow();
            watch.location().and_then(&mut connect)
        },
        || {
            let woke = wait_for_change_or_exit(&watch.borrow(), agent)?;
            if let Woke::AgentExited(_) = woke {
                // The connect that follows an exit must know the location, which may have
                // appeared (a first logon) since the last look.
                watch.borrow_mut().rearm()?;
            }
            Ok(woke)
        },
        || watch.borrow_mut().rearm(),
    )
}

/// What the wait for the shim's own agent found, corrected for a start race.
///
/// Two first connections of one user each log on and each start an agent. The agent that finds the
/// session's slot taken exits 0 at once, and the winner may not be listening yet, so "my agent ended" is
/// not "nobody serves". When the own agent ended (or the lock's holder did), `others` looks for any
/// other agent of the user: one that serves is used, one that is starting is waited for, and only when
/// none exists is the end reported.
pub fn serve_after_own_agent<C>(
    own: Served<C>,
    others: impl FnOnce() -> anyhow::Result<Starting<C>>,
) -> anyhow::Result<Served<C>> {
    if let Served::Connected(_) = own {
        return Ok(own);
    }
    Ok(match others()? {
        Starting::Served(connected) => Served::Connected(connected),
        Starting::No | Starting::Gone => own,
    })
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
        // An agent that has made its socket and not yet called `listen()`, or that has started and not
        // yet made its socket, refuses the connect like no agent at all. It is waited for, never
        // prompted over.
        if let (Absence::NoAgent, Ok(location)) = (kind_of_absence, absent.location) {
            match crate::acl::Sid::current_user()
                .and_then(|user| await_starting_agent(location, &provision::canonical_exe(), &user))
            {
                Ok(Starting::Served(socket)) => return Rescued::Connected { socket, modes: None },
                Ok(Starting::No | Starting::Gone) => {}
                Err(e) => {
                    tracing::warn!("cannot tell whether an agent is starting, so no session is offered: {e:#}");
                    return Rescued::Plain;
                }
            }
        }
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
        tracing::info!(
            "asking Windows to sign {} in and start the background session",
            self.account.name
        );
        match logon::start_background_agent(&self.account, password, &self.exe) {
            Ok(agent) => {
                tracing::info!("Windows started the background session; waiting for it to serve");
                self.started = Some(Started { agent });
                Ok(())
            }
            Err(failure) => {
                tracing::info!(
                    "Windows did not sign {} in: {} ({})",
                    self.account.name,
                    failure.reason,
                    failure.code
                );
                Err(StartFailure::Windows { reason: failure.reason })
            }
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
/// it will not. Every wait here is on the agent itself: its process, and the files it writes.
fn settle(started: Started) -> Result<Socket, String> {
    let Started { agent } = started;
    let logs = || {
        crate::userdir::current_socket_location()
            .map(|location| location.logs_dir())
            .unwrap_or_default()
    };
    let failed = |e: anyhow::Error| text::start_failed(&format!("{e:#}"));
    let watch = SocketWatch::for_current_user().map_err(failed)?;
    let served =
        wait_for_agent(watch, agent.process.0, |location| afunix::connect(&location.path).ok()).map_err(failed)?;
    let served = serve_after_own_agent(served, || {
        let location = crate::userdir::current_socket_location()?;
        let user = Sid::current_user()?;
        await_starting_agent(&location, &provision::canonical_exe(), &user)
    })
    .map_err(failed)?;
    match served {
        Served::Connected(socket) => Ok(socket),
        Served::Ended { code } => Err(text::agent_ended(code, &logs())),
        // `Woke::Gone` is never returned by the wait above, which watches the agent's own process.
        Served::Gone => Err(text::start_failed("the agent ended before it served")),
    }
}

// a starting agent -----

/// What there is to wait for while an agent starts: the holder of the user's lock, and the running
/// agent processes of the user. Either one may be there without the other: an agent takes the lock
/// some time after its process starts.
#[derive(Default)]
struct Evidence {
    holder: Option<starting_agent::HolderWatch>,
    agents: Vec<procwait::Process>,
}

/// The most handles one wait takes (`MAXIMUM_WAIT_OBJECTS`) less the folder watch. The rest are
/// still in `Evidence::agents` and are waited for on a later pass.
const MAX_EVIDENCE_HANDLES: usize = 63;

impl Evidence {
    /// Look again: who holds the lock, and which agent processes run. True if any agent exists.
    fn look(&mut self, lock: &Path, image: &Path, user: &Sid) -> anyhow::Result<bool> {
        self.agents = procwait::user_agents(image, user).context("look for the user's agent processes")?;
        let held = starting_agent::is_held(lock).context("tell whether an agent holds the user's lock")?;
        if !held {
            self.holder = None;
        } else if self.holder.is_none() {
            self.holder = Some(starting_agent::HolderWatch::start(lock)?);
        }
        Ok(held || !self.agents.is_empty())
    }

    /// Wait on the folder watch and on every item of the evidence; an item that ends is
    /// `Woke::Gone`.
    fn wait(&mut self, watch: &SocketWatch) -> anyhow::Result<Woke> {
        let mut handles = vec![watch.handle()];
        handles.extend(self.holder.iter().map(starting_agent::HolderWatch::handle));
        handles.extend(self.agents.iter().map(procwait::Process::handle));
        handles.truncate(1 + MAX_EVIDENCE_HANDLES);
        // SAFETY: every handle is valid for the call: the evidence is owned by `self`.
        let woke = unsafe { WaitForMultipleObjects(&handles, false, INFINITE) };
        let index = woke.0.wrapping_sub(WAIT_OBJECT_0.0) as usize;
        if index == 0 {
            Ok(Woke::Changed)
        } else if index < handles.len() {
            // The holder's event stays set once it fires; a lock held again needs a new watch.
            if self
                .holder
                .as_ref()
                .is_some_and(|holder| holder.handle() == handles[index])
            {
                self.holder = None;
            }
            Ok(Woke::Gone)
        } else {
            anyhow::bail!("waiting for the starting agent failed: {woke:?}")
        }
    }
}

/// Whether an agent that refused the connect is only starting, and if so wait until it serves or
/// every agent has ended. An agent exists if it holds the user's lock or its process runs (see
/// [`starting_agent`] and [`procwait::user_agents`]), never by the code of the refusal.
///
/// The folder watch is armed before the connect that follows each look, so the marker the agent
/// writes after `listen()` is seen by that connect or by the watch. The wait is on the folder, the
/// lock's holder and the agent processes; all are real conditions, so it has no time limit.
fn await_starting_agent(location: &SocketLocation, image: &Path, user: &Sid) -> anyhow::Result<Starting<Socket>> {
    let lock = location.lock_path();
    let watch = RefCell::new(SocketWatch::for_location(location)?);
    let evidence = RefCell::new(Evidence::default());
    wait_while_starting(
        || afunix::connect(&location.path).ok(),
        || evidence.borrow_mut().look(&lock, image, user),
        || evidence.borrow_mut().wait(&watch.borrow()),
        || watch.borrow_mut().rearm(),
    )
}

#[cfg(test)]
#[path = "shim_offer_tests.rs"]
mod shim_offer_tests;
