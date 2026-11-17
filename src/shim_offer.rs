//! shim_offer: what the shim does when a user has no reachable agent.
//!
//! `plan` decides, from facts and without touching anything, whether to say nothing, print the
//! one-line notice of a session without a terminal, or run the offer at the console. The offer is
//! `offer::offer` over the real console (`ConsolePrompt`); when it starts a background session,
//! this waits, on real primitives and without a timeout, until the agent's socket answers.

use std::cell::RefCell;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock, PoisonError};

use anyhow::Context;
use socket2::Socket;
use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
use windows::Win32::System::Threading::{GetExitCodeProcess, INFINITE, WaitForMultipleObjects};

use crate::account::{self, LocalAccount};
use crate::acl::Sid;
use crate::console_modes::ConsoleModes;
use crate::console_prompt::{ConsolePrompt, absence, console_available, is_no_agent};
use crate::logon::{self, StartedAgent, Survival};
use crate::offer::{
    Absence, AccountKind, Disconnected, OfferIo, Offered, SessionKind, StartFailure, non_interactive_notice, offer,
    text,
};
use crate::password_entry::{Password, Step};
use crate::provision::procwait;
use crate::socket_loc::SocketLocation;
use crate::socket_watch::SocketWatch;
use crate::userdir::SocketDir;
use crate::{provision, starting_agent};

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
    /// The user's folder cannot be used (`cause` says what failed and, for a refusal, what to do), so
    /// no agent can serve it: `cause` on stderr (unless the log's failure already says it), no
    /// prompt, no agent started.
    FolderRefused { cause: String },
}

/// Decide. `exec` is whether the session carries a command; `console` whether stdin and stdout are a
/// console. A command, or no console, is a session without a terminal: it never prompts.
///
/// `Absence::Other` (an agent that exists but cannot be reached, a path that is too long, ...) keeps
/// today's message alone, because the notice's first sentence would be false for it. A non-local
/// account is not told to run a command it cannot use.
///
/// `folder_refusal` is why the user's folder cannot be used, if it cannot (see [`Folder::refusal`]). It
/// decides before anything else: the account, the absence and the console do not change that an
/// offer, a prompt or a started agent would only end in the same failure.
pub fn plan(
    exec: bool,
    console: bool,
    absence: Absence,
    account: Option<LocalAccount>,
    folder_refusal: Option<&str>,
) -> Plan {
    if let Some(cause) = folder_refusal {
        return Plan::FolderRefused {
            cause: cause.to_owned(),
        };
    }
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

/// Connect, and while that is refused wait for the folder to change or the agent to end. `connect`
/// is `Ok(None)` when nothing listens yet (see [`connect_if_listening`]); any other failure ends the
/// wait as an error, since waiting does not clear it.
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
    mut connect: impl FnMut() -> anyhow::Result<Option<C>>,
    mut wait: impl FnMut() -> anyhow::Result<Woke>,
    mut rearm: impl FnMut() -> anyhow::Result<()>,
) -> anyhow::Result<Served<C>> {
    loop {
        if let Some(connected) = connect()? {
            return Ok(Served::Connected(connected));
        }
        match wait()? {
            Woke::Changed => rearm()?,
            Woke::AgentExited(code) => {
                return Ok(match connect()? {
                    Some(connected) => Served::Connected(connected),
                    None => Served::Ended { code },
                });
            }
            Woke::Gone => {
                return Ok(match connect()? {
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
    mut connect: impl FnMut() -> anyhow::Result<Option<C>>,
    mut look: impl FnMut() -> anyhow::Result<bool>,
    mut wait: impl FnMut() -> anyhow::Result<Woke>,
    mut rearm: impl FnMut() -> anyhow::Result<()>,
) -> anyhow::Result<Starting<C>> {
    let mut seen = false;
    loop {
        if let Some(connected) = connect()? {
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
    mut connect: impl FnMut(&SocketLocation) -> anyhow::Result<Option<C>>,
) -> anyhow::Result<Served<C>> {
    let watch = RefCell::new(watch);
    wait_until_serving(
        || {
            let watch = watch.borrow();
            watch.location().map_or(Ok(None), &mut connect)
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

// the shim's folder -----

/// What the shim's first walk to its folder found.
enum Walk {
    /// The folders, held: the shim connects through them and logs into them.
    Open(Box<SocketDir>),
    /// `AppData`, `Local` or the private folder is not there, which a connect by path called no agent.
    Missing(Looking),
    /// The walk refused a folder, or could not go on (a sharing violation, a system error): no agent
    /// serves a folder that check refuses, so the shim does not connect.
    Refused(anyhow::Error),
    /// There was no location or no account to walk with; the cause is the error.
    Unwalked(anyhow::Error),
}

/// A folder the shim's walk did not find. It looks again when asked to connect, and keeps what it finds:
/// it goes from missing to found at most once and never back.
struct Looking {
    /// What the first walk did not find: why there is no log, which is asked once, before any connect.
    missing: crate::acl::Missing,
    location: SocketLocation,
    user: Sid,
    found: OnceLock<Box<SocketDir>>,
    /// What the latest look refused, if it did: a look that finds the folder missing, or usable, clears it.
    refused: Mutex<Option<String>>,
}

impl Looking {
    /// The folders, found now or earlier. The walk that looks again makes nothing. What it does not
    /// find is its own error: the folder missing now, or the refusal of what is there now.
    fn folders(&self) -> anyhow::Result<&SocketDir> {
        if let Some(found) = self.found.get() {
            return Ok(found);
        }
        let looked = crate::userdir::inspect_socket_dir(&self.location, &self.user);
        *self.refused.lock().unwrap_or_else(PoisonError::into_inner) = match &looked {
            Err(e) if !e.is::<crate::acl::Missing>() => Some(format!("{e:#}")),
            Ok(_) | Err(_) => None,
        };
        looked.map(|folders| &**self.found.get_or_init(|| Box::new(folders)))
    }
}

/// The shim's folder, from its first act to the end of the run: the location its token gives and the
/// folders of the walk to it, held (so the location's path names them for as long as the shim runs).
/// The shim connects to its agent only through this, and only when the private folder was accepted. A folder
/// that was not there at the first act is looked for again at each connect.
pub(crate) struct Folder {
    location: anyhow::Result<SocketLocation>,
    walk: Walk,
}

impl Folder {
    /// The folder of the account this process runs as.
    pub fn of_current_user() -> Folder {
        Folder::in_location(crate::userdir::current_socket_location(), Sid::current_user())
    }

    /// The folder at `location`, walked as `user`, with the private folder made if it is missing. An
    /// account that cannot be told is not walked.
    pub fn in_location(location: anyhow::Result<SocketLocation>, user: anyhow::Result<Sid>) -> Folder {
        let walk = match (&location, user) {
            (Ok(location), Ok(user)) => match crate::userdir::open_socket_dir(location, &user) {
                Ok(folders) => Walk::Open(Box::new(folders)),
                Err(e) => match e.downcast_ref::<crate::acl::Missing>() {
                    Some(missing) => Walk::Missing(Looking {
                        missing: missing.clone(),
                        location: location.clone(),
                        user,
                        found: OnceLock::new(),
                        refused: Mutex::new(None),
                    }),
                    None => Walk::Refused(e),
                },
            },
            (Err(e), _) => Walk::Unwalked(anyhow::anyhow!("{e:#}")),
            // The cause reaches a login with a command through the log's failure.
            (Ok(_), Err(e)) => Walk::Unwalked(e),
        };
        Folder { location, walk }
    }

    pub fn location(&self) -> &anyhow::Result<SocketLocation> {
        &self.location
    }

    /// Why the private folder cannot be used, if the latest look at it refused it (a link, an owner, an
    /// ACL, a file where a folder is wanted) or failed on the way (access denied, an untrusted mount
    /// point): neither lets an agent serve. The latest look is the first walk, or the last connect that
    /// looked again. `None` when it was accepted, is not there yet (a first login: no profile, no
    /// `AppData`, no folder), or was not walked. A `logs` folder that is refused costs the log only.
    pub fn refusal(&self) -> Option<String> {
        match &self.walk {
            Walk::Refused(e) => Some(format!("{e:#}")),
            Walk::Missing(looking) => looking.refused.lock().unwrap_or_else(PoisonError::into_inner).clone(),
            Walk::Open(_) | Walk::Unwalked(_) => None,
        }
    }

    /// The folder the log goes into, or why there is none. A refused `logs` folder costs the log only.
    pub fn logs(&self) -> anyhow::Result<&crate::acl::DirHandle> {
        match &self.walk {
            Walk::Open(folders) => folders.logs.as_ref().map_err(|e| anyhow::anyhow!("{e:#}")),
            Walk::Missing(looking) => Err(looking.missing.clone().into()),
            Walk::Refused(e) | Walk::Unwalked(e) => Err(anyhow::anyhow!("{e:#}")),
        }
    }

    /// Connect to the agent through the folders held. With no folder accepted there is nothing to
    /// connect through: the error is the walk's, and for a missing folder it is [`is_no_agent`] unless
    /// the folder is there by now, when the connect goes through it.
    pub fn connect(&self) -> anyhow::Result<Socket> {
        match &self.walk {
            Walk::Open(folders) => folders.connect(),
            Walk::Missing(looking) => looking.folders()?.connect(),
            Walk::Refused(e) => Err(anyhow::anyhow!(
                "not connecting through a folder that cannot be used: {e:#}"
            )),
            Walk::Unwalked(e) => Err(anyhow::anyhow!("nothing to connect through: {e:#}")),
        }
    }
}

// the shim's hook -----

/// A shim that found no agent, as the rescue sees it.
pub(crate) struct Absent<'a> {
    /// The session carries a command.
    pub exec: bool,
    /// What the shim's first walk found: where the socket is, and whether the folder was refused.
    pub folder: &'a Folder,
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
        let location = absent.folder.location();
        let kind_of_absence = absence(absent.connect, location);
        // An agent that has made its socket and not yet called `listen()`, or that has started and not
        // yet made its socket, refuses the connect like no agent at all. It is waited for, never
        // prompted over.
        if let (Absence::NoAgent, Ok(location), None) = (kind_of_absence, location, absent.folder.refusal()) {
            match Sid::current_user().and_then(|user| {
                await_starting_agent(location, &provision::canonical_exe(), &user, || {
                    listening(absent.folder.connect().map_err(folder_failure), location)
                })
            }) {
                Ok(Starting::Served(socket)) => return Rescued::Connected { socket, modes: None },
                Ok(Starting::No | Starting::Gone) => {}
                Err(e) => return starting_failed(&e, stderr),
            }
        }
        let console = !absent.exec && console_available();
        // The latest look: the connects of the wait above look at the folder again.
        let cause = absent.folder.refusal();
        match plan(absent.exec, console, kind_of_absence, account, cause.as_deref()) {
            Plan::Nothing => Rescued::Plain,
            Plan::FolderRefused { cause } => {
                // A login with a command is told the cause once, by the fail-open line, which carries
                // `Folder::refusal` (see `shim_pty::connect_or_rescue`).
                if !absent.exec {
                    let _ = writeln!(stderr, "{}", text::folder_refused(&cause));
                }
                Rescued::Plain
            }
            Plan::Notice { user } => {
                let exe = provision::canonical_exe();
                let _ = writeln!(stderr, "{}", non_interactive_notice(&user, &exe.to_string_lossy()));
                Rescued::Plain
            }
            Plan::Offer { account, absence } => run_offer(account, absence),
        }
    }
}

/// The rescue when looking for a starting agent failed: no session is offered, and the login goes on
/// in a plain shell.
///
/// What this can say is a failure of the user's folder found after the shim's walk accepted it (a
/// link put there since): the same line on stderr, as the notice is told. The log did not find it
/// (the walk that set the log up accepted the folder), so no line of the fail-open says it. Any other
/// failure is logged.
fn starting_failed(e: &anyhow::Error, stderr: &mut dyn Write) -> Rescued {
    tracing::warn!("cannot tell whether an agent is starting, so no session is offered: {e:#}");
    if e.is::<FolderFailed>() {
        let _ = writeln!(stderr, "{}", text::folder_refused(&format!("{e:#}")));
    }
    Rescued::Plain
}

/// A started background session, until its socket answers.
struct Started {
    agent: StartedAgent,
}

/// The line for the user when the session just started ends, or may end, with this connection, or `None`.
fn survival_notice(survival: Survival) -> Option<&'static str> {
    match survival {
        Survival::OutlivesConnection => None,
        Survival::EndsWithConnection => Some(text::SESSION_ENDS_WITH_CONNECTION_LINE),
        Survival::MayEndWithConnection => Some(text::SESSION_MAY_END_WITH_CONNECTION_LINE),
    }
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
        self.prompt.read_step().map_err(|e| {
            tracing::warn!("the console input failed: {e}");
            Disconnected
        })
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
            let survival = started.agent.survival;
            match settle(started) {
                Ok(socket) => {
                    if let Some(line) = survival_notice(survival) {
                        prompt.write_text(line);
                    }
                    Rescued::Connected {
                        socket,
                        modes: Some(prompt.into_modes()),
                    }
                }
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
    let logs = || logs_dir(crate::userdir::current_socket_location());
    let failed = |e: anyhow::Error| text::start_failed(&format!("{e:#}"));
    let user = Sid::current_user().map_err(failed)?;
    let watch = SocketWatch::for_current_user().map_err(failed)?;
    // Each connect walks to the folder and holds it first: the profile may not have existed when the
    // wait began, and the folders the agent makes are not the ones that were looked at before.
    let served =
        wait_for_agent(watch, agent.process.0, |location| connect_if_listening(location, &user)).map_err(failed)?;
    let served = serve_after_own_agent(served, || {
        let location = crate::userdir::current_socket_location()?;
        let user = Sid::current_user()?;
        await_starting_agent(&location, &provision::canonical_exe(), &user, || {
            connect_if_listening(&location, &user)
        })
    })
    .map_err(failed)?;
    match served {
        Served::Connected(socket) => Ok(socket),
        Served::Ended { code } => Err(text::agent_ended(code, logs().as_deref())),
        // `Woke::Gone` is never returned by the wait above, which watches the agent's own process.
        Served::Gone => Err(text::start_failed("the agent ended before it served")),
    }
}

/// The folder of the agent's log, if the socket location is known; otherwise `None`, and why is logged.
fn logs_dir(location: anyhow::Result<SocketLocation>) -> Option<PathBuf> {
    match location {
        Ok(location) => Some(location.logs_dir()),
        Err(e) => {
            tracing::warn!("cannot tell where the agent's log is: {e:#}");
            None
        }
    }
}

// a starting agent -----

/// Walk to the user's folder as the agent does, making nothing, and connect through the folders held.
/// `Ok(None)` is "nobody listens there": the folder or the socket file is missing, or the file is
/// there and `listen()` has not run (see [`is_no_agent`]). Any other failure (a folder refused,
/// access denied, a path too long, a protocol error) is not a sign that an agent is starting and
/// does not clear by waiting, so it is an error. A refusal is a [`FolderFailed`].
fn connect_if_listening(location: &SocketLocation, user: &Sid) -> anyhow::Result<Option<Socket>> {
    let folders = match crate::userdir::inspect_socket_dir(location, user) {
        Ok(folders) => folders,
        Err(e) if e.is::<crate::acl::Missing>() => return Ok(None),
        Err(e) => return Err(folder_failure(e)),
    };
    listening(folders.connect(), location)
}

/// The outcome of a connect to the socket at `location` as [`connect_if_listening`] gives it: `Ok(None)`
/// when nobody listens there.
fn listening(connected: anyhow::Result<Socket>, location: &SocketLocation) -> anyhow::Result<Option<Socket>> {
    match connected {
        Ok(socket) => Ok(Some(socket)),
        Err(e) if is_no_agent(&e) => Ok(None),
        // A refusal of the folder is shown as itself.
        Err(e) if e.is::<FolderFailed>() => Err(e),
        Err(e) => Err(e.context(format!("connect to the agent's socket {}", location.path().display()))),
    }
}

/// The user's folder, or the lock file in it, was refused (or could not be opened on the way) while
/// the shim looked for a starting agent. Its text is the cause's.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
struct FolderFailed(anyhow::Error);

/// `e` as [`FolderFailed`] if it is a refusal of the object looked at (a link, a name that is not
/// the folder's own). What the lock, the event or the thread says nothing of the folder.
fn folder_failure(e: anyhow::Error) -> anyhow::Error {
    if e.is::<crate::acl::Refused>() {
        FolderFailed(e).into()
    } else {
        e
    }
}

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
    /// The lock is looked at through the handle of the user's folder, opened afresh each time
    /// because the agent may not have made the folder yet; a folder that is not there holds no lock.
    fn look(&mut self, location: &SocketLocation, image: &Path, user: &Sid) -> anyhow::Result<bool> {
        self.agents = procwait::user_agents(image, user).context("look for the user's agent processes")?;
        let folder = crate::userdir::open_existing_socket_dir(location).map_err(FolderFailed)?;
        let held = match &folder {
            Some(folder) => starting_agent::is_held(folder)
                .context("tell whether an agent holds the user's lock")
                .map_err(folder_failure)?,
            None => false,
        };
        match (&folder, held) {
            (Some(folder), true) if self.holder.is_none() => {
                self.holder = Some(starting_agent::HolderWatch::start(folder).map_err(folder_failure)?);
            }
            (_, true) => {}
            (_, false) => self.holder = None,
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
///
/// `connect` is [`connect_if_listening`] by a walk of its own, or the shim's own [`Folder`] where the shim
/// has one that was walked from its token (the rescue of a login).
fn await_starting_agent(
    location: &SocketLocation,
    image: &Path,
    user: &Sid,
    mut connect: impl FnMut() -> anyhow::Result<Option<Socket>>,
) -> anyhow::Result<Starting<Socket>> {
    let watch = RefCell::new(SocketWatch::for_location(location)?);
    let evidence = RefCell::new(Evidence::default());
    wait_while_starting(
        &mut connect,
        || evidence.borrow_mut().look(location, image, user),
        || evidence.borrow_mut().wait(&watch.borrow()),
        || watch.borrow_mut().rearm(),
    )
}

#[cfg(test)]
#[path = "shim_offer_tests.rs"]
mod shim_offer_tests;
