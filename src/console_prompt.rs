//! console_prompt: the password prompt on the real console, and why the shim has no agent.
//!
//! The console is already in the raw mode the relay uses (`console_modes`), so nothing is echoed and
//! Ctrl+C arrives as a key. Records are peeked one batch at a time and fed to `PasswordEntry`
//! (`batch`), except the last record of each peek, which is fed from the read that removes it (the
//! console may have merged a repeat into it since); only the records fed are taken from the
//! console's queue, and every copy is wiped.
//!
//! The same console also carries the consent question ([`ask_consent`]), which the session's shim writes and reads the
//! answer to itself.

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Console::{
    GetConsoleMode, GetNumberOfConsoleInputEvents, GetStdHandle, INPUT_RECORD, PeekConsoleInputW, ReadConsoleInputW,
    STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, WriteConsoleW,
};

use crate::consent_entry::{ConsentEntry, ConsentStep};
use crate::console_modes::ConsoleModes;
use crate::offer::Absence;
use crate::offer::text::CONSENT_SCREEN_ENTER;
use crate::password_entry::{PasswordEntry, Step};
use crate::protocol::ConsentAnswer;
use crate::socket_loc::SocketLocation;
use crate::userdir::NoProfile;

mod batch;
use batch::{Batch, InputQueue};
#[cfg(test)]
mod fake_queue;

/// Whether stdin and stdout are both a console: the precondition for a prompt. A session without
/// one is a login without a terminal and is never prompted, nor is its console mode touched.
pub fn console_available() -> bool {
    // SAFETY: plain queries on the process's standard handles.
    unsafe {
        let (Ok(stdin), Ok(stdout)) = (GetStdHandle(STD_INPUT_HANDLE), GetStdHandle(STD_OUTPUT_HANDLE)) else {
            return false;
        };
        let mut mode = windows::Win32::System::Console::CONSOLE_MODE(0);
        GetConsoleMode(stdin, &mut mode).is_ok() && GetConsoleMode(stdout, &mut mode).is_ok()
    }
}

/// The raw console, and the password being typed into it.
pub struct ConsolePrompt {
    batch: Batch,
    modes: ConsoleModes,
    entry: PasswordEntry,
}

impl ConsolePrompt {
    /// Put the console into raw mode. `Ok(None)` if there is no console (nothing was changed).
    pub fn enter() -> anyhow::Result<Option<ConsolePrompt>> {
        let modes = ConsoleModes::enter()?;
        if !modes.is_console {
            return Ok(None);
        }
        Ok(Some(ConsolePrompt {
            batch: Batch::new(),
            modes,
            entry: PasswordEntry::new(),
        }))
    }

    /// Hand the raw console on, for the relay that follows a successful logon. Input typed ahead of
    /// the prompt's end was never taken from the console's queue, so the relay reads it in order.
    pub(crate) fn into_modes(self) -> ConsoleModes {
        self.modes
    }

    /// Write `text` to the console (VT, CRLF line ends). It goes as UTF-16: raw UTF-8 bytes are read
    /// in the console's output code page, which is not UTF-8 unless something set it, and an account
    /// name with a non-ASCII letter then shows as other characters.
    pub fn write_text(&mut self, text: &str) {
        let _ = write_console(self.modes.stdout, text);
    }

    /// Block until one entry step finishes: a submitted password, an empty Enter, or a cancel. Of
    /// the console's input only the records up to the finishing one are taken: the rest stays queued
    /// for the next step or, once the prompt is over, for the relay.
    /// The error is the console input's failure (the SSH side is gone).
    pub fn read_step(&mut self) -> Result<Step, windows::core::Error> {
        let mut console = ConsoleInput(self.modes.stdin);
        self.batch.step(&mut console, &mut self.entry, &|| false)
    }
}

/// Write `text` to the console `output` as UTF-16, all of it. The error is the first write that failed or took
/// nothing.
fn write_console(output: HANDLE, text: &str) -> windows::core::Result<()> {
    let units: Vec<u16> = text.encode_utf16().collect();
    let mut rest = units.as_slice();
    while !rest.is_empty() {
        let mut written = 0u32;
        // SAFETY: `rest` and `written` are valid for the call; the handle is the console's output.
        unsafe { WriteConsoleW(output, rest, Some(&mut written), None) }?;
        if written == 0 {
            return Err(windows::core::Error::from_hresult(windows::Win32::Foundation::E_FAIL));
        }
        rest = &rest[written as usize..];
    }
    Ok(())
}

/// Take the console's screen and ask `question` on it: the person's answer is [`ConsentAnswer::Allow`] only for one
/// of `accepted`, without regard to case, and Enter. Anything else, Enter alone, Ctrl+C, a failed read and a `stop`
/// that turns true while the question waits, is [`ConsentAnswer::Refuse`], with no second question.
///
/// The answer is the next line that arrives after the question was asked. What the console had already received
/// before that, what was typed or pasted ahead and what the terminal answered to earlier queries, is the session's,
/// and nothing of it is discarded: every record queued at that moment is taken from the queue, without waiting, and
/// given to `relay` in order, before the question is written. `relay` says `false` when they could not be passed on
/// (the connection is gone): the question is then refused and not written. Keys still on their way from the person's
/// terminal when the question appears are not part of that: they count as typed after it and can answer it. The question is
/// written after the screen's reset, clear and home (`CONSENT_SCREEN_ENTER`), what is typed is echoed, and the session's
/// programs, which wrote to this terminal before and may have left it in any state, can write nothing into it: the
/// agent holds their output. Nothing is written after the answer; the agent repaints the session's screen. An error is
/// a console that could not be read or written to, and nothing was asked.
///
/// `stop` is looked at after the drain, before anything is written (a question that ended meanwhile paints nothing),
/// and in each pass of the wait for the answer, after the queue is looked at and before anything of it is fed: once
/// it is true nothing more is fed, and what is queued stays queued for the relay. Whatever makes it true must then
/// put a record in the queue (the shim's does, with `wake_console_input`), which wakes the read; nothing behind that
/// record is taken by the question.
pub fn ask_consent(
    stdin: HANDLE,
    stdout: HANDLE,
    relay: &mut dyn FnMut(&[INPUT_RECORD]) -> bool,
    question: &str,
    accepted: &[&str],
    stop: &dyn Fn() -> bool,
) -> windows::core::Result<ConsentAnswer> {
    ask_on(
        &mut ConsoleInput(stdin),
        &mut |text| write_console(stdout, text),
        relay,
        question,
        accepted,
        stop,
    )
}

/// [`ask_consent`] on a queue and a way to write that a test can stand in for.
fn ask_on(
    queue: &mut impl InputQueue,
    write: &mut dyn FnMut(&str) -> windows::core::Result<()>,
    relay: &mut dyn FnMut(&[INPUT_RECORD]) -> bool,
    question: &str,
    accepted: &[&str],
    stop: &dyn Fn() -> bool,
) -> windows::core::Result<ConsentAnswer> {
    let mut batch = Batch::new();
    if !batch.drain(queue, relay)? || stop() {
        return Ok(ConsentAnswer::Refuse);
    }
    write(&format!("{CONSENT_SCREEN_ENTER}{question}"))?;
    let mut entry = ConsentEntry::new(accepted);
    loop {
        match batch.step(queue, &mut entry, stop) {
            Ok(ConsentStep::Allow) => return Ok(ConsentAnswer::Allow),
            Ok(ConsentStep::Refuse | ConsentStep::Stopped) => return Ok(ConsentAnswer::Refuse),
            // What is typed is shown; a console that cannot show it has shown the question, and the answer is still read.
            Ok(ConsentStep::Echo(text)) => {
                if let Err(e) = write(&text) {
                    tracing::debug!("the consent question's echo could not be written: {e}");
                }
            }
            Ok(ConsentStep::Continue) => {}
            Err(e) => {
                tracing::warn!("the consent question could not be read: {e}");
                return Ok(ConsentAnswer::Refuse);
            }
        }
    }
}

/// The real console's input queue.
struct ConsoleInput(HANDLE);

impl InputQueue for ConsoleInput {
    fn queued(&mut self) -> windows::core::Result<u32> {
        let mut count = 0u32;
        // SAFETY: `count` is valid for the call; the handle is the console's input.
        unsafe { GetNumberOfConsoleInputEvents(self.0, &mut count) }?;
        Ok(count)
    }

    fn peek(&mut self, records: &mut [INPUT_RECORD]) -> windows::core::Result<u32> {
        let mut count = 0u32;
        // SAFETY: `records` and `count` are valid for the call; the handle is the console's input.
        unsafe { PeekConsoleInputW(self.0, records, &mut count) }?;
        Ok(count)
    }

    fn read(&mut self, records: &mut [INPUT_RECORD]) -> windows::core::Result<u32> {
        let mut count = 0u32;
        // SAFETY: `records` and `count` are valid for the call; the handle is the console's input.
        unsafe { ReadConsoleInputW(self.0, records, &mut count) }?;
        Ok(count)
    }
}

/// The OS errors a `connect` to the user's socket fails with when nothing serves it, as the tests
/// observed them: `WSAENETDOWN` (10050) when the folder is missing, `WSAECONNREFUSED` (10061) when
/// the socket file is missing from an existing folder or is left over from an agent that ended.
const NO_AGENT_CODES: &[i32] = &[10050, 10061];

/// Why the shim has no agent to relay into. Mapped on the **codes Windows returns**, not on
/// `ErrorKind`: a connect to a missing path fails with `WSAENETDOWN`, which `NotFound` and
/// `ConnectionRefused` would both miss, and no user would ever see the prompt.
///
/// A user without a profile can be offered a session (the logon creates the profile). A location whose
/// `agent.sock` is too long is refused before any connect ([`crate::socket_loc::SocketLocationError::TooLong`]); an
/// access denial, a protocol error and any code not observed for a missing folder, a missing file or a stale file
/// are not "no agent" either: they keep today's message and fallback. A `request.sock` over the limit is "no agent":
/// no agent at High can exist for that profile ([`crate::socket_loc::RequestPathTooLong`]).
pub fn absence(connect: &anyhow::Result<socket2::Socket>, location: &anyhow::Result<SocketLocation>) -> Absence {
    let location = match location {
        Ok(location) => location,
        Err(e) if e.downcast_ref::<NoProfile>().is_some() => return Absence::NoProfileYet,
        Err(_) => return Absence::Other,
    };
    let _ = location;
    match connect {
        Err(error) if is_no_agent(error) => Absence::NoAgent,
        _ => Absence::Other,
    }
}

/// Whether a failed walk to the user's socket and connect to it means nothing serves it: a folder of
/// the way is not there, no agent at High can exist for the profile (`request.sock`'s path is over the limit), or the
/// OS code of the connect says so. See [`absence`].
pub fn is_no_agent(error: &anyhow::Error) -> bool {
    error.is::<crate::acl::Missing>()
        || error.is::<crate::socket_loc::RequestPathTooLong>()
        || error
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::raw_os_error)
            .is_some_and(|code| NO_AGENT_CODES.contains(&code))
}

#[cfg(test)]
#[path = "console_prompt_tests.rs"]
mod console_prompt_tests;
