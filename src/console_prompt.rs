//! console_prompt: the password prompt on the real console, and why the shim has no agent.
//!
//! The console is already in the raw mode the relay uses (`console_modes`), so nothing is echoed and
//! Ctrl+C arrives as a key. Records are peeked one batch at a time and fed to `PasswordEntry`
//! (`batch`); only the records fed are taken from the console's queue, and every copy is wiped.

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Console::{
    GetConsoleMode, GetStdHandle, INPUT_RECORD, PeekConsoleInputW, ReadConsoleInputW, STD_INPUT_HANDLE,
    STD_OUTPUT_HANDLE, WriteConsoleW,
};

use crate::console_modes::ConsoleModes;
use crate::offer::Absence;
use crate::password_entry::{PasswordEntry, Step};
use crate::socket_loc::SocketLocation;
use crate::userdir::NoProfile;

mod batch;
use batch::{Batch, InputQueue};

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
        let units: Vec<u16> = text.encode_utf16().collect();
        let mut rest = units.as_slice();
        while !rest.is_empty() {
            let mut written = 0u32;
            // SAFETY: `rest` and `written` are valid for the call; the handle is the console's output.
            let wrote = unsafe { WriteConsoleW(self.modes.stdout, rest, Some(&mut written), None) };
            if wrote.is_err() || written == 0 {
                return;
            }
            rest = &rest[written as usize..];
        }
    }

    /// Block until one entry step finishes: a submitted password, an empty Enter, or a cancel. Of
    /// the console's input only the records up to the finishing one are taken: the rest stays queued
    /// for the next step or, once the prompt is over, for the relay.
    /// The error is the console input's failure (the SSH side is gone).
    pub fn read_step(&mut self) -> Result<Step, windows::core::Error> {
        let mut console = ConsoleInput(self.modes.stdin);
        self.batch.step(&mut console, &mut self.entry)
    }
}

/// The real console's input queue.
struct ConsoleInput(HANDLE);

impl InputQueue for ConsoleInput {
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
/// A user without a profile can be offered a session (the logon creates the profile). A path that
/// is too long, an access denial, a protocol error and any code not observed for a missing folder, a
/// missing file or a stale file are not "no agent": they keep today's message and fallback.
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

/// Whether a failed `connect` to the user's socket means nothing serves it, by the OS code.
pub fn is_no_agent(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .and_then(std::io::Error::raw_os_error)
        .is_some_and(|code| NO_AGENT_CODES.contains(&code))
}

#[cfg(test)]
#[path = "console_prompt_tests.rs"]
mod console_prompt_tests;
