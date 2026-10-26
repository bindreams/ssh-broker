//! console_prompt: the password prompt on the real console, and why the shim has no agent.
//!
//! The console is already in the raw mode the relay uses (`console_modes`), so nothing is echoed and
//! Ctrl+C arrives as a key. Records are read one batch at a time and fed to `PasswordEntry`; the
//! batch buffer is wiped after every read so that no typed character is left in it.

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Console::{
    GetConsoleMode, GetStdHandle, INPUT_RECORD, ReadConsoleInputW, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use zeroize::Zeroize;

use crate::console_modes::ConsoleModes;
use crate::offer::{Absence, Disconnected};
use crate::password_entry::{PasswordEntry, Step};
use crate::socket_loc::SocketLocation;
use crate::userdir::NoProfile;
use crate::vtinput::KeyEvent;

/// `INPUT_RECORD.EventType` of a key record.
const EVT_KEY: u16 = 0x0001;

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
            modes,
            entry: PasswordEntry::new(),
        }))
    }

    /// Hand the raw console on, for the relay that follows a successful logon.
    pub(crate) fn into_modes(self) -> ConsoleModes {
        self.modes
    }

    /// Write `text` to the console (VT, CRLF line ends).
    pub fn write_text(&mut self, text: &str) {
        crate::conpty::write_all_handle(self.modes.stdout.0 as isize, text.as_bytes());
    }

    /// Block until one entry step finishes: a submitted password, an empty Enter, or a cancel.
    /// `Disconnected` if the console input fails (the SSH side is gone).
    pub fn read_step(&mut self) -> Result<Step, Disconnected> {
        let stdin: HANDLE = self.modes.stdin;
        let mut records: [INPUT_RECORD; 32] = unsafe { std::mem::zeroed() };
        loop {
            let mut count = 0u32;
            // SAFETY: `records` and `count` are valid for the call.
            if unsafe { ReadConsoleInputW(stdin, &mut records, &mut count) }.is_err() {
                wipe_records(&mut records);
                return Err(Disconnected);
            }
            let mut finished = None;
            for record in &records[..count as usize] {
                if record.EventType != EVT_KEY {
                    continue;
                }
                // SAFETY: the event type says this is a key record.
                let key = unsafe { record.Event.KeyEvent };
                let event = KeyEvent {
                    virtual_key_code: key.wVirtualKeyCode,
                    virtual_scan_code: key.wVirtualScanCode,
                    // SAFETY: the character is read as the UTF-16 unit it is.
                    unicode_char: unsafe { key.uChar.UnicodeChar },
                    key_down: key.bKeyDown.as_bool(),
                    control_key_state: key.dwControlKeyState,
                    repeat_count: key.wRepeatCount,
                };
                match self.entry.key(&event) {
                    Step::Continue => {}
                    step => {
                        finished = Some(step);
                        break;
                    }
                }
            }
            wipe_records(&mut records);
            if let Some(step) = finished {
                return Ok(step);
            }
        }
    }
}

/// Overwrite a batch of console records: they hold the characters just typed.
fn wipe_records(records: &mut [INPUT_RECORD]) {
    // SAFETY: `INPUT_RECORD` is plain data; zeroing its bytes in place is sound.
    let bytes =
        unsafe { std::slice::from_raw_parts_mut(records.as_mut_ptr().cast::<u8>(), std::mem::size_of_val(records)) };
    bytes.zeroize();
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
    let Err(error) = connect else {
        return Absence::Other;
    };
    match error
        .downcast_ref::<std::io::Error>()
        .and_then(std::io::Error::raw_os_error)
    {
        Some(code) if NO_AGENT_CODES.contains(&code) => Absence::NoAgent,
        _ => Absence::Other,
    }
}

#[cfg(test)]
#[path = "console_prompt_tests.rs"]
mod console_prompt_tests;
