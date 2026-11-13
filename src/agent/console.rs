//! The agent lets go of the console it was started with, so that none shows on the desktop.
//!
//! The logon task starts a console program, and the system gives it a console window on the user's
//! desktop (or a Windows Terminal tab, as the user's default terminal). The agent has no use for that
//! console: it reads nothing from it and writes nothing to it. [`detach_if_alone`] frees it first
//! thing, which closes the window once the console host sees its last client go.
//!
//! The standard handles then point at NUL, so that a write to stderr (a refusal's text) is harmless: the
//! freed console's handle numbers may be reused by a file or a socket.
//!
//! **Only when the agent is the console's one process.** A console that other processes use (the
//! shell an operator ran `ssh-broker agent` from) is theirs, and freeing it from the agent would
//! not close it but would cut the agent off from it. Those keep it.
//!
//! **What the agent starts.** An agent without a console must give every child one that shows no
//! window: a console program started from a process with no console gets a new console, with a
//! window. So every child has a console of its own making, never the agent's:
//! - a session with a terminal runs in a pseudoconsole (`conpty`), whose host shows no window;
//! - a command on pipes starts with `CREATE_NO_WINDOW` (`pipes`), which gives it a console with no
//!   window, and also keeps a Ctrl+C it raises from reaching the agent.
//!
//! A new way to start a process in the agent takes one of the two.
//!
//! **Windows Terminal as the default terminal.** The console is then a tab or window of the terminal,
//! handed over before the agent's first line runs. It is open until [`detach_if_alone`] runs, a
//! moment, and Windows Terminal's connection code closes it when the last client leaves the console
//! with `FreeConsole` (read in its source, not measured here: CI has no Windows Terminal). The CI test
//! looks at a desktop with the system's console host.
//!
//! **Not the manifest's `consoleAllocationPolicy=detached`.** It would remove that moment, and is
//! ruled out for three reasons. It needs Windows 11 24H2 (build 26100) and earlier builds ignore it
//! (Microsoft, "Console Allocation Policy"). It is a property of the exe, and this exe is also the
//! shim, `apply`, `verify` and `console-fallback`, which run from a console and use one; their
//! behaviour under it is unmeasured, and the Windows Terminal specification for the policy says the
//! console APIs fail until a console is allocated. And `FreeConsole` does the same on every build.

use std::os::windows::io::IntoRawHandle as _;

use windows::Win32::Foundation::{ERROR_INVALID_HANDLE, HANDLE};
use windows::Win32::System::Console::{
    FreeConsole, GetConsoleProcessList, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, SetStdHandle,
};

/// What [`detach_if_alone`] did with the agent's console.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetachOutcome {
    /// The agent was alone on its console and freed it.
    Detached,
    /// Other processes use the console. The agent kept it.
    Shared { processes: u32 },
    /// The agent has no console to free.
    NoConsole,
}

/// Free the console of this process if no other process uses it, and point the standard handles at NUL.
/// The error is the failure of the count, of `FreeConsole` or of the redirection: the console, and its
/// window, stay unless `FreeConsole` itself succeeded.
///
/// **The count and the free are two calls, and no call does both.** A process that attaches to this
/// console by id (`AttachConsole`) between them keeps the console, and its window, open: the agent
/// frees its side either way, and the window closes when that process leaves. A process that leaves
/// between them leaves the agent holding a console it counted as shared: the window stays and the
/// agent has no second look.
pub fn detach_if_alone() -> windows::core::Result<DetachOutcome> {
    detach_with(count_processes, || {
        // SAFETY: no pointers; this process's own console.
        unsafe { FreeConsole() }?;
        std_handles_to_nul()
    })
}

/// The number of processes on this process's console. An error is the failure of the call, which
/// answers zero.
fn count_processes() -> windows::core::Result<u32> {
    // Room for two: more than one process is all that matters, and a longer list than the buffer is
    // answered with the count it would need.
    let mut list = [0u32; 2];
    // SAFETY: the buffer is valid for its length.
    match unsafe { GetConsoleProcessList(&mut list) } {
        0 => Err(windows::core::Error::from_thread()),
        processes => Ok(processes),
    }
}

/// [`detach_if_alone`] over the count of processes on the console and the call that frees it, so a
/// test can see what is called for each count without a console of its own.
fn detach_with(
    attached: impl FnOnce() -> windows::core::Result<u32>,
    free: impl FnOnce() -> windows::core::Result<()>,
) -> windows::core::Result<DetachOutcome> {
    match attached() {
        Ok(1) => free().map(|()| DetachOutcome::Detached),
        Ok(processes) => Ok(DetachOutcome::Shared { processes }),
        // A process without a console has no connection to ask: the call fails with an invalid handle.
        Err(e) if e.code() == ERROR_INVALID_HANDLE.to_hresult() => Ok(DetachOutcome::NoConsole),
        Err(e) => Err(e),
    }
}

/// Point stdin, stdout and stderr at one NUL handle, kept open for the life of the process.
///
/// `FreeConsole` closes the console's handles but leaves their numbers in the standard handle slots,
/// and the system may give those numbers to a file or a socket opened later: a write meant for stderr
/// (the refusal text `main` prints) would land in it.
fn std_handles_to_nul() -> windows::core::Result<()> {
    let nul = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("NUL")
        .map_err(windows::core::Error::from)?;
    let nul = HANDLE(nul.into_raw_handle());
    for which in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        // SAFETY: a handle opened here and never closed.
        unsafe { SetStdHandle(which, nul) }?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "console_tests.rs"]
mod console_tests;
