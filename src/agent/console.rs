//! The agent lets go of the console it was started with, so that none shows on the desktop.
//!
//! The logon task starts a console program, and the system gives it a console window on the user's
//! desktop (or a Windows Terminal tab, as the user's default terminal). The agent has no use for that
//! console: it reads nothing from it and writes nothing to it. [`detach_if_alone`] frees it first
//! thing, which closes the window once the console host sees its last client go.
//!
//! The standard handles are then set to null (see [`detach_if_alone`]), so that a write to stderr (a
//! refusal's text) is harmless.
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

use std::num::NonZeroU32;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Console::{
    FreeConsole, GetConsoleProcessList, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, SetStdHandle,
};
use windows::core::HRESULT;

/// What [`detach_if_alone`] did with the agent's console.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetachOutcome {
    /// The agent was alone on its console and freed it. `std_handles_error` is why its standard handles
    /// could not be set to null, if they could not: the console is freed all the same.
    Detached { std_handles_error: Option<HRESULT> },
    /// Other processes use the console. The agent kept it.
    Shared { processes: u32 },
    /// The agent has no console to free: the count of its console's processes came back zero, with
    /// the system error `error` (not measured which one a process without a console gets).
    NoConsole { error: u32 },
}

/// Free the console of this process if no other process uses it, and set the standard handles to null.
/// The error is the failure of `FreeConsole`, with the console, and its window, still there.
///
/// **The count and the free are two calls, and no call does both.** A process that attaches to this
/// console by id (`AttachConsole`) between them keeps the console, and its window, open: the agent
/// frees its side either way, and the window closes when that process leaves. A process that leaves
/// between them leaves the agent holding a console it counted as shared: the window stays and the
/// agent has no second look.
///
/// **Null standard handles.** After `FreeConsole` the standard handles keep their numbers, which may
/// name nothing or, once reused, a file or a socket; a null standard handle is one Rust's stdio treats
/// as absent, and a write to it is dropped (a refusal's text, which `main` prints, must not end the
/// process, or land in a file). No handle is opened for it.
pub fn detach_if_alone() -> windows::core::Result<DetachOutcome> {
    detach_with(count_processes(), || {
        // SAFETY: no pointers; this process's own console.
        unsafe { FreeConsole() }?;
        Ok(null_std_handles().err().map(|e| e.code()))
    })
}

/// The number of processes on this process's console, or the system error of the call, which answers
/// zero.
fn count_processes() -> Result<NonZeroU32, u32> {
    // Room for two: more than one process is all that matters, and a longer list than the buffer is
    // answered with the count it would need.
    let mut list = [0u32; 2];
    // SAFETY: the buffer is valid for its length.
    let counted = unsafe { GetConsoleProcessList(&mut list) };
    // SAFETY: no pointers; this thread's last error.
    NonZeroU32::new(counted).ok_or_else(|| unsafe { windows::Win32::Foundation::GetLastError() }.0)
}

/// [`detach_if_alone`] over the count of processes on the console and the call that frees it (and
/// answers whether the standard handles could be set to null), so a test can see what is called for each
/// count without a console of its own.
fn detach_with(
    attached: Result<NonZeroU32, u32>,
    free: impl FnOnce() -> windows::core::Result<Option<HRESULT>>,
) -> windows::core::Result<DetachOutcome> {
    match attached {
        Ok(one) if one.get() == 1 => free().map(|std_handles_error| DetachOutcome::Detached { std_handles_error }),
        Ok(processes) => Ok(DetachOutcome::Shared {
            processes: processes.get(),
        }),
        Err(error) => Ok(DetachOutcome::NoConsole { error }),
    }
}

/// Set stdin, stdout and stderr to the null handle.
fn null_std_handles() -> windows::core::Result<()> {
    for which in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        // SAFETY: no pointers; this process's own standard handle.
        unsafe { SetStdHandle(which, HANDLE(std::ptr::null_mut())) }?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "console_tests.rs"]
mod console_tests;
