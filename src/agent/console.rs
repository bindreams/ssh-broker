//! The agent lets go of the console it was started with, so that none shows on the desktop.
//!
//! The logon task starts a console program, and the system gives it a console window on the user's
//! desktop (or a Windows Terminal tab, as the user's default terminal). The agent has no use for that
//! console: it reads nothing from it and writes nothing to it. [`detach_if_alone`] frees it first
//! thing, which closes the window once the console host sees its last client go.
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
//! Both start through [`crate::winutil::spawn_suspended`], which takes the console as an argument, so
//! no start can omit it.
//!
//! **Windows Terminal as the default terminal.** The console is then a tab handed over before the
//! agent's first line runs; `FreeConsole` closes it when the last client leaves (from its source, not
//! measured: CI has no Windows Terminal).
//!
//! **Not `consoleAllocationPolicy=detached`.** It needs build 26100, and this exe is also the shim,
//! `apply` and `verify`, which use a console; `FreeConsole` works on every build.

use std::num::NonZeroU32;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Console::{
    CONSOLE_MODE, FreeConsole, GetConsoleMode, GetConsoleProcessList, GetStdHandle, STD_ERROR_HANDLE, STD_HANDLE,
    STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, SetStdHandle,
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
    /// the system error `error`.
    NoConsole { error: u32 },
}

/// Free the console of this process if no other process uses it, and set the standard handles that refer to it to null.
/// The error is the failure of `FreeConsole`, with the console, and its window, still there.
///
/// **Contract.** The agent frees a console it is alone on when it starts. A console shared at that
/// moment is kept for the agent's life, and its window stays even if the others then leave. No call
/// counts and frees in one step: a process that attaches by id (`AttachConsole`) in between keeps the
/// console open, and its window closes when that process leaves.
///
/// **Null standard handles.** After `FreeConsole` the standard handles keep their numbers, which may
/// name nothing or, once reused, a file or a socket; a null standard handle is one Rust's stdio treats
/// as absent, and a write to it is dropped (a refusal's text, which `main` prints, must not end the
/// process, or land in a file). No handle is opened for it. Only the handles that refer to the console
/// are set: one an operator redirected to a file or a pipe is kept.
pub fn detach_if_alone() -> windows::core::Result<DetachOutcome> {
    detach_with(count_processes(), || {
        // Before the free: afterwards no handle answers as a console's.
        let console_handles = console_std_handles(is_console_handle);
        // SAFETY: no pointers; this process's own console.
        unsafe { FreeConsole() }?;
        Ok(null_std_handles(&console_handles).err().map(|e| e.code()))
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

/// The decision of [`detach_if_alone`] over injected inputs, so a test needs no console.
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

/// The standard handles for which `is_console` is true, in the order input, output, error.
fn console_std_handles(is_console: impl Fn(STD_HANDLE) -> bool) -> Vec<STD_HANDLE> {
    [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE]
        .into_iter()
        .filter(|&which| is_console(which))
        .collect()
}

/// Whether the standard handle `which` refers to a console: `GetConsoleMode` succeeds on one and fails on a
/// file, a pipe or no handle at all.
fn is_console_handle(which: STD_HANDLE) -> bool {
    // SAFETY: no pointers beyond the out-parameter, which is valid for the call.
    unsafe {
        let Ok(handle) = GetStdHandle(which) else {
            return false;
        };
        let mut mode = CONSOLE_MODE(0);
        GetConsoleMode(handle, &mut mode).is_ok()
    }
}

fn null_std_handles(which: &[STD_HANDLE]) -> windows::core::Result<()> {
    null_with(which, |which| {
        // SAFETY: no pointers; this process's own standard handle.
        unsafe { SetStdHandle(which, HANDLE(std::ptr::null_mut())) }
    })
}

/// Call `set` for every handle in `which`, whatever an earlier one answered: a handle left alone is stale
/// once the console is freed. Reports the first error.
fn null_with(
    which: &[STD_HANDLE],
    mut set: impl FnMut(STD_HANDLE) -> windows::core::Result<()>,
) -> windows::core::Result<()> {
    let mut first = Ok(());
    for &which in which {
        let set = set(which);
        if first.is_ok() {
            first = set;
        }
    }
    first
}

#[cfg(test)]
#[path = "console_tests.rs"]
mod console_tests;
