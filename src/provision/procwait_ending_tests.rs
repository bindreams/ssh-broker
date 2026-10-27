//! Tests that hold a real process in the ending state: the code that tells an ending process from a
//! failure can only be shown to work against the kernel's own answers. CI only (they start a process
//! and use a debugger's event queue), like the other process tests here, and not run by hand.
//!
//! The state is made by a debugger and not by a race. A process that is debugged cannot finish
//! exiting until its debugger has taken the exit event: its last thread posts the event and waits
//! for the reply, with the process already terminated and its handle not yet signalled. The test is
//! the debugger and takes the event, then looks at the process before it replies.
use super::*;
use std::os::windows::process::CommandExt;
use std::process::{Child, Command, Stdio};

use windows::Wdk::System::Threading::PROCESSINFOCLASS;
use windows::Win32::Foundation::DBG_CONTINUE;
use windows::Win32::System::Diagnostics::Debug::{
    ContinueDebugEvent, DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT, WaitForDebugEvent,
};
use windows::Win32::System::Threading::INFINITE;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const DEBUG_ONLY_THIS_PROCESS: u32 = 0x0000_0002;

fn cmd_exe() -> PathBuf {
    PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot is set")).join(r"System32\cmd.exe")
}

/// A process that was terminated and is held in its exit by this thread, its debugger. Dropping it
/// replies to the exit event, which lets the process finish, and waits for that.
struct HeldEnding {
    child: Child,
    /// The process and thread ids of the exit event, once it has been taken and not answered.
    exit_event: Option<(u32, u32)>,
}

impl HeldEnding {
    fn start() -> HeldEnding {
        let child = Command::new(cmd_exe())
            .args(["/d", "/c", "set /p unused="])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW | DEBUG_ONLY_THIS_PROCESS)
            .spawn()
            .unwrap();
        let mut held = HeldEnding {
            child,
            exit_event: None,
        };
        // The first event is the process's creation: from here it runs, and everything it posts is
        // answered below until the one that ends it.
        let first = next_event();
        reply(&first);
        held.child.kill().unwrap();
        loop {
            let event = next_event();
            if event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT {
                held.exit_event = Some((event.dwProcessId, event.dwThreadId));
                return held;
            }
            reply(&event);
        }
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }
}

impl Drop for HeldEnding {
    fn drop(&mut self) {
        if let Some((pid, tid)) = self.exit_event {
            // SAFETY: the ids of the event this thread was handed and has not answered.
            let _ = unsafe { ContinueDebugEvent(pid, tid, DBG_CONTINUE) };
        }
        let _ = self.child.wait();
    }
}

/// The next debug event of the process this thread started. The wait has no bound: the process
/// posts one for everything it does, and the runner ends a test that never finishes.
fn next_event() -> DEBUG_EVENT {
    let mut event = DEBUG_EVENT::default();
    // SAFETY: a valid out-pointer.
    unsafe { WaitForDebugEvent(&mut event, INFINITE) }.expect("wait for a debug event of the process");
    event
}

fn reply(event: &DEBUG_EVENT) {
    // SAFETY: the ids of an event just received.
    unsafe { ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE) }.expect("reply to a debug event");
}

/// The NTSTATUS of a zero-length query of `class` on `handle`.
fn probe_status(handle: &OwnedHandle, class: PROCESSINFOCLASS) -> i32 {
    let mut needed = 0u32;
    // SAFETY: a size probe: no buffer, zero length.
    unsafe { NtQueryInformationProcess(handle.0, class, std::ptr::null_mut(), 0, &mut needed) }.0
}

#[test]
fn a_process_held_in_its_exit_is_not_exited_and_every_failed_read_of_it_says_it_is_ending() {
    let held = HeldEnding::start();
    let handle = open_for_waiting(held.pid())
        .unwrap()
        .expect("the process is still listed");
    let image_probe = probe_status(&handle, ProcessImageFileNameWin32);
    let command_line_probe = probe_status(&handle, ProcessCommandLineInformation);
    let measured = format!(
        "zero-length probe of the image name: {image_probe:#010x}; of the command line: {command_line_probe:#010x}"
    );

    assert!(
        !has_exited(&handle),
        "the process finished exiting before its debugger replied, so it was never held ({measured})"
    );

    let image = image_of(&handle);
    let process = Process {
        pid: held.pid(),
        handle,
    };
    let command_line = command_line_of(&process);
    let measured = format!(
        "{measured}; image read: {:?}; command line read: {:?}",
        image
            .as_ref()
            .map(|path| path.display().to_string())
            .map_err(|e| format!("{e:#}")),
        command_line.as_ref().map_err(|e| format!("{e:#}"))
    );
    assert!(
        image.is_err() || command_line.is_err(),
        "nothing about the held process failed, so this test pins no detection ({measured})"
    );

    // A failed read of an ending process is told to be that, and not taken for a failure.
    if image.is_err() {
        assert!(
            is_ending_now(&process.handle),
            "the image read failed but the probe did not say ending ({measured})"
        );
    }
    if let Err(e) = &command_line {
        assert!(
            is_ending(e),
            "the command line read failed and was not told to be ending ({measured})"
        );
    }
}

#[test]
fn a_held_ending_process_is_taken_for_running_the_image_only_when_the_caller_says_so() {
    let held = HeldEnding::start();
    let handle = open_for_waiting(held.pid())
        .unwrap()
        .expect("the process is still listed");
    let image_unreadable = image_of(&handle).is_err();
    drop(handle);

    let taken = open_if_image_by(held.pid(), &cmd_exe(), &file_id, IfEnding::TakeForRunning).unwrap();
    let skipped = open_if_image_by(held.pid(), &cmd_exe(), &file_id, IfEnding::Skip).unwrap();

    assert_eq!(
        taken.map(|p| p.pid),
        Some(held.pid()),
        "an ending process that runs, or may run, the image is waited for"
    );
    // If the kernel still answers the image read, the process is identified and taken whatever the
    // caller says; the flag decides only for a process whose image cannot be read.
    assert_eq!(
        skipped.map(|p| p.pid),
        if image_unreadable { None } else { Some(held.pid()) },
        "image unreadable: {image_unreadable}"
    );
}

#[test]
fn terminating_a_held_ending_process_is_not_an_error() {
    let held = HeldEnding::start();
    let handle = open_for_waiting(held.pid())
        .unwrap()
        .expect("the process is still listed");
    let process = Process {
        pid: held.pid(),
        handle,
    };
    process.terminate().unwrap();
}
