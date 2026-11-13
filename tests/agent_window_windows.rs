//! The agent shows no window on the desktop of the session that starts it. Windows only;
//! **Elevated (CI only)**.
//!
//! The logon task starts `ssh-broker agent` from a process with no console, so the system gives
//! the agent a console with a window. The test starts the real agent the same way, with a console
//! of its own (`CREATE_NEW_CONSOLE`), on a desktop of its own, and looks at that desktop from
//! outside: any window on it is a failure.
//!
//! A look that finds nothing proves nothing if the window can never appear there, so a control
//! comes first: a plain console program started the same way must show a window on the same kind of
//! desktop. Without that, the test fails.
#![cfg(windows)]

use std::path::Path;
use std::time::{Duration, Instant};

use ssh_broker::socket_loc;
use windows::Win32::System::Threading::TerminateProcess;

#[path = "common/account.rs"]
mod account_fixture;
#[path = "common/bounded_wait.rs"]
mod bounded_wait;
#[path = "common/desktop.rs"]
mod desktop;
#[path = "common/hard_errors.rs"]
mod hard_errors;
#[path = "common/machine.rs"]
mod machine;
#[path = "common/process_list.rs"]
mod process_list;
#[path = "common/stand_in.rs"]
mod stand_in;

use account_fixture::{Account, Spawned};
use stand_in::Kit;

/// How long the console host may take to make or to destroy a window. Neither has a handle to wait
/// on from outside, so the desktop is looked at again until it is as awaited; this is the failure
/// bound on an external event that may never come. Expiry fails the test with what is on the desktop
/// and is never read as the awaited state.
const WINDOW_BOUND: Duration = Duration::from_secs(120);

/// Look at `child`'s desktop until `awaited` holds of its window classes, or fail at [`WINDOW_BOUND`].
fn wait_for_windows(child: &Spawned, what: &str, awaited: impl Fn(&[String]) -> bool) -> Vec<String> {
    let deadline = Instant::now() + WINDOW_BOUND;
    loop {
        let classes = child.window_classes();
        if awaited(&classes) {
            return classes;
        }
        assert!(
            Instant::now() < deadline,
            "{what}: not so after {WINDOW_BOUND:?}; the windows on the desktop are {classes:?}"
        );
        std::thread::yield_now();
    }
}

fn end(child: &Spawned) {
    // SAFETY: a valid process handle; ending a process that already ended is harmless.
    let _ = unsafe { TerminateProcess(child.process.0, 1) };
}

/// Elevated (CI only). The control: a console program started with a console of its own shows a window
/// on its desktop, which is what the look below depends on.
#[test]
fn a_console_program_with_its_own_console_shows_a_window_to_the_look() {
    let _machine = machine::shared();
    let account = Account::create("winctl", true);
    let cmd = Path::new(r"C:\Windows\System32\cmd.exe");
    // `/k` keeps it running, waiting for input on its console.
    let child = account.spawn_in_new_console(cmd, r#""C:\Windows\System32\cmd.exe" /k"#, cmd.parent().unwrap(), &[]);
    child.resume();
    let classes = wait_for_windows(&child, "a console window appeared", |classes| {
        classes.iter().any(|class| class == "ConsoleWindowClass")
    });
    eprintln!("windows of a console program with a console of its own: {classes:?}");
    end(&child);
}

/// Elevated (CI only). The agent, started as the logon task starts it (a console of its own), frees
/// the console once it runs, and no window is left on the desktop. It is the `--background` form
/// because a CI runner's session is 0, where a desktop agent refuses to start; the console is
/// freed before the two forms differ.
#[test]
fn the_agent_leaves_no_window_on_the_desktop() {
    let _machine = machine::shared();
    let kit = Kit::copy_of_broker("nowin");
    let account = Account::create("nowin", true);
    let command_line = format!(
        "\"{}\" agent --background --expect-user {}",
        kit.exe.display(),
        account.sid_text
    );
    let agent = account.spawn_in_new_console(&kit.exe, &command_line, kit.dir(), &[]);
    agent.resume();

    // Serving comes after the console is freed, so the wait is for the agent that has done everything
    // it does to start.
    let location = socket_loc::for_profile(account.profile()).unwrap();
    stand_in::wait_for_serving_marker(&location, agent.process.0);

    let left = wait_for_windows(&agent, "no window is left on the agent's desktop", |classes| {
        classes.is_empty()
    });
    assert!(left.is_empty());
    // Freeing the console did not end the agent.
    assert!(
        !has_ended(&agent),
        "the agent ended after it freed its console; its log is in {}",
        location.logs_dir().display()
    );
    end(&agent);
}

/// Whether `child` has ended: a state check, not a wait.
fn has_ended(child: &Spawned) -> bool {
    use windows::Win32::Foundation::WAIT_TIMEOUT;
    use windows::Win32::System::Threading::WaitForSingleObject;
    // SAFETY: a valid process handle.
    let state = unsafe { WaitForSingleObject(child.process.0, 0) }; // sleep-ok: zero-timeout state check of a process handle, not a wait
    state != WAIT_TIMEOUT
}
