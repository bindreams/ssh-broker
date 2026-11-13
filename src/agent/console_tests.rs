//! Tests for [`super::detach_with`], [`super::console_std_handles`] and [`super::null_with`], which touch no console, and for
//! [`super::is_console_handle`] and [`super::null_std_handles`] on real handles, in a child process.

use std::cell::Cell;
use std::num::NonZeroU32;

use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_INVALID_HANDLE};
use windows::Win32::System::Console::{STD_ERROR_HANDLE, STD_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE};
use windows::core::HRESULT;

use super::{DetachOutcome, console_std_handles, detach_with, is_console_handle, null_std_handles, null_with};

/// What `detach_with` answers when the console count is `counted`, and whether it freed the console.
fn run(counted: Result<NonZeroU32, u32>) -> (windows::core::Result<DetachOutcome>, bool) {
    let freed = Cell::new(false);
    let outcome = detach_with(counted, || {
        freed.set(true);
        Ok(None)
    });
    (outcome, freed.get())
}

fn count(processes: u32) -> Result<NonZeroU32, u32> {
    Ok(NonZeroU32::new(processes).unwrap())
}

#[test]
fn an_agent_alone_on_its_console_frees_it() {
    let (outcome, freed) = run(count(1));
    assert_eq!(
        outcome.unwrap(),
        DetachOutcome::Detached {
            std_handles_error: None
        }
    );
    assert!(freed);
}

#[test]
fn an_agent_sharing_its_console_keeps_it() {
    for processes in [2, 3, u32::MAX] {
        let (outcome, freed) = run(count(processes));
        assert_eq!(outcome.unwrap(), DetachOutcome::Shared { processes });
        assert!(!freed, "{processes} processes use the console");
    }
}

/// Whatever the reason the count is zero, the agent has no console to free; the reason is kept.
#[test]
fn a_count_of_zero_is_no_console_whatever_the_error_code() {
    for code in [ERROR_INVALID_HANDLE.0, ERROR_ACCESS_DENIED.0, 0] {
        let (outcome, freed) = run(Err(code));
        assert_eq!(outcome.unwrap(), DetachOutcome::NoConsole { error: code });
        assert!(!freed);
    }
}

#[test]
fn a_console_that_cannot_be_freed_is_an_error() {
    let outcome = detach_with(count(1), || Err(windows::core::Error::from_hresult(HRESULT(-1))));
    assert!(outcome.is_err());
}

/// The standard handles that could not be reset do not undo the detach: the outcome says so and keeps the code.
#[test]
fn standard_handles_that_could_not_be_reset_leave_the_agent_detached() {
    let outcome = detach_with(count(1), || Ok(Some(HRESULT(-2)))).unwrap();
    assert_eq!(
        outcome,
        DetachOutcome::Detached {
            std_handles_error: Some(HRESULT(-2))
        }
    );
}

fn chosen(consoles: &[STD_HANDLE]) -> Vec<STD_HANDLE> {
    console_std_handles(|which| consoles.contains(&which))
}

/// An operator who redirected a standard handle to a file or a pipe keeps it: only the handles that refer to
/// the console are nulled.
#[test]
fn only_the_standard_handles_that_refer_to_the_console_are_chosen() {
    let all = [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE];
    assert_eq!(chosen(&all), all);
    assert_eq!(chosen(&[]), []);
    assert_eq!(chosen(&[STD_INPUT_HANDLE]), [STD_INPUT_HANDLE]);
    assert_eq!(
        chosen(&[STD_INPUT_HANDLE, STD_ERROR_HANDLE]),
        [STD_INPUT_HANDLE, STD_ERROR_HANDLE]
    );
}

/// A handle that cannot be set does not leave the later ones un-nulled: they are stale once the console is freed.
/// The error reported is the first.
#[test]
fn every_handle_is_attempted_and_the_first_error_is_reported() {
    let attempted = std::cell::RefCell::new(Vec::new());
    let all = [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE];
    let result = null_with(&all, |which| {
        attempted.borrow_mut().push(which);
        match which {
            STD_INPUT_HANDLE => Err(windows::core::Error::from_hresult(HRESULT(-1))),
            STD_OUTPUT_HANDLE => Err(windows::core::Error::from_hresult(HRESULT(-2))),
            _ => Ok(()),
        }
    });
    assert_eq!(attempted.into_inner(), all);
    assert_eq!(result.unwrap_err().code(), HRESULT(-1));
}

#[test]
fn no_error_is_reported_when_every_handle_is_set() {
    assert!(null_with(&[STD_INPUT_HANDLE, STD_ERROR_HANDLE], |_| Ok(())).is_ok());
}

const CHILD_FLAG: &str = "SSH_BROKER_CONSOLE_TEST_CHILD";
const CHILD_OK: &str = "REAL_HANDLES_OK";

/// Child half of [`real_handles_are_told_apart_and_only_the_console_ones_are_nulled`], started only by it. Its
/// standard input is NUL, its output a pipe and its error the console it has of its own (`CONOUT$`).
#[test]
#[ignore = "run as a child of agent::console::console_tests::real_handles_are_told_apart_and_only_the_console_ones_are_nulled"]
fn child_nulls_the_console_handle_and_keeps_the_others() {
    use std::os::windows::io::IntoRawHandle as _;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Console::{GetStdHandle, SetStdHandle};

    assert!(
        std::env::var_os(CHILD_FLAG).is_some(),
        "this is a child half; its parent starts it with {CHILD_FLAG} set"
    );
    let console = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("CONOUT$")
        .expect("open the console of this process: it has one of its own");
    // SAFETY: a valid handle, kept open for the life of the process.
    unsafe { SetStdHandle(STD_ERROR_HANDLE, HANDLE(console.into_raw_handle())) }.expect("make the console the error");

    let [input, output, error] = [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE];
    assert!(!is_console_handle(input), "NUL is not a console");
    assert!(!is_console_handle(output), "a pipe is not a console");
    assert!(is_console_handle(error), "CONOUT$ is a console");
    assert_eq!(console_std_handles(is_console_handle), [error]);

    // SAFETY: no pointers.
    let output_before = unsafe { GetStdHandle(output) }.unwrap();
    null_std_handles(&[error]).expect("set the console's handle to null");
    // SAFETY: no pointers.
    let (error_after, output_after) = unsafe { (GetStdHandle(error), GetStdHandle(output)) };
    assert!(
        error_after.as_ref().map_or(true, |handle| handle.is_invalid()),
        "the error is still {error_after:?}"
    );
    assert_eq!(
        output_after.unwrap(),
        output_before,
        "the redirected output was touched"
    );
    println!("{CHILD_OK}");
}

/// A pipe and NUL are not consoles and keep their handles, and the console's is told apart and set to null:
/// the real `GetConsoleMode` and `SetStdHandle`, which the injected tests above do not reach. A child process,
/// since the handles are the process's own.
#[test]
fn real_handles_are_told_apart_and_only_the_console_ones_are_nulled() {
    use std::os::windows::process::CommandExt as _;
    use std::process::Stdio;
    /// `CREATE_NO_WINDOW`: the child has a console of its own with no window.
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "agent::console::console_tests::child_nulls_the_console_handle_and_keeps_the_others",
            "--ignored",
            "--nocapture",
        ])
        .env(CHILD_FLAG, "1")
        .stdin(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains(CHILD_OK),
        "the child did not finish its checks: {stdout} {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
