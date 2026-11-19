//! Windows-only tests for the EXEC child (run on a real Windows host).
use super::*;
use crate::test_support::drain;

#[test]
fn exec_separates_stdout_stderr_and_returns_code() {
    let child = ExecChild::spawn("cmd.exe /c echo OUT& echo ERR 1>&2& exit /b 5", None, None, &[]).unwrap();
    let out_t = drain(child.stdout_read_raw());
    let err_t = drain(child.stderr_read_raw());

    let code = child.wait().unwrap();
    // Child exited → its write ends closed → the drain threads hit EOF and finish.
    let out = out_t.join().unwrap();
    let err = err_t.join().unwrap();

    assert!(
        String::from_utf8_lossy(&out).contains("OUT"),
        "stdout was: {:?}",
        String::from_utf8_lossy(&out)
    );
    assert!(
        String::from_utf8_lossy(&err).contains("ERR"),
        "stderr was: {:?}",
        String::from_utf8_lossy(&err)
    );
    assert_eq!(code, 5);
}

/// `CreateProcessW` rejects a command line that starts with whitespace, and the command is
/// relayed as the client sent it, so the spawn trims the leading edge.
#[test]
fn exec_runs_a_command_with_whitespace_at_its_edges() {
    for command in [
        "  cmd.exe /c exit /b 3",
        "\tcmd.exe /c exit /b 3\r\n",
        "\r\ncmd.exe /c exit /b 3",
    ] {
        let child = ExecChild::spawn(command, None, None, &[]).unwrap_or_else(|e| panic!("{command:?}: {e}"));
        assert_eq!(child.wait().unwrap(), 3, "{command:?}");
    }
}

/// The relayed command reaches the program whole: `cmd` reads its raw command line, so trailing
/// spaces after the arguments are printed.
#[test]
fn exec_keeps_the_trailing_spaces_of_a_command() {
    let child = ExecChild::spawn("  cmd.exe /c echo a   ", None, None, &[]).unwrap();
    let out_t = drain(child.stdout_read_raw());
    let err_t = drain(child.stderr_read_raw());
    assert_eq!(child.wait().unwrap(), 0);
    let out = out_t.join().unwrap();
    err_t.join().unwrap();

    assert_eq!(String::from_utf8_lossy(&out), "a   \r\n"); // spaces-ok: the child writes them, and the test reads them back
}

/// What `cmd /c set` prints in a child started with `extra_env`: its environment, by upper-cased name.
fn environment_of_a_child(extra_env: &[(&str, &str)]) -> std::collections::BTreeMap<String, String> {
    let child = ExecChild::spawn("cmd.exe /c set", None, None, extra_env).unwrap();
    let out_t = drain(child.stdout_read_raw());
    let err_t = drain(child.stderr_read_raw());
    assert_eq!(child.wait().unwrap(), 0);
    let out = out_t.join().unwrap();
    err_t.join().unwrap();
    String::from_utf8_lossy(&out)
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(name, value)| (name.to_uppercase(), value.to_owned()))
        .collect()
}

/// A start with `extra_env` gives the child the id and leaves every other variable as this process has it; a
/// start with none gives it this process's environment, with no id.
#[test]
fn the_session_environment_carries_its_id_and_nothing_else_changes() {
    let id = "00112233445566778899aabbccddeeff";
    let inherited: Vec<(String, String)> = std::env::vars()
        .filter(|(name, _)| !name.starts_with('=') && !name.eq_ignore_ascii_case(crate::protocol::SESSION_VARIABLE))
        .collect();
    assert!(!inherited.is_empty(), "a test process has an environment");

    let with = environment_of_a_child(&[(crate::protocol::SESSION_VARIABLE, id)]);
    assert_eq!(
        with.get(crate::protocol::SESSION_VARIABLE).map(String::as_str),
        Some(id)
    );
    for (name, value) in &inherited {
        assert_eq!(with.get(&name.to_uppercase()), Some(value), "{name} changed");
    }

    let without = environment_of_a_child(&[]);
    assert!(
        !without.contains_key(crate::protocol::SESSION_VARIABLE),
        "a start with no extra variable gave the child an id"
    );
    for (name, value) in &inherited {
        assert_eq!(without.get(&name.to_uppercase()), Some(value), "{name} changed");
    }
}

/// A file that exists and cannot be started (here, not a program at all) is an error from `spawn`.
/// Without the thread's hard-error boxes switched off, `CreateProcessW` raises a message box on the
/// interactive desktop and waits for an answer; in a session nobody watches, that is a hang.
#[test]
fn a_file_that_cannot_start_is_an_error_and_not_a_message_box() {
    let dir = std::env::temp_dir().join(format!("sb-pipes-stub-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let stub = dir.join("stub.exe");
    std::fs::write(&stub, b"MZ").unwrap();
    let result = ExecChild::spawn(&format!("\"{}\" -c x", stub.display()), None, None, &[]);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(result.is_err(), "a file that is not a program started");
}

// A program the loader cannot load =====

/// Make a program that cannot load end with its status instead of a message box on a desktop nobody
/// watches. The setting is this test process's, which nextest gives to this test alone.
fn loader_failures_end_the_program() {
    use windows::Win32::System::Diagnostics::Debug::{SEM_FAILCRITICALERRORS, SetErrorMode};
    // SAFETY: no pointers.
    unsafe { SetErrorMode(SEM_FAILCRITICALERRORS) };
}

/// A program whose import is missing is STARTED. `CreateProcessW` succeeds, the
/// loader ends the process with `STATUS_DLL_NOT_FOUND` before `main`, and nothing was written to either stream. So
/// `spawn` cannot tell it from a healthy program; the status is known only when the process ends.
#[test]
fn a_program_with_a_missing_dll_starts_and_ends_with_the_loader_status_and_no_output() {
    const STATUS_DLL_NOT_FOUND: u32 = 0xC000_0135;
    loader_failures_end_the_program();
    let exe = crate::command_line_probe::example("missing_dll");
    let child = ExecChild::spawn(&format!("\"{}\"", exe.display()), None, None, &[]).expect("the program starts");
    let out_t = drain(child.stdout_read_raw());
    let err_t = drain(child.stderr_read_raw());
    // UNBOUNDED on purpose: the loader ends the process, or nextest's bound names this test.
    let code = child.wait().unwrap();
    assert_eq!(code as u32, STATUS_DLL_NOT_FOUND, "{code:#x}");
    assert!(out_t.join().unwrap().is_empty() && err_t.join().unwrap().is_empty());
}

/// A working directory that is not one is the session's failure, not the program's: the shell would be
/// blamed, and cmd.exe would meet the same failure.
#[test]
fn a_missing_working_directory_is_not_the_programs_fault() {
    let missing = std::env::temp_dir().join(format!("sb-pipes-no-such-dir-{}", std::process::id()));
    let error = ExecChild::spawn("cmd.exe /c exit", Some(&missing), None, &[])
        .err()
        .expect("a missing working directory started a program");
    assert!(matches!(error, StartError::Other(_)), "{error:?}");
}

/// A file that is not a program is the program's fault, whatever the working directory.
#[test]
fn a_file_that_cannot_start_is_the_programs_fault() {
    let dir = std::env::temp_dir().join(format!("sb-pipes-fault-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let stub = dir.join("stub.exe");
    std::fs::write(&stub, b"MZ").unwrap();
    let error = ExecChild::spawn(&format!("\"{}\"", stub.display()), Some(&dir), None, &[])
        .err()
        .expect("a file that is not a program started");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(matches!(error, StartError::Program(_)), "{error:?}");
}
