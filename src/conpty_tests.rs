//! Unit tests for the `conpty` module. Windows-only (the module is `#[cfg(windows)]`);
//! they run on a real Windows host via the cross-compile -> scp -> run loop.
use super::*;

/// Drain a raw output handle to EOF on a thread (EOF arrives after `close_pty`).
fn drain(out_raw: isize) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = read_handle(out_raw, &mut buf);
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        out
    })
}

#[test]
fn conpty_runs_child_and_captures_output() {
    let mut session = PtySession::spawn("cmd.exe /c echo conpty-works", 80, 24, None, None).unwrap();
    let reader = drain(session.out_read_raw());

    let code = session.wait().unwrap();
    session.close_pty(); // -> output pipe hits EOF -> reader ends
    let out = reader.join().unwrap();

    let text = String::from_utf8_lossy(&out);
    assert!(text.contains("conpty-works"), "captured output was: {text:?}");
    assert_eq!(code, 0);
}

#[test]
fn conpty_resize_on_live_session_succeeds() {
    // A shell that stays open so the pseudoconsole is live when we resize it.
    let mut session = PtySession::spawn("cmd.exe /k", 80, 24, None, None).unwrap();
    let reader = drain(session.out_read_raw());

    session.resize(120, 40).expect("ResizePseudoConsole on a live session");

    session.job().kill_tree().unwrap();
    let _ = session.wait();
    session.close_pty();
    let _ = reader.join();
}

/// As `pipes_tests::a_file_that_cannot_start_is_an_error_and_not_a_message_box`, for a pseudoconsole.
#[test]
fn a_file_that_cannot_start_is_an_error_and_not_a_message_box() {
    let dir = std::env::temp_dir().join(format!("sb-conpty-stub-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let stub = dir.join("stub.exe");
    std::fs::write(&stub, b"MZ").unwrap();
    let result = PtySession::spawn(&format!("\"{}\" -c x", stub.display()), 80, 24, None, None);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(result.is_err(), "a file that is not a program started");
}

/// As in `pipes_tests`, for a pseudoconsole: the program starts, and ends with the loader status. What it
/// wrote is conhost's own setup and the window title, nothing of the program's.
#[test]
fn a_program_with_a_missing_dll_starts_and_ends_with_the_loader_status() {
    use windows::Win32::System::Diagnostics::Debug::{SEM_FAILCRITICALERRORS, SetErrorMode};
    const STATUS_DLL_NOT_FOUND: u32 = 0xC000_0135;
    // SAFETY: no pointers. This process's own mode, so that the loader ends the program instead of raising a box.
    unsafe { SetErrorMode(SEM_FAILCRITICALERRORS) };
    let exe = crate::command_line_probe::example("missing_dll");
    let mut session =
        PtySession::spawn(&format!("\"{}\"", exe.display()), 80, 24, None, None).expect("the program starts");
    let reader = drain(session.out_read_raw());
    let code = session.wait().unwrap();
    session.close_pty();
    reader.join().unwrap();
    assert_eq!(code as u32, STATUS_DLL_NOT_FOUND, "{code:#x}");
}

/// As in `pipes_tests`: the working directory is not the program's fault.
#[test]
fn a_missing_working_directory_is_not_the_programs_fault() {
    let missing = std::env::temp_dir().join(format!("sb-conpty-no-such-dir-{}", std::process::id()));
    let error = PtySession::spawn("cmd.exe /c exit", 80, 24, Some(&missing), None)
        .err()
        .expect("a missing working directory started a program");
    assert!(matches!(error, StartError::Other(_)), "{error:?}");
}

/// A pseudoconsole child can be given one handle besides its console, and the spawn still reports a program
/// that cannot start as the program's fault.
#[test]
fn a_file_that_cannot_start_is_the_programs_fault_with_a_handle_to_inherit() {
    let dir = std::env::temp_dir().join(format!("sb-conpty-fault-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let stub = dir.join("stub.exe");
    std::fs::write(&stub, b"MZ").unwrap();
    let pipe = crate::winutil::Handoff::new(0).unwrap();
    let error = PtySession::spawn(&format!("\"{}\"", stub.display()), 80, 24, None, Some(pipe.read()))
        .err()
        .expect("a file that is not a program started");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(matches!(error, StartError::Program(_)), "{error:?}");
}
