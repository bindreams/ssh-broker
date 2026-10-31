//! Windows-only tests for the EXEC child (run on a real Windows host).
use super::*;
use crate::conpty::read_handle;
use std::thread;

/// Drain a raw read handle to EOF on a thread (concurrent draining avoids a full-pipe
/// deadlock when the child writes a lot to one stream).
fn drain(raw: isize) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = read_handle(raw, &mut buf);
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        out
    })
}

#[test]
fn exec_separates_stdout_stderr_and_returns_code() {
    let child = ExecChild::spawn("cmd.exe /c echo OUT& echo ERR 1>&2& exit /b 5", None).unwrap();
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
        let child = ExecChild::spawn(command, None).unwrap_or_else(|e| panic!("{command:?}: {e}"));
        assert_eq!(child.wait().unwrap(), 3, "{command:?}");
    }
}

/// The relayed command reaches the program whole: `cmd` reads its raw command line, so trailing
/// spaces after the arguments are printed.
#[test]
fn exec_keeps_the_trailing_spaces_of_a_command() {
    let child = ExecChild::spawn("  cmd.exe /c echo a   ", None).unwrap();
    let out_t = drain(child.stdout_read_raw());
    let err_t = drain(child.stderr_read_raw());
    assert_eq!(child.wait().unwrap(), 0);
    let out = out_t.join().unwrap();
    err_t.join().unwrap();

    assert_eq!(String::from_utf8_lossy(&out), "a   \r\n");
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
    let result = ExecChild::spawn(&format!("\"{}\" -c x", stub.display()), None);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(result.is_err(), "a file that is not a program started");
}

// MEASUREMENT (ssh-broker#55 round 8, F3): what a program the loader cannot load does after a
// successful start. Printed always (nextest `success-output`); replaced by the real tests.

fn measure_loader_failure(label: &str) {
    let exe = crate::command_line_probe::example("missing_dll");
    let started = ExecChild::spawn(&format!("\"{}\"", exe.display()), None);
    let child = match started {
        Ok(child) => child,
        Err(e) => {
            eprintln!("MEASURE {label}: start failed: {e}");
            return;
        }
    };
    eprintln!("MEASURE {label}: start Ok");
    let job = child.job();
    let out_t = drain(child.stdout_read_raw());
    let err_t = drain(child.stderr_read_raw());
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let code = child.wait();
        let _ = tx.send(code);
    });
    // A failure bound on an external event (a child that may sit in a message box).
    let waited = rx.recv_timeout(std::time::Duration::from_secs(30)); // sleep-ok: failure bound, a hang is reported
    match waited {
        Ok(code) => eprintln!(
            "MEASURE {label}: ended, exit code {:?}",
            code.map(|c| format!("{:#010x}", c as u32))
        ),
        Err(_) => {
            eprintln!("MEASURE {label}: still running after 30 s (a message box?)");
            let _ = job.kill_tree();
        }
    }
    let out = out_t.join().unwrap();
    let err = err_t.join().unwrap();
    eprintln!("MEASURE {label}: stdout {out:?} stderr {err:?}");
}

#[test]
fn measure_loader_failure_default_error_mode() {
    measure_loader_failure("pipes, default process error mode");
}

#[test]
fn measure_loader_failure_process_fails_critical_errors() {
    use windows::Win32::System::Diagnostics::Debug::{SEM_FAILCRITICALERRORS, SetErrorMode};
    let previous = unsafe { SetErrorMode(SEM_FAILCRITICALERRORS) };
    eprintln!("MEASURE the test process's own error mode was {previous:?}");
    measure_loader_failure("pipes, process error mode FAILCRITICALERRORS");
}
