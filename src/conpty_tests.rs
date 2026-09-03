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
    let mut session = PtySession::spawn("cmd.exe /c echo conpty-works", 80, 24, None).unwrap();
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
    let mut session = PtySession::spawn("cmd.exe /k", 80, 24, None).unwrap();
    let reader = drain(session.out_read_raw());

    session.resize(120, 40).expect("ResizePseudoConsole on a live session");

    session.kill().unwrap();
    let _ = session.wait();
    session.close_pty();
    let _ = reader.join();
}
