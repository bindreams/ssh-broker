//! Windows-only tests for the EXEC child (run on winhost).
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
