//! Test stand-in for a program of an unelevated session that tries to attach to the console of another process:
//! given process ids as arguments, it detaches from its own console and calls `AttachConsole` on each in turn, and
//! ends with one line `pid=<n> error=<code>` per id (`error=0` is an attachment that was granted), then
//! `finished.`. It reads and writes nothing of any console it attaches to, leaves it again at once, and exits 0
//! whatever the answers. Its standard output must be redirected (a pipe or a file): the lines are printed after
//! the last attempt, when it has no console of its own to print to. Only Windows has consoles.

#[cfg(windows)]
fn main() {
    use std::io::Write;
    use windows::Win32::System::Console::{AttachConsole, FreeConsole};

    let ids: Vec<u32> = std::env::args()
        .skip(1)
        .map(|arg| arg.parse().expect("process ids, as numbers"))
        .collect();
    // A process attaches to one console at a time, and `AttachConsole` of a second is refused for that.
    // SAFETY: no arguments; a failure is a process that had no console, which is what is wanted.
    let _ = unsafe { FreeConsole() };
    let mut lines = Vec::new();
    for id in ids {
        // SAFETY: no pointers. A process id that is not one, or is one this process may not attach to, fails.
        let attached = unsafe { AttachConsole(id) };
        let error = match &attached {
            Ok(()) => 0,
            Err(e) => e.code().0 & 0xFFFF,
        };
        if attached.is_ok() {
            // SAFETY: as above; the console is left as it was found.
            let _ = unsafe { FreeConsole() };
        }
        lines.push(format!("pid={id} error={error}"));
    }
    let mut out = std::io::stdout().lock();
    for line in lines {
        writeln!(out, "{line}").unwrap();
    }
    writeln!(out, "finished.").unwrap();
    out.flush().unwrap();
}

#[cfg(not(windows))]
fn main() {
    std::process::exit(2)
}
