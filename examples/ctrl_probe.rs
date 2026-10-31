//! Test stand-in for a program that answers console control events: prints `ready`, then one
//! `event <n>` line for the first Ctrl+C or Ctrl+Break that reaches it, or `stdin` for the first line
//! read from its input, and ends with `finished.`. With the argument `reenable` it first clears the
//! "ignore Ctrl+C" setting a parent can leave (inherited by
//! its children), and prints `cleared`. Only Windows has console control events.

#[cfg(windows)]
fn main() {
    use std::io::Write;
    use std::sync::{Mutex, OnceLock, mpsc};
    use windows::Win32::System::Console::SetConsoleCtrlHandler;

    static EVENTS: OnceLock<Mutex<mpsc::Sender<u32>>> = OnceLock::new();

    extern "system" fn handler(event: u32) -> windows::core::BOOL {
        if let Some(sender) = EVENTS.get() {
            let _ = sender.lock().unwrap().send(event);
        }
        true.into()
    }

    let (sender, receiver) = mpsc::channel();
    EVENTS.set(Mutex::new(sender)).unwrap();
    if std::env::args().nth(1).as_deref() == Some("reenable") {
        // SAFETY: no pointers.
        unsafe { SetConsoleCtrlHandler(None, false) }.unwrap();
        println!("cleared");
    }
    // SAFETY: `handler` has the signature the call needs and lives as long as the process.
    unsafe { SetConsoleCtrlHandler(Some(handler), true) }.unwrap();
    let from_stdin = EVENTS.get().unwrap().lock().unwrap().clone();
    std::thread::spawn(move || {
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
        let _ = from_stdin.send(u32::MAX);
    });
    println!("ready");
    std::io::stdout().flush().unwrap();
    match receiver.recv().unwrap() {
        u32::MAX => println!("stdin"),
        event => println!("event {event}"),
    }
    println!("finished.");
}

#[cfg(not(windows))]
fn main() {
    std::process::exit(2)
}
