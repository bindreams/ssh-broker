//! Test stand-in for a program that answers console control events: prints `ready`, then one
//! `event <n>` line for the first Ctrl+C or Ctrl+Break that reaches it, or `stdin` for the first line
//! read from its input, and ends with `finished.`. With the argument `reenable` it first clears the
//! "ignore Ctrl+C" setting a parent can leave (inherited by its children), and prints `cleared`. With
//! `no-stdin` it reads nothing, so it never takes input meant for a program that runs after it. With
//! `raise-ctrl-c` or `raise-ctrl-break` it raises that event on every process of its console, after
//! `ready`. Only Windows has console control events.

#[cfg(windows)]
fn main() {
    use std::io::Write;
    use std::sync::{Mutex, OnceLock, mpsc};
    use windows::Win32::System::Console::{
        CTRL_BREAK_EVENT, CTRL_C_EVENT, GenerateConsoleCtrlEvent, SetConsoleCtrlHandler,
    };

    static EVENTS: OnceLock<Mutex<mpsc::Sender<u32>>> = OnceLock::new();

    extern "system" fn handler(event: u32) -> windows::core::BOOL {
        if let Some(sender) = EVENTS.get() {
            let _ = sender.lock().unwrap().send(event);
        }
        true.into()
    }

    let (sender, receiver) = mpsc::channel();
    EVENTS.set(Mutex::new(sender)).unwrap();
    let has_arg = |name| std::env::args().skip(1).any(|arg| arg == name);
    if has_arg("reenable") {
        // SAFETY: no pointers.
        unsafe { SetConsoleCtrlHandler(None, false) }.unwrap();
        println!("cleared");
    }
    // SAFETY: `handler` has the signature the call needs and lives as long as the process.
    unsafe { SetConsoleCtrlHandler(Some(handler), true) }.unwrap();
    if !has_arg("no-stdin") {
        let from_stdin = EVENTS.get().unwrap().lock().unwrap().clone();
        std::thread::spawn(move || {
            let mut line = String::new();
            let _ = std::io::stdin().read_line(&mut line);
            let _ = from_stdin.send(u32::MAX);
        });
    }
    println!("ready");
    std::io::stdout().flush().unwrap();
    for (name, event) in [("raise-ctrl-c", CTRL_C_EVENT), ("raise-ctrl-break", CTRL_BREAK_EVENT)] {
        if has_arg(name) {
            // SAFETY: no pointers; group 0 is every process on this console.
            unsafe { GenerateConsoleCtrlEvent(event, 0) }.unwrap();
        }
    }
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
