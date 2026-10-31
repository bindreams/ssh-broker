//! SPIKE, NOT FOR MERGE. `ctrl_flag chain [label]` prints whether this process and each ancestor has the
//! "ignore Ctrl+C" setting. `ctrl_flag calibrate` checks that reading against the things that set it.

#[cfg(windows)]
fn main() {
    use std::os::windows::process::CommandExt;
    use windows::Win32::System::Console::SetConsoleCtrlHandler;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let flag = || ssh_broker::ctrl_flag_spike::console_flags(std::process::id());
    let chain = |label: &str| {
        println!("[{label}] ctrl_flag pid {}", std::process::id());
        print!("{}", ssh_broker::ctrl_flag_spike::chain(std::process::id()));
    };
    match args.first().map(String::as_str) {
        Some("chain") => chain(args.get(1).map_or("chain", String::as_str)),
        Some("calibrate") => {
            println!("start: {:?}", flag());
            // SAFETY: no pointers.
            unsafe { SetConsoleCtrlHandler(None, true) }.unwrap();
            println!("after SetConsoleCtrlHandler(NULL, TRUE): {:?} (expect bit 0 set)", flag());
            // SAFETY: no pointers.
            unsafe { SetConsoleCtrlHandler(None, false) }.unwrap();
            println!("after SetConsoleCtrlHandler(NULL, FALSE): {:?} (expect bit 0 clear)", flag());
            let exe = std::env::current_exe().unwrap();
            let child = |flags: u32, label: &str| {
                let status = std::process::Command::new(&exe)
                    .args(["chain", label])
                    .creation_flags(flags)
                    .status()
                    .unwrap();
                println!("({label} child exit {status})");
            };
            child(0, "child of a process with the setting clear, no flags (expect clear)");
            child(0x200, "child of a process with the setting clear, CREATE_NEW_PROCESS_GROUP (expect set)");
            // SAFETY: no pointers.
            unsafe { SetConsoleCtrlHandler(None, true) }.unwrap();
            child(0, "child of a process with the setting set, no flags (expect set: inherited)");
            child(0x0800_0000, "child of a process with the setting set, CREATE_NO_WINDOW (inherited?)");
            child(0x0000_0010, "child of a process with the setting set, CREATE_NEW_CONSOLE (inherited?)");
        }
        _ => {
            eprintln!("usage: ctrl_flag chain [label] | calibrate");
            std::process::exit(2);
        }
    }
}

#[cfg(not(windows))]
fn main() {
    std::process::exit(2)
}
