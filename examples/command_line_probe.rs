//! Test probe: writes the raw command line this process was started with to the file named by
//! `PROBE_OUT`, or to `<this exe>.line` when that is not set (a copy of the probe in a directory
//! of its own then has an output of its own). `tests/conhost_windows.rs` runs it under
//! `conhost.exe`; the agent tests use it as the configured shell.

/// `PROBE_HANDLE_CLOSE` set: a console control handler that handles every event, installed before anything else runs.
#[cfg(windows)]
fn handle_console_events() {
    use windows::Win32::System::Console::SetConsoleCtrlHandler;
    extern "system" fn handler(_event: u32) -> windows::core::BOOL {
        true.into()
    }
    // SAFETY: `handler` has the signature the call needs and lives as long as the process.
    unsafe { SetConsoleCtrlHandler(Some(handler), true) }.expect("install the handler");
}

fn main() {
    #[cfg(windows)]
    if std::env::var_os("PROBE_HANDLE_CLOSE").is_some() {
        handle_console_events();
    }
    let out = std::env::var_os("PROBE_OUT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            let mut beside = std::env::current_exe().expect("the probe's own path").into_os_string();
            beside.push(".line");
            beside.into()
        });
    std::fs::write(out, ssh_broker::cmdline::current()).expect("write the command line");
}
