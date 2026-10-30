use std::path::{Path, PathBuf};

use ssh_broker::account::current_account;
use ssh_broker::acl::Sid;
use ssh_broker::logon::start_background_agent;
use ssh_broker::route::{AgentArgs, BackgroundArgs, Route};
use ssh_broker::shim_offer::{Served, wait_for_agent};
use ssh_broker::socket_watch::SocketWatch;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Threading::{CreateEventW, GetProcessId, INFINITE, WaitForSingleObject};
use windows::core::PCWSTR;

#[path = "../../tests/common/file_signal.rs"]
mod file_signal;
#[path = "hosted_console.rs"]
mod hosted_console;
#[path = "../../tests/common/password.rs"]
mod password;

pub fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let dir = std::env::current_exe().unwrap().parent().unwrap().to_path_buf();
    match args.first().map(String::as_str) {
        Some("agent") => agent(&dir, &args),
        Some("shim") => shim(Path::new(&args[1])),
        Some("pty") => pty(Path::new(&args[1]), &args[2]),
        Some("connect") => connect(Path::new(&args[1]), Path::new(&args[2])),
        Some("console-size") => console_size(),
        // `<DefaultShell> -c <command>`: what sshd runs when this is the DefaultShell.
        Some("-c") => probe(),
        _ => std::process::exit(2),
    }
}

/// What `start_background_agent` starts: records who it runs as, makes its socket folder and writes
/// the `serving` marker the way the real agent does after `listen()`, and, if `agent.plan` exists,
/// waits for the file `agent.go` and then writes `agent.ack`.
fn agent(dir: &Path, args: &[String]) {
    let Route::Agent(AgentArgs {
        background: Some(BackgroundArgs {
            expect_user: Some(expect),
        }),
    }) = ssh_broker::route(args, &ssh_broker::cmdline::current())
    else {
        std::fs::write(dir.join("agent.error"), "unexpected command line").unwrap();
        std::process::exit(2);
    };
    let user = Sid::current_user().unwrap();
    let sid = user.to_sddl().unwrap();
    let session = ssh_broker::provision::probe::current_session_id();
    let info = format!(
        "pid={}\nsid={sid}\nexpect_user_matches={}\nsession={session}\n",
        std::process::id(),
        sid == expect
    );
    std::fs::write(dir.join("agent.info"), info).unwrap();
    let made = ssh_broker::userdir::current_socket_location()
        .and_then(|location| {
            ssh_broker::userdir::ensure_socket_dir(&location, &user)?;
            Ok(location)
        })
        .and_then(|location| Ok(ssh_broker::agent_background::mark_listening(&location)?));
    if let Err(e) = made {
        std::fs::write(
            dir.join("agent.error"),
            format!("make the socket folder and marker: {e:#}"),
        )
        .unwrap();
        std::process::exit(3);
    }
    if !dir.join("agent.plan").exists() {
        return;
    }
    // The record that this process got as far as waiting: a process that ended without it never did.
    file_signal::publish(&dir.join("agent.waiting"), "waiting");
    file_signal::wait_for_file(&dir.join("agent.go"), None, None, "the test's go signal");
    file_signal::publish(&dir.join("agent.ack"), "ack");
}

fn shim(dir: &Path) {
    let input = std::fs::read_to_string(dir.join("shim.input")).unwrap();
    let mut lines = input.lines();
    let (password, agent_exe) = (lines.next().unwrap(), lines.next().unwrap());
    // The logon's own log lines (its job, its probe, its claim) go to `shim.log`, for a test to print.
    let result = match std::fs::File::create(dir.join("shim.log")) {
        Ok(file) => {
            let log = tracing_subscriber::fmt()
                .with_writer(std::sync::Mutex::new(file))
                .with_ansi(false)
                .finish();
            tracing::subscriber::with_default(log, || run_shim(password, &PathBuf::from(agent_exe)))
        }
        Err(e) => format!("create shim.log failed: {e}"),
    };
    file_signal::publish(&dir.join("shim.result"), &result);
    if dir.join("shim.hold").exists() {
        // Blocks until this process is killed (the caller's job closing).
        // SAFETY: an unnamed, never-signalled event.
        unsafe {
            let never = CreateEventW(None, true, false, PCWSTR::null()).unwrap();
            WaitForSingleObject(never, INFINITE);
        }
    }
}

/// What the real shim does after the prompt, with the stand-in agent: start the agent through the
/// logon, then wait, from this token and with the product's own watch, until the agent has made its
/// folder and written the marker.
fn run_shim(password: &str, agent_exe: &Path) -> String {
    let account = match current_account() {
        Ok(account) => account,
        Err(e) => return format!("current_account failed: {e:#}"),
    };
    let watch = match SocketWatch::for_current_user() {
        Ok(watch) => watch,
        Err(e) => return format!("watch the socket failed: {e:#}"),
    };
    let started = match start_background_agent(&account, &password::password(password), agent_exe) {
        Ok(started) => started,
        Err(e) => return format!("logon failed: {} {}", e.code, e.reason),
    };
    // SAFETY: a valid process handle.
    let pid = unsafe { GetProcessId(started.process.0) };
    let served = wait_for_agent(watch, HANDLE(started.process.0.0), |location| {
        Ok(location.serving_marker_path().is_file().then_some(()))
    });
    match served {
        Ok(Served::Connected(())) => format!("Ready pid={pid} survival={:?}", started.survival),
        Ok(Served::Ended { code }) => format!("AgentExited {code} pid={pid}"),
        Ok(Served::Gone) => format!("AgentGone pid={pid}"),
        Err(e) => format!("wait failed: {e:#}"),
    }
}

/// What the shim would find itself in under sshd: its session, its job and its logon type, printed as
/// `key=value` lines. Run as sshd's `DefaultShell`, this is the measurement of the shim's own
/// environment (`tests/real_sshd_windows.rs`).
fn probe() {
    use windows::Win32::System::JobObjects::{
        IsProcessInJob, JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
        QueryInformationJobObject,
    };
    use windows::Win32::System::Threading::GetCurrentProcess;
    use windows::core::BOOL;

    let mut in_job = BOOL(0);
    // SAFETY: valid handles and out-pointer; no job handle means "any job".
    let asked = unsafe { IsProcessInJob(GetCurrentProcess(), None, &mut in_job) };
    println!("session={}", ssh_broker::provision::probe::current_session_id());
    println!("logon_type={:?}", ssh_broker::provision::probe::current_logon_type());
    println!("in_job={}", asked.is_ok() && in_job.as_bool());
    let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    // SAFETY: a buffer of the size passed; no job handle queries the calling process's own job.
    let queried = unsafe {
        QueryInformationJobObject(
            None,
            JobObjectExtendedLimitInformation,
            (&mut info as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            None,
        )
    };
    match queried {
        Ok(()) => {
            let flags = info.BasicLimitInformation.LimitFlags.0;
            println!("job_limit_flags={flags:#x}");
            println!("job_kill_on_close={}", flags & 0x2000 != 0);
            println!("job_breakaway_ok={}", flags & 0x800 != 0);
            println!("job_silent_breakaway_ok={}", flags & 0x1000 != 0);
        }
        Err(e) => println!("job_limit_flags=unavailable ({e})"),
    }
    println!(
        "sid={}",
        Sid::current_user().and_then(|sid| sid.to_sddl()).unwrap_or_default()
    );
}

/// Host `command` in a pseudoconsole, the way sshd hosts the shim: input arrives on stdin as
/// win32-input-mode key sequences, output leaves on stdout, and the exit code is the command's. The
/// caller starts this as an account's network token, so `command` (the shim) runs as that account
/// on a console of its own. The command runs in a kill-on-close job that allows breakaway, which is the
/// job it has under sshd (M8), and the job closes when this process ends, as sshd's does with the
/// session.
fn pty(cwd: &Path, command: &str) {
    use std::io::{Read, Write};

    let job = hosted_console::job::KillOnCloseJob::create_allowing_breakaway();
    let mut console = hosted_console::HostedConsole::start(command, cwd, &job).expect("start the pseudoconsole");
    let (in_raw, out_raw) = (console.in_write.raw(), console.out_read.raw());
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin();
        let mut buf = [0u8; 4096];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    if !ssh_broker::conpty::write_all_handle(in_raw, &buf[..n]) {
                        return;
                    }
                }
            }
        }
    });
    let output = std::thread::spawn(move || {
        let mut stdout = std::io::stdout();
        let mut buf = [0u8; 4096];
        loop {
            let n = ssh_broker::conpty::read_handle(out_raw, &mut buf);
            if n == 0 || stdout.write_all(&buf[..n]).and_then(|()| stdout.flush()).is_err() {
                return;
            }
        }
    });
    let code = console.wait();
    // Closing the pseudoconsole delivers its buffered tail and ends the output thread.
    console.close();
    let _ = output.join();
    // Process exit closes the job, which ends what is still in it; a logon child that broke away stays.
    drop(job);
    std::process::exit(code);
}

/// Print `size=<columns>x<rows>` for the console this runs on, then wait for the console to be resized
/// and print it again. Waiting is on the console's own resize event, so a test that resizes the console
/// the command's client runs on needs no time to pass.
fn console_size() {
    use std::io::Write as _;
    use std::os::windows::io::AsRawHandle as _;
    use windows::Win32::System::Console::{
        CONSOLE_MODE, CONSOLE_SCREEN_BUFFER_INFO, ENABLE_WINDOW_INPUT, GetConsoleMode, GetConsoleScreenBufferInfo,
        INPUT_RECORD, ReadConsoleInputW, SetConsoleMode, WINDOW_BUFFER_SIZE_EVENT,
    };

    let open = |name: &str| {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(name)
            .unwrap_or_else(|e| panic!("open {name}: {e}"))
    };
    // The console itself, not the standard handles, which a host may leave null.
    let (input_file, mut output_file) = (open("CONIN$"), open("CONOUT$"));
    let (input, output) = (HANDLE(input_file.as_raw_handle()), HANDLE(output_file.as_raw_handle()));
    let size = || {
        let mut info = CONSOLE_SCREEN_BUFFER_INFO::default();
        // SAFETY: a console output handle and an out-pointer.
        unsafe { GetConsoleScreenBufferInfo(output, &mut info) }.expect("GetConsoleScreenBufferInfo");
        let window = info.srWindow;
        format!(
            "size={}x{}",
            window.Right - window.Left + 1,
            window.Bottom - window.Top + 1
        )
    };

    // The event is queued only while the mode asks for it, so this comes before the first line the
    // test waits for.
    let mut mode = CONSOLE_MODE::default();
    // SAFETY: a console input handle and an out-pointer.
    unsafe { GetConsoleMode(input, &mut mode) }.expect("GetConsoleMode");
    // SAFETY: as above.
    unsafe { SetConsoleMode(input, mode | ENABLE_WINDOW_INPUT) }.expect("SetConsoleMode");
    writeln!(output_file, "{}", size()).expect("write the size");

    let mut records = [INPUT_RECORD::default(); 16];
    loop {
        let mut read = 0u32;
        // SAFETY: a console input handle, a buffer of the length passed, an out-pointer.
        unsafe { ReadConsoleInputW(input, &mut records, &mut read) }.expect("ReadConsoleInputW");
        if records[..read as usize]
            .iter()
            .any(|record| u32::from(record.EventType) == WINDOW_BUFFER_SIZE_EVENT)
        {
            writeln!(output_file, "{}", size()).expect("write the size");
            return;
        }
    }
}

/// Connect to the socket at `socket` and write what happened to `result`: `connected`, `os error <n>`
/// or the error's text.
fn connect(socket: &Path, result: &Path) {
    let text = match ssh_broker::afunix::connect(socket) {
        Ok(_) => "connected".to_string(),
        Err(e) => match e
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::raw_os_error)
        {
            Some(code) => format!("os error {code}"),
            None => format!("{e:#}"),
        },
    };
    std::fs::write(result, text).unwrap();
}
