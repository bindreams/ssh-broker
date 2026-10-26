use std::path::{Path, PathBuf};

use ssh_broker::account::current_account;
use ssh_broker::acl::Sid;
use ssh_broker::logon::start_background_agent;
use ssh_broker::ready::{ReadyEvent, Waited};
use ssh_broker::route::{AgentArgs, BackgroundArgs, Route};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Threading::{CreateEventW, GetProcessId, INFINITE, WaitForSingleObject};
use windows::core::PCWSTR;

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
        _ => std::process::exit(2),
    }
}

fn agent(dir: &Path, args: &[String]) {
    let Route::Agent(AgentArgs {
        background:
            Some(BackgroundArgs {
                ready_event: Some(name),
                expect_user: Some(expect),
            }),
    }) = ssh_broker::route(args, &ssh_broker::cmdline::current())
    else {
        std::fs::write(dir.join("agent.error"), "unexpected command line").unwrap();
        std::process::exit(2);
    };
    let sid = Sid::current_user().unwrap().to_sddl().unwrap();
    let session = ssh_broker::provision::probe::current_session_id();
    let info = format!(
        "pid={}\nsid={sid}\nexpect_user_matches={}\nsession={session}\n",
        std::process::id(),
        sid == expect
    );
    std::fs::write(dir.join("agent.info"), info).unwrap();
    let ready = match ReadyEvent::open(&name) {
        Ok(ready) => ready,
        Err(e) => {
            std::fs::write(dir.join("agent.error"), format!("open the ready event: {e:#}")).unwrap();
            std::process::exit(3);
        }
    };
    ready.signal().unwrap();
    let Ok(plan) = std::fs::read_to_string(dir.join("agent.plan")) else {
        return;
    };
    let named = |key: &str| {
        let line = plan.lines().find_map(|l| l.strip_prefix(key)).unwrap();
        ReadyEvent::open(line).unwrap()
    };
    let (go, ack) = (named("go="), named("ack="));
    // SAFETY: a valid event handle; the wait is on an event the test sets.
    unsafe { WaitForSingleObject(go.as_handle(), INFINITE) };
    ack.signal().unwrap();
}

fn shim(dir: &Path) {
    let input = std::fs::read_to_string(dir.join("shim.input")).unwrap();
    let mut lines = input.lines();
    let (password, agent_exe, reported) = (lines.next().unwrap(), lines.next().unwrap(), lines.next().unwrap());
    let result = run_shim(password, &PathBuf::from(agent_exe));
    let reported = match ReadyEvent::open(reported) {
        Ok(event) => event,
        Err(e) => {
            let result = format!("{result}\nopen the reported event failed: {e:#}");
            std::fs::write(dir.join("shim.result"), result).unwrap();
            std::process::exit(4);
        }
    };
    std::fs::write(dir.join("shim.result"), result).unwrap();
    reported.signal().unwrap();
    if dir.join("shim.hold").exists() {
        // Blocks until this process is killed (the caller's job closing).
        // SAFETY: an unnamed, never-signalled event.
        unsafe {
            let never = CreateEventW(None, true, false, PCWSTR::null()).unwrap();
            WaitForSingleObject(never, INFINITE);
        }
    }
}

fn run_shim(password: &str, agent_exe: &Path) -> String {
    let account = match current_account() {
        Ok(account) => account,
        Err(e) => return format!("current_account failed: {e:#}"),
    };
    let (ready, name) = match ReadyEvent::create() {
        Ok(made) => made,
        Err(e) => return format!("create the ready event failed: {e:#}\n{}", diagnose_named_objects()),
    };
    let started = match start_background_agent(&account, &password::password(password), agent_exe, &name) {
        Ok(started) => started,
        Err(e) => return format!("logon failed: {} {}", e.code, e.reason),
    };
    // SAFETY: a valid process handle.
    let pid = unsafe { GetProcessId(started.process.0) };
    match ready.wait_with(HANDLE(started.process.0.0)) {
        Ok(Waited::Ready) => format!("Ready pid={pid}"),
        Ok(Waited::AgentExited(code)) => format!("AgentExited {code} pid={pid}"),
        Err(e) => format!("wait failed: {e:#}"),
    }
}

/// What this token can and cannot do with named events, for the report of a failed ready event:
/// the token (`whoami /all`) and `CreateEventW` in each namespace, with no descriptor, with a plain
/// one, with the product's DACL, and with the product's DACL and label.
fn diagnose_named_objects() -> String {
    let token = std::process::Command::new("whoami")
        .arg("/all")
        .output()
        .map(|out| String::from_utf8_lossy(&out.stdout).into_owned())
        .unwrap_or_else(|e| format!("(whoami did not run: {e})"));
    let sid = Sid::current_user().and_then(|sid| sid.to_sddl()).unwrap_or_default();
    let session = ssh_broker::provision::probe::current_session_id();
    let mut report = format!("session={session} sid={sid}\n");
    let tag = std::process::id();
    let dacl = format!("D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x100002;;;{sid})");
    let tries: [(String, String, Option<String>); 8] = [
        ("unnamed".into(), String::new(), None),
        ("Global, no descriptor".into(), format!(r"Global\sb-diag-a-{tag}"), None),
        ("Local, no descriptor".into(), format!(r"Local\sb-diag-b-{tag}"), None),
        (
            "Global, Everyone all access".into(),
            format!(r"Global\sb-diag-c-{tag}"),
            Some("D:(A;;GA;;;WD)".into()),
        ),
        (
            "Global, the product's DACL, no label".into(),
            format!(r"Global\sb-diag-d-{tag}"),
            Some(dacl.clone()),
        ),
        (
            "Global, the product's DACL and label".into(),
            format!(r"Global\sb-diag-e-{tag}"),
            Some(ssh_broker::ready::descriptor_sddl(&sid)),
        ),
        (
            "Local, the product's DACL and label".into(),
            format!(r"Local\sb-diag-f-{tag}"),
            Some(ssh_broker::ready::descriptor_sddl(&sid)),
        ),
        (
            "Global, label only".into(),
            format!(r"Global\sb-diag-g-{tag}"),
            Some("S:(ML;;NW;;;ME)".into()),
        ),
    ];
    for (what, name, sddl) in tries {
        report += &format!("CreateEventW {what}: {}\n", try_event(&name, sddl.as_deref()));
    }
    report + "whoami /all:\n" + &token
}

/// `CreateEventW` of `name` (unnamed if empty) with the descriptor `sddl`, as text: the outcome.
fn try_event(name: &str, sddl: Option<&str>) -> String {
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
    use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows::core::BOOL;

    let wide = |text: &str| -> Vec<u16> { text.encode_utf16().chain(std::iter::once(0)).collect() };
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    if let Some(sddl) = sddl {
        // SAFETY: NUL-terminated input and a valid out-pointer; freed below.
        if let Err(e) = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(wide(sddl).as_ptr()), 1, &mut descriptor, None)
        } {
            return format!("the descriptor {sddl:?} did not build: {e}");
        }
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: BOOL(0),
    };
    let name_w = wide(name);
    // SAFETY: the pointers are to locals that outlive the call.
    let made = unsafe {
        CreateEventW(
            sddl.map(|_| &attributes as *const SECURITY_ATTRIBUTES),
            true,
            false,
            if name.is_empty() {
                PCWSTR::null()
            } else {
                PCWSTR(name_w.as_ptr())
            },
        )
    };
    if sddl.is_some() {
        // SAFETY: the descriptor the conversion allocated.
        let _ = unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
    }
    match made {
        Ok(handle) => {
            // SAFETY: the handle just made.
            let _ = unsafe { windows::Win32::Foundation::CloseHandle(handle) };
            "ok".into()
        }
        Err(e) => format!("{e}"),
    }
}

/// Host `command` in a pseudoconsole, the way the agent hosts a shell: input arrives on stdin as
/// win32-input-mode key sequences, output leaves on stdout, and the exit code is the command's. The
/// caller starts this as an account's network token, so `command` (the shim) runs as that account
/// on a console of its own.
fn pty(cwd: &Path, command: &str) {
    use std::io::{Read, Write};

    let mut session =
        ssh_broker::conpty::PtySession::spawn(command, 80, 25, Some(cwd)).expect("start the pseudoconsole");
    let (in_raw, out_raw) = (session.in_write_raw(), session.out_read_raw());
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
    let code = session.wait().unwrap_or(1);
    // Closing the pseudoconsole delivers its buffered tail and ends the output thread.
    session.close_pty();
    let _ = output.join();
    std::process::exit(code);
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
