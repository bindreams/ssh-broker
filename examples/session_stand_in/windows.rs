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
    std::fs::write(dir.join("shim.result"), result).unwrap();
    ReadyEvent::open(reported).unwrap().signal().unwrap();
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
        Err(e) => return format!("create the ready event failed: {e:#}"),
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
