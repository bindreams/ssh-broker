//! The stand-in shim: the process that plays sshd's part for one account.
//!
//! It runs under the account's network-logon token, with RedirectionGuard switched on in itself
//! (the orchestrator puts it in a kill-on-close job). Everything it learns goes to `standin.res`.
//!
//! `stand-in <rundir> <scenario>`; the rest comes from `<rundir>/input.txt`.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};

use windows::Win32::Foundation::HANDLE;

use crate::logon::{self, Logon, Started};
use crate::rec::{Input, Rec};
use crate::win::{self, DirWatch, Event};

pub fn run(dir: &Path, scenario: &str) -> i32 {
    let rec = Rec::create(dir, "standin");
    rec.put("scenario", scenario);
    rec.put("pid", std::process::id());
    let input = Input::read(dir);
    win::redirection_guard_state(&rec, "standin_before_we_apply");
    win::redirection_guard_on(&rec);
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        self_facts(&rec, dir);
        match scenario {
            "m1" => m1(&rec, dir, &input),
            "m4" => m4(&rec, &input),
            "m5a" => m5a(&rec, &input),
            "m7" => m7(&rec, &input),
            "m7gated" => m7gated(&rec, &input),
            other => rec.put("fatal", format!("unknown scenario {other}")),
        }
    }));
    match outcome {
        Ok(()) => {
            rec.put("done", "true");
            0
        }
        Err(panic) => {
            let text = panic
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| panic.downcast_ref::<&str>().map(|s| (*s).to_owned()))
                .unwrap_or_else(|| "panic".into());
            rec.put("fatal", text);
            101
        }
    }
}

/// What the stand-in itself is, and the controls: it must be blocked at a junction its account
/// made, and its DPAPI user-scope call must fail.
fn self_facts(rec: &Rec, dir: &Path) {
    let pid = std::process::id();
    rec.put("parent_pid", win::parent_of(pid));
    rec.put("ts_session", win::session_of(pid));
    win::own_token_facts(rec, "standin");
    win::redirection_guard_state(rec, "standin");
    win::own_job_facts(rec, "standin");
    win::profile_dir_facts(rec, "standin");
    win::dpapi_facts(rec, "standin");
    let target = dir.join("jct-target");
    let link = junction_path(dir);
    let made = std::fs::create_dir_all(&target)
        .and_then(|()| std::fs::write(target.join("probe.txt"), "junction-ok"))
        .map_err(|e| e.to_string())
        .and_then(|()| win::make_junction(&link, &target));
    match made {
        Ok(()) => win::read_through_junction(rec, "standin.junction_the_account_made", &link),
        Err(e) => rec.put(
            "standin.junction_the_account_made",
            format!("could not make the junction: {e}"),
        ),
    }
}

pub fn junction_path(dir: &Path) -> PathBuf {
    dir.join("jct-link")
}

fn quote(text: &str) -> String {
    format!("\"{text}\"")
}

// M1, M2, M3, M6, M8: one logon of the background agent's stand-in -----------------------------------

fn m1(rec: &Rec, dir: &Path, input: &Input) {
    let (user, password) = (input.req("user"), input.req("password"));
    let exe = Path::new(input.req("exe"));
    let name = input.get("child_name").unwrap_or("child");
    let mut args = format!(
        "child {} {name} {}",
        quote(&dir.display().to_string()),
        quote(&format!("junction={}", junction_path(dir).display()))
    );
    for key in ["ready", "go", "ack"] {
        if let Some(value) = input.get(key) {
            args.push_str(&format!(" {}", quote(&format!("{key}={value}"))));
        }
    }
    if input.get("grandchild").is_some() {
        args.push_str(" grandchild=1");
    }
    let started = logon::start(
        &Logon {
            user,
            password,
            exe,
            args: &args,
            breakaway: input.get("breakaway").is_some(),
            redirect_to: None,
        },
        rec,
        "logon",
    );
    let Started { process, pid } = match started {
        Ok(s) => s,
        Err(e) => {
            rec.err("logon", &e);
            return;
        }
    };
    rec.put("logon", "ok");
    rec.put("child_pid", pid);
    rec.put("child_ts_session", win::session_of(pid));
    rec.put("child_parent_pid", win::parent_of(pid));
    rec.put("stand_in_ts_session", win::session_of(std::process::id()));

    if let Some(ready) = input.get("ready") {
        let ready = Event::open(ready).expect("open the child's ready event");
        let woken = win::wait_any(&[ready.handle(), process.0]);
        rec.put("child_ready", woken == 0);
        if woken == 0 {
            if let Some(name) = input.get("standin_ready") {
                Event::open(name).expect("open the stand-in's ready event").set();
            }
        }
    }
    win::wait_one(process.0);
    rec.put("child_exit_code", format!("{:#x}", win::exit_code(process.0)));
    drop(process);
    if let Some(name) = input.get("closed") {
        // The stand-in holds no handle to the child any more.
        Event::open(name).expect("open the closed event").set();
    }

    if input.get("redirect").is_some() {
        redirect(rec, dir, user, password);
    }
}

/// Whether a logon child can use standard output redirected to a file.
fn redirect(rec: &Rec, dir: &Path, user: &str, password: &str) {
    let out = dir.join("redirect.txt");
    let cmd = system32("cmd.exe");
    let started = logon::start(
        &Logon {
            user,
            password,
            exe: &cmd,
            args: "/c echo redirect-ok",
            breakaway: false,
            redirect_to: Some(&out),
        },
        rec,
        "redirect",
    );
    match started {
        Ok(s) => {
            win::wait_one(s.process.0);
            rec.put("redirect_exit_code", format!("{:#x}", win::exit_code(s.process.0)));
            rec.put(
                "redirect_file",
                std::fs::read_to_string(&out).map_or_else(|e| format!("unreadable: {e}"), |t| t.trim().to_owned()),
            );
        }
        Err(e) => rec.err("redirect", &e),
    }
}

fn system32(program: &str) -> PathBuf {
    Path::new(&std::env::var_os("SystemRoot").expect("SystemRoot"))
        .join("System32")
        .join(program)
}

// M4: the real agent, twice, for one user ------------------------------------------------------

const WAITING: &str = "waiting for the agent of another session";
const SLOT_EXIT: &str = "another agent already runs in this session";

enum Mark {
    Waiting,
    SlotExit,
    Exited(u32),
}

fn agent_log(loc: &ssh_broker::socket_loc::SocketLocation) -> String {
    let mut text = String::new();
    if let Ok(entries) = std::fs::read_dir(loc.logs_dir()) {
        let mut files: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with("agent.log"))
            })
            .collect();
        files.sort();
        for file in files {
            text.push_str(&std::fs::read_to_string(file).unwrap_or_default());
        }
    }
    text
}

fn counts(log: &str) -> (usize, usize) {
    (log.matches(WAITING).count(), log.matches(SLOT_EXIT).count())
}

/// Wait with no limit until `agent` logs that it waits or that it leaves for another agent of
/// its session, or exits.
fn wait_mark(loc: &ssh_broker::socket_loc::SocketLocation, baseline: (usize, usize), agent: HANDLE) -> Mark {
    let watch = DirWatch::new(&loc.logs_dir(), false).expect("watch the logs folder");
    loop {
        let (waiting, slot) = counts(&agent_log(loc));
        if waiting > baseline.0 {
            return Mark::Waiting;
        }
        if slot > baseline.1 {
            return Mark::SlotExit;
        }
        if win::wait_any(&[watch.handle(), agent]) == 0 {
            watch.rearm();
        } else {
            let (waiting, slot) = counts(&agent_log(loc));
            return if waiting > baseline.0 {
                Mark::Waiting
            } else if slot > baseline.1 {
                Mark::SlotExit
            } else {
                Mark::Exited(win::exit_code(agent))
            };
        }
    }
}

/// Wait with no limit until a connection to the agent's socket succeeds; `Err` carries the exit
/// code if the agent exits first.
fn wait_serving(loc: &ssh_broker::socket_loc::SocketLocation, agent: HANDLE) -> Result<(), u32> {
    let local = loc.dir.parent().expect("the socket folder has a parent").to_owned();
    let watch = DirWatch::new(&local, true).expect("watch the profile's AppData\\Local");
    loop {
        if ssh_broker::afunix::connect(&loc.path).is_ok() {
            return Ok(());
        }
        if win::wait_any(&[watch.handle(), agent]) == 0 {
            watch.rearm();
        } else {
            return Err(win::exit_code(agent));
        }
    }
}

fn start_agent(rec: &Rec, label: &str, input: &Input) -> Option<Started> {
    let started = logon::start(
        &Logon {
            user: input.req("user"),
            password: input.req("password"),
            exe: Path::new(input.req("broker")),
            args: "agent",
            breakaway: false,
            redirect_to: None,
        },
        rec,
        label,
    );
    match started {
        Ok(s) => {
            rec.put(&format!("{label}.pid"), s.pid);
            rec.put(&format!("{label}.ts_session"), win::session_of(s.pid));
            Some(s)
        }
        Err(e) => {
            rec.err(&format!("{label}.start"), &e);
            None
        }
    }
}

fn m4(rec: &Rec, input: &Input) {
    let loc = match ssh_broker::userdir::current_socket_location() {
        Ok(loc) => loc,
        Err(e) => {
            rec.put("socket_location", format!("ERROR {e:#}"));
            return;
        }
    };
    let Some(first) = start_agent(rec, "agent1", input) else {
        return;
    };
    match wait_serving(&loc, first.process.0) {
        Ok(()) => rec.put("agent1.state", "serving (a connection to its socket succeeded)"),
        Err(code) => {
            rec.put("agent1.state", format!("exited {code:#x} before it served"));
            log_tail(rec, &loc);
            return;
        }
    }

    let mut waiter: Option<Started> = None;
    let mut others = Vec::new();
    for label in ["agent2", "agent3"] {
        let baseline = counts(&agent_log(&loc));
        let Some(agent) = start_agent(rec, label, input) else {
            continue;
        };
        let mark = wait_mark(&loc, baseline, agent.process.0);
        match mark {
            Mark::Waiting => {
                rec.put(
                    &format!("{label}.state"),
                    "waits on agent.lock (it logged that it waits)",
                );
                if waiter.is_none() {
                    waiter = Some(agent);
                    continue;
                }
            }
            Mark::SlotExit => rec.put(
                &format!("{label}.state"),
                "left: another agent already runs in this session (the session slot)",
            ),
            Mark::Exited(code) => rec.put(
                &format!("{label}.state"),
                format!("exited {code:#x} with no wait or slot line"),
            ),
        }
        others.push(agent);
    }

    match &waiter {
        Some(waiter) => {
            win::terminate(first.process.0);
            win::wait_one(first.process.0);
            rec.put("agent1.killed", "true");
            match wait_serving(&loc, waiter.process.0) {
                Ok(()) => rec.put("takeover", "the waiting agent bound and serves after agent1 was killed"),
                Err(code) => rec.put(
                    "takeover",
                    format!("the waiting agent exited {code:#x} instead of taking over"),
                ),
            }
        }
        None => rec.put("takeover", "not testable: no second agent waited on the lock"),
    }
    log_tail(rec, &loc);
    for agent in waiter.iter().chain(others.iter()).chain(std::iter::once(&first)) {
        win::terminate(agent.process.0);
    }
}

fn log_tail(rec: &Rec, loc: &ssh_broker::socket_loc::SocketLocation) {
    let log = agent_log(loc);
    let lines: Vec<&str> = log.lines().collect();
    for (i, line) in lines.iter().skip(lines.len().saturating_sub(30)).enumerate() {
        rec.put(&format!("agent_log.{i:02}"), line);
    }
}

// M5(a): a standard user registering a task for itself --------------------------------------------

fn m5a(rec: &Rec, input: &Input) {
    use crate::tasks::{self, Spec};
    tasks::init_com();
    let machine = std::env::var("COMPUTERNAME").unwrap_or_default();
    let user = input.req("user");
    let qualified = format!("{machine}\\{user}");
    let exe = PathBuf::from(input.req("exe"));
    let name = "sbspike-selfreg";
    let spec = Spec {
        name,
        qualified_name: &qualified,
        bare_name: user,
        sid: input.req("sid"),
        password: input.req("password"),
        exe: &exe,
        args: "child x y",
        sddl: None,
    };
    match tasks::register_password_task(&spec) {
        Ok(variant) => {
            rec.put(
                "register_own_task",
                format!("ACCEPTED (account named in the XML by variant {variant})"),
            );
            match tasks::delete(name) {
                Ok(()) => rec.put("register_own_task.cleanup", "deleted"),
                Err(e) => rec.err("register_own_task.cleanup", &e),
            }
        }
        Err(failures) => {
            rec.put("register_own_task", "REFUSED");
            for (i, failure) in failures.iter().enumerate() {
                rec.put(&format!("register_own_task.failure{i}"), failure);
            }
        }
    }
}

// M7: what Windows says ----------------------------------------------------------------------

fn try_logon(rec: &Rec, label: &str, user: &str, password: &str) {
    let cmd = system32("cmd.exe");
    let started = logon::start(
        &Logon {
            user,
            password,
            exe: &cmd,
            args: "/c exit 0",
            breakaway: false,
            redirect_to: None,
        },
        rec,
        label,
    );
    match started {
        Ok(s) => {
            win::wait_one(s.process.0);
            rec.put(
                label,
                format!("logon succeeded; child exit {:#x}", win::exit_code(s.process.0)),
            );
        }
        Err(e) => rec.put(
            label,
            format!(
                "FAILED win32={} hresult={:#010x} text={:?}",
                e.code().0 as u32 & 0xFFFF,
                e.code().0 as u32,
                e.message().trim()
            ),
        ),
    }
}

fn m7(rec: &Rec, input: &Input) {
    for case in input.all("case") {
        let mut parts = case.splitn(3, '|');
        let (label, user, password) = (parts.next().unwrap(), parts.next().unwrap(), parts.next().unwrap_or(""));
        try_logon(rec, &format!("case.{label}"), user, password);
        rec.put(&format!("case.{label}.password_length"), password.chars().count());
    }
}

fn m7gated(rec: &Rec, input: &Input) {
    Event::open(input.req("standin_ready"))
        .expect("open the ready event")
        .set();
    win::wait_one(Event::open(input.req("go")).expect("open the go event").handle());
    try_logon(rec, "gated_logon", input.req("user"), input.req("password"));
}
