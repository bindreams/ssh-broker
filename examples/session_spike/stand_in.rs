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
use crate::win::{self, Event};

pub fn run(dir: &Path, scenario: &str) -> i32 {
    let rec = Rec::create(dir, "standin");
    rec.put("scenario", scenario);
    rec.put("pid", std::process::id());
    let input = Input::read(dir);
    win::redirection_guard_state(&rec, "standin_before_we_apply");
    // M5(a) also runs the stand-in without RedirectionGuard (`rg=off`) to see whether it matters.
    if input.get("rg") == Some("off") {
        rec.put("redirection_guard_applied", "no: the run asked for rg=off");
    } else {
        win::redirection_guard_on(&rec);
    }
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        self_facts(&rec, dir);
        match scenario {
            "m1" => m1(&rec, dir, &input),
            "m4" => m4(&rec, &input),
            "m5a" => m5a(&rec, dir, &input),
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
        let ready = Event::open_recorded(rec, "child_ready", ready);
        let woken = win::wait_any(&[ready.handle(), process.0]);
        rec.put("child_ready", woken == 0);
        if woken == 0
            && let Some(name) = input.get("standin_ready")
        {
            Event::open_recorded(rec, "standin_ready", name).set();
        }
    }
    win::wait_one(process.0);
    rec.put("child_exit_code", format!("{:#x}", win::exit_code(process.0)));
    drop(process);
    if let Some(name) = input.get("closed") {
        // The stand-in holds no handle to the child any more.
        Event::open_recorded(rec, "closed", name).set();
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

// Neither wait below can be driven by a directory-change notification, which is what the first
// version used and what hung M4:
// - the agent binds its socket (the file appears: one notification), checks the file's ACL, and
//   only then listens, with no file change after the first. A connect made on that notification
//   is refused, and no later notification comes while the agent serves.
// - NTFS can hold back size and last-write notifications for a file that is appended to through
//   an open handle (the agent's log) until the handle closes.
// So each looks at the real condition again every second, and stops when the agent exits. The
// one-second wait on the agent's handle is the interval between two looks, not a proof of state.

/// Wait with no limit until `agent` logs that it waits or that it leaves for another agent of
/// its session, or exits.
fn wait_mark(
    rec: &Rec,
    label: &str,
    loc: &ssh_broker::socket_loc::SocketLocation,
    baseline: (usize, usize),
    agent: HANDLE,
) -> Mark {
    rec.put(
        "m4.waiting",
        format!("{label}: for a log line that it waits or leaves for another agent of its session, or for it to exit"),
    );
    let mut exited = false;
    loop {
        let (waiting, slot) = counts(&agent_log(loc));
        if waiting > baseline.0 {
            return Mark::Waiting;
        }
        if slot > baseline.1 {
            return Mark::SlotExit;
        }
        if exited {
            // Looked at the log once more after the exit, so its last lines count.
            return Mark::Exited(win::exit_code(agent));
        }
        exited = win::wait_bounded(agent, 1);
    }
}

/// Wait with no limit until a connection to the agent's socket succeeds; `Err` carries the exit
/// code if the agent exits first. A change in why the connect fails is recorded.
fn wait_serving(
    rec: &Rec,
    label: &str,
    loc: &ssh_broker::socket_loc::SocketLocation,
    agent: HANDLE,
) -> Result<(), u32> {
    rec.put(
        "m4.waiting",
        format!(
            "{label}: for a connection to {} to succeed, or for it to exit",
            loc.path.display()
        ),
    );
    let mut last_error: Option<String> = None;
    loop {
        match ssh_broker::afunix::connect(&loc.path) {
            Ok(_) => return Ok(()),
            Err(e) => {
                let text = format!("{e:#}");
                if last_error.as_deref() != Some(text.as_str()) {
                    rec.put(&format!("m4.{label}.connect_failed"), &text);
                    last_error = Some(text);
                }
            }
        }
        if win::wait_bounded(agent, 1) {
            return Err(win::exit_code(agent));
        }
    }
}

fn start_agent(rec: &Rec, label: &str, input: &Input) -> Option<Started> {
    rec.put("m4.waiting", format!("{label}: CreateProcessWithLogonW to return"));
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
    match wait_serving(rec, "agent1", &loc, first.process.0) {
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
        let mark = wait_mark(rec, label, &loc, baseline, agent.process.0);
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
            rec.put("m4.waiting", "agent1: to exit after TerminateProcess");
            win::wait_one(first.process.0);
            rec.put("agent1.killed", "true");
            match wait_serving(rec, "takeover", &loc, waiter.process.0) {
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
    rec.put("m4.waiting", "nothing: ending the agents and the stand-in");
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

/// The registration from this process, whose token and RedirectionGuard setting the orchestrator
/// chose; and, if `clw=1`, from `CreateProcessWithLogonW` children (an interactive logon, as the
/// product's background agent would be) with RedirectionGuard off and on.
fn m5a(rec: &Rec, dir: &Path, input: &Input) {
    crate::selfreg::attempt(rec, "standin", input);
    if input.get("clw").is_none() {
        return;
    }
    let exe = Path::new(input.req("exe"));
    for guard in ["off", "on"] {
        let name = format!("selfreg_clw_rg{guard}");
        let args = format!("child {} {name} selfreg={guard}", quote(&dir.display().to_string()));
        let started = logon::start(
            &Logon {
                user: input.req("user"),
                password: input.req("password"),
                exe,
                args: &args,
                breakaway: false,
                redirect_to: None,
            },
            rec,
            &name,
        );
        match started {
            Ok(child) => {
                win::wait_one(child.process.0);
                rec.put(
                    &format!("{name}.exit_code"),
                    format!("{:#x}", win::exit_code(child.process.0)),
                );
            }
            Err(e) => rec.err(&format!("{name}.start"), &e),
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
    Event::open_recorded(rec, "standin_ready", input.req("standin_ready")).set();
    win::wait_one(Event::open_recorded(rec, "go", input.req("go")).handle());
    try_logon(rec, "gated_logon", input.req("user"), input.req("password"));
}
