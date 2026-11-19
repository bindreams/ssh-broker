//! A measurement, not a test of the product: when does the logon session of an agent that the installed exe's
//! password prompt started end after `logout`, under the real sshd? Windows only; **Elevated (CI only)**.
//!
//! Each case starts a session at the prompt, runs `logout` in a default session (a second login), and then reads
//! only: LSA's list of logon sessions once a second until the agent's is gone, the processes still in it, the
//! processes of the first connection, and afterwards a historical query of the Security log for 4634 and 4647. It
//! touches no process it did not start. Every case ends with a panic that carries the record: nextest shows the
//! output of a failing test only.
#![cfg(windows)]

use std::collections::BTreeMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ssh_broker::provision::registry::{OPENSSH_KEY, set_default_shell_under};
use ssh_broker::provision::{canonical_exe, procwait};
use ssh_broker::winutil::OwnedHandle;
use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, FILETIME, HANDLE, LUID, WAIT_OBJECT_0};
use windows::Win32::Security::Authentication::Identity::{LsaEnumerateLogonSessions, LsaFreeReturnBuffer};
use windows::Win32::System::EventLog::{
    EVT_HANDLE, EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtQueryForwardDirection, EvtRender,
    EvtRenderEventXml,
};
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, WaitForSingleObject,
};
use windows::core::{HRESULT, PCWSTR};

#[path = "common/account.rs"]
mod account_fixture;
#[path = "common/agent_conn.rs"]
mod agent_conn;
#[path = "common/bounded_wait.rs"]
mod bounded_wait;
#[path = "common/desktop.rs"]
mod desktop;
#[path = "common/hard_errors.rs"]
mod hard_errors;
#[path = "common/logon_session.rs"]
mod logon_session;
#[path = "common/machine.rs"]
mod machine;
#[path = "common/password.rs"]
mod password;
#[path = "common/process_list.rs"]
mod process_list;
#[path = "common/session_end.rs"]
mod session_end;
#[path = "common/sshd_rig.rs"]
mod sshd_rig;
#[path = "common/stand_in.rs"]
mod stand_in;

use account_fixture::{Account, ServiceLogon, holders};
use sshd_rig::{Login, no_shell_to_carry, run_client};
use stand_in::Kit;

/// How long the logon session may stay listed before the case records "still there": an external event that may
/// never happen, so this is the failure bound surfaced to a human, not a synchronization.
const STILL_THERE_BOUND: Duration = Duration::from_secs(900);

/// The pause between two samples of LSA's list: the measurement's resolution.
const SAMPLE_EVERY: Duration = Duration::from_secs(1);

/// FILETIME ticks (100 ns since 1601) at the Unix epoch.
const UNIX_EPOCH_AS_FILETIME: u64 = 116_444_736_000_000_000;

/// The reply the agent gives `logout`.
const ENDING: &str = "ending your background session.";

// The four cases =====

/// Elevated (CI only). An administrator (Batch logon), the first connection open while `logout` runs and after.
#[test]
fn administrator_with_the_first_connection_open() {
    measure("administrator, first connection open", "lmao", true, false)
}

/// Elevated (CI only). An administrator (Batch logon), the first connection closed before `logout` runs.
#[test]
fn administrator_with_the_first_connection_closed() {
    measure("administrator, first connection closed", "lmac", true, true)
}

/// Elevated (CI only). A standard account (interactive secondary logon), the first connection open.
#[test]
fn standard_account_with_the_first_connection_open() {
    measure("standard account, first connection open", "lmso", false, false)
}

/// Elevated (CI only). A standard account (interactive secondary logon), the first connection closed first.
#[test]
fn standard_account_with_the_first_connection_closed() {
    measure("standard account, first connection closed", "lmsc", false, true)
}

// One case =====

/// `ssh -T host -- "& '<exe>' logout"`, in the session the account's default login gets.
fn logout_over_ssh(kit: &Kit, login: &Login<'_>) -> sshd_rig::Outcome {
    let mut ssh = login.command();
    ssh.arg("-T").arg("--").arg(format!("& '{}' logout", kit.exe.display()));
    run_client(ssh, false, kit.dir())
}

/// Run one case and end in a panic that carries the record.
fn measure(case: &str, tag: &str, administrator: bool, close_first: bool) -> ! {
    let mut rec = Record::new();
    let _machine = machine::exclusive();
    account_fixture::assert_elevated();
    // Without the auditing the system writes no 4634, and the query below would be empty for that reason.
    logon_session::assert_logoff_auditing();
    let kit = Kit::broker_with_helper(tag);
    let account = Account::create(tag, true);
    if administrator {
        account.make_administrator();
    }
    let level = account.integrity();
    let _end = session_end::LogOutOnDrop::new(&canonical_exe(), &account, ServiceLogon::Sshd);
    let login = Login::new(&kit, &account);
    set_default_shell_under(OPENSSH_KEY, &kit.exe.to_string_lossy(), &no_shell_to_carry())
        .expect("set the shim as DefaultShell");
    let mut facts = vec![
        format!("case: {case}"),
        format!("windows: {}", windows_build()),
        format!("account level: {level:?}"),
    ];

    rec.note("login: ssh started");
    let mut first = Some(login.start());
    first.as_mut().expect("just made").log_in(&account.password);
    rec.note("login: the password prompt answered, the shell is up");

    // The agent the installed exe's prompt started, its logon session, and who is in it.
    let agents = procwait::user_agents(&canonical_exe(), &account.sid, level).expect("list the agents of the account");
    assert_eq!(agents.len(), 1, "the login must have started one agent at {level:?}");
    let agent_pid = agents[0].pid;
    let id = logon_session::logon_id(agents[0].handle());
    let own = std::process::id();
    let held: Vec<(u32, OwnedHandle)> = logon_session::processes_of(id)
        .into_iter()
        .filter(|(pid, _)| *pid != own)
        .collect();
    let names = image_names();
    facts.push(format!("agent: pid {agent_pid}, logon id {id:#x}"));
    facts.push(format!(
        "logon sessions of the account before logout: {}",
        match holders::sessions_of(&account.sid_text) {
            Ok(sessions) => sessions.iter().map(ToString::to_string).collect::<Vec<_>>().join(" | "),
            Err(why) => format!("not read: {why}"),
        }
    ));
    facts.push(format!(
        "processes in the agent's logon session before logout: {}",
        held.iter()
            .map(|(pid, _)| label(&names, *pid))
            .collect::<Vec<_>>()
            .join(", ")
    ));
    let held_pids: Vec<u32> = held.iter().map(|(pid, _)| *pid).collect();
    let connection = account_processes_outside(&account.sid_text, &held_pids);
    facts.push(format!(
        "processes of the account outside that session (the first connection's, tracked below): {}",
        connection.iter().map(Tracked::label).collect::<Vec<_>>().join(", ")
    ));

    if close_first {
        first.take().expect("just made").leave();
        rec.note("first connection: closed by typing exit, before logout");
        let still = procwait::user_agents(&canonical_exe(), &account.sid, level).expect("list the agents again");
        assert_eq!(
            still.iter().map(|agent| agent.pid).collect::<Vec<_>>(),
            [agent_pid],
            "the agent must outlive the first connection"
        );
    }

    let logout_started = SystemTime::now();
    rec.note("logout: second login started");
    let outcome = logout_over_ssh(&kit, &login);
    rec.note(format!("logout: the client returned (exit {:?})", outcome.code));
    assert!(
        outcome.stderr.contains(ENDING),
        "the agent's reply is missing from stderr (exit {:?}):\n{}\n{}",
        outcome.code,
        outcome.stderr,
        (login.diagnostics())()
    );

    // The exits, read from the handles held since before logout. The bound is a failure bound on an exit that may
    // never come; nothing is ended here when it expires.
    for (pid, process) in &held {
        if !wait_exit(process.0, bounded_wait::CHILD_EXIT_BOUND) {
            rec.fail(&format!("{} was still running after logout", label(&names, *pid)));
        }
    }
    rec.note("every process listed before logout has exited");
    let exit_of = |process: HANDLE| process_times(process).map(|(_, exit)| filetime_to_system_time(exit));
    let agent_exit = exit_of(agents[0].handle()).expect("read the agent's exit time");
    let mut last_exit = agent_exit;
    for (pid, process) in &held {
        let exit = exit_of(process.0).expect("read an exit time");
        last_exit = last_exit.max(exit);
        rec.note_at(exit, format!("[exit] {}", label(&names, *pid)));
    }
    // A handle on a process keeps its token, and so the logon session, alive: none is held from here on.
    drop(held);
    drop(agents);
    rec.note("every handle on the session's processes dropped; sampling starts");

    // The sampling. Only reads.
    let mut previous: Option<String> = None;
    let mut samples = 0u32;
    let mut last_listed = None;
    let mut first_gone = None;
    let sampling = Instant::now();
    loop {
        let wall = SystemTime::now();
        let listed = lsa_lists(id);
        let members = match members_of(id) {
            Ok(found) => found.join(", "),
            Err(why) => format!("not listed: {why}"),
        };
        let running: Vec<String> = connection.iter().filter(|p| p.running()).map(Tracked::label).collect();
        let client = match first.as_mut() {
            None => "closed before logout".to_owned(),
            Some(session) => match session.child.try_wait() {
                Ok(None) => "running".to_owned(),
                Ok(Some(status)) => format!("exited ({status})"),
                Err(e) => format!("unreadable ({e})"),
            },
        };
        let state = format!(
            "LSA lists the session: {listed}; processes in it: [{members}]; the first connection's processes \
             running: [{}]; first ssh client: {client}",
            running.join(", ")
        );
        if previous.as_deref() != Some(state.as_str()) {
            rec.note_at(wall, format!("[sample {samples}] {state}"));
            previous = Some(state);
        }
        samples += 1;
        if !listed {
            first_gone = Some(wall);
            break;
        }
        last_listed = Some(wall);
        if sampling.elapsed() >= STILL_THERE_BOUND {
            rec.note_at(
                wall,
                format!(
                    "still there after {} s ({samples} samples)",
                    STILL_THERE_BOUND.as_secs()
                ),
            );
            break;
        }
        let next = sampling + SAMPLE_EVERY * samples;
        let pause = next.saturating_duration_since(Instant::now());
        std::thread::sleep(pause); // sleep-ok: the cadence of a measurement of time; nothing is synchronized by it
    }
    let tail = first.as_mut().map(|session| {
        while let Ok(chunk) = session.output.try_recv() {
            session.transcript.extend_from_slice(&chunk);
        }
        session.text()
    });

    // The Security log, read once the wait is over (a query, not a subscription).
    let after_wait = SystemTime::now();
    rec.note_at(after_wait, "security log: queries start");
    let by_id = query_log(&by_logon_id(id));
    let by_user = query_log(&by_user_name(&account.name));
    let since = after_wait
        .duration_since(logout_started)
        .unwrap_or_default()
        .saturating_add(Duration::from_secs(60));
    let recent = query_log(&since_ms(since.as_millis()));
    let by_id_again = query_log(&by_logon_id(id));
    let mut events: BTreeMap<(SystemTime, u32, String), (LogEvent, Vec<&str>)> = BTreeMap::new();
    let mut query_notes = Vec::new();
    for (tag, result) in [("by id", &by_id), ("by account", &by_user), ("since logout", &recent)] {
        match result {
            Ok(found) => {
                query_notes.push(format!("query {tag}: {} event(s)", found.len()));
                for event in found {
                    events
                        .entry((event.time, event.event_id, event.logon_id.clone()))
                        .or_insert_with(|| (event.clone(), Vec::new()))
                        .1
                        .push(tag);
                }
            }
            Err(why) => query_notes.push(format!("query {tag} failed: {why}")),
        }
    }
    query_notes.push(match &by_id_again {
        Ok(found) => format!("query by id read again at the end: {} event(s)", found.len()),
        Err(why) => format!("query by id read again failed: {why}"),
    });
    for (event, found_by) in events.values() {
        rec.note_at(
            event.time,
            format!(
                "[log] {} logon id {} user {} logon type {} (found by: {})",
                event.event_id,
                event.logon_id,
                event.user,
                event.logon_type,
                found_by.join(", ")
            ),
        );
    }
    let after_sessions = match holders::sessions_of(&account.sid_text) {
        Ok(sessions) => sessions.iter().map(ToString::to_string).collect::<Vec<_>>().join(" | "),
        Err(why) => format!("not read: {why}"),
    };

    let mut summary = vec![
        format!("agent exit: {} UTC", clock(agent_exit)),
        format!(
            "last exit of a process of the session: +{:.3} s",
            secs(last_exit, agent_exit)
        ),
        format!(
            "last sample with the session listed: {}",
            last_listed.map_or("none".to_owned(), |t| format!("+{:.3} s", secs(t, agent_exit)))
        ),
        match first_gone {
            Some(t) => format!("first sample with the session gone: +{:.3} s", secs(t, agent_exit)),
            None => format!(
                "the session was still there after {} s ({samples} samples)",
                STILL_THERE_BOUND.as_secs()
            ),
        },
    ];
    for event_id in [4634u32, 4647] {
        let found: Vec<&LogEvent> = by_id
            .as_ref()
            .map(|found| found.iter().filter(|event| event.event_id == event_id).collect())
            .unwrap_or_default();
        summary.push(if found.is_empty() {
            format!("{event_id} for logon id {id:#x} in the log: none")
        } else {
            format!(
                "{event_id} for logon id {id:#x} in the log: {}",
                found
                    .iter()
                    .map(|event| format!("TimeCreated +{:.3} s", secs(event.time, agent_exit)))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        });
    }
    summary.extend(query_notes);
    summary.push(format!("logon sessions of the account at the end: {after_sessions}"));
    if let Some(tail) = tail {
        summary.push(format!(
            "what the first connection showed after logout (last 300 characters): {:?}",
            tail.chars()
                .rev()
                .take(300)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<String>()
        ));
    }
    panic!(
        "MEASURED (this test fails on purpose):\n{}\n\ntimeline (seconds from the agent's exit | wall clock UTC | \
         seconds since the test's start):\n{}\n\nsummary:\n{}",
        facts.join("\n"),
        rec.render(agent_exit),
        summary.join("\n")
    )
}

// The record =====

/// What happened and when, in the order it was noted.
struct Record {
    start: Instant,
    started: SystemTime,
    rows: Vec<(SystemTime, Option<Duration>, String)>,
}

impl Record {
    fn new() -> Record {
        Record {
            start: Instant::now(),
            started: SystemTime::now(),
            rows: Vec::new(),
        }
    }

    /// A step that happens now.
    fn note(&mut self, what: impl Into<String>) {
        self.rows
            .push((SystemTime::now(), Some(self.start.elapsed()), what.into()));
    }

    /// Something that happened at `wall`, read from the system (or sampled just then).
    fn note_at(&mut self, wall: SystemTime, what: impl Into<String>) {
        let since = wall.duration_since(self.started).ok();
        self.rows.push((wall, since, what.into()));
    }

    /// The rows by time, each with its seconds from `base`.
    fn render(&self, base: SystemTime) -> String {
        let mut rows: Vec<&(SystemTime, Option<Duration>, String)> = self.rows.iter().collect();
        rows.sort_by_key(|row| row.0);
        rows.iter()
            .map(|(wall, since, what)| {
                format!(
                    "{:+10.3} | {} | {:>8} | {what}",
                    secs(*wall, base),
                    clock(*wall),
                    since.map_or("-".to_owned(), |d| format!("{:.3}", d.as_secs_f64()))
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// End the case where the measurement could not be taken.
    fn fail(&self, why: &str) -> ! {
        panic!(
            "MEASURED (this test fails on purpose): the measurement is incomplete: {why}\n{}",
            self.render(self.started)
        )
    }
}

/// Seconds from `base` to `t`, negative when `t` is earlier.
fn secs(t: SystemTime, base: SystemTime) -> f64 {
    match t.duration_since(base) {
        Ok(d) => d.as_secs_f64(),
        Err(e) => -e.duration().as_secs_f64(),
    }
}

/// `HH:MM:SS.mmm` of the UTC day.
fn clock(t: SystemTime) -> String {
    let since = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let day = since.as_secs() % 86_400;
    format!(
        "{:02}:{:02}:{:02}.{:03}",
        day / 3600,
        day % 3600 / 60,
        day % 60,
        since.subsec_millis()
    )
}

fn filetime_to_system_time(ticks: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_nanos(ticks.saturating_sub(UNIX_EPOCH_AS_FILETIME) * 100)
}

/// The Windows product name, build and update revision, from the registry (read only).
fn windows_build() -> String {
    let (_, text) = sshd_rig::run("reg", &["query", r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"]);
    text.lines()
        .map(str::trim)
        .filter(|line| {
            ["ProductName", "CurrentBuild", "UBR", "DisplayVersion"]
                .iter()
                .any(|key| line.starts_with(key))
        })
        .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect::<Vec<_>>()
        .join("; ")
}

// Processes (reads only) =====

/// A process of the first connection, told apart from a later process that reuses its id by its creation time.
struct Tracked {
    pid: u32,
    name: String,
    created: u64,
}

impl Tracked {
    fn label(&self) -> String {
        format!("{}#{}", self.name, self.pid)
    }

    /// Whether that same process is still running.
    fn running(&self) -> bool {
        // SAFETY: a plain open by id; the handle is closed by `OwnedHandle`.
        let Ok(handle) =
            (unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE, false, self.pid) })
        else {
            return false;
        };
        let handle = OwnedHandle(handle);
        process_times(handle.0).is_some_and(|(created, _)| created == self.created)
            && !process_list::has_exited(handle.0)
    }
}

/// Every process of the account `sid_text` that is not one of `exclude`: what the first connection runs.
fn account_processes_outside(sid_text: &str, exclude: &[u32]) -> Vec<Tracked> {
    let own = std::process::id();
    let mut found = Vec::new();
    for entry in process_list::snapshot() {
        if entry.pid == 0 || entry.pid == own || exclude.contains(&entry.pid) {
            continue;
        }
        // SAFETY: a plain open by id; the handle is closed by `OwnedHandle`.
        let Ok(handle) = (unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                false,
                entry.pid,
            )
        }) else {
            continue;
        };
        let handle = OwnedHandle(handle);
        if process_list::owner_sddl(handle.0).as_deref() != Some(sid_text) {
            continue;
        }
        if let Some((created, _)) = process_times(handle.0) {
            found.push(Tracked {
                pid: entry.pid,
                name: entry.exe,
                created,
            });
        }
    }
    found
}

/// `(creation, exit)` of `process` in FILETIME ticks; the exit is 0 while it runs.
fn process_times(process: HANDLE) -> Option<(u64, u64)> {
    let (mut created, mut exited, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: a process handle with query access and valid out-pointers.
    unsafe { GetProcessTimes(process, &mut created, &mut exited, &mut kernel, &mut user) }.ok()?;
    let ticks = |t: FILETIME| (u64::from(t.dwHighDateTime) << 32) | u64::from(t.dwLowDateTime);
    Some((ticks(created), ticks(exited)))
}

/// Wait for `process` to exit, up to `bound`: an exit that may never come, whose expiry is reported.
fn wait_exit(process: HANDLE, bound: Duration) -> bool {
    let millis = u32::try_from(bound.as_millis()).expect("a bound shorter than INFINITE");
    // SAFETY: a process handle with SYNCHRONIZE access, held by the caller.
    let rc = unsafe { WaitForSingleObject(process, millis) }; // sleep-ok: failure bound on an external exit; expiry is reported and is not read as state
    rc == WAIT_OBJECT_0
}

/// Image names by process id, as the system lists them now.
fn image_names() -> BTreeMap<u32, String> {
    process_list::snapshot()
        .into_iter()
        .map(|entry| (entry.pid, entry.exe))
        .collect()
}

fn label(names: &BTreeMap<u32, String>, pid: u32) -> String {
    format!("{}#{pid}", names.get(&pid).map_or("?", String::as_str))
}

/// The processes whose token is in logon session `id`, by image and id; one that has exited and is still listed is
/// marked. The handles opened to read them are closed before this returns.
fn members_of(id: u64) -> Result<Vec<String>, String> {
    session_end::attempt("list the processes of the logon session", || {
        let names = image_names();
        let own = std::process::id();
        let mut found: Vec<String> = logon_session::processes_of(id)
            .into_iter()
            .filter(|(pid, _)| *pid != own)
            .map(|(pid, process)| {
                let marker = if process_list::has_exited(process.0) {
                    " (exited, still listed)"
                } else {
                    ""
                };
                format!("{}{marker}", label(&names, pid))
            })
            .collect();
        found.sort();
        found
    })
}

// LSA and the Security log (reads only) =====

/// Whether `LsaEnumerateLogonSessions` lists logon session `id`.
fn lsa_lists(id: u64) -> bool {
    let mut count = 0u32;
    let mut list: *mut LUID = std::ptr::null_mut();
    // SAFETY: valid out-pointers; the list LSA allocates is freed below.
    let status = unsafe { LsaEnumerateLogonSessions(&mut count, &mut list) };
    assert!(
        status.0 == 0 && !list.is_null(),
        "LsaEnumerateLogonSessions failed: NTSTATUS {:#010x}",
        status.0
    );
    // SAFETY: LSA returned `count` consecutive LUIDs, read before they are freed.
    let ids = unsafe { std::slice::from_raw_parts(list, count as usize) };
    let listed = ids
        .iter()
        .any(|luid| (u64::from(luid.HighPart as u32) << 32) | u64::from(luid.LowPart) == id);
    // SAFETY: the buffer came from LSA.
    let _ = unsafe { LsaFreeReturnBuffer(list.cast()) };
    listed
}

/// A 4634 or 4647 event of the Security log.
#[derive(Clone)]
struct LogEvent {
    event_id: u32,
    time: SystemTime,
    logon_id: String,
    user: String,
    logon_type: String,
}

const LOGOFF_EVENTS: &str = "(EventID=4634 or EventID=4647)";

/// 4634 and 4647 whose `TargetLogonId` is `id` in either spelling of the hex digits.
fn by_logon_id(id: u64) -> String {
    format!(
        "*[System[{LOGOFF_EVENTS}]] and *[EventData[Data[@Name='TargetLogonId']='{id:#x}' or \
         Data[@Name='TargetLogonId']='0x{id:X}']]"
    )
}

/// 4634 and 4647 of the account `name`, whatever the logon id.
fn by_user_name(name: &str) -> String {
    format!("*[System[{LOGOFF_EVENTS}]] and *[EventData[Data[@Name='TargetUserName']='{name}']]")
}

/// 4634 and 4647 written in the last `millis` milliseconds, of any account.
fn since_ms(millis: u128) -> String {
    format!("*[System[{LOGOFF_EVENTS} and TimeCreated[timediff(@SystemTime) <= {millis}]]]")
}

/// Run a historical query on the Security channel, oldest first.
fn query_log(xpath: &str) -> Result<Vec<LogEvent>, String> {
    let channel = account_fixture::wide("Security");
    let query = account_fixture::wide(xpath);
    // SAFETY: NUL-terminated inputs; the result set is closed below.
    let results = unsafe {
        EvtQuery(
            None,
            PCWSTR(channel.as_ptr()),
            PCWSTR(query.as_ptr()),
            EvtQueryChannelPath.0 | EvtQueryForwardDirection.0,
        )
    }
    .map_err(|e| format!("query the Security log: {e}"))?;
    let mut events = Vec::new();
    let outcome = loop {
        let mut batch = [0isize; 16];
        let mut returned = 0u32;
        // SAFETY: a valid result set and a buffer of the length passed; INFINITE (u32::MAX) returns at the end of
        // the results with ERROR_NO_MORE_ITEMS.
        match unsafe { EvtNext(results, &mut batch, u32::MAX, 0, &mut returned) } {
            Ok(()) => {}
            Err(e) if e.code().0 as u32 == 0x8007_0103 => break Ok(()),
            Err(e) => break Err(format!("read the results: {e}")),
        }
        for raw in &batch[..returned as usize] {
            let event = EVT_HANDLE(*raw);
            let rendered = render_xml(event);
            // SAFETY: the event handle EvtNext just returned.
            let _ = unsafe { EvtClose(event) };
            match rendered {
                Ok(xml) => events.extend(parse_event(&xml)),
                Err(why) => events.push(LogEvent {
                    event_id: 0,
                    time: UNIX_EPOCH,
                    logon_id: format!("unreadable event: {why}"),
                    user: String::new(),
                    logon_type: String::new(),
                }),
            }
        }
    };
    // SAFETY: the handle from `EvtQuery`.
    let _ = unsafe { EvtClose(results) };
    outcome.map(|()| events)
}

fn render_xml(event: EVT_HANDLE) -> Result<String, String> {
    let (mut used, mut properties) = (0u32, 0u32);
    // SAFETY: a size query, with no buffer.
    let sized = unsafe { EvtRender(None, event, EvtRenderEventXml.0, 0, None, &mut used, &mut properties) };
    match sized {
        Err(e) if e.code() == HRESULT::from_win32(ERROR_INSUFFICIENT_BUFFER.0) => {}
        other => return Err(format!("size an event: {other:?}")),
    }
    let mut buffer = vec![0u16; (used as usize).div_ceil(2)];
    let bytes = (buffer.len() * 2) as u32;
    // SAFETY: a buffer of the `bytes` passed.
    unsafe {
        EvtRender(
            None,
            event,
            EvtRenderEventXml.0,
            bytes,
            Some(buffer.as_mut_ptr().cast()),
            &mut used,
            &mut properties,
        )
    }
    .map_err(|e| format!("render an event: {e}"))?;
    let len = (used as usize / 2).min(buffer.len());
    Ok(String::from_utf16_lossy(&buffer[..len])
        .trim_end_matches('\0')
        .to_owned())
}

/// The text after `marker`, up to the quote that follows the quote opening it.
fn quoted<'a>(xml: &'a str, marker: &str) -> Option<&'a str> {
    let rest = xml.split_once(marker)?.1;
    let quote = rest.chars().next()?;
    rest[quote.len_utf8()..].split(quote).next()
}

/// The text of `<Data Name='name'>...</Data>`.
fn data<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    [format!("Name='{name}'>"), format!("Name=\"{name}\">")]
        .iter()
        .find_map(|marker| xml.split_once(marker.as_str()))?
        .1
        .split('<')
        .next()
}

fn parse_event(xml: &str) -> Option<LogEvent> {
    let event_id = xml
        .split_once("<EventID")?
        .1
        .split_once('>')?
        .1
        .split('<')
        .next()?
        .trim()
        .parse()
        .ok()?;
    let time = parse_time(quoted(xml, "SystemTime=")?)?;
    let field = |name: &str| data(xml, name).unwrap_or("-").to_owned();
    Some(LogEvent {
        event_id,
        time,
        logon_id: field("TargetLogonId"),
        user: field("TargetUserName"),
        logon_type: field("LogonType"),
    })
}

/// `2026-11-19T12:34:56.1234567Z` as a time.
fn parse_time(text: &str) -> Option<SystemTime> {
    let (date, time) = text.strip_suffix('Z')?.split_once('T')?;
    let mut date = date.split('-');
    let (year, month, day): (i64, i64, i64) = (
        date.next()?.parse().ok()?,
        date.next()?.parse().ok()?,
        date.next()?.parse().ok()?,
    );
    let (clock, fraction) = time.split_once('.').unwrap_or((time, ""));
    let mut clock = clock.split(':');
    let (hours, minutes, seconds): (i64, i64, i64) = (
        clock.next()?.parse().ok()?,
        clock.next()?.parse().ok()?,
        clock.next()?.parse().ok()?,
    );
    let nanos: u32 = format!("{fraction:0<9}")[..9].parse().ok()?;
    // Days since 1970-01-01 of a proleptic Gregorian date.
    let shifted_year = if month <= 2 { year - 1 } else { year };
    let era = shifted_year.div_euclid(400);
    let year_of_era = shifted_year - era * 400;
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    let total = u64::try_from(days * 86_400 + hours * 3600 + minutes * 60 + seconds).ok()?;
    Some(UNIX_EPOCH + Duration::new(total, nanos))
}
