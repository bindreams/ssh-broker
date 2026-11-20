//! Spike 6 (throwaway, not for merge): what Windows' `sudo` and gsudo do when an unelevated SSH session runs them.
//! Windows only; **Elevated (CI only)**: each test makes a local administrator, logs it in through the runner's sshd
//! and starts its agent, as `consent_windows` does.
//!
//! All of it is observation. A command is started in the session, and what it prints, how it ends and which
//! processes appear are recorded as `SPIKE6 <question>: ...` lines (`hive::record`: printed, and appended to the file
//! CI prints after the tests). The measurement answers no prompt, sends nothing to another process's window and
//! touches nothing that belongs to another process; what it started it ends by ending its own SSH session. The
//! answers are data: a test asserts only that the measurement ran.
#![cfg(windows)]

#[path = "common/account.rs"]
mod account_fixture;
#[path = "common/agent_conn.rs"]
mod agent_conn;
#[path = "common/bounded_wait.rs"]
mod bounded_wait;
#[path = "common/child_entry.rs"]
mod child_entry;
#[path = "common/command_line_probe.rs"]
mod command_line_probe;
#[path = "common/desktop.rs"]
mod desktop;
#[path = "common/drain.rs"]
mod drain;
#[path = "common/elevate_rig.rs"]
mod elevate_rig;
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

use std::collections::BTreeSet;
use std::os::windows::io::AsRawHandle as _;
use std::time::{Duration, Instant};

use ssh_broker::winutil::OwnedHandle;
use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, WaitForSingleObject,
};

use account_fixture::hive;
use elevate_rig::{HIGH, SCROLLBACK, Started, an_administrator};
use sshd_rig::{SILENCE_BOUND, SshSession};

/// How often the follow loop looks at the process list while it waits on the session's stream.
const POLL: Duration = Duration::from_millis(250);

/// How long the end of the session may take to be seen (the ssh client's exit, the command's processes gone). The
/// expiry is the datum: "still there after N s".
const TEARDOWN_BOUND: Duration = Duration::from_secs(30);

/// What the command's script prints first (the shell's process id) and last (`$LASTEXITCODE`). The script builds each
/// from two pieces, so the typed line, which a terminal echoes, never holds the marker itself.
const BEGIN: &str = "SPIKE6-BEGIN pid=";
const EXIT: &str = "SPIKE6-EXIT=";

/// The registry key of the UAC policy values.
const POLICIES: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";

/// One observation: `SPIKE6 <tag>: <text>`.
fn line(tag: &str, text: &str) {
    hive::record(&format!("SPIKE6 {tag}: {text}"));
}

/// `text` on one line, its runs of white space as single spaces.
fn flat(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn how(terminal: bool) -> &'static str {
    if terminal {
        "with a terminal"
    } else {
        "without a terminal"
    }
}

/// What `command` is run as in the session: the shell's id first, the command, then `$LASTEXITCODE`.
fn script(command: &str) -> String {
    format!(
        "Write-Output ('SPIKE6-' + 'BEGIN pid=' + $PID); {command}; Write-Output ('SPIKE6-' + 'EXIT=' + $LASTEXITCODE)"
    )
}

/// What follows the first `marker` of `text` that its line has ended after, up to the end of that line.
fn after_marker(text: &str, marker: &str) -> Option<String> {
    text.match_indices(marker).find_map(|(at, _)| {
        let rest = &text[at + marker.len()..];
        let end = rest.find(['\r', '\n'])?;
        Some(rest[..end].trim().to_owned())
    })
}

/// The number `text` starts with.
fn leading_number(text: &str) -> Option<i64> {
    let sign = usize::from(text.starts_with('-'));
    let digits = text[sign..].chars().take_while(char::is_ascii_digit).count();
    text[..sign + digits].parse().ok()
}

/// The ids of the `consent.exe` processes the system lists: UAC's prompt.
fn consents() -> BTreeSet<u32> {
    process_list::snapshot()
        .into_iter()
        .filter(|entry| entry.exe.eq_ignore_ascii_case("consent.exe"))
        .map(|entry| entry.pid)
        .collect()
}

/// The session the system says process `pid` is in.
fn session_of(pid: u32) -> String {
    let mut session = 0u32;
    // SAFETY: a plain call by process id with a valid out-pointer.
    match unsafe { ProcessIdToSessionId(pid, &mut session) } {
        Ok(()) => session.to_string(),
        Err(e) => format!("unknown ({e})"),
    }
}

/// The shell of the session and everything under it, held open.
struct Tree {
    root: Option<(u32, OwnedHandle)>,
    members: Vec<process_list::Member>,
    unopened: Vec<String>,
}

impl Tree {
    fn of(shell: Option<u32>) -> Tree {
        let root = shell.and_then(|pid| {
            // SAFETY: a plain open by id; the handle is closed by `OwnedHandle`.
            unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE, false, pid) }
                .ok()
                .map(|handle| (pid, OwnedHandle(handle)))
        });
        let (members, unopened) = match &root {
            Some((pid, handle)) => {
                let below = process_list::descendants(handle.0, *pid);
                (below.members, below.unopened)
            }
            None => (Vec::new(), Vec::new()),
        };
        Tree {
            root,
            members,
            unopened,
        }
    }

    fn describe(&self) -> String {
        let shell = match &self.root {
            Some((pid, handle)) => format!(
                "the shell {pid} {}",
                if process_list::has_exited(handle.0) {
                    "has exited"
                } else {
                    "is running"
                }
            ),
            None => "the shell could not be opened (it is gone, or its id was never printed)".to_owned(),
        };
        let below: Vec<String> = self
            .members
            .iter()
            .map(|m| {
                format!(
                    "{} {} (parent {}, {})",
                    m.pid,
                    m.exe,
                    m.parent,
                    if process_list::has_exited(m.handle()) {
                        "has exited"
                    } else {
                        "running"
                    }
                )
            })
            .collect();
        let below = if below.is_empty() {
            "nothing".to_owned()
        } else {
            below.join(", ")
        };
        let unopened = if self.unopened.is_empty() {
            String::new()
        } else {
            format!("; could not be opened: {}", self.unopened.join(", "))
        };
        format!("{shell}; under it: {below}{unopened}")
    }

    /// Wait for the shell and each process under it to end, at most `bound` in all: how long it took, and the ones
    /// still running when it ran out.
    fn wait_gone(&self, bound: Duration) -> (Duration, Vec<String>) {
        let started = Instant::now();
        let mut running = Vec::new();
        let held = self
            .root
            .iter()
            .map(|(pid, handle)| (format!("the shell {pid}"), handle.0))
            .chain(
                self.members
                    .iter()
                    .map(|m| (format!("{} {}", m.pid, m.exe), m.handle())),
            );
        for (name, handle) in held {
            let left = u32::try_from(bound.saturating_sub(started.elapsed()).as_millis()).unwrap();
            // SAFETY: a live handle with the right to wait.
            let rc = unsafe { WaitForSingleObject(handle, left) }; // sleep-ok: the bound is the datum (does the command's process end after its session is closed); expiry is recorded as "still running", not read as state
            if rc != WAIT_OBJECT_0 {
                running.push(name);
            }
        }
        (started.elapsed(), running)
    }
}

/// What came first after the command was started.
enum Followed {
    /// The command printed its exit marker.
    Ended { exit: String, after: Duration },
    /// The session's stream closed with no exit marker.
    Closed { after: Duration },
    /// A `consent.exe` that was not there before appeared.
    Prompt { consent: u32, after: Duration },
    /// Neither, for [`SILENCE_BOUND`].
    Neither,
}

/// Read the session's stream and the process list in turn until the command ends, a `consent.exe` not in
/// `consents_before` appears, or [`SILENCE_BOUND`] has passed. The bound is the datum here: neither event may ever
/// come.
fn follow(session: &mut SshSession, from: usize, consents_before: &BTreeSet<u32>) -> Followed {
    let started = Instant::now();
    let mut closed = false;
    loop {
        let text = String::from_utf8_lossy(&session.transcript[from..]).into_owned();
        if let Some(exit) = after_marker(&text, EXIT) {
            return Followed::Ended {
                exit,
                after: started.elapsed(),
            };
        }
        if closed {
            return Followed::Closed {
                after: started.elapsed(),
            };
        }
        if let Some(&consent) = consents().difference(consents_before).next() {
            return Followed::Prompt {
                consent,
                after: started.elapsed(),
            };
        }
        if started.elapsed() >= SILENCE_BOUND {
            return Followed::Neither;
        }
        let received = session.output.recv_timeout(POLL); // sleep-ok: reads the stream in turn with the process list; the total is bounded by SILENCE_BOUND, which is the datum, and no expiry is read as state
        match received {
            Ok(chunk) => session.transcript.extend_from_slice(&chunk),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => closed = true,
        }
    }
}

/// What the command printed, as lines: the rows of the screen after the shell's id for a session with a terminal, the
/// stream itself otherwise.
fn output_lines(session: &SshSession, from: usize, terminal: bool) -> Vec<String> {
    let rows: Vec<String> = if terminal {
        let history = sshd_rig::rendered(&session.transcript, SCROLLBACK).history();
        let rows: Vec<String> = history.lines().map(str::to_owned).collect();
        let begin = rows.iter().rposition(|row| row.starts_with(BEGIN));
        rows[begin.map_or(0, |at| at + 1)..].to_vec()
    } else {
        String::from_utf8_lossy(&session.transcript[from..])
            .lines()
            .map(str::to_owned)
            .collect()
    };
    rows.into_iter()
        .map(|row| row.trim().to_owned())
        .filter(|row| !row.is_empty() && !row.starts_with(BEGIN))
        .collect()
}

/// Run `command` in an unelevated session of the administrator (`terminal`: with a terminal) and record what
/// follows as `SPIKE6 <tag>: <subject>: ...` lines: the command ended (its output, `$LASTEXITCODE` and whether the
/// output shows High integrity), or a `consent.exe` appeared (its id and session, and the shell's session), or neither
/// happened in [`SILENCE_BOUND`] (with the process tree under the command). Then the session is closed, and whether
/// the command's processes are gone is recorded. Returns the command's output lines.
fn observe(admin: &Started<'_>, tag: &str, subject: &str, terminal: bool, command: &str) -> Vec<String> {
    let mut terminal_session = terminal.then(|| admin.terminal_session_asking(None));
    let consents_before = consents();
    let listed_before: BTreeSet<(u32, String)> = process_list::snapshot()
        .into_iter()
        .map(|entry| (entry.pid, entry.exe))
        .collect();
    let (mut session, from) = match terminal_session.take() {
        Some(mut session) => {
            let from = session.transcript.len();
            session.type_line(&script(command));
            (session, from)
        }
        None => {
            let mut ssh = admin.login.command_with(None);
            ssh.arg("-T").arg("--").arg(script(command));
            (SshSession::start_as_given(ssh, admin.diagnostics()), 0)
        }
    };
    line(
        tag,
        &format!(
            "{subject}: started `{command}` {}{}; {} consent.exe already listed",
            how(terminal),
            if terminal {
                ""
            } else {
                " (ssh -T; stdin an open pipe nobody writes to)"
            },
            consents_before.len()
        ),
    );

    let followed = follow(&mut session, from, &consents_before);
    let text = String::from_utf8_lossy(&session.transcript[from..]).into_owned();
    let shell = after_marker(&text, BEGIN)
        .and_then(|pid| leading_number(&pid))
        .and_then(|pid| u32::try_from(pid).ok());
    let tree = Tree::of(shell);
    let new: Vec<(u32, u32, String)> = process_list::snapshot()
        .into_iter()
        .filter(|entry| !listed_before.contains(&(entry.pid, entry.exe.clone())))
        .map(|entry| (entry.pid, entry.parent, entry.exe))
        .collect();
    let output = output_lines(&session, from, terminal);

    match &followed {
        Followed::Ended { exit, after } => line(
            tag,
            &format!(
                "{subject}: the command ended after {:.1} s; $LASTEXITCODE is {:?} (parsed: {:?}); output shows High integrity: {}",
                after.as_secs_f32(),
                exit,
                leading_number(exit),
                output.iter().any(|row| row.contains(HIGH))
            ),
        ),
        Followed::Closed { after } => line(
            tag,
            &format!(
                "{subject}: the session's stream closed after {:.1} s with no exit marker (the command did not print its $LASTEXITCODE); output shows High integrity: {}",
                after.as_secs_f32(),
                output.iter().any(|row| row.contains(HIGH))
            ),
        ),
        Followed::Prompt { consent, after } => line(
            tag,
            &format!(
                "{subject}: a consent.exe appeared after {:.1} s that was not there before: process {consent}, in session {}; the SSH session's shell ({}) is in session {}",
                after.as_secs_f32(),
                session_of(*consent),
                shell.map_or_else(|| "unknown".to_owned(), |pid| pid.to_string()),
                shell.map_or_else(|| "unknown".to_owned(), session_of),
            ),
        ),
        Followed::Neither => line(
            tag,
            &format!(
                "{subject}: neither ended nor raised a prompt in {} s",
                SILENCE_BOUND.as_secs()
            ),
        ),
    }
    line(
        tag,
        &format!("{subject}: the process tree under the command: {}", tree.describe()),
    );
    let new_text: Vec<String> = new
        .iter()
        .map(|(pid, parent, exe)| format!("{pid} {exe} (parent {parent}, session {})", session_of(*pid)))
        .collect();
    line(
        tag,
        &format!(
            "{subject}: processes listed now that were not before the command started: {}",
            if new_text.is_empty() {
                "none".to_owned()
            } else {
                new_text.join(", ")
            }
        ),
    );
    for row in &output {
        line(tag, &format!("{subject}: output: {row}"));
    }
    let raw = String::from_utf8_lossy(&session.transcript[from..]).into_owned();
    let raw: String = raw
        .chars()
        .rev()
        .take(3000)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    line(
        tag,
        &format!("{subject}: the stream since the command started, escaped (last 3000 characters): {raw:?}"),
    );
    let client_stderr = std::fs::read_to_string(&admin.login.stderr_path).unwrap_or_default();
    line(
        tag,
        &format!("{subject}: the ssh client's stderr: {:?}", flat(&client_stderr)),
    );

    // Without a terminal, the client's own end is part of what follows an ended command.
    if !terminal && !matches!(followed, Followed::Prompt { .. } | Followed::Neither) {
        let handle = HANDLE(session.child.as_raw_handle());
        let millis = u32::try_from(TEARDOWN_BOUND.as_millis()).unwrap();
        // SAFETY: the client is our own child and its handle is live.
        let rc = unsafe { WaitForSingleObject(handle, millis) }; // sleep-ok: the bound is the datum (does the client end once the command has); expiry is recorded, not read as state
        let ended = if rc == WAIT_OBJECT_0 {
            let code = session.child.wait().ok().and_then(|status| status.code());
            format!("the ssh client ended with exit code {code:?}")
        } else {
            format!("the ssh client was still running {} s later", TEARDOWN_BOUND.as_secs())
        };
        line(tag, &format!("{subject}: {ended}"));
    }

    // Close the session: the client is ended, and sshd and the agent end what the session started.
    let _ = session.child.kill();
    let _ = session.child.wait();
    drop(session);
    line(
        tag,
        &format!("{subject}: the session was closed (the ssh client ended)"),
    );
    let (took, running) = tree.wait_gone(TEARDOWN_BOUND);
    line(
        tag,
        &format!(
            "{subject}: after the close, the processes under the command: {}",
            if running.is_empty() {
                format!("all gone after {:.1} s", took.as_secs_f32())
            } else {
                format!(
                    "still running after {} s: {}",
                    TEARDOWN_BOUND.as_secs(),
                    running.join(", ")
                )
            }
        ),
    );
    let listed_now: BTreeSet<(u32, String)> = process_list::snapshot()
        .into_iter()
        .map(|entry| (entry.pid, entry.exe))
        .collect();
    let remaining: Vec<String> = new
        .iter()
        .filter(|(pid, _, exe)| listed_now.contains(&(*pid, exe.clone())))
        .map(|(pid, _, exe)| format!("{pid} {exe}"))
        .collect();
    line(
        tag,
        &format!(
            "{subject}: of the processes that were new, still listed after the close (just then): {}",
            if remaining.is_empty() {
                "none".to_owned()
            } else {
                remaining.join(", ")
            }
        ),
    );

    assert!(
        shell.is_some(),
        "{subject}: the session never printed the shell's id: the command line did not run\nthe stream:\n{text}\n{}",
        (admin.diagnostics())()
    );
    output
}

/// A registry value as `reg query` prints it, on one line.
fn registry_line(key: &str, value: &str) -> String {
    let (_, text) = sshd_rig::run("reg", &["query", key, "/v", value]);
    flat(&text)
}

// Context =====

/// Elevated (CI only). CTX: the Windows build, the UAC policy values, the session id and integrity of the unelevated
/// session (with a terminal and without), whether `sudo.exe` and `gsudo` are found there, and what `sudo config`
/// prints.
#[test]
fn spike6_ctx_the_machine_and_the_unelevated_session() {
    let _machine = machine::exclusive();
    let version = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    for value in ["ProductName", "CurrentBuildNumber", "UBR"] {
        line("CTX", &format!("windows: {}", registry_line(version, value)));
    }
    for value in ["EnableLUA", "ConsentPromptBehaviorAdmin", "PromptOnSecureDesktop"] {
        line("CTX", &format!("policy: {}", registry_line(POLICIES, value)));
    }
    let (found, where_sudo) = sshd_rig::run("where.exe", &["sudo"]);
    line(
        "CTX",
        &format!(
            "where.exe sudo (the test process, elevated): found {found}: {}",
            flat(&where_sudo)
        ),
    );
    if found {
        let (ok, config) = sshd_rig::run("sudo", &["config"]);
        line(
            "CTX",
            &format!(
                "sudo config (the test process, elevated): success {ok}: {}",
                flat(&config)
            ),
        );
    }

    let (kit, account, _end) = an_administrator("spk6");
    let admin = Started::start(&kit, &account);
    for terminal in [true, false] {
        observe(
            &admin,
            "CTX",
            &format!("the unelevated session {}", how(terminal)),
            terminal,
            "Write-Output ('SESSION=' + (Get-Process -Id $PID).SessionId); whoami /groups | Select-String 'Mandatory Label'; \
             where.exe sudo; where.exe gsudo",
        );
    }
}

// Q1: Windows' sudo =====

/// Set the mode of Windows' `sudo` as Microsoft documents (`sudo config --enable <mode>`, from this elevated test
/// process) and start `sudo whoami /groups` in the unelevated session, with a terminal and without one.
fn sudo_in_mode(mode: &str) {
    let _machine = machine::exclusive();
    let (found, where_sudo) = sshd_rig::run("where.exe", &["sudo"]);
    if !found {
        line(
            "Q1",
            &format!(
                "sudo {mode}: sudo.exe is not on the runner (where.exe sudo: {}); Q1 is answered",
                flat(&where_sudo)
            ),
        );
        return;
    }
    line("Q1", &format!("sudo {mode}: sudo.exe is at {}", flat(&where_sudo)));
    let (ok, set) = sshd_rig::run("sudo", &["config", "--enable", mode]);
    line(
        "Q1",
        &format!(
            "sudo {mode}: `sudo config --enable {mode}` (elevated): success {ok}: {}",
            flat(&set)
        ),
    );
    let (ok, config) = sshd_rig::run("sudo", &["config"]);
    line(
        "Q1",
        &format!(
            "sudo {mode}: `sudo config` afterwards (elevated): success {ok}: {}",
            flat(&config)
        ),
    );

    let (kit, account, _end) = an_administrator("spk6");
    let admin = Started::start(&kit, &account);
    for terminal in [true, false] {
        observe(
            &admin,
            "Q1",
            &format!("sudo {mode}, {}", how(terminal)),
            terminal,
            "sudo whoami /groups",
        );
    }
}

/// Elevated (CI only). Q1 for `forceNewWindow`.
#[test]
fn spike6_q1_sudo_force_new_window() {
    sudo_in_mode("forceNewWindow");
}

/// Elevated (CI only). Q1 for `disableInput`.
#[test]
fn spike6_q1_sudo_disable_input() {
    sudo_in_mode("disableInput");
}

/// Elevated (CI only). Q1 for `normal`, the inline mode.
#[test]
fn spike6_q1_sudo_normal() {
    sudo_in_mode("normal");
}

// Q2: gsudo =====

/// Elevated (CI only). Q2: `gsudo whoami /groups` in the unelevated session, with a terminal and without one. The
/// workflow installs gsudo; a machine without it fails the test.
#[test]
fn spike6_q2_gsudo() {
    let _machine = machine::exclusive();
    let (found, where_gsudo) = sshd_rig::run("where.exe", &["gsudo"]);
    assert!(
        found,
        "gsudo is not on the machine: the workflow's `choco install gsudo -y` step must put it on the PATH (where.exe: {where_gsudo})"
    );
    let (_, version) = sshd_rig::run("gsudo", &["--version"]);
    line(
        "Q2",
        &format!(
            "gsudo is at {}; `gsudo --version` (elevated): {}",
            flat(&where_gsudo),
            flat(&version)
        ),
    );

    let (kit, account, _end) = an_administrator("spk6");
    let admin = Started::start(&kit, &account);
    let seen = observe(
        &admin,
        "Q2",
        "where.exe gsudo in the unelevated session",
        false,
        "where.exe gsudo",
    );
    assert!(
        seen.iter().any(|row| row.to_lowercase().contains("gsudo")),
        "the unelevated session does not find gsudo: {seen:?}"
    );
    for terminal in [true, false] {
        observe(
            &admin,
            "Q2",
            &format!("gsudo, {}", how(terminal)),
            terminal,
            "gsudo whoami /groups",
        );
    }
}
