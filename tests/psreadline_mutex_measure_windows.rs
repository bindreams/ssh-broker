//! A measurement, not a check: where typed keys get lost in a session the password prompt started. Windows
//! only; **Elevated (CI only)**. It fails on purpose: its panic text is the record, and nextest prints a
//! failing test's output only.
//!
//! The scenario is the one `prompt_path_windows` runs (a fresh account, the shim on a console of its own,
//! the password at the prompt, the background agent's PowerShell as the shell), repeated until a typed line
//! is not answered. After the login and the first answer, the I/O counters of every process on the path of a
//! key (the helper, its two `conhost`s, the shim, the agent, the agent's `conhost`, the shell) are read once,
//! as the baseline. Then each line is typed the moment the answer to the one before has been read, with
//! nothing else done between lines: a walk of the processes costs tens of milliseconds, and a line typed
//! after that pause was never lost. The counters are read again only when a line is not answered (and once at
//! the end of a repetition that had no stall), and are compared with the key-event bytes typed since the
//! baseline: each process on the path should show those bytes read or written, and the first that does not
//! shows where the bytes stopped. The test only observes: it lists processes, reads their counters and the
//! logs, and types into its own session.
#![cfg(windows)]

use std::fmt::Write as _;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::{SystemTime, UNIX_EPOCH};

use ssh_broker::socket_loc::SocketLocation;
use ssh_broker::vtinput::{KeyEvent, encode_key_event};
use ssh_broker::winutil::OwnedHandle;
use windows::Wdk::System::SystemServices::RtlGetVersion;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::System::SystemInformation::OSVERSIONINFOW;
use windows::Win32::System::Threading::{
    GetProcessIoCounters, GetProcessTimes, IO_COUNTERS, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
};

#[path = "common/account.rs"]
mod account_fixture;
#[path = "common/bounded_wait.rs"]
mod bounded_wait;
#[path = "common/desktop.rs"]
mod desktop;
#[path = "common/hard_errors.rs"]
mod hard_errors;
#[path = "common/machine.rs"]
mod machine;
#[path = "common/password.rs"]
mod password;
#[path = "common/process_list.rs"]
mod process_list;
#[path = "common/pty_client.rs"]
mod pty_client;
#[path = "common/stand_in.rs"]
mod stand_in;

use account_fixture::Account;
use pty_client::PtyRun;
use stand_in::Kit;

/// How many fresh-account repetitions to run at most.
const REPETITIONS: usize = 20;
/// Lines typed after the baseline, each at once after the answer to the one before, before `exit`.
const MARKER_LINES: usize = 40;

/// What the prompt says first, as in `prompt_path_windows`.
const PROMPT: &str = "Enter your Windows password to start one.";
/// The start of a PowerShell prompt.
const SHELL_PROMPT: &str = "PS C:\\";
/// The first line the prompt tests type at the shell: PSReadLine out, so the host's own reader reads on.
const REMOVE_MODULE: &str =
    "Remove-Module PSReadLine -ErrorAction SilentlyContinue; Write-Output ('psreadline' + '-off')";

// The record -----

/// Everything observed, as text; the panic that ends the test carries it.
#[derive(Default)]
struct Record {
    text: String,
    /// What the running repetition has noted; moved to `text` when the repetition ends.
    pending: String,
    /// Lines typed in all.
    lines_typed: usize,
    /// Where the first stall came, once it has.
    stall: Option<String>,
}

impl Record {
    fn line(&mut self, text: impl AsRef<str>) {
        self.text.push_str(text.as_ref());
        self.text.push('\n');
    }

    fn note(&mut self, text: impl AsRef<str>) {
        self.pending.push_str(text.as_ref());
        self.pending.push('\n');
    }
}

enum Verdict {
    Worked,
    Failed,
}

/// A typed line that was not answered, and what the fixture said when it gave up.
struct Stalled {
    /// Its place among the lines typed in the repetition, from 1.
    number: usize,
    /// The line as the record shows it: its text, except for the password.
    shown: String,
    why: String,
}

/// The counters of the processes on the path at one moment, and the key-event bytes typed before it.
struct Baseline {
    typed: usize,
    counters: Vec<Counters>,
}

/// What a repetition has typed, for comparing with the counters.
#[derive(Default)]
struct Session {
    /// Lines typed, the stalled one included.
    lines: usize,
    /// Bytes of key events typed since the session began, the stalled line included.
    typed: usize,
    /// Taken after the first answer; `None` before it.
    baseline: Option<Baseline>,
}

impl Session {
    /// Type `text` as a line (`shown` is what the record says it was) and wait, bounded, for `wait` to see its
    /// answer. Nothing else is done, so that the next line can follow at once.
    fn type_line(
        &mut self,
        run: &mut PtyRun,
        shown: &str,
        text: &str,
        wait: impl FnOnce(&mut PtyRun),
    ) -> Result<(), Stalled> {
        self.lines += 1;
        self.typed += key_bytes(text) + enter_bytes();
        bounded(run, |run| {
            run.type_line(text);
            wait(run);
        })
        .map_err(|why| Stalled {
            number: self.lines,
            shown: shown.to_owned(),
            why,
        })
    }

    /// Where the typed bytes and the counters are measured from.
    fn since(&self) -> &'static str {
        if self.baseline.is_some() {
            "the baseline, taken after the first answer"
        } else {
            "the session's start (no baseline yet; each process's totals are since it began)"
        }
    }

    /// Bytes of key events typed since the baseline (the session's start, if there is none).
    fn typed_since_baseline(&self) -> usize {
        self.typed - self.baseline.as_ref().map_or(0, |baseline| baseline.typed)
    }

    /// What each process's counters rose by since the baseline, as of `now`.
    fn counters_since_baseline(&self, now: &[Counters]) -> String {
        counters_delta(
            self.baseline
                .as_ref()
                .map_or(&[][..], |baseline| baseline.counters.as_slice()),
            now,
        )
    }
}

/// Elevated (CI only). Fails on purpose; read the panic text.
#[test]
fn typed_keys_loss_measurement() {
    let _machine = machine::shared();
    account_fixture::assert_elevated();
    let mut record = Record::default();
    record.line(format!(
        "Windows {}; this test process is pid {} in Windows session {}",
        windows_version(),
        std::process::id(),
        session_text(std::process::id())
    ));
    let (mut ran, mut ended_by_panic_in) = (0, None);
    for n in 1..=REPETITIONS {
        ran = n;
        record.pending.clear();
        let verdict = catch_unwind(AssertUnwindSafe(|| repetition(n, &mut record)));
        let pending = std::mem::take(&mut record.pending);
        record.line(pending);
        match verdict {
            Ok(Verdict::Worked) => {}
            Ok(Verdict::Failed) => break,
            Err(panic) => {
                record.line(format!("repetition {n} panicked: {}", panic_text(&panic)));
                ended_by_panic_in = Some(n);
                break;
            }
        }
    }
    let outcome = match (&record.stall, ended_by_panic_in) {
        (Some(stall), _) => format!("the first stall came at {stall}"),
        (None, Some(n)) => format!("no typed line stalled; repetition {n} ended in a panic outside a typed line"),
        (None, None) => "no typed line stalled".to_owned(),
    };
    panic!(
        "MEASURED (this test fails on purpose): {ran} of {REPETITIONS} repetitions ran and {} lines were typed in all; {outcome}\n\n{}",
        record.lines_typed, record.text
    );
}

/// One fresh account, logged in through the prompt, and the lines typed at its shell.
fn repetition(n: usize, record: &mut Record) -> Verdict {
    let kit = Kit::broker_with_helper("psr");
    let account = Account::create("psr", true);
    let location = account.socket_location();
    record.note(format!(
        "\n######## repetition {n}: account {} ({})",
        account.name, account.sid_text
    ));
    let mut run = start_run(&kit, &account);
    run.read_until(PROMPT);
    let mut session = Session::default();
    let typed = typed_lines(record, &mut session, &mut run, &account, &location);
    record.lines_typed += session.lines;
    match typed {
        Ok(()) => Verdict::Worked,
        Err(stalled) => {
            record.stall = Some(format!(
                "line {} ({}) of repetition {n}, the {}th line typed in all",
                stalled.number, stalled.shown, record.lines_typed
            ));
            at_stall(record, &mut run, &account, &location, &session, &stalled);
            Verdict::Failed
        }
    }
}

/// The lines of a repetition. The login and the first answer come first, and then the counters are read once;
/// the marker lines follow, each typed the moment the previous answer has been read. The first line that is
/// not answered ends the repetition.
fn typed_lines(
    record: &mut Record,
    session: &mut Session,
    run: &mut PtyRun,
    account: &Account,
    location: &SocketLocation,
) -> Result<(), Stalled> {
    session.type_line(run, "(the password)", &account.password, |_| {
        stand_in::wait_for_serving_marker_of_a_task(location, stand_in::SERVING_BOUND);
    })?;
    run.read_until(SHELL_PROMPT);
    session.type_line(run, REMOVE_MODULE, REMOVE_MODULE, |run| {
        run.read_until("psreadline-off");
    })?;
    session.baseline = Some(Baseline {
        typed: session.typed,
        counters: path_counters(account),
    });
    for k in 1..=MARKER_LINES {
        // Two digits, so that no marker is the start of another: the console's text is never consumed.
        let marker = format!("marker-{k:02}");
        let line = format!("Write-Output ('marker' + '-{k:02}')");
        session.type_line(run, &line, &line, |run| run.read_until(&marker))?;
    }
    record.note(format!(
        "no stall in the {MARKER_LINES} marker lines; {} bytes of key events typed since the baseline; \
         change in each process's I/O counters since it, at {} UTC: {}",
        session.typed_since_baseline(),
        clock(now_filetime()),
        one_line(&session.counters_since_baseline(&path_counters(account)))
    ));
    session.type_line(run, "exit", "exit", |run| {
        run.finish();
    })
}

/// `rows` of `counters_delta`, on one line.
fn one_line(rows: &str) -> String {
    rows.lines().map(str::trim).collect::<Vec<_>>().join(" | ")
}

/// What is recorded once a line is not answered: the line, the key-event bytes typed since the baseline and
/// what each process's counters rose by since it, the fixture's report (the console text, and the process
/// tree with thread wait reasons), whether later keys are echoed, the counters over that probe, and the logs.
fn at_stall(
    record: &mut Record,
    run: &mut PtyRun,
    account: &Account,
    location: &SocketLocation,
    session: &Session,
    stalled: &Stalled,
) {
    let why = stalled.why.as_str();
    let now = path_counters(account);
    record.note(format!(
        "\n== THE STALL at {} UTC: line {} of the repetition, {:?}; {} bytes of key events typed since {}, \
         the stalled line included ({} lines typed in the repetition); change in each process's I/O counters since then:\n{}",
        clock(now_filetime()),
        stalled.number,
        stalled.shown,
        session.typed_since_baseline(),
        session.since(),
        session.lines,
        session.counters_since_baseline(&now)
    ));
    record.note(format!("as the fixture reported it:\n{why}"));
    if !why.contains("process tree:") {
        let tree = helper_of(account).map_or_else(
            || "the helper is gone".to_owned(),
            |(pid, helper)| bounded_wait::process_tree(helper.0, pid),
        );
        record.note(format!("process tree:\n{tree}"));
    }
    let probed = catch_unwind(AssertUnwindSafe(|| typing_probe(record, run)));
    if let Err(panic) = probed {
        record.note(format!("the typing probe panicked: {}", panic_text(&panic)));
    }
    let after_probe = path_counters(account);
    record.note(format!(
        "change in each process's I/O counters from the stall's reading to the end of the typing probe:\n{}",
        counters_delta(&now, &after_probe)
    ));
    record.note(format!(
        "the logs (agent.log, shim.log), at {} UTC:\n{}",
        clock(now_filetime()),
        stand_in::read_logs(location)
    ));
}

/// The shim of `account` on a console, with the logs printed when a wait fails.
fn start_run(kit: &Kit, account: &Account) -> PtyRun {
    let location = account.try_socket_location();
    PtyRun::start(kit, account, &kit.exe).with_context(move || {
        let logs = location.as_ref().map(stand_in::read_logs).unwrap_or_default();
        format!("logs of the account (shim.log, agent.log):\n{logs}")
    })
}

// What each process on the path did -----

/// One process on the path of a key, with its I/O counters at one moment.
struct Counters {
    /// 0 for a descendant the fixture could not open: its row has no counters.
    pid: u32,
    label: String,
    io: Result<IO_COUNTERS, String>,
}

/// A process of the path before its counters are read.
struct Row<'a> {
    pid: u32,
    parent: u32,
    exe: &'a str,
    created: u64,
    handle: HANDLE,
}

/// The helper of `account` (a child of this test process), opened for reading: the root of the path.
fn helper_of(account: &Account) -> Option<(u32, OwnedHandle)> {
    process_list::snapshot()
        .into_iter()
        .filter(|entry| entry.exe.eq_ignore_ascii_case("helper.exe") && entry.parent == std::process::id())
        .find_map(|entry| {
            // SAFETY: a plain open by id; the handle is closed by `OwnedHandle`.
            let handle = OwnedHandle(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, entry.pid) }.ok()?);
            (process_list::owner_sddl(handle.0).as_deref() == Some(account.sid_text.as_str()))
                .then_some((entry.pid, handle))
        })
}

/// The counters of the helper and of every process the fixture finds under it (its two `conhost`s, the shim,
/// the agent, the agent's `conhost`, the shell), oldest first. Empty once the helper is gone.
fn path_counters(account: &Account) -> Vec<Counters> {
    let Some((root_pid, root)) = helper_of(account) else {
        return Vec::new();
    };
    let tree = process_list::descendants(root.0, root_pid);
    let mut rows = vec![Row {
        pid: root_pid,
        parent: std::process::id(),
        exe: "helper.exe",
        created: creation_time(root.0).unwrap_or(0),
        handle: root.0,
    }];
    rows.extend(tree.members.iter().map(|member| Row {
        pid: member.pid,
        parent: member.parent,
        exe: &member.exe,
        created: creation_time(member.handle()).unwrap_or(0),
        handle: member.handle(),
    }));
    rows.sort_by_key(|row| row.created);
    let mut counters: Vec<Counters> = rows
        .iter()
        .map(|row| {
            let siblings: Vec<&Row> = rows
                .iter()
                .filter(|other| other.parent == row.parent && other.exe.eq_ignore_ascii_case(row.exe))
                .collect();
            let rank = if siblings.len() > 1 {
                format!(
                    ", #{} of {} by creation",
                    siblings.iter().filter(|other| other.created < row.created).count() + 1,
                    siblings.len()
                )
            } else {
                String::new()
            };
            let parent = rows
                .iter()
                .find(|other| other.pid == row.parent)
                .map_or("the test", |other| other.exe);
            Counters {
                pid: row.pid,
                label: format!("{} (parent {parent}{rank})", row.exe),
                io: io_counters(row.handle),
            }
        })
        .collect();
    counters.extend(tree.unopened.iter().map(|note| Counters {
        pid: 0,
        label: format!("not examined: {note}"),
        io: Err("the process was not opened".to_owned()),
    }));
    counters
}

fn io_counters(process: HANDLE) -> Result<IO_COUNTERS, String> {
    let mut counters = IO_COUNTERS::default();
    // SAFETY: a live handle with query access; a valid out-pointer.
    unsafe { GetProcessIoCounters(process, &mut counters) }
        .map(|()| counters)
        .map_err(|e| e.to_string())
}

/// One row per process of `after`: what its operation and byte counts rose by since `before`.
fn counters_delta(before: &[Counters], after: &[Counters]) -> String {
    let mut text = String::new();
    for now in after {
        let change = match (&now.io, before.iter().find(|was| was.pid == now.pid).map(|was| &was.io)) {
            (Err(why), _) => format!("counters unreadable: {why}"),
            (Ok(now), Some(Ok(was))) => rise(was, now),
            (Ok(now), None) => format!(
                "not in the earlier reading; its totals: {}",
                rise(&IO_COUNTERS::default(), now)
            ),
            (Ok(_), Some(Err(why))) => format!("counters unreadable in the earlier reading: {why}"),
        };
        let _ = writeln!(text, "    pid {} {}: {change}", now.pid, now.label);
    }
    for gone in before
        .iter()
        .filter(|was| was.pid != 0 && !after.iter().any(|now| now.pid == was.pid))
    {
        let _ = writeln!(text, "    pid {} {}: gone by the later reading", gone.pid, gone.label);
    }
    if text.is_empty() {
        text.push_str("    no process on the path\n");
    }
    text
}

fn rise(was: &IO_COUNTERS, now: &IO_COUNTERS) -> String {
    format!(
        "reads {} ops {} bytes; writes {} ops {} bytes; other {} ops {} bytes",
        now.ReadOperationCount.saturating_sub(was.ReadOperationCount),
        now.ReadTransferCount.saturating_sub(was.ReadTransferCount),
        now.WriteOperationCount.saturating_sub(was.WriteOperationCount),
        now.WriteTransferCount.saturating_sub(was.WriteTransferCount),
        now.OtherOperationCount.saturating_sub(was.OtherOperationCount),
        now.OtherTransferCount.saturating_sub(was.OtherTransferCount),
    )
}

// Whether the keys get lost, or the path is dead -----

/// The key events `PtyRun::type_text` sends for `text` (a down and an up event per UTF-16 unit), in bytes.
fn key_bytes(text: &str) -> usize {
    text.encode_utf16().map(|unit| event_bytes(unit, 0)).sum()
}

/// The key events `PtyRun::press_enter` sends, in bytes.
fn enter_bytes() -> usize {
    event_bytes(0x0D, 0x0D)
}

fn event_bytes(unicode_char: u16, virtual_key_code: u16) -> usize {
    [true, false]
        .into_iter()
        .map(|key_down| {
            encode_key_event(&KeyEvent {
                virtual_key_code,
                virtual_scan_code: 0,
                unicode_char,
                key_down,
                control_key_state: 0,
                repeat_count: 1,
            })
            .len()
        })
        .sum()
}

/// Run `wait`, one of the fixture's reads, turning its failure (the console silent for the fixture's bound, or
/// closed, or a write to it refused) into the failure's text.
fn bounded(run: &mut PtyRun, wait: impl FnOnce(&mut PtyRun)) -> Result<(), String> {
    catch_unwind(AssertUnwindSafe(|| wait(run))).map_err(|panic| panic_text(&panic))
}

/// The first line of a fixture failure's text: what it was waiting for. The whole text is in the record once,
/// at the stall.
fn first_line(text: &str) -> &str {
    text.lines().next().unwrap_or_default()
}

/// After a line stalled: type a line the length of the longest one that stopped, in pieces, and record per
/// piece what came back; then type a second short line. Later keys echoed mean a chunk was lost; none
/// echoed means the path is dead.
///
/// Each piece but the last ends in a capital that occurs once in the line, and its echo is the count of
/// that capital in the console text rising by one. A piece's echo is not matched as a string: the console
/// breaks a long line at the right edge with cursor movements in the middle of it.
fn typing_probe(record: &mut Record, run: &mut PtyRun) {
    const LINE_LEN: usize = 258;
    const PIECE_LEN: usize = 32;
    const FILLER: &str = "0123456789abcdefghijklmnop";
    let mut chars: Vec<char> = "Write-Output ('mrk' + 'done') #".chars().collect();
    while chars.len() < LINE_LEN {
        chars.push(
            FILLER
                .chars()
                .nth(chars.len() % FILLER.len())
                .expect("a filler character"),
        );
    }
    for k in 0..chars.len().div_ceil(PIECE_LEN) - 1 {
        chars[(k + 1) * PIECE_LEN - 1] = char::from(b'A' + u8::try_from(k).expect("few pieces"));
    }
    record.note(format!(
        "\n-- typing a {LINE_LEN}-character line in pieces of {PIECE_LEN} after the stalled line"
    ));
    let mut sent = 0;
    let mut stalled = false;
    for (k, piece) in chars.chunks(PIECE_LEN).enumerate() {
        let text: String = piece.iter().collect();
        let last = (k + 1) * PIECE_LEN >= LINE_LEN;
        let needle = (!last).then(|| *piece.last().expect("a piece has characters"));
        let before_count = needle.map_or(0, |c| run.text().matches(c).count());
        let before_bytes = run.bytes().len();
        let bytes = key_bytes(&text);
        run.type_text(&text);
        sent += bytes;
        let outcome = match needle {
            None => "the last piece: no echo is waited for; Enter follows".to_owned(),
            Some(c) => match bounded(run, |run| run.read_until_count(&c.to_string(), before_count + 1)) {
                Ok(()) => format!("its last character {c:?} was echoed"),
                Err(why) => {
                    stalled = true;
                    format!("its last character {c:?} was NOT echoed ({})", first_line(&why))
                }
            },
        };
        record.note(format!(
            "piece {k}: {} characters, {bytes} bytes of key events sent ({sent} in all); {outcome}; the console wrote {} more bytes",
            piece.len(),
            run.bytes().len() - before_bytes
        ));
        if stalled {
            break;
        }
    }
    if !stalled {
        run.press_enter();
        sent += enter_bytes();
        let answered = bounded(run, |run| run.read_until("mrkdone"));
        record.note(format!(
            "Enter: {} bytes sent ({sent} in all); the line was answered: {}",
            enter_bytes(),
            answered.map_or_else(|why| format!("NO ({})", first_line(&why)), |()| "yes".to_owned())
        ));
    }
    let second = "Write-Output ('probe' + '-two')";
    let before_bytes = run.bytes().len();
    let answered = bounded(run, |run| {
        run.type_line(second);
        run.read_until("probe-two");
    });
    record.note(format!(
        "the second line ({} characters, {} bytes of key events) was answered: {}; the console wrote {} more bytes",
        second.len(),
        key_bytes(second) + enter_bytes(),
        answered.map_or_else(|why| format!("NO ({})", first_line(&why)), |()| "yes".to_owned()),
        run.bytes().len() - before_bytes
    ));
    let shown = run.text();
    let tail: String = shown
        .chars()
        .rev()
        .take(1500)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    record.note(format!(
        "the last 1500 characters the console showed:\n{}",
        tail.replace('\x1b', "<ESC>")
    ));
}

fn panic_text(panic: &Box<dyn std::any::Any + Send>) -> String {
    panic
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| panic.downcast_ref::<&str>().map(|text| (*text).to_owned()))
        .unwrap_or_else(|| "(a panic with no text)".to_owned())
}

// Process facts -----

fn session_of(pid: u32) -> Option<u32> {
    let mut session = 0u32;
    // SAFETY: a valid out-pointer.
    unsafe { ProcessIdToSessionId(pid, &mut session) }.ok()?;
    Some(session)
}

fn session_text(pid: u32) -> String {
    session_of(pid).map_or_else(|| "?".to_owned(), |session| session.to_string())
}

fn creation_time(process: HANDLE) -> Option<u64> {
    let (mut created, mut exited, mut kernel, mut user) = Default::default();
    // SAFETY: a live handle with query access; valid out-pointers.
    unsafe { GetProcessTimes(process, &mut created, &mut exited, &mut kernel, &mut user) }.ok()?;
    Some((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
}

fn now_filetime() -> u64 {
    let since_epoch = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    (since_epoch.as_secs() + 11_644_473_600) * 10_000_000 + u64::from(since_epoch.subsec_nanos()) / 100
}

/// The time of day of a FILETIME, to the millisecond, in UTC: the form the logs' timestamps take.
fn clock(filetime: u64) -> String {
    let seconds = filetime / 10_000_000;
    let of_day = seconds % 86_400;
    format!(
        "{:02}:{:02}:{:02}.{:03}",
        of_day / 3600,
        of_day % 3600 / 60,
        of_day % 60,
        filetime / 10_000 % 1000
    )
}

fn windows_version() -> String {
    let mut info = OSVERSIONINFOW {
        dwOSVersionInfoSize: size_of::<OSVERSIONINFOW>() as u32,
        ..Default::default()
    };
    // SAFETY: a valid structure with its size set.
    let status = unsafe { RtlGetVersion(&mut info) };
    format!(
        "{}.{}.{} (RtlGetVersion status {:#x})",
        info.dwMajorVersion, info.dwMinorVersion, info.dwBuildNumber, status.0
    )
}
