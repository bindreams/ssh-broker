//! A measurement, not a check: where typed keys get lost in a session the password prompt started. Windows
//! only; **Elevated (CI only)**. It fails on purpose: its panic text is the record, and nextest prints a
//! failing test's output only.
//!
//! The scenario is the one `prompt_path_windows` runs (a fresh account, the shim on a console of its own,
//! the password at the prompt, the background agent's PowerShell as the shell), repeated until a typed line
//! is not answered. Every typed line is bounded, and around each the I/O counters of every process on the
//! path of a key (the helper, its two `conhost`s, the shim, the agent, the agent's `conhost`, the shell) are
//! read, so that a stalled line shows which process's reads and writes did not move. The test only observes:
//! it lists processes, reads their counters and the logs, and types into its own session.
#![cfg(windows)]

use std::fmt::Write as _;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

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

/// How many fresh-account repetitions to run at most: about 12 minutes at the 15 to 40 s one takes.
const REPETITIONS: usize = 20;
/// The first repetitions give the normal picture of what a line costs each process; their per-line counters
/// are printed. A later repetition's are printed only if it is the one that stalled.
const NORMAL_PICTURE: usize = 3;
/// Lines typed after the first answered one, before `exit`.
const EXTRA_LINES: usize = 3;

/// What the prompt says first, as in `prompt_path_windows`.
const PROMPT: &str = "Enter your Windows password to start one.";
/// The start of a PowerShell prompt.
const SHELL_PROMPT: &str = "PS C:\\";
/// The first line the prompt tests type at the shell: PSReadLine out, so the host's own reader reads on.
const REMOVE_MODULE: &str =
    "Remove-Module PSReadLine -ErrorAction SilentlyContinue; Write-Output ('psreadline' + '-off')";
/// The line that stalled in round 1's real tests: long, typed at once after the first answer.
const PROFILE_LINE: &str = "Write-Output ('profile=' + $env:USERPROFILE + '.')";

// The record -----

/// Everything observed, as text; the panic that ends the test carries it.
#[derive(Default)]
struct Record {
    text: String,
    /// What the running repetition has noted; moved to `text` when the repetition is one to print.
    pending: String,
    /// Lines typed in all, and in the running repetition.
    lines_typed: usize,
    in_repetition: usize,
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
    number: usize,
    label: &'static str,
    why: String,
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
        record.in_repetition = 0;
        let verdict = catch_unwind(AssertUnwindSafe(|| repetition(n, &mut record)));
        if n <= NORMAL_PICTURE || !matches!(verdict, Ok(Verdict::Worked)) {
            let pending = std::mem::take(&mut record.pending);
            record.line(pending);
        }
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
    match typed_lines(record, &mut run, &account, &location) {
        Ok(()) => Verdict::Worked,
        Err(stalled) => {
            record.stall = Some(format!(
                "line {} ({}) of repetition {n}, the {}th line typed in all",
                stalled.number, stalled.label, record.lines_typed
            ));
            at_stall(record, &mut run, &account, &location, &stalled.why);
            Verdict::Failed
        }
    }
}

/// The lines of a repetition, each at once after the answer to the one before; the first stalled one ends it.
fn typed_lines(
    record: &mut Record,
    run: &mut PtyRun,
    account: &Account,
    location: &SocketLocation,
) -> Result<(), Stalled> {
    typed_line(record, run, account, "password", &account.password, |_| {
        stand_in::wait_for_serving_marker_of_a_task(location, stand_in::SERVING_BOUND);
    })?;
    run.read_until(SHELL_PROMPT);
    typed_line(record, run, account, "remove-module", REMOVE_MODULE, |run| {
        run.read_until("psreadline-off");
    })?;
    typed_line(record, run, account, "profile", PROFILE_LINE, |run| {
        run.read_until("profile=C:");
    })?;
    for k in 1..=EXTRA_LINES {
        let marker = format!("marker-{k}");
        let line = format!("Write-Output ('marker' + '-{k}')");
        typed_line(record, run, account, "marker", &line, |run| run.read_until(&marker))?;
    }
    typed_line(record, run, account, "exit", "exit", |run| {
        run.finish();
    })
}

/// Type `text` as a line and wait, bounded, for `wait` to see its answer; note what each process on the path
/// did with it. `label` is for the record: the password is never printed.
fn typed_line(
    record: &mut Record,
    run: &mut PtyRun,
    account: &Account,
    label: &'static str,
    text: &str,
    wait: impl FnOnce(&mut PtyRun),
) -> Result<(), Stalled> {
    record.lines_typed += 1;
    record.in_repetition += 1;
    let number = record.in_repetition;
    let sent = key_bytes(text) + enter_bytes();
    let before = path_counters(account);
    let wrote = run.bytes().len();
    let typed_at = clock(now_filetime());
    let started = Instant::now();
    let outcome = bounded(run, |run| {
        run.type_line(text);
        wait(run);
    });
    let took = started.elapsed().as_millis();
    let after = path_counters(account);
    let verdict = if outcome.is_ok() {
        format!("answered after {took} ms")
    } else {
        format!("NOT answered: the fixture gave up after {took} ms")
    };
    record.note(format!(
        "line {number} ({label}; {} characters, {sent} bytes of key events) typed at {typed_at} UTC; {verdict}; \
         the console wrote {} more bytes; change in each process's I/O counters over the line:\n{}",
        text.chars().count(),
        run.bytes().len().saturating_sub(wrote),
        counters_delta(&before, &after)
    ));
    outcome.map_err(|why| Stalled { number, label, why })
}

/// What is recorded once a line is not answered: the fixture's report (the console text, and the process tree
/// with thread wait reasons), whether later keys are echoed, the counters over that probe, and the logs.
fn at_stall(record: &mut Record, run: &mut PtyRun, account: &Account, location: &SocketLocation, why: &str) {
    record.note(format!("\n== THE STALL, as the fixture reported it:\n{why}"));
    if !why.contains("process tree:") {
        let tree = helper_of(account).map_or_else(
            || "the helper is gone".to_owned(),
            |(pid, helper)| bounded_wait::process_tree(helper.0, pid),
        );
        record.note(format!("process tree:\n{tree}"));
    }
    let before_probe = path_counters(account);
    let probed = catch_unwind(AssertUnwindSafe(|| typing_probe(record, run)));
    if let Err(panic) = probed {
        record.note(format!("the typing probe panicked: {}", panic_text(&panic)));
    }
    let after_probe = path_counters(account);
    record.note(format!(
        "change in each process's I/O counters over the whole typing probe:\n{}",
        counters_delta(&before_probe, &after_probe)
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
                "appeared during the line; its totals: {}",
                rise(&IO_COUNTERS::default(), now)
            ),
            (Ok(_), Some(Err(why))) => format!("counters unreadable before the line: {why}"),
        };
        let _ = writeln!(text, "    pid {} {}: {change}", now.pid, now.label);
    }
    for gone in before
        .iter()
        .filter(|was| was.pid != 0 && !after.iter().any(|now| now.pid == was.pid))
    {
        let _ = writeln!(text, "    pid {} {}: gone by the end of the line", gone.pid, gone.label);
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
