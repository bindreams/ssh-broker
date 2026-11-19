//! Throwaway measurement: which waits on a Windows AF_UNIX socket lose their wake (M1 to M5).
//!
//! Every test ends in `panic!` with its record, prefixed `MEASURED (this test fails on purpose):`, because
//! nextest shows the output of a failing test only. Not elevated: it uses sockets and threads of its own in a
//! temp directory. `AFUNIX_MEASURE_N` overrides the number of trials of every loop (for sizing a run).
//!
//! "Already waiting" is established, not hoped for. The waiter thread hands its own thread handle to the
//! peer and enters the call (`recv`, `WSAPoll`, `accept`). The peer asks `GetThreadIOPendingFlag` of that
//! handle until it reads true, which it is exactly while the thread has an I/O request issued and not yet
//! completed: the blocking call has gone into the kernel and is parked there. Only then does the peer act.
//! If the waiter returns before the flag was ever seen, the peer does not act and the trial is counted
//! as "not established". The flag is re-checked with no cap; no sleep stands in for it.
//!
//! A miss is DETECTED, never waited out: every wait carries a generous failure bound of its own (a read
//! timeout, a poll timeout, a bounded wait for the result), and after it expires the state is looked at.
#![cfg(windows)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::os::windows::io::AsRawSocket;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use socket2::{Domain, SockAddr, Socket, Type};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Networking::WinSock::{
    POLLERR, POLLHUP, POLLNVAL, POLLPRI, POLLRDBAND, POLLRDNORM, POLLWRBAND, POLLWRNORM, SOCKET, WSAGetLastError,
    WSAPOLL_EVENT_FLAGS, WSAPOLLFD, WSAPoll,
};
use windows::Win32::System::Threading::{
    GetCurrentThreadId, GetThreadIOPendingFlag, OpenThread, THREAD_QUERY_INFORMATION,
};
use windows::core::BOOL;

/// A read that returns by itself later than this after the peer acted is "late", with its delay.
const LATE: Duration = Duration::from_millis(250);
/// The failure bound of a read (`SO_RCVTIMEO`): a read still waiting after it is a miss.
const READ_TIMEOUT: Duration = Duration::from_secs(3);
/// The failure bound of a poll, in milliseconds.
const POLL_TIMEOUT_MS: i32 = 3000;
/// The failure bound on a waiter that has a bound of its own: a waiter still out after this is stuck.
const WAITER_BOUND: Duration = Duration::from_secs(30);
/// The failure bound of an accept: its client's connect has succeeded this long ago.
const ACCEPT_BOUND: Duration = Duration::from_secs(5);
/// A loop of misses ends after this many (each costs its bound); the record says how many trials ran.
const MISS_CAP: u32 = 25;

const DEFAULT_M2: u32 = 20_000;
const DEFAULT_M1: u32 = 10_000;
const DEFAULT_M3: u32 = 50;
const DEFAULT_M4: u32 = 100;
const DEFAULT_M5: u32 = 20_000;

/// How many trials a loop runs.
fn trials(default: u32) -> u32 {
    match std::env::var("AFUNIX_MEASURE_N") {
        Ok(n) => n.parse().expect("AFUNIX_MEASURE_N is a number"),
        Err(_) => default,
    }
}

// The machine -----

/// The Windows build as `reg query` of the version key shows it.
fn windows_build() -> String {
    let out = std::process::Command::new("reg")
        .args(["query", r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"])
        .output()
        .expect("reg query runs");
    assert!(out.status.success(), "reg query failed: {out:?}");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::trim)
        .filter(|l| {
            ["ProductName", "DisplayVersion", "CurrentBuild", "UBR", "BuildLab "]
                .iter()
                .any(|k| l.starts_with(k))
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// A directory of the test's own for its socket files, removed at the end.
struct Scratch {
    dir: PathBuf,
}

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("afwm-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("make the scratch directory");
        Scratch { dir }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn listening(path: &Path, backlog: i32) -> Socket {
    let listener = Socket::new(Domain::UNIX, Type::STREAM, None).unwrap();
    listener.bind(&SockAddr::unix(path).unwrap()).unwrap();
    listener.listen(backlog).unwrap();
    listener
}

fn connect_to(path: &Path) -> Socket {
    let client = Socket::new(Domain::UNIX, Type::STREAM, None).unwrap();
    client.connect(&SockAddr::unix(path).unwrap()).unwrap();
    client
}

/// A connected AF_UNIX pair `(server, client)`, made as the product makes them (`accept_raw` on the
/// listener, a plain connect).
fn pair(dir: &Path, i: u32) -> (Socket, Socket) {
    let path = dir.join(i.to_string());
    let listener = listening(&path, 1);
    let client = connect_to(&path);
    let (server, _) = listener.accept_raw().unwrap();
    drop(listener);
    let _ = std::fs::remove_file(&path);
    (server, client)
}

// Knowing that the waiter is inside the call -----

/// This thread's own handle, to ask whether it has an I/O request pending.
struct ThreadProbe(HANDLE);

// SAFETY: a thread handle is usable from any thread.
unsafe impl Send for ThreadProbe {}

impl ThreadProbe {
    fn of_current() -> ThreadProbe {
        // SAFETY: plain calls; the handle is closed in `Drop`.
        let handle = unsafe { OpenThread(THREAD_QUERY_INFORMATION, false, GetCurrentThreadId()) }.expect("OpenThread");
        ThreadProbe(handle)
    }

    fn io_pending(&self) -> bool {
        let mut pending = BOOL(0);
        // SAFETY: `self.0` is an open thread handle; `pending` is a valid out pointer.
        unsafe { GetThreadIOPendingFlag(self.0, &mut pending) }.expect("GetThreadIOPendingFlag");
        pending.as_bool()
    }
}

impl Drop for ThreadProbe {
    fn drop(&mut self) {
        // SAFETY: the handle came from `OpenThread` and is closed once.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

/// What the peer and the waiter share.
struct Ctx {
    /// Stamped by the peer just before it acts, for the delay of a wake.
    acted: OnceLock<Instant>,
    /// Set by a waiter that reads, once its first read has returned data and just before its next read.
    second_wait: AtomicBool,
}

/// The peer's view of the waiter.
struct Waiter<'a> {
    probe: &'a ThreadProbe,
    ctx: &'a Ctx,
    done: &'a AtomicBool,
}

impl Waiter<'_> {
    /// Block until the waiter has taken its first data and is inside its next call again (its first call's
    /// request has completed by then, so a pending request is the second call's), or has returned.
    fn until_waiting_again(&self) {
        while !(self.ctx.second_wait.load(Ordering::Acquire) && self.probe.io_pending()) {
            if self.done.load(Ordering::Acquire) {
                return;
            }
            std::thread::yield_now();
        }
    }
}

/// Run `wait` on a thread of its own; once that thread is inside its blocking call (see the module doc), run
/// `act` on this thread. `act` may hand back a socket to hold open until the result is in.
///
/// Returns the waiter's result, or the channel it will still arrive on if the waiter was not back after
/// `bound`, and whether the waiter was seen inside the call before `act` (when not, `act` did not run).
fn wait_then<R: Send + 'static>(
    wait: impl FnOnce(Arc<Ctx>) -> R + Send + 'static,
    act: impl FnOnce(&Waiter) -> Option<Socket>,
    bound: Duration,
) -> (Result<R, Receiver<R>>, bool) {
    let ctx = Arc::new(Ctx {
        acted: OnceLock::new(),
        second_wait: AtomicBool::new(false),
    });
    let done = Arc::new(AtomicBool::new(false));
    let (probe_tx, probe_rx) = mpsc::channel();
    let (result_tx, result_rx) = mpsc::channel();
    {
        let (ctx, done) = (Arc::clone(&ctx), Arc::clone(&done));
        std::thread::spawn(move || {
            probe_tx.send(ThreadProbe::of_current()).unwrap();
            let result = wait(ctx);
            done.store(true, Ordering::Release);
            let _ = result_tx.send(result);
        });
    }
    let probe = probe_rx.recv().expect("the waiter thread sends its handle");
    let established = loop {
        if probe.io_pending() {
            break true;
        }
        if done.load(Ordering::Acquire) {
            break false;
        }
        std::thread::yield_now();
    };
    let keep = if established {
        ctx.acted.set(Instant::now()).expect("stamped once");
        act(&Waiter {
            probe: &probe,
            ctx: &ctx,
            done: &done,
        })
    } else {
        None
    };
    // A failure bound that detects a lost wake of the call under measurement, not a sync of our own code.
    let waited = result_rx.recv_timeout(bound); // sleep-ok: the bound detects the lost wake being measured
    let result = match waited {
        Ok(result) => Ok(result),
        Err(_) => Err(result_rx),
    };
    drop(keep);
    (result, established)
}

fn delay_since(acted: &OnceLock<Instant>) -> Duration {
    acted.get().map_or(Duration::ZERO, Instant::elapsed)
}

// What a waiter reports and how it is counted -----

/// One trial's outcome.
struct Verdict {
    /// What happened, without numbers that vary; trials with the same key are counted together.
    key: String,
    /// The close or the data was there and the wait did not see it within its bound.
    miss: bool,
    /// The wait returned by itself, this many milliseconds after the peer acted, later than `LATE`.
    late_ms: Option<u128>,
    /// The particulars, kept for the first few trials that were misses.
    detail: String,
}

impl Verdict {
    fn returned(key: String, acted: &OnceLock<Instant>) -> Verdict {
        let delay = delay_since(acted);
        Verdict {
            key,
            miss: false,
            late_ms: (delay > LATE).then_some(delay.as_millis()),
            detail: String::new(),
        }
    }
}

#[derive(Default)]
struct Stats {
    run: u32,
    not_established: u32,
    misses: u32,
    tally: BTreeMap<String, u32>,
    late_ms: Vec<u128>,
    details: Vec<String>,
}

impl Stats {
    fn count(&mut self, key: impl Into<String>) {
        *self.tally.entry(key.into()).or_default() += 1;
    }

    /// Count one trial. `result` is `None` when the waiter was not back within the failure bound of the
    /// harness (beyond its own).
    fn add(&mut self, established: bool, result: Option<Verdict>) {
        self.run += 1;
        if !established {
            self.not_established += 1;
            return;
        }
        let Some(verdict) = result else {
            self.misses += 1;
            self.count("STUCK: the waiter was not back after its own failure bound and the harness's");
            return;
        };
        if verdict.miss {
            self.misses += 1;
            if self.details.len() < 12 {
                self.details.push(format!("trial {}: {}", self.run - 1, verdict.detail));
            }
        }
        if let Some(ms) = verdict.late_ms {
            self.late_ms.push(ms);
        }
        self.count(verdict.key);
    }

    fn render(&self, label: &str, out: &mut String) {
        writeln!(
            out,
            "{label}: trials run {}, waiter not established (peer did not act) {}, misses {}",
            self.run, self.not_established, self.misses
        )
        .unwrap();
        for (key, count) in &self.tally {
            writeln!(out, "    {count} x {key}").unwrap();
        }
        if !self.late_ms.is_empty() {
            writeln!(
                out,
                "    returned by itself later than {} ms after the peer acted: {} (delays, ms: {:?})",
                LATE.as_millis(),
                self.late_ms.len(),
                self.late_ms
            )
            .unwrap();
        }
        for detail in &self.details {
            writeln!(out, "    {detail}").unwrap();
        }
    }
}

/// The record's opening: the title and the Windows build.
fn record_start(name: &str) -> String {
    format!("{name}\nWindows: {}\n", windows_build())
}

fn finish(record: String) -> ! {
    panic!("MEASURED (this test fails on purpose):\n{record}")
}

// Looking at results -----

fn show<T>(result: &std::io::Result<T>, ok: impl Fn(&T) -> String) -> String {
    match result {
        Ok(value) => format!("Ok({})", ok(value)),
        Err(e) => format!("Err({:?}, os {:?})", e.kind(), e.raw_os_error()),
    }
}

fn show_read(result: &std::io::Result<usize>) -> String {
    show(result, |n| n.to_string())
}

fn read_once(sock: &Socket) -> std::io::Result<usize> {
    let mut buf = [0u8; 64];
    let mut reader = sock;
    reader.read(&mut buf)
}

#[derive(Clone, Copy)]
enum Events {
    Rdnorm,
    None,
}

impl Events {
    fn flags(self) -> WSAPOLL_EVENT_FLAGS {
        match self {
            Events::Rdnorm => POLLRDNORM,
            Events::None => WSAPOLL_EVENT_FLAGS(0),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Events::Rdnorm => "events POLLRDNORM",
            Events::None => "events 0",
        }
    }
}

/// One `WSAPoll` of one socket: `(count of ready sockets, revents)`.
fn poll(sock: &Socket, events: Events, timeout_ms: i32) -> std::io::Result<(i32, i16)> {
    let mut fds = [WSAPOLLFD {
        fd: SOCKET(sock.as_raw_socket() as usize),
        events: events.flags(),
        revents: WSAPOLL_EVENT_FLAGS(0),
    }];
    // SAFETY: `fds` is a live array of one entry; the socket outlives the call.
    let rc = unsafe { WSAPoll(fds.as_mut_ptr(), 1, timeout_ms) };
    if rc < 0 {
        return Err(std::io::Error::from_raw_os_error(unsafe { WSAGetLastError() }.0));
    }
    Ok((rc, fds[0].revents.0))
}

fn revents_name(revents: i16) -> String {
    let names = [
        (POLLRDNORM, "RDNORM"),
        (POLLRDBAND, "RDBAND"),
        (POLLWRNORM, "WRNORM"),
        (POLLWRBAND, "WRBAND"),
        (POLLPRI, "PRI"),
        (POLLERR, "ERR"),
        (POLLHUP, "HUP"),
        (POLLNVAL, "NVAL"),
    ];
    let set: Vec<&str> = names
        .iter()
        .filter(|(flag, _)| revents & flag.0 != 0)
        .map(|(_, n)| *n)
        .collect();
    if set.is_empty() { "0".to_owned() } else { set.join("|") }
}

fn show_poll(result: &std::io::Result<(i32, i16)>) -> String {
    show(result, |(rc, revents)| {
        format!("rc {rc}, revents {}", revents_name(*revents))
    })
}

// M2: a blocking recv that is already waiting -----

/// Read to the end with `SO_RCVTIMEO` set. A read that times out is a miss; the next read then says whether
/// the close was there all along.
fn recv_waiter(sock: &Socket, ctx: &Ctx) -> Verdict {
    let acted = &ctx.acted;
    let mut got = 0usize;
    let mut worst_late: Option<u128> = None;
    let mut buf = [0u8; 64];
    loop {
        let mut reader = sock;
        match reader.read(&mut buf) {
            Ok(0) => {
                let mut verdict = Verdict::returned("end-of-stream seen by the read".to_owned(), acted);
                verdict.late_ms = verdict.late_ms.or(worst_late);
                return verdict;
            }
            Ok(n) => {
                got += n;
                ctx.second_wait.store(true, Ordering::Release);
                let delay = delay_since(acted);
                if delay > LATE {
                    worst_late = Some(worst_late.map_or(delay.as_millis(), |w| w.max(delay.as_millis())));
                }
            }
            Err(e) if matches!(e.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock) => {
                let started = Instant::now();
                let next = read_once(sock);
                let took = started.elapsed();
                let next_key = match &next {
                    Ok(0) if took < LATE => "end-of-stream at once".to_owned(),
                    Ok(0) => "end-of-stream, but not at once".to_owned(),
                    Ok(_) => "more data".to_owned(),
                    Err(e) => format!("error {:?}", e.kind()),
                };
                return Verdict {
                    key: format!("MISS after {got} bytes; the next read: {next_key}"),
                    miss: true,
                    late_ms: None,
                    detail: format!(
                        "read timed out (os {:?}) after {got} bytes; next read {} in {} ms",
                        e.raw_os_error(),
                        show_read(&next),
                        took.as_millis()
                    ),
                };
            }
            Err(e) => {
                return Verdict {
                    key: format!("other read error {:?} after {got} bytes", e.kind()),
                    miss: false,
                    late_ms: None,
                    detail: String::new(),
                };
            }
        }
    }
}

/// N trials of a read to the end that is already waiting when the peer writes five bytes. With
/// `close_while_waiting_again` the peer closes only once the reader has taken the bytes and is inside its
/// next read; without it, the peer closes straight after writing, so the reader's second read may begin
/// before or after the close.
fn m2_variant(scratch: &Scratch, close_while_waiting_again: bool, record: &mut String) {
    let mut stats = Stats::default();
    for i in 0..trials(DEFAULT_M2) {
        if stats.misses >= MISS_CAP {
            break;
        }
        let (server, client) = pair(&scratch.dir, i);
        client.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
        let client = Arc::new(client);
        let reader = Arc::clone(&client);
        let (result, established) = wait_then(
            move |ctx| recv_waiter(&reader, &ctx),
            move |waiter| {
                let mut server = server;
                server.write_all(b"hello").unwrap();
                if close_while_waiting_again {
                    waiter.until_waiting_again();
                }
                drop(server);
                None
            },
            WAITER_BOUND,
        );
        stats.add(established, result.ok());
    }
    let label = if close_while_waiting_again {
        "M2 blocking read (SO_RCVTIMEO 3 s) in its own call when the peer writes five bytes; the peer closes only when the read is again in its second call"
    } else {
        "M2 blocking read (SO_RCVTIMEO 3 s) in its own call when the peer writes five bytes and closes straight after"
    };
    stats.render(label, record);
}

#[test]
fn m2_a_blocking_recv_already_waiting_when_the_peer_writes_and_closes() {
    let scratch = Scratch::new("m2");
    let mut record =
        record_start("M2: a blocking recv that is already waiting when the peer writes five bytes and closes");
    m2_variant(&scratch, false, &mut record);
    m2_variant(&scratch, true, &mut record);
    finish(record);
}

// M1: a WSAPoll that is already waiting -----

/// One poll with `timeout_ms`. A poll that returns nothing is a miss when the peer did write (and closed);
/// then a fresh poll with timeout 0 and a non-blocking recv (twice) are asked once each.
fn poll_waiter(
    sock: &Socket,
    events: Events,
    timeout_ms: i32,
    look_after_a_miss: bool,
    acted: &OnceLock<Instant>,
) -> Verdict {
    let first = poll(sock, events, timeout_ms);
    match first {
        Ok((rc, revents)) if rc > 0 => {
            Verdict::returned(format!("poll returned, revents {}", revents_name(revents)), acted)
        }
        Ok(_) if !look_after_a_miss => Verdict {
            key: "poll timed out".to_owned(),
            miss: false,
            late_ms: None,
            detail: String::new(),
        },
        Ok(_) => {
            let fresh = poll(sock, events, 0);
            sock.set_nonblocking(true).unwrap();
            let first_recv = read_once(sock);
            let second_recv = read_once(sock);
            let looked = format!(
                "fresh poll(0): {}; non-blocking recv: {} then {}",
                show_poll(&fresh),
                show_read(&first_recv),
                show_read(&second_recv)
            );
            Verdict {
                key: format!("MISS: poll timed out; {looked}"),
                miss: true,
                late_ms: None,
                detail: format!("poll timed out; {looked}"),
            }
        }
        Err(e) => Verdict {
            key: format!("poll error {:?} (os {:?})", e.kind(), e.raw_os_error()),
            miss: false,
            late_ms: None,
            detail: String::new(),
        },
    }
}

/// N trials of a poll that is already waiting while the peer writes (and closes, if `close`).
fn m1_variant(scratch: &Scratch, events: Events, close: bool, record: &mut String) {
    let mut stats = Stats::default();
    for i in 0..trials(DEFAULT_M1) {
        if stats.misses >= MISS_CAP {
            break;
        }
        let (server, client) = pair(&scratch.dir, i);
        let client = Arc::new(client);
        let poller = Arc::clone(&client);
        let (result, established) = wait_then(
            move |ctx| poll_waiter(&poller, events, POLL_TIMEOUT_MS, true, &ctx.acted),
            move |_| {
                let mut server = server;
                server.write_all(b"hello").unwrap();
                if close { None } else { Some(server) }
            },
            WAITER_BOUND,
        );
        stats.add(established, result.ok());
    }
    let label = format!(
        "M1 {} , peer {}",
        events.name(),
        if close { "writes and closes" } else { "only writes" }
    );
    stats.render(&label, record);
}

#[test]
fn m1_a_wsapoll_already_waiting_when_the_peer_writes_and_closes_or_only_writes() {
    let scratch = Scratch::new("m1");
    let mut record =
        record_start("M1: WSAPoll (timeout 3 s) on a socket, the peer's action after the poll is in the kernel");
    m1_variant(&scratch, Events::Rdnorm, true, &mut record);
    m1_variant(&scratch, Events::None, true, &mut record);
    m1_variant(&scratch, Events::Rdnorm, false, &mut record);
    record.push_str(
        "(the peer-only-writes case with events 0 is not run: it can only time out, nothing is expected to wake it)\n",
    );
    finish(record);
}

// M3: FIONBIO on one handle of a duplicated pair -----

#[test]
fn m3_fionbio_on_one_handle_of_a_duplicated_pair() {
    let scratch = Scratch::new("m3");
    let mut record =
        record_start("M3: set_nonblocking(true) (FIONBIO) on one handle; recv on the other with nothing to read");
    let mut stats = Stats::default();
    for i in 0..trials(DEFAULT_M3) {
        for (set_on_original, label) in [
            (true, "set on the original, recv on the duplicate"),
            (false, "set on the duplicate, recv on the original"),
        ] {
            let (server, original) = pair(&scratch.dir, i);
            let duplicate = original.try_clone().unwrap();
            let (set_on, recv_on) = if set_on_original {
                (&original, &duplicate)
            } else {
                (&duplicate, &original)
            };
            recv_on.set_read_timeout(Some(Duration::from_millis(1000))).unwrap();
            set_on.set_nonblocking(true).unwrap();
            let started = Instant::now();
            let result = read_once(recv_on);
            let took = started.elapsed();
            let when = if took < Duration::from_millis(500) {
                "at once"
            } else {
                "only when the 1 s read timeout expired"
            };
            stats.run += 1;
            stats.count(format!("{label}: {} {when}", show_read(&result)));
            drop(server);
        }
    }
    stats.render("M3", &mut record);
    finish(record);
}

// M4: a local shutdown(Both) on one handle of a duplicated pair -----

#[test]
fn m4_a_local_shutdown_both_on_one_handle_of_a_duplicated_pair() {
    let scratch = Scratch::new("m4");
    let mut record = record_start(
        "M4: shutdown(Both) on one handle, a WSAPoll (timeout 500 ms) already waiting on the duplicate; the peer stays open and silent",
    );
    for events in [Events::Rdnorm, Events::None] {
        let mut stats = Stats::default();
        let mut after = Stats::default();
        for i in 0..trials(DEFAULT_M4) {
            let (server, original) = pair(&scratch.dir, i);
            let original = Arc::new(original);
            let duplicate = Arc::new(original.try_clone().unwrap());
            let poller = Arc::clone(&duplicate);
            let shutter = Arc::clone(&original);
            let (result, established) = wait_then(
                move |ctx| poll_waiter(&poller, events, 500, false, &ctx.acted),
                move |_| {
                    shutter.shutdown(std::net::Shutdown::Both).unwrap();
                    Some(server)
                },
                WAITER_BOUND,
            );
            stats.add(established, result.ok());
            if !established {
                continue;
            }
            let fresh = poll(&duplicate, events, 0);
            duplicate.set_nonblocking(true).unwrap();
            let on_duplicate = read_once(&duplicate);
            after.run += 1;
            after.count(format!("fresh poll(0) on the other handle: {}", show_poll(&fresh)));
            after.count(format!(
                "non-blocking recv on the other handle: {}",
                show_read(&on_duplicate)
            ));
        }
        stats.render(&format!("M4a {}", events.name()), &mut record);
        after.render(
            &format!("M4b {} (looked at after the poll ended)", events.name()),
            &mut record,
        );
    }
    finish(record);
}

// M5: a blocking accept that is already waiting -----

fn accept_waiter(listener: &Socket, acted: &OnceLock<Instant>) -> Verdict {
    match listener.accept_raw() {
        Ok(_) => Verdict::returned("accept returned a connection".to_owned(), acted),
        Err(e) => Verdict {
            key: format!("accept error {:?} (os {:?})", e.kind(), e.raw_os_error()),
            miss: false,
            late_ms: None,
            detail: String::new(),
        },
    }
}

#[test]
fn m5_a_blocking_accept_already_waiting_when_a_client_connects() {
    let scratch = Scratch::new("m5");
    let mut record =
        record_start("M5: blocking accept_raw; the client's connect succeeded, the accept had 5 s to return");
    let mut stats = Stats::default();
    let mut leaked = 0u32;
    for i in 0..trials(DEFAULT_M5) {
        if stats.misses >= MISS_CAP {
            break;
        }
        let path = scratch.dir.join(i.to_string());
        let listener = Arc::new(listening(&path, 128));
        let accepting = Arc::clone(&listener);
        let connect_path = path.clone();
        let (result, established) = wait_then(
            move |ctx| accept_waiter(&accepting, &ctx.acted),
            move |_| Some(connect_to(&connect_path)),
            ACCEPT_BOUND,
        );
        match result {
            Ok(verdict) => stats.add(established, Some(verdict)),
            Err(still_waiting) => {
                stats.run += 1;
                stats.misses += 1;
                let fresh = poll(&listener, Events::Rdnorm, 0);
                let clone = listener.try_clone().unwrap();
                clone.set_nonblocking(true).unwrap();
                let second = clone.accept_raw();
                let looked = format!(
                    "fresh poll(0) on the listener: {}; non-blocking accept on a duplicate: {}",
                    show_poll(&fresh),
                    show(&second, |_| "a connection".to_owned())
                );
                let kick = connect_to(&path);
                let kicked = still_waiting.recv_timeout(ACCEPT_BOUND); // sleep-ok: the bound detects the lost wake being measured
                let after_kick = match kicked {
                    Ok(verdict) => format!("after one more connect the stuck accept returned ({})", verdict.key),
                    Err(_) => {
                        leaked += 1;
                        "after one more connect the stuck accept stayed stuck (its thread is left blocked)".to_owned()
                    }
                };
                drop(kick);
                stats.count(format!("MISS: accept not back; {looked}; {after_kick}"));
                if stats.details.len() < 12 {
                    stats
                        .details
                        .push(format!("trial {i}: accept not back; {looked}; {after_kick}"));
                }
            }
        }
    }
    stats.render("M5", &mut record);
    writeln!(record, "    accept threads left blocked: {leaked}").unwrap();
    finish(record);
}
