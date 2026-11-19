//! Unit tests for the `afunix` module.
use std::path::Path;

use crate::socket_loc::Integrity;

#[test]
fn unix_addr_accepts_a_normal_short_path() {
    assert!(super::unix_addr(Path::new("/tmp/ssh-broker/a.sock")).is_ok());
}

#[test]
fn a_read_limit_is_rounded_up_to_whole_milliseconds_and_never_to_zero() {
    use std::time::Duration;
    for (limit, rounded) in [
        (Duration::ZERO, Duration::from_millis(1)),
        (Duration::from_nanos(1), Duration::from_millis(1)),
        (Duration::from_micros(500), Duration::from_millis(1)),
        (Duration::from_micros(999), Duration::from_millis(1)),
        (Duration::from_millis(1), Duration::from_millis(1)),
        (Duration::from_nanos(1_000_001), Duration::from_millis(2)),
        (Duration::from_micros(1500), Duration::from_millis(2)),
        (Duration::from_secs(30), Duration::from_secs(30)),
        (Duration::MAX, Duration::from_millis(u64::MAX)),
    ] {
        assert_eq!(super::whole_milliseconds_up(limit), rounded, "{limit:?}");
    }
}

#[test]
fn unix_addr_rejects_an_overlong_path() {
    // sockaddr_un sun_path is ~108 bytes; a 200-char path must be rejected loudly.
    let long = format!("/tmp/{}.sock", "x".repeat(200));
    assert!(super::unix_addr(Path::new(&long)).is_err());
}

/// Create a short-pathed socket directory; on Windows, harden it so `bind`'s fail-closed
/// ACL gate is satisfied. Kept short because `sockaddr_un` paths are ~104-108 bytes.
fn setup_socket_dir(tag: &str) -> std::path::PathBuf {
    let base = if cfg!(windows) {
        std::env::temp_dir()
    } else {
        std::path::PathBuf::from("/tmp")
    };
    let dir = base.join(format!("sb-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    #[cfg(windows)]
    {
        let me = crate::acl::Sid::current_user().unwrap();
        crate::acl::harden_dir(&dir, &me).unwrap();
    }
    dir
}

#[test]
fn listen_connect_echo() {
    use std::io::{Read, Write};
    let dir = setup_socket_dir("echo");
    let sock_path = dir.join("s");

    let listener = super::Listener::bind(&sock_path, Integrity::Medium).unwrap();
    let client = std::thread::spawn({
        let p = sock_path.clone();
        move || {
            let (_rx, mut tx) = super::split(super::connect(&p).unwrap()).unwrap();
            tx.write_all(b"hello").unwrap();
        }
    });

    let (mut rx, _tx) = super::split(listener.accept().unwrap()).unwrap();
    let mut buf = [0u8; 5];
    rx.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"hello");

    client.join().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn split_halves_are_independent_and_shutdown_signals_eof() {
    use std::io::{Read, Write};
    let dir = setup_socket_dir("split");
    let sock_path = dir.join("s");
    let listener = super::Listener::bind(&sock_path, Integrity::Medium).unwrap();

    let client = std::thread::spawn({
        let p = sock_path.clone();
        move || {
            let (mut rx, mut tx) = super::split(super::connect(&p).unwrap()).unwrap();
            tx.write_all(b"req").unwrap();
            // read the server's reply until EOF (server shuts down its write half)
            let mut reply = Vec::new();
            rx.read_to_end(&mut reply).unwrap();
            reply
        }
    });

    let server = listener.accept().unwrap();
    let (mut rx, mut tx) = super::split(server).unwrap();

    // The rx half receives the client's request...
    let mut buf = [0u8; 3];
    rx.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"req");

    // ...and the tx half sends a reply; shutdown_write FINs so the client's read_to_end ends.
    tx.write_all(b"reply").unwrap();
    tx.shutdown_write().unwrap();

    let reply = client.join().unwrap();
    assert_eq!(reply, b"reply");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_write_that_finds_the_buffer_full_goes_on_when_the_peer_reads() {
    use std::io::{Read, Write};
    /// More than the socket buffers hold, so the writer must wait for the reader.
    const TOTAL: usize = 8 * 1024 * 1024;
    let dir = setup_socket_dir("full-buffer");
    let sock_path = dir.join("s");
    let listener = super::Listener::bind(&sock_path, Integrity::Medium).unwrap();

    let writer = std::thread::spawn({
        let p = sock_path.clone();
        move || {
            let (_rx, mut tx) = super::split(super::connect(&p).unwrap()).unwrap();
            let chunk = [b'x'; 64 * 1024];
            for _ in 0..TOTAL / chunk.len() {
                tx.write_all(&chunk).unwrap();
            }
            tx.shutdown_write().unwrap();
        }
    });

    let (mut rx, _tx) = super::split(listener.accept().unwrap()).unwrap();
    let mut got = Vec::new();
    rx.read_to_end(&mut got).unwrap();
    writer.join().unwrap();
    assert_eq!(got.len(), TOTAL);
    let _ = std::fs::remove_dir_all(&dir);
}

/// How long the test below lets a waiting loop run, and the most turns it may make in that time:
/// a loop that pauses for a slice between two looks makes about five, one that spins makes
/// hundreds of thousands.
#[cfg(windows)]
const OBSERVED: std::time::Duration = std::time::Duration::from_millis(500);
#[cfg(windows)]
const MOST_TURNS: u32 = 20;

/// A `wait` that does what the real one does, counts its calls in `turns`, and fails once `OBSERVED`
/// has passed since `since`, which ends the loop that called it.
#[cfg(windows)]
fn counting_wait<'a>(
    turns: &'a std::cell::Cell<u32>,
    since: std::time::Instant,
) -> impl FnMut(&socket2::Socket, super::IoKind, std::time::Duration) -> std::io::Result<()> + 'a {
    move |sock, kind, timeout| {
        turns.set(turns.get() + 1);
        if since.elapsed() >= OBSERVED {
            return Err(std::io::Error::other("observed long enough"));
        }
        super::wait(sock, kind, timeout)
    }
}

/// A peer that has shut down its write side and does not read: `WSAPoll` answers a wait on the other
/// end at once with the hang-up whatever it was asked for, while a `send` into the full buffer still
/// finds no room. The write must not turn into a spin.
#[cfg(windows)]
#[test]
fn a_write_waiting_for_room_does_not_spin_when_the_peer_has_half_closed_and_does_not_read() {
    use std::io::Write;
    let (server, client, dir) = crate::test_support::raw_socket_pair("half-closed-full");
    server.shutdown(std::net::Shutdown::Write).unwrap();
    client.set_nonblocking(true).unwrap();
    for size in [64 * 1024, 1] {
        let chunk = vec![0u8; size];
        loop {
            match (&client).write(&chunk) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("filling the buffer: {e}"),
            }
        }
    }
    let turns = std::cell::Cell::new(0);
    let err = super::write_waiting_by(&client, &[0u8], counting_wait(&turns, std::time::Instant::now()))
        .expect_err("nobody reads, so the write never gets room");
    assert_eq!(err.to_string(), "observed long enough");
    assert!(
        turns.get() <= MOST_TURNS,
        "{} turns in {OBSERVED:?}: the wait does not pause",
        turns.get()
    );
    drop((server, client));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A read whose peer has closed is woken by the hang-up alone, and its next `recv` reports the end at once:
/// pausing for the rest of the slice would delay every clean close. Only a write, which a full buffer
/// keeps from sending whatever the poll says, has a spin to prevent. `wait` pauses exactly when `pauses`
/// says so, so this table is the whole rule.
#[test]
fn only_a_write_pauses_when_the_poll_returns_for_something_else() {
    use super::{IoKind, Polled, pauses};
    assert!(
        !pauses(IoKind::Read, Polled::Other),
        "a read whose poll answered with the hang-up only"
    );
    assert!(!pauses(IoKind::Read, Polled::Asked));
    assert!(!pauses(IoKind::Read, Polled::TimedOut));
    assert!(
        pauses(IoKind::Write, Polled::Other),
        "a write whose poll did not report room"
    );
    assert!(!pauses(IoKind::Write, Polled::Asked));
    assert!(!pauses(IoKind::Write, Polled::TimedOut));
}

#[cfg(windows)]
use crate::test_support::LOST_WAKE_LIMIT;

/// A thread's own handle, to ask whether the thread has an I/O request issued and not yet completed:
/// it is exactly then parked in the kernel inside a blocking call.
#[cfg(windows)]
struct ThreadProbe(crate::winutil::OwnedHandle);

#[cfg(windows)]
impl ThreadProbe {
    fn of_current() -> ThreadProbe {
        use windows::Win32::System::Threading::{GetCurrentThreadId, OpenThread, THREAD_QUERY_INFORMATION};
        // SAFETY: plain calls; the handle is closed by `OwnedHandle`.
        let handle = unsafe { OpenThread(THREAD_QUERY_INFORMATION, false, GetCurrentThreadId()) }.expect("OpenThread");
        ThreadProbe(crate::winutil::OwnedHandle(handle))
    }

    fn io_pending(&self) -> bool {
        use windows::Win32::System::Threading::GetThreadIOPendingFlag;
        use windows::core::BOOL;
        let mut pending = BOOL(0);
        // SAFETY: `self.0.0` is an open thread handle; `pending` is a valid out pointer.
        unsafe { GetThreadIOPendingFlag(self.0.0, &mut pending) }.expect("GetThreadIOPendingFlag");
        pending.as_bool()
    }
}

/// Run `wait` on a thread of its own; once that thread is parked inside a call (`ThreadProbe`), run
/// `act` on this one. Returns what `wait` returned. The re-check of the flag has no cap: `wait`
/// returning ends it too, and then `act` does not run and the caller's assertion says what came back.
#[cfg(windows)]
fn act_once_waiting<R: Send + 'static>(wait: impl FnOnce() -> R + Send + 'static, act: impl FnOnce()) -> R {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, mpsc};
    let done = Arc::new(AtomicBool::new(false));
    let (probe_tx, probe_rx) = mpsc::channel();
    let waiter = std::thread::spawn({
        let done = Arc::clone(&done);
        move || {
            probe_tx.send(ThreadProbe::of_current()).unwrap();
            let result = wait();
            done.store(true, Ordering::Release);
            result
        }
    });
    let probe = probe_rx.recv().expect("the waiter sends its handle");
    let mut parked = false;
    while !parked && !done.load(Ordering::Acquire) {
        parked = probe.io_pending();
        std::thread::yield_now();
    }
    if parked {
        act();
    }
    waiter.join().unwrap()
}

/// The peer writes and closes at once, while the reader is already waiting: a blocking `recv` on
/// Windows AF_UNIX loses the close about once in fifty, and its reader then sleeps until its limit.
/// Every read here is a read of the transport, which must see the close.
#[cfg(windows)]
#[test]
fn a_read_already_waiting_when_the_peer_closes_sees_the_close() {
    use std::io::Read;
    const TRIALS: u32 = 500;
    for i in 0..TRIALS {
        let (server, client, dir) = crate::test_support::raw_socket_pair(&format!("closes-{i}"));
        let (mut rx, tx) = super::split(client).unwrap();
        rx.set_read_timeout(Some(LOST_WAKE_LIMIT));
        let (server_rx, mut server_tx) = super::split(server).unwrap();
        let read_to_the_end = move || {
            let mut got = Vec::new();
            rx.read_to_end(&mut got).map(|_| got)
        };
        let got = act_once_waiting(read_to_the_end, || {
            use std::io::Write;
            server_tx.write_all(b"hello").unwrap();
            drop((server_rx, server_tx));
        });
        assert_eq!(got.as_deref().ok(), Some(&b"hello"[..]), "trial {i}: {got:?}");
        drop(tx);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// A poll that is already waiting does not wake for a shutdown of the same socket while no input is
/// unread (measured), so the end of the read is the re-check, not the poll.
#[cfg(windows)]
#[test]
fn a_read_on_one_half_ends_when_the_other_half_shuts_down_both_ways() {
    use std::io::Read;
    let (server, client, dir) = crate::test_support::raw_socket_pair("shutdown-both");
    let (mut rx, tx) = super::split(client).unwrap();
    rx.set_read_timeout(Some(LOST_WAKE_LIMIT));
    let read = act_once_waiting(move || rx.read(&mut [0u8; 8]), || tx.shutdown_both().unwrap());
    assert!(
        !matches!(&read, Err(e) if e.kind() == std::io::ErrorKind::TimedOut),
        "the read did not end when the other half shut the connection down: {read:?}"
    );
    drop(server);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bind_refuses_when_a_live_listener_holds_the_path() {
    let dir = setup_socket_dir("live");
    let p = dir.join("s");
    let _first = super::Listener::bind(&p, Integrity::Medium).unwrap();
    assert!(
        super::Listener::bind(&p, Integrity::Medium).is_err(),
        "binding over a live listener must fail (no hijack)"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bind_reclaims_a_stale_socket_file() {
    let dir = setup_socket_dir("stale");
    let p = dir.join("s");
    drop(super::Listener::bind(&p, Integrity::Medium).unwrap()); // listener closed; the socket file may linger
    // A fresh bind must reclaim the dead path rather than fail.
    let _second = super::Listener::bind(&p, Integrity::Medium).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(windows)]
#[test]
fn bind_refuses_an_unhardened_directory() {
    // No harden_dir -> the inherited/default DACL must fail the fail-closed gate.
    let dir = std::env::temp_dir().join(format!("sb-unhardened-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("s");
    assert!(
        super::Listener::bind(&p, Integrity::Medium).is_err(),
        "bind must refuse a directory that is not locked down"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(windows)]
#[test]
fn bound_listener_socket_is_not_inheritable() {
    let dir = setup_socket_dir("noinherit");
    let p = dir.join("s");
    let listener = super::Listener::bind(&p, Integrity::Medium).unwrap();
    assert!(
        listener.inherit_flag_is_clear(),
        "the listening socket must not be inheritable (else children leak the ACL boundary)"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(windows)]
#[test]
fn a_connection_is_born_non_inheritable() {
    // Measures the OS: `accept_raw` is `accept` and nothing more. A listener made with
    // `WSA_FLAG_NO_HANDLE_INHERIT` yields sockets that are non-inheritable from the start, so no
    // child spawned by another thread can inherit one between `accept` and any later fix-up.
    let dir = setup_socket_dir("born");
    let p = dir.join("s");
    let listener = super::Listener::bind(&p, Integrity::Medium).unwrap();
    let client = super::connect(&p).unwrap();
    let (accepted, _) = listener.sock.accept_raw().unwrap();
    assert!(
        !super::is_inheritable(&accepted).unwrap(),
        "an accepted socket of a no-inherit listener is inheritable at birth"
    );
    drop((accepted, client));
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(windows)]
#[test]
fn an_accepted_connection_is_not_inheritable() {
    let dir = setup_socket_dir("accepted");
    let p = dir.join("s");
    let listener = super::Listener::bind(&p, Integrity::Medium).unwrap();
    let _client = super::connect(&p).unwrap();
    let accepted = listener.accept().unwrap();
    assert!(!super::is_inheritable(&accepted).unwrap());
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(windows)]
#[test]
fn a_connection_that_arrives_inheritable_is_refused_not_fixed_up() {
    // Control: a socket made without the flag is inheritable, so the check can tell.
    let sock = socket2::Socket::new_raw(socket2::Domain::UNIX, socket2::Type::STREAM, None).unwrap();
    assert!(super::is_inheritable(&sock).unwrap(), "control: made without the flag");
    // Fixing it up afterwards would leave the window open for the whole life of the accept loop's
    // handoff; a connection that was ever inheritable is refused.
    let err = super::finish_accept(Ok(sock), super::harden_accepted).expect_err("must be refused");
    match err {
        super::AcceptError::Refused { cause, .. } => {
            assert!(format!("{cause:#}").contains("inheritable"), "{cause:#}")
        }
        other => panic!("{other:?}"),
    }
}

// shares of one connection -----

/// `Conn::new` is `pub`, so it clears the inherit flag itself rather than relying on `accept` or `connect`.
#[cfg(windows)]
#[test]
fn a_connection_made_of_an_inheritable_socket_is_not_inheritable() {
    let sock = socket2::Socket::new_raw(socket2::Domain::UNIX, socket2::Type::STREAM, None).unwrap();
    assert!(super::is_inheritable(&sock).unwrap(), "control: made without the flag");
    let conn = super::Conn::new(sock).unwrap();
    assert!(
        !super::is_inheritable(&conn).unwrap(),
        "a child started now would inherit the connection"
    );
}

/// The halves of a split connection and a hang-up watcher are shares of one socket handle. Were either a
/// second handle (a `try_clone` is born inheritable on Windows), a child started meanwhile (a shell, say)
/// would inherit it and hold the connection open after the agent closed everything of its own.
#[cfg(windows)]
#[test]
fn a_child_started_while_connections_are_split_does_not_hold_them_open() {
    crate::test_support::assert_a_child_does_not_hold_a_connection_open("holds-connection", |conn| {
        crate::hangup::HangupWatcher::new(conn.clone()).unwrap()
    });
}

// the socket file's own ACL ----------------------------------------------------------------

#[cfg(windows)]
#[test]
fn bind_creates_a_socket_file_with_exactly_the_three_aces() {
    let dir = setup_socket_dir("file-acl");
    let p = dir.join("agent.sock");
    let _listener = super::Listener::bind(&p, Integrity::Medium).unwrap();
    let me = crate::acl::Sid::current_user().unwrap();
    assert!(
        crate::acl::verify_file_acl(&p, &me, Integrity::Medium).unwrap(),
        "the file is born with the directory's inheritable ACEs and nothing else"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(windows)]
#[test]
fn bind_refuses_a_dir_that_is_widened_after_it_was_hardened() {
    let dir = setup_socket_dir("widened");
    let status = std::process::Command::new("icacls")
        .arg(&dir)
        .args(["/grant", "*S-1-1-0:(OI)(CI)F"])
        .status()
        .unwrap();
    assert!(status.success());
    let p = dir.join("agent.sock");
    let err = format!(
        "{:#}",
        super::Listener::bind(&p, Integrity::Medium).err().expect("must refuse")
    );
    assert!(err.contains("not locked down"), "{err}");
    assert!(!p.exists(), "nothing was bound");
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(windows)]
#[test]
fn bind_removes_the_socket_and_refuses_when_the_file_acl_does_not_verify() {
    let dir = setup_socket_dir("bad-file");
    let p = dir.join("agent.sock");
    let err = super::Listener::bind_with(&p, Integrity::Medium, &|_, _| Ok(false))
        .err()
        .expect("must refuse");
    let who = crate::acl::Sid::current_user().unwrap().describe();
    assert_eq!(
        format!("{err:#}"),
        format!(
            "the socket file {}; refusing to listen (fail-closed)",
            crate::socket_loc::file_acl_refusal(&p, &who, Integrity::Medium)
        )
    );
    assert!(!p.exists(), "a socket whose ACL is unproven is not left behind");
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(windows)]
#[test]
fn bind_removes_the_socket_when_the_file_acl_cannot_be_read() {
    let dir = setup_socket_dir("unreadable-file");
    let p = dir.join("agent.sock");
    let result = super::Listener::bind_with(&p, Integrity::Medium, &|_, _| anyhow::bail!("cannot read it"));
    assert!(result.is_err());
    assert!(!p.exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bind_reports_a_live_listener_as_already_listening() {
    let dir = setup_socket_dir("already");
    let p = dir.join("s");
    let _first = super::Listener::bind(&p, Integrity::Medium).unwrap();
    let err = super::Listener::bind(&p, Integrity::Medium)
        .err()
        .expect("a live listener holds the path");
    assert!(
        err.downcast_ref::<super::AlreadyListening>().is_some(),
        "the caller must be able to tell this from a real failure: {err:#}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(windows)]
#[test]
fn an_agent_that_takes_over_the_lock_reclaims_the_dead_agents_socket() {
    use crate::agent_lock::UserLock;
    let dir = setup_socket_dir("takeover");
    let sock = dir.join("agent.sock");
    let lock = dir.join("agent.lock");

    // The first agent serves under the lock and dies: lock released, socket file left behind.
    let first_lock = UserLock::try_acquire(&lock).unwrap().unwrap();
    drop(super::Listener::bind(&sock, Integrity::Medium).unwrap());
    assert!(sock.exists(), "control: the dead agent left its socket file");
    drop(first_lock);

    // The second takes the lock, then binds over the stale file.
    let _second_lock = UserLock::acquire(&lock, || panic!("the lock was free")).unwrap();
    let _second = super::Listener::bind(&sock, Integrity::Medium).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

// accept errors -----

#[cfg(windows)]
fn raw(code: i32) -> std::io::Error {
    std::io::Error::from_raw_os_error(code)
}

#[cfg(windows)]
#[test]
fn a_connection_the_peer_dropped_while_queued_is_that_connections_loss() {
    // WSAECONNRESET and WSAECONNABORTED: the listener is fine; this one connection is gone.
    for code in [10054, 10053] {
        assert!(
            matches!(
                super::classify_accept_error(raw(code)),
                super::AcceptError::Connection(_)
            ),
            "{code}"
        );
    }
}

#[cfg(windows)]
#[test]
fn an_interruption_is_to_be_retried() {
    // WSAEINTR: a blocking call was cancelled; nothing was consumed and nothing is wrong.
    assert!(matches!(
        super::classify_accept_error(raw(10004)),
        super::AcceptError::Interrupted(_)
    ));
}

#[cfg(windows)]
#[test]
fn an_interrupted_wait_is_recognised_by_winsocks_code() {
    // `std` has no `ErrorKind` for WSAEINTR, so the kind alone does not say it.
    assert!(super::is_interruption(&raw(10004)));
    assert!(super::is_interruption(&std::io::ErrorKind::Interrupted.into()));
    assert!(!super::is_interruption(&raw(10035)));
}

#[cfg(windows)]
#[test]
fn a_shortage_of_descriptors_or_buffers_is_exhaustion_and_keeps_its_code() {
    // WSAEMFILE and WSAENOBUFS clear only when something else lets go of a resource.
    for code in [10024, 10055] {
        match super::classify_accept_error(raw(code)) {
            super::AcceptError::Exhausted { code: got, .. } => assert_eq!(got, code),
            other => panic!("{code} classified as {other:?}"),
        }
    }
}

#[cfg(windows)]
#[test]
fn codes_accept_never_hands_on_are_fatal_and_say_so() {
    // WSAEWOULDBLOCK is the non-blocking listener's "nothing yet", which `accept_waiting` waits out, and
    // WSAEINPROGRESS needs a Winsock 1.1 blocking call in progress; getting either here means something
    // is wrong.
    for code in [10035, 10036] {
        match super::classify_accept_error(raw(code)) {
            super::AcceptError::Fatal(e) => {
                let text = format!("{e:#}");
                assert!(text.contains(&code.to_string()), "{text}");
                assert!(text.contains("cannot return"), "{text}");
            }
            other => panic!("{code} classified as {other:?}"),
        }
    }
}

#[cfg(windows)]
#[test]
fn a_broken_listener_is_fatal() {
    // WSAEINVAL (not listening), WSAENOTSOCK, WSAENETDOWN, and a code Winsock does not document
    // for accept: none of them is a connection's fault or goes away by itself.
    for code in [10022, 10038, 10050, 99999] {
        assert!(
            matches!(super::classify_accept_error(raw(code)), super::AcceptError::Fatal(_)),
            "{code}"
        );
    }
}

#[cfg(windows)]
#[test]
fn an_accepted_connection_that_cannot_be_hardened_is_refused_not_fatal() {
    // The socket must not reach a child with its inherit flag set, so it is refused (and answered); the
    // listener has nothing wrong with it.
    let sock = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None).unwrap();
    let err = super::finish_accept(Ok(sock), |_| anyhow::bail!("SetHandleInformation failed"))
        .expect_err("a connection that cannot be hardened is not handed out");
    match err {
        super::AcceptError::Refused { cause, .. } => {
            assert!(format!("{cause:#}").contains("SetHandleInformation"), "{cause:#}")
        }
        other => panic!("{other:?}"),
    }
}

#[cfg(windows)]
#[test]
fn an_accepted_connection_that_hardens_is_handed_out() {
    let sock = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None).unwrap();
    assert!(super::finish_accept(Ok(sock), |_| Ok(())).is_ok());
}

// the elevated folder -----

#[cfg(windows)]
#[test]
fn bind_for_the_elevated_folder_refuses_a_directory_without_the_label() {
    let dir = setup_socket_dir("no-label");
    let p = dir.join("agent.sock");
    let err = format!(
        "{:#}",
        super::Listener::bind(&p, Integrity::High).err().expect("must refuse")
    );
    assert!(err.contains("not locked down"), "{err}");
    assert!(!p.exists(), "nothing was bound");
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(windows)]
#[test]
fn bind_checks_the_socket_file_for_the_integrity_it_binds_for() {
    let dir = setup_socket_dir("file-integrity");
    let p = dir.join("agent.sock");
    let asked = std::cell::Cell::new(None);
    let listener = super::Listener::bind_with(&p, Integrity::Medium, &|_, integrity| {
        asked.set(Some(integrity));
        Ok(true)
    });
    assert!(listener.is_ok());
    assert_eq!(asked.get(), Some(Integrity::Medium));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A folder made the way the elevated agent's is, in the temp dir: born labelled. Elevated (CI only).
#[cfg(windows)]
fn labelled_socket_dir(tag: &str) -> std::path::PathBuf {
    crate::test_support::assert_elevated();
    let parent = std::env::temp_dir().join(format!("sb-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&parent);
    std::fs::create_dir_all(&parent).unwrap();
    let root = crate::acl::open_root(&parent).unwrap();
    let me = crate::acl::Sid::current_user().unwrap();
    crate::acl::ensure_private_dir(&root, "d", &me, crate::acl::Hold::Shared, Integrity::High)
        .expect("an elevated process makes the labelled folder");
    parent.join("d")
}

/// Elevated (CI only): in the folder born labelled a High bind succeeds, and the socket file carries
/// the label it inherited.
#[cfg(windows)]
#[test]
fn bind_in_the_elevated_folder_leaves_a_socket_file_that_carries_the_label() {
    let dir = labelled_socket_dir("bind-high");
    let p = dir.join("agent.sock");
    let me = crate::acl::Sid::current_user().unwrap();
    let _listener = super::Listener::bind(&p, Integrity::High).expect("the folder carries the label");
    assert!(crate::acl::verify_file_acl(&p, &me, Integrity::High).unwrap());
    let _ = std::fs::remove_dir_all(dir.parent().unwrap());
}

/// Elevated (CI only): a High bind asks the socket file check for High, as the Medium one asks for Medium.
#[cfg(windows)]
#[test]
fn bind_checks_the_socket_file_for_high_when_it_binds_for_high() {
    let dir = labelled_socket_dir("file-integrity-high");
    let p = dir.join("agent.sock");
    let asked = std::cell::Cell::new(None);
    let listener = super::Listener::bind_with(&p, Integrity::High, &|_, integrity| {
        asked.set(Some(integrity));
        Ok(true)
    });
    assert!(listener.is_ok());
    assert_eq!(asked.get(), Some(Integrity::High));
    let _ = std::fs::remove_dir_all(dir.parent().unwrap());
}

/// Elevated (CI only): a socket file that does not carry the label is refused and removed, though the
/// folder is the elevated one. The label is taken off the file from inside the check, which is the
/// moment between `bind` and `listen`.
#[cfg(windows)]
#[test]
fn bind_removes_a_socket_file_without_the_label_and_refuses_to_listen() {
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Security::Authorization::{SE_FILE_OBJECT, SetNamedSecurityInfoW};
    use windows::Win32::Security::LABEL_SECURITY_INFORMATION;
    use windows::core::PCWSTR;

    let dir = labelled_socket_dir("bind-unlabelled");
    let p = dir.join("agent.sock");
    let me = crate::acl::Sid::current_user().unwrap();
    let err = super::Listener::bind_with(&p, Integrity::High, &|path, integrity| {
        assert!(
            crate::acl::verify_file_acl(path, &me, integrity).unwrap(),
            "control: the file was born with the label"
        );
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
        // SAFETY: a NUL-terminated path; a null SACL with the label requested removes the label.
        unsafe {
            SetNamedSecurityInfoW(
                PCWSTR(wide.as_ptr()),
                SE_FILE_OBJECT,
                LABEL_SECURITY_INFORMATION,
                None,
                None,
                None,
                Some(std::ptr::null()),
            )
        }
        .ok()
        .expect("take the label off the socket file");
        crate::acl::verify_file_acl(path, &me, integrity)
    })
    .err()
    .expect("must refuse");
    assert!(format!("{err:#}").contains("socket file"), "{err:#}");
    assert!(!p.exists(), "a socket whose label is unproven is not left behind");
    let _ = std::fs::remove_dir_all(dir.parent().unwrap());
}
