use super::*;
use crate::afunix::split;
use socket2::{Domain, SockAddr, Socket, Type};
use std::io::{Read, Write};
use std::sync::Mutex;

/// What `f` logged on this thread, as text.
fn logged(f: impl FnOnce()) -> String {
    struct Capture(Arc<Mutex<Vec<u8>>>);
    impl Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let sink = Arc::new(Mutex::new(Vec::new()));
    let writer = Arc::clone(&sink);
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || Capture(Arc::clone(&writer)))
        .with_ansi(false)
        .finish();
    tracing::subscriber::with_default(subscriber, f);
    let bytes = sink.lock().unwrap().clone();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// A connected AF_UNIX pair in a temp dir (no ACLs: these tests exercise the watcher, not the
/// security boundary). Returns the server side, the client side and the dir to remove.
fn pair(tag: &str) -> (Socket, Socket, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("sb-hangup-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("s");
    let listener = Socket::new(Domain::UNIX, Type::STREAM, None).unwrap();
    listener.bind(&SockAddr::unix(&path).unwrap()).unwrap();
    listener.listen(1).unwrap();
    let client = Socket::new(Domain::UNIX, Type::STREAM, None).unwrap();
    client.connect(&SockAddr::unix(&path).unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    (server, client, dir)
}

/// The peer closes while nothing is unread.
#[test]
fn watcher_returns_when_the_peer_closes() {
    let (server, client, dir) = pair("close");
    let (_rx, tx) = split(server).unwrap();
    let (watcher, _waker) = HangupWatcher::new(&tx).unwrap();
    let t = std::thread::spawn(move || watcher.wait());
    client.shutdown(std::net::Shutdown::Both).unwrap();
    drop(client);
    t.join().unwrap().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The peer closes with frames still queued on our side, which is the case a reader-based
/// detector cannot see: the FIN sits behind them. The watcher must also leave them unread.
#[test]
fn watcher_returns_when_the_peer_closes_with_unread_input() {
    let (server, mut client, dir) = pair("unread");
    let (mut rx, tx) = split(server).unwrap();
    let (watcher, _waker) = HangupWatcher::new(&tx).unwrap();
    client.write_all(b"unread-frames").unwrap();
    client.shutdown(std::net::Shutdown::Both).unwrap();
    drop(client);
    let t = std::thread::spawn(move || watcher.wait());
    t.join().unwrap().unwrap();
    let mut buf = [0u8; 13];
    rx.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"unread-frames");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The session's own `shutdown_both` does not wake a poll on a duplicate of an idle socket, so
/// the waker is what ends the wait. The peer stays open throughout.
#[test]
fn watcher_returns_after_local_shutdown() {
    let (server, client, dir) = pair("local");
    let (_rx, tx) = split(server).unwrap();
    let (watcher, waker) = HangupWatcher::new(&tx).unwrap();
    let t = std::thread::spawn(move || watcher.wait());
    tx.shutdown_both().unwrap();
    waker.wake().unwrap();
    t.join().unwrap().unwrap();
    drop(client);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A wake sent before the watcher starts waiting is not lost.
#[test]
fn watcher_returns_when_woken_before_it_waits() {
    let (server, client, dir) = pair("early");
    let (_rx, tx) = split(server).unwrap();
    let (watcher, waker) = HangupWatcher::new(&tx).unwrap();
    waker.wake().unwrap();
    watcher.wait().unwrap();
    drop(client);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Bytes that did not come from `wake` leave the teardown flag clear, so the watcher reports a
/// wake but keeps waiting; only a hangup or a real wake ends `wait`. More than one read buffer's
/// worth of them must be drained in a single report (the channel is read until `WouldBlock`),
/// neither ending the wait nor failing it.
#[test]
fn a_large_write_without_the_teardown_flag_is_drained_whole_and_does_not_end_the_wait() {
    let (server, client, dir) = pair("spurious");
    let (_rx, tx) = split(server).unwrap();
    let (watcher, waker) = HangupWatcher::new(&tx).unwrap();
    // Room for everything below, so it all reaches the receiving end without anyone reading.
    let wanted = 2 * WAKE_READ_BUF + 1;
    socket2::SockRef::from(&watcher.wake_rx)
        .set_recv_buffer_size(4 * WAKE_READ_BUF)
        .unwrap();
    let junk = vec![0u8; wanted];
    let mut sent = 0;
    while sent < wanted {
        match (&waker.wake_tx).write(&junk[sent..]) {
            Ok(n) => sent += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => panic!("writing to the wake channel failed: {e}"),
        }
    }
    assert_eq!(sent, wanted, "the wake channel took less than a read buffer and a half");
    // Wait until every byte has arrived, so no byte is still in flight when the drain looks.
    let mut peeked = vec![0u8; wanted];
    loop {
        match watcher.wake_rx.peek(&mut peeked) {
            Ok(n) if n == wanted => break,
            Ok(_) => std::thread::yield_now(),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::yield_now(),
            Err(e) => panic!("peeking at the wake channel failed: {e}"),
        }
    }
    assert_eq!(watcher.poll_once().unwrap(), Ready::Wake);
    assert!(!watcher.torn_down.load(Ordering::Acquire));
    // One report drained all of it: a drain that stopped after one read would leave the rest.
    assert_eq!(watcher.poll_ready(0).unwrap(), None);
    // Still waiting: closing the peer is what ends it.
    let t = std::thread::spawn(move || watcher.wait());
    client.shutdown(std::net::Shutdown::Both).unwrap();
    drop(client);
    t.join().unwrap().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The wake channel closing without a wake (EOF, flag clear) is neither an error nor a reason to
/// stop watching, and the closed channel is not polled again: it would report readable forever.
#[test]
fn a_closed_wake_channel_without_the_flag_keeps_watching_the_session() {
    let (server, client, dir) = pair("eof");
    let (_rx, tx) = split(server).unwrap();
    let (watcher, waker) = HangupWatcher::new(&tx).unwrap();
    waker.wake_tx.shutdown(std::net::Shutdown::Write).unwrap();
    assert_eq!(watcher.poll_once().unwrap(), Ready::Wake);
    assert!(!watcher.torn_down.load(Ordering::Acquire));
    // With the closed channel still polled, it would report readable here.
    assert_eq!(watcher.poll_ready(0).unwrap(), None);
    client.shutdown(std::net::Shutdown::Both).unwrap();
    drop(client);
    assert_eq!(watcher.poll_once().unwrap(), Ready::Hangup);
    drop(waker);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A failed read on the wake channel (here a reset) is logged, then ends polling the channel like
/// EOF does: a reset socket stays readable forever.
#[test]
fn a_failed_read_on_the_wake_channel_is_logged_and_stops_polling_it() {
    let (server, client, dir) = pair("reset");
    let (_rx, tx) = split(server).unwrap();
    let (watcher, waker) = HangupWatcher::new(&tx).unwrap();
    // A zero linger turns the waker's close into a RST, which the watcher reads as an error.
    socket2::SockRef::from(&waker.wake_tx)
        .set_linger(Some(std::time::Duration::ZERO))
        .unwrap();
    drop(waker);
    let mut ready = None;
    let log = logged(|| ready = Some(watcher.poll_once().unwrap()));
    assert_eq!(ready, Some(Ready::Wake));
    assert!(
        log.contains("WARN") && log.contains("wake channel"),
        "the failed read was not logged: {log:?}"
    );
    // With the failed channel still polled, it would report readable here.
    assert_eq!(watcher.poll_ready(0).unwrap(), None);
    drop(client);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A full wake queue means a wake is already pending, so waking again is success and still sets
/// the flag.
#[test]
fn waking_a_full_wake_queue_is_success() {
    let (server, client, dir) = pair("full");
    let (_rx, tx) = split(server).unwrap();
    let (watcher, waker) = HangupWatcher::new(&tx).unwrap();
    // Nobody reads: fill the queue until the socket says it is full.
    let filler = [0u8; 4096];
    loop {
        match (&waker.wake_tx).write(&filler) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => panic!("filling the wake channel failed: {e}"),
        }
    }
    waker.wake().unwrap();
    assert!(watcher.torn_down.load(Ordering::Acquire));
    drop(client);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Dropping the waker ends the wait, as a wake does.
#[test]
fn watcher_returns_when_the_waker_is_dropped() {
    let (server, client, dir) = pair("dropped");
    let (_rx, tx) = split(server).unwrap();
    let (watcher, waker) = HangupWatcher::new(&tx).unwrap();
    let t = std::thread::spawn(move || watcher.wait());
    drop(waker);
    t.join().unwrap().unwrap();
    drop(client);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A connection to the listener's port that is not the pair's own never becomes the wake channel,
/// even when it arrives first, and the listener's port cannot be bound by another socket.
#[test]
fn a_foreign_connection_to_the_listener_does_not_become_the_wake_channel() {
    let mut foreign = None;
    let mut rebind = None;
    let (rx, tx) = wake_pair_with(|_, addr| {
        // SO_REUSEADDR would let a second socket take over a non-exclusive port.
        let other = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
        other.set_reuse_address(true).unwrap();
        rebind = Some(other.bind(&SockAddr::from(addr)));
        foreign = Some(TcpStream::connect(addr).unwrap());
    })
    .unwrap();

    let rebind = rebind.unwrap();
    assert!(rebind.is_err(), "another socket bound the wake listener's port");

    (&tx).write_all(b"w").unwrap();
    let mut got = [0u8; 1];
    // The pair is connected to each other: a blocking read on the receiving end sees our byte.
    rx.set_nonblocking(false).unwrap();
    (&rx).read_exact(&mut got).unwrap();
    assert_eq!(&got, b"w");

    // Nothing reached the foreign connection, and it was closed rather than kept.
    let mut foreign = foreign.unwrap();
    let mut buf = [0u8; 1];
    assert_eq!(
        foreign.read(&mut buf).unwrap(),
        0,
        "the foreign connection was not dropped"
    );
}

/// Whether `SO_EXCLUSIVEADDRUSE` is set on `socket`.
fn is_exclusive(socket: &Socket) -> bool {
    use windows::Win32::Networking::WinSock::getsockopt;
    use windows::core::PSTR;
    let mut value = 0i32;
    let mut len = size_of::<i32>() as i32;
    // SAFETY: a plain getsockopt on a live socket into an int-sized buffer.
    let rc = unsafe {
        getsockopt(
            SOCKET(socket.as_raw_socket() as usize),
            SOL_SOCKET,
            SO_EXCLUSIVEADDRUSE,
            PSTR(&mut value as *mut i32 as *mut u8),
            &mut len,
        )
    };
    assert_eq!(rc, 0, "getsockopt failed: {}", std::io::Error::last_os_error());
    value != 0
}

/// The listener has `SO_EXCLUSIVEADDRUSE`. A rebind attempt cannot pin this: on this OS another
/// socket cannot bind a specific loopback address that a plain listener holds either, so the
/// option is read back instead. The control: a socket without it reads back clear.
#[test]
fn the_wake_listener_has_the_exclusive_option() {
    let plain = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
    assert!(!is_exclusive(&plain), "the control: a plain socket reads back clear");
    exclusive_addr_use(&plain).unwrap();
    assert!(is_exclusive(&plain), "the readback sees the option once it is set");

    let mut exclusive = None;
    wake_pair_with(|listener, _| exclusive = Some(is_exclusive(listener))).unwrap();
    assert_eq!(exclusive, Some(true));
}

/// Two pairs never share endpoints: each wake reaches only its own watcher.
#[test]
fn wake_pairs_are_independent() {
    let (rx_a, tx_a) = wake_pair().unwrap();
    let (rx_b, _tx_b) = wake_pair().unwrap();
    (&tx_a).write_all(b"a").unwrap();
    rx_a.set_nonblocking(false).unwrap();
    let mut got = [0u8; 1];
    (&rx_a).read_exact(&mut got).unwrap();
    assert_eq!(&got, b"a");
    let mut buf = [0u8; 1];
    assert_eq!(
        (&rx_b).read(&mut buf).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

/// Smoke test: Windows loopback does not surface a reset at `accept`, so this never reaches the
/// skip branch of `accept_own`; the injected `accept_own_*` tests are the coverage for it. It
/// only checks that connections closed with a reset do not break the pair.
#[test]
fn foreign_connections_closed_with_a_reset_do_not_break_the_pair_smoke() {
    let (rx, tx) = wake_pair_with(|_, addr| {
        for _ in 0..50 {
            let foreign = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
            foreign.connect(&SockAddr::from(addr)).unwrap();
            // A zero linger turns the close into a RST.
            foreign.set_linger(Some(std::time::Duration::ZERO)).unwrap();
            drop(foreign);
        }
    })
    .unwrap();

    (&tx).write_all(b"w").unwrap();
    rx.set_nonblocking(false).unwrap();
    let mut got = [0u8; 1];
    (&rx).read_exact(&mut got).unwrap();
    assert_eq!(&got, b"w");
}

/// `accept` failing with a reset or an abort means the queue entry is gone, so the loop accepts
/// again; the errors cannot be provoked reliably on loopback, so they are injected.
#[test]
fn accept_own_skips_entries_the_peer_reset_and_returns_the_matching_one() {
    use std::io::{Error, ErrorKind};
    let own: SocketAddr = "127.0.0.1:5000".parse().unwrap();
    let foreign: SocketAddr = "127.0.0.1:6000".parse().unwrap();
    let mut script = vec![
        Err(Error::from(ErrorKind::ConnectionReset)),
        Ok(("foreign", Some(foreign))),
        Err(Error::from(ErrorKind::ConnectionAborted)),
        Ok(("ours", Some(own))),
    ]
    .into_iter();
    let got = accept_own(own, || script.next().expect("accepted past the matching entry")).unwrap();
    assert_eq!(got, "ours");
}

/// Any other `accept` failure is a real error and ends the pair's creation.
#[test]
fn accept_own_propagates_other_accept_errors() {
    use std::io::{Error, ErrorKind};
    let own: SocketAddr = "127.0.0.1:5000".parse().unwrap();
    let err = accept_own::<()>(own, || Err(Error::from(ErrorKind::PermissionDenied))).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::PermissionDenied);
}
