use super::*;
use crate::afunix::split;
use socket2::{Domain, SockAddr, Socket, Type};
use std::io::{Read, Write};

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
/// wake but keeps waiting; only a hangup or a real wake ends `wait`. More than a read buffer's
/// worth of them must neither end the wait nor fail it.
#[test]
fn a_large_write_without_the_teardown_flag_does_not_end_the_wait() {
    let (server, client, dir) = pair("spurious");
    let (_rx, tx) = split(server).unwrap();
    let (watcher, waker) = HangupWatcher::new(&tx).unwrap();
    let junk = vec![0u8; 2 * WAKE_READ_BUF];
    let mut sent = 0;
    // A non-blocking write takes what fits; one send buffer's worth is enough to exceed a read.
    while sent < WAKE_READ_BUF + 1 {
        sent += (&waker.wake_tx).write(&junk[sent..]).unwrap();
    }
    assert_eq!(watcher.poll_once().unwrap(), Ready::Wake);
    assert!(!watcher.torn_down.load(Ordering::Acquire));
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
    let (rx, tx) = wake_pair_with(|addr| {
        // SO_REUSEADDR is how a second socket would take over a port that is not exclusive.
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
