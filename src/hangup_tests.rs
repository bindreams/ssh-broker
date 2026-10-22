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

/// A datagram that did not come from `wake` leaves the teardown flag clear, so the watcher
/// reports a wake but keeps waiting; only a hangup or a real wake ends `wait`.
#[test]
fn a_wake_without_the_teardown_flag_does_not_end_the_wait() {
    let (server, client, dir) = pair("spurious");
    let (_rx, tx) = split(server).unwrap();
    let (watcher, waker) = HangupWatcher::new(&tx).unwrap();
    waker.wake_tx.send(&[0]).unwrap();
    assert_eq!(watcher.poll_once().unwrap(), Ready::Wake);
    assert!(!watcher.torn_down.load(std::sync::atomic::Ordering::Acquire));
    // Still waiting: closing the peer is what ends it.
    let t = std::thread::spawn(move || watcher.wait());
    client.shutdown(std::net::Shutdown::Both).unwrap();
    drop(client);
    t.join().unwrap().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
