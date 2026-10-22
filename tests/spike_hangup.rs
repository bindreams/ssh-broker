//! THROWAWAY spike (never merged): what can block on an AF_UNIX socket without consuming data
//! and return when the peer hangs up?
#![cfg(windows)]
use socket2::{Domain, SockAddr, Socket, Type};
use std::os::windows::io::AsRawSocket;
use windows::Win32::Networking::WinSock::*;

fn pair(tag: &str) -> (Socket, Socket, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("sb-spike-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("s");
    let l = Socket::new(Domain::UNIX, Type::STREAM, None).unwrap();
    l.bind(&SockAddr::unix(&path).unwrap()).unwrap();
    l.listen(1).unwrap();
    let c = Socket::new(Domain::UNIX, Type::STREAM, None).unwrap();
    c.connect(&SockAddr::unix(&path).unwrap()).unwrap();
    let (srv, _) = l.accept().unwrap();
    (srv, c, dir)
}

fn raw(s: &Socket) -> SOCKET {
    SOCKET(s.as_raw_socket() as usize)
}

fn poll(s: &Socket, events: WSAPOLL_EVENT_FLAGS, timeout: i32) -> (i32, i16) {
    let mut fd = WSAPOLLFD {
        fd: raw(s),
        events,
        revents: WSAPOLL_EVENT_FLAGS(0),
    };
    let rc = unsafe { WSAPoll(&mut fd, 1, timeout) };
    (rc, fd.revents.0)
}

fn describe(label: &str, srv: &Socket) {
    let dup = srv.try_clone().unwrap();
    let (rc0, rev0) = poll(&dup, WSAPOLL_EVENT_FLAGS(0), 0);
    let (rc1, rev1) = poll(&dup, POLLRDNORM, 0);
    println!(
        "{label}: WSAPoll(events=0,t=0) rc={rc0} revents={rev0:#x} (HUP={:#x} ERR={:#x}) | WSAPoll(RDNORM,t=0) rc={rc1} revents={rev1:#x}",
        POLLHUP.0, POLLERR.0
    );
    // MSG_PEEK only when readable, so it cannot block.
    if rev1 & POLLRDNORM.0 != 0 || rev1 & POLLHUP.0 != 0 {
        let mut b = [0u8; 8];
        let n = unsafe { recv(raw(&dup), &mut b, MSG_PEEK) };
        println!("{label}: recv(MSG_PEEK) -> {n} (wsaerr {:?})", unsafe { WSAGetLastError() });
    }
}

#[test]
fn spike() {
    // (a) peer closed, nothing unread.
    let (srv, cli, dir) = pair("a");
    cli.shutdown(std::net::Shutdown::Both).unwrap();
    drop(cli);
    describe("(a) peer closed, nothing unread", &srv);
    drop(srv);
    let _ = std::fs::remove_dir_all(&dir);

    // (b) peer wrote then closed; unread bytes queued on our side.
    let (srv, mut cli, dir) = pair("b");
    use std::io::Write;
    cli.write_all(b"unread-frames").unwrap();
    cli.shutdown(std::net::Shutdown::Both).unwrap();
    drop(cli);
    describe("(b) peer closed, unread queued", &srv);
    drop(srv);
    let _ = std::fs::remove_dir_all(&dir);

    // (b2) peer wrote, still open: baseline that RDNORM fires and HUP does not.
    let (srv, mut cli, dir) = pair("b2");
    cli.write_all(b"unread-frames").unwrap();
    describe("(b2) peer open, unread queued", &srv);
    drop(cli);
    drop(srv);
    let _ = std::fs::remove_dir_all(&dir);

    // (b3) peer open, nothing queued: baseline.
    let (srv, cli, dir) = pair("b3");
    describe("(b3) peer open, idle", &srv);
    drop(cli);
    drop(srv);
    let _ = std::fs::remove_dir_all(&dir);

    // (c) local shutdown_both of a dup'd handle while another thread blocks in WSAPoll(events=0).
    for unread in [false, true] {
        let (srv, mut cli, dir) = pair("c");
        if unread {
            cli.write_all(b"unread-frames").unwrap();
        }
        let waiter = srv.try_clone().unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let t = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            // bounded only so a negative result cannot hang the spike
            poll(&waiter, WSAPOLL_EVENT_FLAGS(0), 5000)
        });
        started_rx.recv().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(300)); // sleep-ok: throwaway spike
        let t0 = std::time::Instant::now();
        srv.shutdown(std::net::Shutdown::Both).unwrap();
        let (rc, rev) = t.join().unwrap();
        println!(
            "(c) local shutdown_both, unread={unread}: waiter WSAPoll(events=0) returned rc={rc} revents={rev:#x} after {:?} (5s bound => timeout)",
            t0.elapsed()
        );
        drop(cli);
        drop(srv);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // (d) real shape: waiter blocked in WSAPoll(events=0) on a dup while the PEER closes, unread queued.
    for unread in [false, true] {
        let (srv, mut cli, dir) = pair("d");
        if unread {
            cli.write_all(b"unread-frames").unwrap();
        }
        let waiter = srv.try_clone().unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let t = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            poll(&waiter, WSAPOLL_EVENT_FLAGS(0), 5000)
        });
        started_rx.recv().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(300)); // sleep-ok: throwaway spike
        let t0 = std::time::Instant::now();
        cli.shutdown(std::net::Shutdown::Both).unwrap();
        drop(cli);
        let (rc, rev) = t.join().unwrap();
        println!(
            "(d) peer closes while waiter blocked, unread={unread}: WSAPoll(events=0) rc={rc} revents={rev:#x} after {:?}",
            t0.elapsed()
        );
        drop(srv);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // WSAEventSelect(FD_CLOSE) on a dup'd handle: (a)/(b) after the fact, and its effect on blocking mode.
    for unread in [false, true] {
        let (srv, mut cli, dir) = pair("e");
        if unread {
            cli.write_all(b"unread-frames").unwrap();
        }
        let dup = srv.try_clone().unwrap();
        let ev = unsafe { WSACreateEvent() }.unwrap();
        let rc = unsafe { WSAEventSelect(raw(&dup), Some(ev), FD_CLOSE as i32) };
        cli.shutdown(std::net::Shutdown::Both).unwrap();
        drop(cli);
        let mut ne = WSANETWORKEVENTS::default();
        let rc2 = unsafe { WSAEnumNetworkEvents(raw(&dup), ev, &mut ne) };
        println!(
            "(e) WSAEventSelect(FD_CLOSE) unread={unread}: select rc={rc}, enum rc={rc2}, lNetworkEvents={:#x} (FD_CLOSE={:#x}) closeErr={}",
            ne.lNetworkEvents, FD_CLOSE, ne.iErrorCode[5]
        );
        // Side effect: is the ORIGINAL socket now non-blocking? An idle recv would block forever if not.
        let (srv2, cli2, dir2) = pair("e2");
        let dup2 = srv2.try_clone().unwrap();
        let ev2 = unsafe { WSACreateEvent() }.unwrap();
        unsafe { WSAEventSelect(raw(&dup2), Some(ev2), FD_CLOSE as i32) };
        let mut b = [0u8; 4];
        let n = unsafe { recv(raw(&srv2), &mut b, SEND_RECV_FLAGS(0)) };
        println!(
            "(e) after WSAEventSelect on a dup, recv on the ORIGINAL idle socket returned {n} wsaerr={:?} (WSAEWOULDBLOCK=10035 => non-blocking leak)",
            unsafe { WSAGetLastError() }
        );
        drop(cli2);
        drop(srv2);
        let _ = std::fs::remove_dir_all(&dir2);
        drop(srv);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // (c3) local wake alternatives while the waiter blocks in WSAPoll(events=0), idle, peer open.
    // (c3a) shutdown(Write) only, (c3b) shutdown(Read) only.
    for how in [std::net::Shutdown::Write, std::net::Shutdown::Read] {
        let (srv, cli, dir) = pair("c3");
        let waiter = srv.try_clone().unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let t = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            poll(&waiter, WSAPOLL_EVENT_FLAGS(0), 3000)
        });
        started_rx.recv().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(300)); // sleep-ok: throwaway spike
        let t0 = std::time::Instant::now();
        srv.shutdown(how).unwrap();
        let (rc, rev) = t.join().unwrap();
        println!("(c3) local shutdown({how:?}) idle: rc={rc} revents={rev:#x} after {:?} (3s bound)", t0.elapsed());
        drop(cli);
        drop(srv);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // (c4) CancelSynchronousIo on the waiter thread.
    {
        use std::os::windows::io::AsRawHandle;
        let (srv, cli, dir) = pair("c4");
        let waiter = srv.try_clone().unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let t = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            let r = poll(&waiter, WSAPOLL_EVENT_FLAGS(0), 3000);
            (r, unsafe { WSAGetLastError() })
        });
        started_rx.recv().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(300)); // sleep-ok: throwaway spike
        let t0 = std::time::Instant::now();
        let h = windows::Win32::Foundation::HANDLE(t.as_raw_handle());
        let cancelled = unsafe { windows::Win32::System::IO::CancelSynchronousIo(h) };
        let ((rc, rev), err) = t.join().unwrap();
        println!(
            "(c4) CancelSynchronousIo -> {cancelled:?}; waiter rc={rc} revents={rev:#x} wsaerr={err:?} after {:?} (3s bound)",
            t0.elapsed()
        );
        drop(cli);
        drop(srv);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // (c5) two-socket poll: the session socket plus a loopback UDP wake socket; wake by sending a datagram.
    {
        let (srv, cli, dir) = pair("c5");
        let wake_rx = Socket::new(Domain::IPV4, Type::DGRAM, None).unwrap();
        wake_rx.bind(&"127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap().into()).unwrap();
        let wake_addr = wake_rx.local_addr().unwrap();
        let waiter = srv.try_clone().unwrap();
        let wake_rx2 = wake_rx.try_clone().unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let t = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            let mut fds = [
                WSAPOLLFD { fd: raw(&waiter), events: WSAPOLL_EVENT_FLAGS(0), revents: WSAPOLL_EVENT_FLAGS(0) },
                WSAPOLLFD { fd: raw(&wake_rx2), events: POLLRDNORM, revents: WSAPOLL_EVENT_FLAGS(0) },
            ];
            let rc = unsafe { WSAPoll(fds.as_mut_ptr(), 2, 3000) };
            (rc, fds[0].revents.0, fds[1].revents.0)
        });
        started_rx.recv().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(300)); // sleep-ok: throwaway spike
        let t0 = std::time::Instant::now();
        let tx = Socket::new(Domain::IPV4, Type::DGRAM, None).unwrap();
        tx.send_to(b"x", &wake_addr).unwrap();
        let (rc, r0, r1) = t.join().unwrap();
        println!("(c5) wake datagram: rc={rc} session revents={r0:#x} wake revents={r1:#x} after {:?} (3s bound)", t0.elapsed());
        drop(cli);
        drop(srv);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
