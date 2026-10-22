//! hangup: notice that the SSH side of a relayed session is gone, without reading the socket.
//!
//! The frame reader cannot be the only detector. Once its sink parks on a full queue it stops
//! reading, and the peer's FIN sits unseen behind the unread frames. A command that also prints
//! nothing leaves no output pump to fail a write, so the session would outlive its client.
//!
//! [`HangupWatcher`] blocks in `WSAPoll` on a duplicate of the session socket, which reports
//! `POLLHUP` for a closed peer without consuming a byte. A poll on a duplicate does not wake for
//! a local `shutdown_write`, nor for a local `shutdown_both` unless input is unread, so a second
//! socket joins the same poll: [`Waker::wake`] writes to it at teardown. It is one end of a
//! loopback TCP connection this module made (see [`wake_pair`]); [`accept_own`] admits only that
//! connection, so no other process can write to the other end.

use crate::afunix::ConnTx;
use socket2::{Domain, SockAddr, Socket, Type};
use std::cell::Cell;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::os::windows::io::AsRawSocket;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use windows::Win32::Networking::WinSock::{
    POLLERR, POLLHUP, POLLNVAL, POLLRDNORM, SO_EXCLUSIVEADDRUSE, SOCKET, SOL_SOCKET, WSAGetLastError,
    WSAPOLL_EVENT_FLAGS, WSAPOLLFD, WSAPoll, setsockopt,
};

/// Waits for the peer of a session socket to hang up.
pub struct HangupWatcher {
    session: Socket,
    wake_rx: TcpStream,
    /// The wake channel reached EOF or failed: its `Waker` is gone. Stop polling it, since a
    /// closed socket stays readable forever.
    wake_closed: Cell<bool>,
    torn_down: Arc<AtomicBool>,
}

/// Ends a [`HangupWatcher::wait`] once the session is being torn down locally. Dropping it does
/// the same.
pub struct Waker {
    wake_tx: TcpStream,
    torn_down: Arc<AtomicBool>,
}

/// What ended one poll.
#[derive(Debug, PartialEq, Eq)]
enum Ready {
    Hangup,
    Wake,
}

/// Bytes read from the wake channel per call; only bounds how often the flag is re-checked.
const WAKE_READ_BUF: usize = 64 * 1024;

impl HangupWatcher {
    /// Watch `tx`'s socket through a duplicate handle.
    pub fn new(tx: &ConnTx) -> std::io::Result<(HangupWatcher, Waker)> {
        let session = tx.try_clone_socket()?;
        let (wake_rx, wake_tx) = wake_pair()?;
        Ok(Self::from_parts(session, wake_rx, wake_tx))
    }

    fn from_parts(session: Socket, wake_rx: TcpStream, wake_tx: TcpStream) -> (HangupWatcher, Waker) {
        let torn_down = Arc::new(AtomicBool::new(false));
        let watcher = HangupWatcher {
            session,
            wake_rx,
            wake_closed: Cell::new(false),
            torn_down: Arc::clone(&torn_down),
        };
        (watcher, Waker { wake_tx, torn_down })
    }

    /// Block, with no timeout, until the peer has closed its end or the session's [`Waker`] has
    /// woken or been dropped. Never consumes bytes from the stream. An error means the poll itself
    /// failed, not that the peer is gone.
    pub fn wait(self) -> std::io::Result<()> {
        loop {
            match self.poll_once()? {
                Ready::Hangup => return Ok(()),
                // Something arrived on the wake channel: only the flag says it was a real wake.
                Ready::Wake if self.torn_down.load(Ordering::Acquire) => return Ok(()),
                Ready::Wake => {}
            }
        }
    }

    fn poll_once(&self) -> std::io::Result<Ready> {
        loop {
            if let Some(ready) = self.poll_ready(-1)? {
                return Ok(ready);
            }
        }
    }

    /// One `WSAPoll` with `timeout_ms` (-1 blocks until something is ready, 0 only asks).
    fn poll_ready(&self, timeout_ms: i32) -> std::io::Result<Option<Ready>> {
        // No requested events on the session socket: `WSAPoll` reports hangup regardless, and
        // never reports readable data, which is not this watcher's business.
        let mut fds = [
            WSAPOLLFD {
                fd: SOCKET(self.session.as_raw_socket() as usize),
                events: WSAPOLL_EVENT_FLAGS(0),
                revents: WSAPOLL_EVENT_FLAGS(0),
            },
            WSAPOLLFD {
                fd: SOCKET(self.wake_rx.as_raw_socket() as usize),
                events: POLLRDNORM,
                revents: WSAPOLL_EVENT_FLAGS(0),
            },
        ];
        let polled = if self.wake_closed.get() { 1 } else { fds.len() };
        // SAFETY: `fds` is a live array of at least `polled` entries; both sockets outlive the call.
        let rc = unsafe { WSAPoll(fds.as_mut_ptr(), polled as u32, timeout_ms) };
        if rc < 0 {
            return Err(std::io::Error::from_raw_os_error(unsafe { WSAGetLastError() }.0));
        }
        if fds[0].revents.0 != 0 {
            return Ok(Some(Ready::Hangup));
        }
        let wake = fds[1].revents.0;
        if polled > 1 && wake != 0 {
            if wake & POLLNVAL.0 != 0 {
                return Err(std::io::Error::other("the wake socket is not a socket"));
            }
            debug_assert!(wake & (POLLRDNORM.0 | POLLHUP.0 | POLLERR.0) != 0);
            self.drain_wake_channel();
            return Ok(Some(Ready::Wake));
        }
        Ok(None)
    }

    /// Read everything pending on the wake channel and discard it. Data and EOF both mean only
    /// "re-check the flag"; EOF or a failed read also ends polling the channel.
    fn drain_wake_channel(&self) {
        let mut buf = vec![0u8; WAKE_READ_BUF];
        loop {
            match (&self.wake_rx).read(&mut buf) {
                Ok(0) => return self.wake_closed.set(true),
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => {
                    tracing::warn!("reading the hangup watcher's wake channel failed; no longer polling it: {e}");
                    return self.wake_closed.set(true);
                }
            }
        }
    }
}

impl Waker {
    /// Make the watcher's `wait` return. Call after the session's own teardown has begun. A full
    /// wake queue is success: a wake is already pending.
    pub fn wake(&self) -> std::io::Result<()> {
        self.torn_down.store(true, Ordering::Release);
        match (&self.wake_tx).write(&[1]) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
            Err(e) => Err(e),
        }
    }
}

impl Drop for Waker {
    fn drop(&mut self) {
        // Set the flag before waking, so the watcher sees it when it re-checks.
        self.torn_down.store(true, Ordering::Release);
    }
}

/// A connected loopback TCP pair `(receiving, sending)` that nothing else can reach.
///
/// The listener's exact address cannot be rebound (measured, with or without
/// `SO_EXCLUSIVEADDRUSE` on the listener: 10048, or 10013 with `SO_REUSEADDR`). A wildcard bind
/// on its port succeeds unless the second socket itself sets `SO_EXCLUSIVEADDRUSE` (10048), and
/// it does not receive connects to `127.0.0.1:port`. The listener is closed as soon as the pair exists. A foreign
/// process may still connect to the port before that; [`accept_own`] is what excludes it: the
/// accepted connection is ours only if its peer address is the connecting socket's own, and any
/// other is dropped.
fn wake_pair() -> std::io::Result<(TcpStream, TcpStream)> {
    wake_pair_with(|_, _| {})
}

/// [`wake_pair`], calling `listening` with the listener and its address once it accepts
/// connections.
fn wake_pair_with(listening: impl FnOnce(&Socket, SocketAddr)) -> std::io::Result<(TcpStream, TcpStream)> {
    let listener = Socket::new(Domain::IPV4, Type::STREAM, None)?;
    exclusive_addr_use(&listener)?;
    listener.bind(&SockAddr::from(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))?;
    listener.listen(128)?;
    let addr = listener
        .local_addr()?
        .as_socket()
        .ok_or_else(|| std::io::Error::other("the wake listener has no socket address"))?;
    listening(&listener, addr);

    let tx = TcpStream::connect(addr)?;
    let tx_local = tx.local_addr()?;
    let rx = accept_own(tx_local, || {
        let (conn, peer) = listener.accept()?;
        Ok((TcpStream::from(conn), peer.as_socket()))
    })?;
    rx.set_nonblocking(true)?;
    tx.set_nonblocking(true)?;
    Ok((rx, tx))
}

/// Calls `accept` until it yields the connection whose peer is `own`, dropping the others.
///
/// A foreign connection reset or aborted before it is accepted is a consumed queue entry, not a
/// failure, so it is accepted past like any other foreign one. Every other error is returned.
fn accept_own<C>(
    own: SocketAddr,
    mut accept: impl FnMut() -> std::io::Result<(C, Option<SocketAddr>)>,
) -> std::io::Result<C> {
    loop {
        match accept() {
            Ok((conn, peer)) if peer == Some(own) => return Ok(conn),
            Ok(_) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                ) => {}
            Err(e) => return Err(e),
        }
    }
}

fn exclusive_addr_use(socket: &Socket) -> std::io::Result<()> {
    let on = 1i32.to_ne_bytes();
    // SAFETY: a plain setsockopt on a live socket with an int-sized value.
    let rc = unsafe {
        setsockopt(
            SOCKET(socket.as_raw_socket() as usize),
            SOL_SOCKET,
            SO_EXCLUSIVEADDRUSE,
            Some(&on),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::from_raw_os_error(unsafe { WSAGetLastError() }.0));
    }
    Ok(())
}

#[cfg(test)]
#[path = "hangup_tests.rs"]
mod hangup_tests;
