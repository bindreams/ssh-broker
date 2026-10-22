//! hangup: notice that the SSH side of a relayed session is gone, without reading the socket.
//!
//! The frame reader cannot be the only detector. Once its sink parks on a full queue it stops
//! reading, and the peer's FIN sits unseen behind the unread frames. A command that also prints
//! nothing leaves no output pump to fail a write, so the session would outlive its client.
//!
//! [`HangupWatcher`] blocks in `WSAPoll` on a duplicate of the session socket, which reports
//! `POLLHUP` for a closed peer without consuming a byte. A poll on a duplicate does not wake for
//! the session's own `shutdown_both` unless input is unread, so a second, connected loopback
//! socket joins the same poll: [`Waker::wake`] writes to it at teardown.

use crate::afunix::ConnTx;
use socket2::Socket;
use std::net::{Ipv4Addr, UdpSocket};
use std::os::windows::io::AsRawSocket;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use windows::Win32::Networking::WinSock::{
    POLLERR, POLLHUP, POLLNVAL, POLLRDNORM, SOCKET, WSAGetLastError, WSAPOLL_EVENT_FLAGS, WSAPOLLFD, WSAPoll,
};

/// Waits for the peer of a session socket to hang up. See the module docs.
pub struct HangupWatcher {
    session: Socket,
    wake_rx: UdpSocket,
    torn_down: Arc<AtomicBool>,
}

/// Ends a [`HangupWatcher::wait`] once the session is being torn down locally.
pub struct Waker {
    wake_tx: UdpSocket,
    torn_down: Arc<AtomicBool>,
}

/// What ended one poll.
#[derive(Debug, PartialEq, Eq)]
enum Ready {
    Hangup,
    Wake,
}

impl HangupWatcher {
    /// Watch `tx`'s socket through a duplicate handle. The two wake sockets are each connected
    /// to the other, so no other local process can send to the receiving one.
    pub fn new(tx: &ConnTx) -> anyhow::Result<(HangupWatcher, Waker)> {
        let session = tx.try_clone_socket()?;
        let wake_rx = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        let wake_tx = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        wake_rx.connect(wake_tx.local_addr()?)?;
        wake_tx.connect(wake_rx.local_addr()?)?;
        wake_rx.set_nonblocking(true)?;
        wake_tx.set_nonblocking(true)?;
        let torn_down = Arc::new(AtomicBool::new(false));
        let watcher = HangupWatcher {
            session,
            wake_rx,
            torn_down: Arc::clone(&torn_down),
        };
        Ok((watcher, Waker { wake_tx, torn_down }))
    }

    /// Block, with no timeout, until the peer has closed its end or [`Waker::wake`] has run. Never
    /// consumes bytes from the stream. An error means the poll itself failed, not that the peer
    /// is gone.
    pub fn wait(self) -> std::io::Result<()> {
        loop {
            match self.poll_once()? {
                Ready::Hangup => return Ok(()),
                // A datagram without the flag did not come from `wake`: keep watching.
                Ready::Wake if self.torn_down.load(Ordering::Acquire) => return Ok(()),
                Ready::Wake => {}
            }
        }
    }

    fn poll_once(&self) -> std::io::Result<Ready> {
        // No requested events on the session socket: `WSAPoll` reports hangup regardless, and
        // never reports readable data, which is not this watcher's business.
        let mut fds = [
            WSAPOLLFD {
                fd: SOCKET(self.session.as_raw_socket() as usize),
                events: WSAPOLL_EVENT_FLAGS(0),
                revents: WSAPOLL_EVENT_FLAGS(0),
            },
            WSAPOLLFD {
                fd: SOCKET(std::os::windows::io::AsRawSocket::as_raw_socket(&self.wake_rx) as usize),
                events: POLLRDNORM,
                revents: WSAPOLL_EVENT_FLAGS(0),
            },
        ];
        loop {
            // SAFETY: `fds` is a live array of the length passed; both sockets outlive the call.
            let rc = unsafe { WSAPoll(fds.as_mut_ptr(), fds.len() as u32, -1) };
            if rc < 0 {
                return Err(std::io::Error::from_raw_os_error(unsafe { WSAGetLastError() }.0));
            }
            if fds[0].revents.0 != 0 {
                return Ok(Ready::Hangup);
            }
            let wake = fds[1].revents;
            if wake.0 & (POLLERR.0 | POLLHUP.0 | POLLNVAL.0) != 0 {
                return Err(std::io::Error::other("the wake socket failed"));
            }
            if wake.0 & POLLRDNORM.0 != 0 {
                let mut buf = [0u8; 8];
                match self.wake_rx.recv(&mut buf) {
                    Ok(_) => return Ok(Ready::Wake),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e),
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
        match self.wake_tx.send(&[1]) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
#[path = "hangup_tests.rs"]
mod hangup_tests;
