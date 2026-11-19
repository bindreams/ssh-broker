//! afunix: AF_UNIX stream listener/connector via socket2 (Windows-supported).
//!
//! The agent binds and the shim connects at a path both derive from the user's profile (see
//! `socket_loc`). The `sockaddr_un` path limit (~108 bytes) is surfaced loudly rather than
//! failing cryptically deep in the OS.
//!
//! This module is the only code that reads, writes or accepts on an AF_UNIX socket, and it never
//! blocks in the OS to do it. A blocking `recv` on Windows AF_UNIX sometimes misses the wake of a
//! peer that wrote and closed at once, and then sleeps for ever. So every connection is non-blocking,
//! and one loop ([`read_waiting`], [`write_waiting`], `Listener::accept`) makes the call, and on
//! `WouldBlock` waits for the socket for at most [`RECHECK_EVERY`] and makes the call again. The
//! wait is only a sleep that may end early; what it reports is never read.

use socket2::{Domain, SockAddr, Socket, Type};
use std::cell::Cell;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::socket_loc::Integrity;

/// Build a `SockAddr` for an AF_UNIX pathname socket, surfacing an over-long path
/// (`sockaddr_un` overflow) as a clear error instead of a cryptic OS failure.
pub fn unix_addr(path: &Path) -> anyhow::Result<SockAddr> {
    SockAddr::unix(path).map_err(|e| {
        anyhow::anyhow!(
            "AF_UNIX socket path is invalid or too long ({} bytes; sockaddr_un limit ~108): {e}",
            path.as_os_str().len()
        )
    })
}

/// A live agent already answers on the socket path.
///
/// Typed so that a caller can tell "someone else serves" from a failure to bind. The agent holds
/// the per-user lock when it binds, so for it this is an error, not a reason to exit quietly.
#[derive(Debug, thiserror::Error)]
#[error("an agent is already listening on {}", .0.display())]
pub struct AlreadyListening(pub PathBuf);

/// AF_UNIX stream listener. On Windows, `bind` is **fail-closed** twice: it refuses unless the
/// socket directory's DACL verifies as locked down (it decides who can create or replace the
/// socket), and it removes the socket again unless the socket **file's** own DACL verifies (it
/// decides who can connect: Windows AF_UNIX has no `SO_PEERCRED`, and traverse checks on the
/// folders above are bypassed by `SeChangeNotifyPrivilege`). Both must also carry the High mandatory
/// label when the socket is bound for `Integrity::High` (see `acl::ensure_private_dir`).
pub struct Listener {
    sock: Socket,
}

impl Listener {
    pub fn bind(path: &Path, integrity: Integrity) -> anyhow::Result<Self> {
        Self::bind_with(path, integrity, &socket_file_acl_ok)
    }

    /// [`Self::bind`] with the check of the bound socket file as a parameter, so a test can make
    /// it refuse. Production passes the real one.
    fn bind_with(
        path: &Path,
        integrity: Integrity,
        socket_file_ok: &dyn Fn(&Path, Integrity) -> anyhow::Result<bool>,
    ) -> anyhow::Result<Self> {
        // Fail-closed: never bind in a directory that isn't locked down. The grantee is
        // `current_user` because the AGENT (which calls bind) runs as the user whose profile
        // holds the directory. If bind ever ran under a different identity, a directory
        // hardened for the real user would simply fail this gate.
        #[cfg(windows)]
        {
            let dir = path
                .parent()
                .ok_or_else(|| anyhow::anyhow!("socket path has no parent directory"))?;
            let me = crate::acl::Sid::current_user()?;
            anyhow::ensure!(
                crate::acl::verify_dir_acl(dir, &me, integrity)?,
                "socket directory {} is not locked down; refusing to bind (fail-closed)",
                dir.display()
            );
        }
        // Reclaim a leftover socket file from a PRIOR run — but never blind-unlink: a live
        // agent might hold it. Probe-connect to classify, and refuse if live. (A concurrent
        // double-launch is closed by the per-user lock the agent holds before it binds; the probe
        // only handles a stale file left by a dead predecessor.)
        if path.exists() {
            if connect(path).is_ok() {
                return Err(AlreadyListening(path.to_path_buf()).into());
            }
            // No listener answered. Only reclaim if the entry is actually a socket, and
            // surface a removal failure rather than letting bind fail cryptically.
            #[cfg(unix)]
            {
                use std::os::unix::fs::FileTypeExt;
                let is_sock = std::fs::symlink_metadata(path)
                    .map(|m| m.file_type().is_socket())
                    .unwrap_or(false);
                anyhow::ensure!(
                    is_sock,
                    "{} exists and is not a socket; refusing to remove it",
                    path.display()
                );
            }
            std::fs::remove_file(path)
                .map_err(|e| anyhow::anyhow!("failed to reclaim stale socket {}: {e}", path.display()))?;
        }
        let sock = Socket::new(Domain::UNIX, Type::STREAM, None)?;
        // Non-blocking, so that `accept` is the waiting loop and not a blocking call that can miss its wake.
        sock.set_nonblocking(true)?;
        sock.bind(&unix_addr(path)?)?;
        // The file exists now but nothing listens, so nobody can queue a connection: prove who
        // may connect before anyone can. A socket whose ACL cannot be proven is not left behind.
        let proven = socket_file_ok(path, integrity);
        if !matches!(proven, Ok(true)) {
            drop(sock);
            let _ = std::fs::remove_file(path);
            return match proven {
                Ok(_) => Err(anyhow::anyhow!(
                    "the socket file {}; refusing to listen (fail-closed)",
                    crate::socket_loc::file_acl_refusal(path, &grantee()?, integrity)
                )),
                Err(e) => Err(e.context(format!("check the socket file {}", path.display()))),
            };
        }
        sock.listen(128)?;
        // Don't leak the listening socket into spawned children (would defeat the ACL).
        #[cfg(windows)]
        set_no_inherit(&sock)?;
        Ok(Listener { sock })
    }

    /// Accept one connection, waiting for it with no limit (in slices, see [`RECHECK_EVERY`]). A
    /// failure says what the caller should do about it: see [`AcceptError`].
    ///
    /// The connection is never inheritable, not even for an instant: the listener is made with
    /// `WSA_FLAG_NO_HANDLE_INHERIT`, which Winsock carries to the sockets `accept` returns, and a
    /// connection that arrives inheritable anyway is refused rather than fixed up afterwards (a
    /// child spawned on another thread in between would inherit it).
    ///
    /// The connection's blocking mode is the OS's to say (some platforms hand on the listener's); it
    /// becomes non-blocking in [`split`] and [`try_split`], which every reader and writer goes through.
    pub fn accept(&self) -> Result<Socket, AcceptError> {
        finish_accept(accept_waiting(&self.sock), harden_accepted)
    }
}

/// Accept on the non-blocking `listener`, waiting for a connection in slices of [`RECHECK_EVERY`], with no cap.
fn accept_waiting(listener: &Socket) -> std::io::Result<Socket> {
    loop {
        match accept_from(listener) {
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => wait(listener, IoKind::Read, RECHECK_EVERY)?,
            accepted => return accepted,
        }
    }
}

/// Why `accept` failed, by what the serving loop should do next.
#[derive(Debug)]
pub enum AcceptError {
    /// This one connection is lost: the peer dropped it while it queued. The listener is fine, and
    /// each such failure consumed a connection, so a run of them is bounded by the peers' own
    /// behaviour.
    Connection(anyhow::Error),
    /// A connection arrived but must not be handed out (it is inheritable by child processes). The
    /// peer is waiting, so the caller answers it on `socket` and does not hand it to a shell.
    Refused { socket: Socket, cause: anyhow::Error },
    /// `WSAEINTR`: the call was interrupted. Nothing was consumed; call `accept` again.
    Interrupted(std::io::Error),
    /// `WSAEMFILE` or `WSAENOBUFS`: no descriptor or buffer is left. It clears only when something
    /// lets go of one, so the caller waits for one of its own connections to end and then tries
    /// again; with none, nothing can free a resource and the listener is as good as broken.
    Exhausted { code: i32, source: std::io::Error },
    /// The listener is broken, or the failure is one `accept` is not documented to have.
    Fatal(anyhow::Error),
}

impl std::fmt::Display for AcceptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AcceptError::Connection(e) | AcceptError::Fatal(e) | AcceptError::Refused { cause: e, .. } => {
                write!(f, "{e:#}")
            }
            AcceptError::Interrupted(source) | AcceptError::Exhausted { source, .. } => write!(f, "{source}"),
        }
    }
}

impl std::error::Error for AcceptError {}

/// The OS `accept`, with nothing done to the socket afterwards on Windows (see [`Listener::accept`]).
#[cfg(windows)]
fn accept_from(listener: &Socket) -> std::io::Result<Socket> {
    listener.accept_raw().map(|(sock, _)| sock)
}

/// Off Windows `accept` also sets close-on-exec, which is the platform's way of the same thing.
#[cfg(not(windows))]
fn accept_from(listener: &Socket) -> std::io::Result<Socket> {
    listener.accept().map(|(sock, _)| sock)
}

/// Turn the outcome of the OS `accept` into a connection ready to hand out. A connection that
/// fails `harden` is never handed out: it would reach children of the brokered shell. It comes back
/// as [`AcceptError::Refused`], for the caller to answer.
fn finish_accept(
    raw: std::io::Result<Socket>,
    harden: impl FnOnce(&Socket) -> anyhow::Result<()>,
) -> Result<Socket, AcceptError> {
    match raw {
        Ok(sock) => match harden(&sock) {
            Ok(()) => Ok(sock),
            Err(e) => Err(AcceptError::Refused {
                socket: sock,
                cause: e.context("an accepted connection is not safe to hand out"),
            }),
        },
        Err(e) => Err(classify_accept_error(e)),
    }
}

/// Sort an `accept` failure by Winsock's documented causes. A peer that reset or aborted a queued
/// connection is that connection's loss; `WSAEINTR` is an interruption; `WSAEMFILE` and
/// `WSAENOBUFS` are exhaustion; everything else (not listening, not a socket, the network down) is
/// a broken listener. That includes `WSAEWOULDBLOCK` and `WSAEINPROGRESS`: the first is the
/// non-blocking listener's "nothing yet", which [`accept_waiting`] waits out and never hands on, and
/// the second needs a Winsock 1.1 blocking call in progress, which nothing here installs; so neither
/// can reach this function.
fn classify_accept_error(e: std::io::Error) -> AcceptError {
    use std::io::ErrorKind;
    match e.kind() {
        ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted => return AcceptError::Connection(e.into()),
        ErrorKind::Interrupted => return AcceptError::Interrupted(e),
        _ => {}
    }
    by_winsock_code(e)
}

/// The Winsock codes `std` has no `ErrorKind` for, by what they mean for `accept`.
#[cfg(windows)]
fn by_winsock_code(e: std::io::Error) -> AcceptError {
    use windows::Win32::Networking::WinSock::{WSAEINPROGRESS, WSAEINTR, WSAEMFILE, WSAENOBUFS, WSAEWOULDBLOCK};
    match e.raw_os_error() {
        Some(code) if code == WSAEINTR.0 => AcceptError::Interrupted(e),
        Some(code) if code == WSAEMFILE.0 || code == WSAENOBUFS.0 => AcceptError::Exhausted { code, source: e },
        Some(code) if code == WSAEWOULDBLOCK.0 || code == WSAEINPROGRESS.0 => {
            AcceptError::Fatal(anyhow::Error::new(e).context(format!(
                "accept returned code {code}, which the waiting accept loop and a process with no Winsock 1.1 blocking hook cannot return"
            )))
        }
        _ => AcceptError::Fatal(e.into()),
    }
}

#[cfg(not(windows))]
fn by_winsock_code(e: std::io::Error) -> AcceptError {
    AcceptError::Fatal(e.into())
}

/// Refuse a freshly accepted connection that a child could inherit.
fn harden_accepted(sock: &Socket) -> anyhow::Result<()> {
    #[cfg(windows)]
    anyhow::ensure!(
        !is_inheritable(sock)?,
        "the connection is inheritable by child processes"
    );
    #[cfg(not(windows))]
    let _ = sock;
    Ok(())
}

/// Whether a child process could inherit `sock`.
#[cfg(windows)]
fn is_inheritable(sock: &Socket) -> anyhow::Result<bool> {
    use std::os::windows::io::AsRawSocket;
    use windows::Win32::Foundation::{GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT};
    let handle = HANDLE(sock.as_raw_socket() as usize as *mut core::ffi::c_void);
    let mut flags = 0u32;
    // SAFETY: `handle` is the open socket of `sock`; `flags` is a valid out pointer.
    unsafe { GetHandleInformation(handle, &mut flags) }?;
    Ok(flags & HANDLE_FLAG_INHERIT.0 != 0)
}

/// Does the socket file at `path` grant exactly the current user, SYSTEM and Administrators, and for
/// `Integrity::High` carry the High label?
#[cfg(windows)]
fn socket_file_acl_ok(path: &Path, integrity: Integrity) -> anyhow::Result<bool> {
    crate::acl::verify_file_acl(path, &crate::acl::Sid::current_user()?, integrity)
}

/// Who the socket file must grant, as the refusal names them: the account this process runs as.
#[cfg(windows)]
fn grantee() -> anyhow::Result<String> {
    Ok(crate::acl::Sid::current_user()?.describe())
}

#[cfg(not(windows))]
fn grantee() -> anyhow::Result<String> {
    Ok("the user".to_owned())
}

/// Off Windows there is no ACL to check; the directory's mode is the platform's concern.
#[cfg(not(windows))]
fn socket_file_acl_ok(_path: &Path, _integrity: Integrity) -> anyhow::Result<bool> {
    Ok(true)
}

/// Connect to an AF_UNIX stream socket at `path`. A bare path names whatever is there when the call runs;
/// prefer `userdir::SocketDir::connect`.
pub(crate) fn connect(path: &Path) -> anyhow::Result<Socket> {
    let sock = Socket::new(Domain::UNIX, Type::STREAM, None)?;
    sock.connect(&unix_addr(path)?)?;
    #[cfg(windows)]
    set_no_inherit(&sock)?;
    Ok(sock)
}

/// Clear the `HANDLE_FLAG_INHERIT` bit on a socket so it is never duplicated into a
/// spawned child — otherwise a child (the brokered shell) would inherit the listening
/// socket or another session's connection, defeating the ACL boundary.
#[cfg(windows)]
fn set_no_inherit(sock: &Socket) -> anyhow::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows::Win32::Foundation::{HANDLE, HANDLE_FLAG_INHERIT, HANDLE_FLAGS, SetHandleInformation};
    let handle = HANDLE(sock.as_raw_socket() as usize as *mut core::ffi::c_void);
    unsafe {
        SetHandleInformation(handle, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0))?;
    }
    Ok(())
}

/// Read half of a split connection (mirrors the relay test transport's read half).
pub struct ConnRx {
    sock: Socket,
    limit: Cell<Option<Duration>>,
}
/// Write half of a split connection.
pub struct ConnTx(Socket);

/// Split a connected socket into independent read/write halves, each owning a dup'd OS
/// handle, so one thread can `pump_decode` while another writes frames — mirroring the
/// relay's two-pump model.
///
/// Both halves are non-blocking, and that is one mode for the connection: the mode belongs to the
/// socket and not to the handle (measured on Windows), so a handle of it that sets the mode back
/// (a `try_clone_socket` copy) undoes it for the halves.
pub fn split(sock: Socket) -> anyhow::Result<(ConnRx, ConnTx)> {
    try_split(sock).map_err(|(_, e)| e)
}

/// A connection that [`try_split`] could not split: both directions on the one socket, for a party
/// that has to answer it all the same.
pub struct Whole {
    sock: Socket,
    limit: Cell<Option<Duration>>,
}

impl Whole {
    pub fn of(sock: Socket) -> Whole {
        Whole {
            sock,
            limit: Cell::new(None),
        }
    }

    /// See [`ConnRx::set_read_timeout`].
    pub fn set_read_timeout(&self, limit: Option<Duration>) -> std::io::Result<()> {
        self.limit.set(limit);
        Ok(())
    }

    /// Send FIN on the write direction.
    pub fn shutdown_write(&self) -> anyhow::Result<()> {
        self.sock.shutdown(std::net::Shutdown::Write)?;
        Ok(())
    }
}

impl Read for &Whole {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        read_waiting(&self.sock, buf, self.limit.get())
    }
}

impl Write for &Whole {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        write_waiting(&self.sock, buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        (&self.sock).flush()
    }
}

/// [`split`] that gives the connection back, with the reason, when it cannot be split.
///
/// The socket is made non-blocking first, so the connection given back is non-blocking unless that
/// was the failure.
pub fn try_split(sock: Socket) -> Result<(ConnRx, ConnTx), (Whole, anyhow::Error)> {
    if let Err(e) = sock.set_nonblocking(true) {
        return Err((Whole::of(sock), e.into()));
    }
    let write_half = match sock.try_clone() {
        Ok(write_half) => write_half,
        Err(e) => return Err((Whole::of(sock), e.into())),
    };
    // Said on both halves, though it is one mode for the socket (see `split`), so that nothing here
    // rests on that.
    if let Err(e) = write_half.set_nonblocking(true) {
        return Err((Whole::of(sock), e.into()));
    }
    // Clear inherit on BOTH halves: callers should hand in an already-cleared socket
    // (from accept/connect), but split is `pub` and must not depend on that.
    #[cfg(windows)]
    if let Err(e) = set_no_inherit(&sock).and_then(|()| set_no_inherit(&write_half)) {
        return Err((Whole::of(sock), e));
    }
    Ok((
        ConnRx {
            sock,
            limit: Cell::new(None),
        },
        ConnTx(write_half),
    ))
}

impl ConnRx {
    /// Make a `read` that finds nothing fail with `TimedOut` once `limit` has passed since the read
    /// began (`None`: wait as long as it takes). The limit is a bound on a client that may never
    /// send or close, never proof that nothing is coming. A read that passes the limit has
    /// looked at the socket once more first, so what has arrived is read and not reported as a
    /// time out.
    pub fn set_read_timeout(&self, limit: Option<Duration>) -> std::io::Result<()> {
        self.limit.set(limit);
        Ok(())
    }
}

/// The longest one wait for a socket lasts before the call it waits for is made again.
///
/// It is the latency of a wake the OS lost (a blocking call on a Windows AF_UNIX socket can miss
/// one), never a bound and never proof of anything: a wait that ends by this slice proves nothing,
/// and the loop has no cap. 100 ms is below what a person notices when a prompt ends, and costs
/// about ten wakeups a second per idle waiting thread.
pub(crate) const RECHECK_EVERY: Duration = Duration::from_millis(100);

/// What a [`wait`] waits for the socket to be ready to do.
#[derive(Clone, Copy)]
enum IoKind {
    Read,
    Write,
}

/// Read from the non-blocking `sock`, waiting for something to read for up to `limit` (`None`: no
/// limit). The wait is a sleep that may end early and is never read: each time it ends, `recv` is
/// called again, which is what finds data, the close, or a shutdown that the wait did not wake for.
/// A limit that has passed is `TimedOut`, after one more `recv`. Every other result is `recv`'s.
fn read_waiting(sock: &Socket, buf: &mut [u8], limit: Option<Duration>) -> std::io::Result<usize> {
    // A limit too long to be a point in time is no limit.
    let deadline = limit.and_then(|limit| Instant::now().checked_add(limit));
    loop {
        let mut reader = sock;
        match reader.read(buf) {
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            result => return result,
        }
        let slice = match deadline {
            None => RECHECK_EVERY,
            Some(deadline) => {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(std::io::ErrorKind::TimedOut.into());
                }
                left.min(RECHECK_EVERY)
            }
        };
        wait(sock, IoKind::Read, slice)?;
    }
}

/// Write to the non-blocking `sock`, waiting for room with no limit, as [`read_waiting`] waits.
/// Every result but `WouldBlock` is `send`'s, so a write may be partial.
fn write_waiting(sock: &Socket, buf: &[u8]) -> std::io::Result<usize> {
    loop {
        let mut writer = sock;
        match writer.write(buf) {
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            result => return result,
        }
        wait(sock, IoKind::Write, RECHECK_EVERY)?;
    }
}

/// Sleep until `sock` may be ready for `kind`, or `timeout` has passed, whichever is first. What
/// the OS says is not looked at: the caller calls again. An error is the poll's own failing.
#[cfg(windows)]
fn wait(sock: &Socket, kind: IoKind, timeout: Duration) -> std::io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows::Win32::Networking::WinSock::{
        POLLRDNORM, POLLWRNORM, SOCKET, WSAGetLastError, WSAPOLL_EVENT_FLAGS, WSAPOLLFD, WSAPoll,
    };
    let events = match kind {
        IoKind::Read => POLLRDNORM,
        IoKind::Write => POLLWRNORM,
    };
    let mut fds = [WSAPOLLFD {
        fd: SOCKET(sock.as_raw_socket() as usize),
        events,
        revents: WSAPOLL_EVENT_FLAGS(0),
    }];
    let millis = i32::try_from(whole_milliseconds_up(timeout).as_millis()).unwrap_or(i32::MAX);
    // SAFETY: `fds` is a live array of one entry; the socket outlives the call.
    let rc = unsafe { WSAPoll(fds.as_mut_ptr(), 1, millis) };
    if rc < 0 {
        let e = std::io::Error::from_raw_os_error(unsafe { WSAGetLastError() }.0);
        // An interruption ended the sleep early, which any end does.
        return if e.kind() == std::io::ErrorKind::Interrupted {
            Ok(())
        } else {
            Err(e)
        };
    }
    Ok(())
}

#[cfg(unix)]
fn wait(sock: &Socket, kind: IoKind, timeout: Duration) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let mut fds = [libc::pollfd {
        fd: sock.as_raw_fd(),
        events: match kind {
            IoKind::Read => libc::POLLIN,
            IoKind::Write => libc::POLLOUT,
        },
        revents: 0,
    }];
    let millis = libc::c_int::try_from(whole_milliseconds_up(timeout).as_millis()).unwrap_or(libc::c_int::MAX);
    // SAFETY: `fds` is a live array of one entry; the descriptor is open for the call.
    let rc = unsafe { libc::poll(fds.as_mut_ptr(), 1, millis) };
    if rc < 0 {
        let e = std::io::Error::last_os_error();
        // A signal ended the sleep early, which any end does.
        return if e.kind() == std::io::ErrorKind::Interrupted {
            Ok(())
        } else {
            Err(e)
        };
    }
    Ok(())
}

/// `limit` rounded up to whole milliseconds, at least one: a poll takes whole milliseconds, and 0
/// would return at once.
fn whole_milliseconds_up(limit: Duration) -> Duration {
    let millis = limit.as_nanos().div_ceil(1_000_000).max(1);
    Duration::from_millis(u64::try_from(millis).unwrap_or(u64::MAX))
}

impl ConnTx {
    /// A new handle on the same underlying socket, for a thread that must watch the connection
    /// without owning one of the split halves.
    pub fn try_clone_socket(&self) -> std::io::Result<Socket> {
        self.0.try_clone()
    }

    /// Send FIN on the write half. A `try_clone` dup does NOT FIN on drop, so without an
    /// explicit shutdown the peer would block forever and never observe `PeerClosed`.
    pub fn shutdown_write(&self) -> anyhow::Result<()> {
        self.0.shutdown(std::net::Shutdown::Write)?;
        Ok(())
    }

    /// Shut down both directions of the connection: FIN the write side AND end a read of the OTHER
    /// split half. A read that is waiting on the other half does not wake for this (measured on
    /// Windows: a poll on a duplicate does not), but its next re-check, at most [`RECHECK_EVERY`] later,
    /// calls `recv` again, and `recv` on the shared socket reports the end. `split` uses
    /// `try_clone` (WSADuplicateSocketW on Windows / `dup` on Unix): both halves are descriptors
    /// over one underlying socket.
    ///
    /// Not for a peer that may still be sending: closing with its input unread resets the
    /// connection and can lose the final frame. Use [`Self::shutdown_write`] and read until the
    /// peer is gone.
    pub fn shutdown_both(&self) -> anyhow::Result<()> {
        self.0.shutdown(std::net::Shutdown::Both)?;
        Ok(())
    }
}

impl Read for ConnRx {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        read_waiting(&self.sock, buf, self.limit.get())
    }
}

impl Write for ConnTx {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        write_waiting(&self.0, buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

/// Test-only accessor: is the listening socket's `HANDLE_FLAG_INHERIT` bit cleared?
#[cfg(all(windows, test))]
impl Listener {
    pub(crate) fn inherit_flag_is_clear(&self) -> bool {
        matches!(is_inheritable(&self.sock), Ok(false))
    }
}

#[cfg(test)]
#[path = "afunix_tests.rs"]
mod afunix_tests;
