//! afunix: AF_UNIX stream listener/connector via socket2 (Windows-supported).
//!
//! The agent binds and the shim connects at a path both derive from the user's profile (see
//! `socket_loc`). The `sockaddr_un` path limit (~108 bytes) is surfaced loudly rather than
//! failing cryptically deep in the OS.

use socket2::{Domain, SockAddr, Socket, Type};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

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
/// folders above are bypassed by `SeChangeNotifyPrivilege`).
pub struct Listener {
    sock: Socket,
}

impl Listener {
    pub fn bind(path: &Path) -> anyhow::Result<Self> {
        Self::bind_with(path, &socket_file_acl_ok)
    }

    /// [`Self::bind`] with the check of the bound socket file as a parameter, so a test can make
    /// it refuse. Production passes the real one.
    fn bind_with(path: &Path, socket_file_ok: &dyn Fn(&Path) -> anyhow::Result<bool>) -> anyhow::Result<Self> {
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
                crate::acl::verify_dir_acl(dir, &me)?,
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
        sock.bind(&unix_addr(path)?)?;
        // The file exists now but nothing listens, so nobody can queue a connection: prove who
        // may connect before anyone can. A socket whose ACL cannot be proven is not left behind.
        let proven = socket_file_ok(path);
        if !matches!(proven, Ok(true)) {
            drop(sock);
            let _ = std::fs::remove_file(path);
            return match proven {
                Ok(_) => Err(anyhow::anyhow!(
                    "the socket file {} does not grant exactly the user, SYSTEM and Administrators; \
                     refusing to listen (fail-closed)",
                    path.display()
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

    /// Accept one connection. A failure says what the caller should do about it: see
    /// [`AcceptError`].
    ///
    /// The connection is never inheritable, not even for an instant: the listener is made with
    /// `WSA_FLAG_NO_HANDLE_INHERIT`, which Winsock carries to the sockets `accept` returns, and a
    /// connection that arrives inheritable anyway is refused rather than fixed up afterwards (a
    /// child spawned on another thread in between would inherit it).
    pub fn accept(&self) -> Result<Socket, AcceptError> {
        finish_accept(accept_from(&self.sock), harden_accepted)
    }
}

/// Why `accept` failed, by what the serving loop should do next.
#[derive(Debug)]
pub enum AcceptError {
    /// This one connection is lost (the peer dropped it while it queued, or it could not be set
    /// up). The listener is fine, and each such failure consumed a connection, so a run of them is
    /// bounded by the peers' own behaviour.
    Connection(anyhow::Error),
    /// `WSAEINTR`: the call was interrupted. Nothing was consumed; call `accept` again.
    Interrupted(std::io::Error),
    /// `WSAEMFILE` or `WSAENOBUFS`: no descriptor or buffer is left. It clears only when something
    /// lets go of one, so the caller waits for one of its own connections to end and then tries
    /// again; with none, nothing can free a resource and the listener is as good as broken.
    Exhausted { code: i32, source: std::io::Error },
    /// The listener is broken, or the failure is one a blocking listener is not documented to have.
    Fatal(anyhow::Error),
}

impl std::fmt::Display for AcceptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AcceptError::Connection(e) | AcceptError::Fatal(e) => write!(f, "{e:#}"),
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
/// fails `harden` is never handed out: it would reach children of the brokered shell.
fn finish_accept(
    raw: std::io::Result<Socket>,
    harden: impl FnOnce(&Socket) -> anyhow::Result<()>,
) -> Result<Socket, AcceptError> {
    match raw {
        Ok(sock) => match harden(&sock) {
            Ok(()) => Ok(sock),
            Err(e) => Err(AcceptError::Connection(
                e.context("an accepted connection is not safe to hand out; dropping it"),
            )),
        },
        Err(e) => Err(classify_accept_error(e)),
    }
}

/// Sort an `accept` failure by Winsock's documented causes. A peer that reset or aborted a queued
/// connection is that connection's loss; `WSAEINTR` is an interruption; `WSAEMFILE` and
/// `WSAENOBUFS` are exhaustion; everything else (not listening, not a socket, the network down) is
/// a broken listener. That includes `WSAEWOULDBLOCK` and `WSAEINPROGRESS`: the first needs a
/// non-blocking socket and the second a Winsock 1.1 blocking call in progress, and this listener
/// is blocking and installs no blocking hook, so they cannot occur.
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
                "accept returned code {code}, which a blocking listener with no Winsock 1.1 blocking hook cannot return"
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

/// Does the socket file at `path` grant exactly the current user, SYSTEM and Administrators?
#[cfg(windows)]
fn socket_file_acl_ok(path: &Path) -> anyhow::Result<bool> {
    crate::acl::verify_file_acl(path, &crate::acl::Sid::current_user()?)
}

/// Off Windows there is no ACL to check; the directory's mode is the platform's concern.
#[cfg(not(windows))]
fn socket_file_acl_ok(_path: &Path) -> anyhow::Result<bool> {
    Ok(true)
}

/// Connect to an AF_UNIX stream socket at `path`.
pub fn connect(path: &Path) -> anyhow::Result<Socket> {
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
pub struct ConnRx(Socket);
/// Write half of a split connection.
pub struct ConnTx(Socket);

/// Split a connected socket into independent read/write halves, each owning a dup'd OS
/// handle, so one thread can `pump_decode` while another writes frames — mirroring the
/// relay's two-pump model.
pub fn split(sock: Socket) -> anyhow::Result<(ConnRx, ConnTx)> {
    try_split(sock).map_err(|(_, e)| e)
}

/// A connection that [`try_split`] could not split: both directions on the one socket, for a party
/// that has to answer it all the same.
pub struct Whole(Socket);

impl Whole {
    pub fn of(sock: Socket) -> Whole {
        Whole(sock)
    }

    /// See [`ConnRx::set_read_timeout`].
    pub fn set_read_timeout(&self, limit: Option<std::time::Duration>) -> std::io::Result<()> {
        self.0.set_read_timeout(limit.map(whole_milliseconds_up))
    }

    /// Send FIN on the write direction.
    pub fn shutdown_write(&self) -> anyhow::Result<()> {
        self.0.shutdown(std::net::Shutdown::Write)?;
        Ok(())
    }
}

impl Read for &Whole {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        (&self.0).read(buf)
    }
}

impl Write for &Whole {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        (&self.0).write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        (&self.0).flush()
    }
}

/// [`split`] that gives the connection back, with the reason, when it cannot be split.
pub fn try_split(sock: Socket) -> Result<(ConnRx, ConnTx), (Whole, anyhow::Error)> {
    let write_half = match sock.try_clone() {
        Ok(write_half) => write_half,
        Err(e) => return Err((Whole(sock), e.into())),
    };
    // Clear inherit on BOTH halves: callers should hand in an already-cleared socket
    // (from accept/connect), but split is `pub` and must not depend on that.
    #[cfg(windows)]
    if let Err(e) = set_no_inherit(&sock).and_then(|()| set_no_inherit(&write_half)) {
        return Err((Whole(sock), e));
    }
    Ok((ConnRx(sock), ConnTx(write_half)))
}

impl ConnRx {
    /// Make a `read` that finds nothing fail with `TimedOut` or `WouldBlock` once `limit` has
    /// passed (`None`: block as long as it takes).
    ///
    /// `limit` is rounded up to whole milliseconds, and to at least one: the OS takes whole
    /// milliseconds, and a limit that reached it as 0 would mean no limit at all. Measured on
    /// AF_UNIX: after a timeout, a read still delivers what arrives and still reports the close.
    pub fn set_read_timeout(&self, limit: Option<std::time::Duration>) -> std::io::Result<()> {
        self.0.set_read_timeout(limit.map(whole_milliseconds_up))
    }
}

/// `limit` rounded up to whole milliseconds, at least one.
fn whole_milliseconds_up(limit: std::time::Duration) -> std::time::Duration {
    let millis = limit.as_nanos().div_ceil(1_000_000).max(1);
    std::time::Duration::from_millis(u64::try_from(millis).unwrap_or(u64::MAX))
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

    /// Shut down both directions of the connection: FIN the write side AND unblock a sibling
    /// thread blocked reading the OTHER split half. That cross-half unblock works because
    /// `split` uses `try_clone` (WSADuplicateSocketW on Windows / `dup` on Unix): both halves
    /// are descriptors over one underlying socket, so a shutdown here tears down that shared
    /// socket's read side.
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
        self.0.read(buf)
    }
}

impl Write for ConnTx {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
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
