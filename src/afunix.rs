//! afunix: AF_UNIX stream listener/connector via socket2 (Windows-supported).
//!
//! The socket path is kept short and is shared by both the agent (bind) and the shim
//! (connect). The `sockaddr_un` path limit (~108 bytes) is surfaced loudly rather than
//! failing cryptically deep in the OS.

use socket2::{Domain, SockAddr, Socket, Type};
use std::io::{Read, Write};
use std::path::Path;

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

/// The fixed production socket directory — the hardened, ACL-locked dir the agent binds
/// inside and the shim connects into. Kept deliberately short to stay within the
/// `sockaddr_un` path limit, and under `ProgramData` (a system path, not user-specific).
#[cfg(windows)]
pub fn socket_dir() -> std::path::PathBuf {
    std::path::Path::new(r"C:\ProgramData\ssh-broker\s").to_path_buf()
}

/// The fixed production socket path, shared by the agent (bind) and the shim (connect)
/// so they always agree. Lives directly under [`socket_dir`].
#[cfg(windows)]
pub fn socket_path() -> std::path::PathBuf {
    socket_dir().join("a.sock")
}

/// AF_UNIX stream listener. On Windows, `bind` is **fail-closed**: it refuses unless the
/// socket directory's DACL verifies as locked down — Windows AF_UNIX has no
/// `SO_PEERCRED`, so that NTFS ACL is the entire access-control boundary.
pub struct Listener {
    sock: Socket,
}

impl Listener {
    pub fn bind(path: &Path) -> anyhow::Result<Self> {
        // Fail-closed: never bind in a directory that isn't locked down. The grantee is
        // `current_user` because the AGENT (which calls bind) runs as the auto-login
        // account the boundary protects — so current_user IS the target. (The by-name
        // resolution the acl docstring describes is the `apply`/provisioning path, which
        // may run as SYSTEM; that is Phase 7. If bind ever ran under a different identity,
        // a dir hardened for the real user would simply fail this gate — fail-closed.)
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
        // agent might hold it. Probe-connect to classify, and refuse if live. (Concurrent
        // double-launch is closed by the agent's single-instance mutex, acquired before
        // bind — Phase 4; the probe only handles a stale file left by a dead predecessor.)
        if path.exists() {
            if connect(path).is_ok() {
                anyhow::bail!("an agent is already listening on {}; refusing to bind", path.display());
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
        sock.listen(128)?;
        // Don't leak the listening socket into spawned children (would defeat the ACL).
        #[cfg(windows)]
        set_no_inherit(&sock)?;
        Ok(Listener { sock })
    }

    pub fn accept(&self) -> anyhow::Result<Socket> {
        let sock = self.sock.accept()?.0;
        #[cfg(windows)]
        set_no_inherit(&sock)?;
        Ok(sock)
    }
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
    let write_half = sock.try_clone()?;
    // Clear inherit on BOTH halves: callers should hand in an already-cleared socket
    // (from accept/connect), but split is `pub` and must not depend on that.
    #[cfg(windows)]
    {
        set_no_inherit(&sock)?;
        set_no_inherit(&write_half)?;
    }
    Ok((ConnRx(sock), ConnTx(write_half)))
}

impl ConnTx {
    /// Send FIN on the write half. A `try_clone` dup does NOT FIN on drop, so without an
    /// explicit shutdown the peer would block forever and never observe `PeerClosed`.
    pub fn shutdown_write(&self) -> anyhow::Result<()> {
        self.0.shutdown(std::net::Shutdown::Write)?;
        Ok(())
    }

    /// Shut down both directions of the connection. Used at teardown to FIN the write side
    /// (delivering a final EXIT frame) AND unblock a sibling thread blocked reading the
    /// OTHER split half. That cross-half unblock works because `split` uses `try_clone`
    /// (WSADuplicateSocketW on Windows / `dup` on Unix): both halves are descriptors over
    /// one underlying socket, so a shutdown here tears down that shared socket's read side.
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
        use std::os::windows::io::AsRawSocket;
        use windows::Win32::Foundation::{GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT};
        let handle = HANDLE(self.sock.as_raw_socket() as usize as *mut core::ffi::c_void);
        let mut flags = 0u32;
        unsafe {
            if GetHandleInformation(handle, &mut flags).is_err() {
                return false;
            }
        }
        flags & HANDLE_FLAG_INHERIT.0 == 0
    }
}

#[cfg(test)]
#[path = "afunix_tests.rs"]
mod afunix_tests;
