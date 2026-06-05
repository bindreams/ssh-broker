//! afunix: AF_UNIX stream listener/connector via socket2 (Windows-supported).
//!
//! The socket path is kept short and is shared by both the agent (bind) and the shim
//! (connect). The `sockaddr_un` path limit (~108 bytes) is surfaced loudly rather than
//! failing cryptically deep in the OS.

use socket2::SockAddr;
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

#[cfg(test)]
#[path = "afunix_tests.rs"]
mod afunix_tests;
