//! Helpers shared by the unit tests on every host: the elevation policies a login can ask for. The
//! Windows-only helpers are in the `windows` submodule, re-exported here.

use crate::protocol::ElevationPolicy;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::*;

pub const POLICIES: [ElevationPolicy; 4] = [
    ElevationPolicy::Never,
    ElevationPolicy::Prompt,
    ElevationPolicy::AutoApprove,
    ElevationPolicy::Always,
];

/// Every answer a login can give: each of the four policies, and none.
pub fn asked_policies() -> impl Iterator<Item = Option<ElevationPolicy>> {
    POLICIES.map(Some).into_iter().chain([None])
}

/// Read `stream`, an AF_UNIX connection, until its peer has closed, and return the bytes. Reads in slices
/// (`set_read_timeout` is the stream's own, e.g. `ConnRx::set_read_timeout`) and reads again when a slice times
/// out: each read re-checks the real condition, and a timed-out slice proves nothing. A blocking read that is
/// already waiting when the peer closes sometimes never wakes on Windows (measured: the next read after a
/// timeout returns end-of-stream at once), so a plain `read_to_end` can hang.
///
/// It leaves the socket blocking (no read timeout) when it returns the bytes, and with the slice's timeout
/// set when it returns an error. It relies on a timed-out read losing no bytes: measured for AF_UNIX (see
/// `afunix::ConnRx::set_read_timeout`), not promised by Winsock.
pub fn read_until_the_peer_closes<S: std::io::Read>(
    stream: &mut S,
    set_read_timeout: impl Fn(&S, Option<std::time::Duration>) -> std::io::Result<()>,
) -> std::io::Result<Vec<u8>> {
    use std::io::ErrorKind::{Interrupted, TimedOut, WouldBlock};
    set_read_timeout(stream, Some(std::time::Duration::from_millis(100)))?;
    let (mut bytes, mut chunk) = (Vec::new(), [0u8; 4096]);
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => bytes.extend_from_slice(&chunk[..n]),
            Err(e) if matches!(e.kind(), Interrupted | TimedOut | WouldBlock) => {}
            Err(e) => return Err(e),
        }
    }
    set_read_timeout(stream, None)?;
    Ok(bytes)
}

/// Input for a command's forwarder: ends at EOF, counts reads, and signals when dropped (the count is final then).
pub struct RecordedInput {
    data: std::io::Cursor<Vec<u8>>,
    dropped: std::sync::mpsc::Sender<()>,
    reads: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl RecordedInput {
    /// The input, the receiver that gets one message when it is dropped, and its read count.
    pub fn new(
        data: &[u8],
    ) -> (
        RecordedInput,
        std::sync::mpsc::Receiver<()>,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) {
        let (dropped, was_dropped) = std::sync::mpsc::channel();
        let reads = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let input = RecordedInput {
            data: std::io::Cursor::new(data.to_vec()),
            dropped,
            reads: std::sync::Arc::clone(&reads),
        };
        (input, was_dropped, reads)
    }
}

impl std::io::Read for RecordedInput {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        std::io::Read::read(&mut self.data, buf)
    }
}

impl Drop for RecordedInput {
    fn drop(&mut self) {
        let _ = self.dropped.send(());
    }
}
