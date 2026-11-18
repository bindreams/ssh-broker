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

/// Input that a test hands a command's forwarder: it ends at EOF, counts its reads, and says when it is
/// dropped, which the forwarder does as it returns and a forwarder that was never started does when it is itself
/// dropped. Once the drop is said, the count is final.
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
