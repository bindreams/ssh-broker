//! Helpers shared by the unit tests on every host: the elevation policies a login can ask for, a closed standard
//! stream, and the stand-in for the sshd step's task. The Windows-only helpers are in the `windows` submodule, re-exported here.

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

/// A standard stream that has been closed, as by a dropped SSH connection: every write and flush fails.
pub struct ClosedStream;

impl std::io::Write for ClosedStream {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::BrokenPipe.into())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::ErrorKind::BrokenPipe.into())
    }
}

/// What the stand-in task and the tests around it record, in order.
pub type TaskLog = std::rc::Rc<std::cell::RefCell<Vec<String>>>;

/// A stand-in for the Task Scheduler behind the sshd step: every call is pushed to `log` as `task: <call>`, and
/// each answer is what the test sets.
pub struct FakeSshdTask {
    pub log: TaskLog,
    pub register: Result<(), &'static str>,
    pub run: Result<(), &'static str>,
    pub wait: Result<crate::provision::schtasks::WaitOutcome, &'static str>,
    pub report: Result<String, &'static str>,
    pub remove: Result<(), &'static str>,
}

impl FakeSshdTask {
    /// A task that works and whose step reported one note and closed its report.
    pub fn new(log: &TaskLog) -> FakeSshdTask {
        FakeSshdTask {
            log: std::rc::Rc::clone(log),
            register: Ok(()),
            run: Ok(()),
            wait: Ok(crate::provision::schtasks::WaitOutcome::Ended),
            report: Ok(format!(
                "sshd restarted; it accepts SSH_BROKER_ELEVATION\r\n{}\r\n",
                crate::provision::sshd_task::REPORT_END
            )),
            remove: Ok(()),
        }
    }

    fn call<T: Clone>(&self, name: &str, answer: &Result<T, &'static str>) -> anyhow::Result<T> {
        self.log.borrow_mut().push(format!("task: {name}"));
        answer.clone().map_err(|cause| anyhow::anyhow!("{cause}"))
    }
}

impl crate::provision::sshd_task::SshdTask for FakeSshdTask {
    fn register(&mut self) -> anyhow::Result<()> {
        self.call("register", &self.register)
    }
    fn run(&mut self) -> anyhow::Result<()> {
        self.call("run", &self.run)
    }
    fn wait(&mut self) -> anyhow::Result<crate::provision::schtasks::WaitOutcome> {
        self.call("wait", &self.wait)
    }
    fn report(&mut self) -> anyhow::Result<String> {
        self.call("report", &self.report)
    }
    fn remove(&mut self) -> anyhow::Result<()> {
        self.call("remove", &self.remove)
    }
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
