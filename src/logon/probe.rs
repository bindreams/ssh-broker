//! The probe: what a breakaway from the caller's jobs gets a new process, found out before the logon.
//!
//! The logon child cannot be asked. It is in some job of the Secondary Logon service's whatever
//! happens (CI round 9: a child that outlived its caller's jobs was still `InJob`), and the flags of
//! the call say what was asked, not what Windows did (CI round 8: an outer job kept a child the
//! innermost one let go). So the shim starts a process of its own, with the flags the logon would use,
//! and reads where it landed. The probe is suspended for its whole life and never runs a line of code.

use std::mem::size_of;

use windows::Win32::Foundation::WAIT_OBJECT_0;
use windows::Win32::System::Threading::{
    CREATE_BREAKAWAY_FROM_JOB, CREATE_NO_WINDOW, CREATE_SUSPENDED, CreateProcessW, INFINITE, PROCESS_INFORMATION,
    STARTUPINFOW, TerminateProcess, WaitForSingleObject,
};
use windows::core::PCWSTR;

use super::{CallerJob, ChildJob, ERROR_ACCESS_DENIED, LogonFailure};
use crate::winutil::OwnedHandle;

/// What the probe found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Probe {
    /// The caller is in no job: nothing it owns closes on the connection, and no probe was started.
    CallerInNoJob,
    /// The innermost job forbids breakaway (`ERROR_ACCESS_DENIED`), so the logon child stays in it.
    Refused,
    /// The probe was started with breakaway and sits where this says.
    Started(ChildJob),
    /// No answer: the caller's job could not be read, or the probe could not be started or examined.
    Failed,
}

/// The probe for a caller in `job`. `start` makes it and is not called where the caller's own jobs
/// make it unnecessary or impossible. A caller in a job is probed whatever the job's flags say: the
/// flags of the innermost job are not the whole chain.
pub fn probe_for(job: &CallerJob, start: impl FnOnce() -> Probe) -> Probe {
    match job {
        CallerJob::NotInJob => Probe::CallerInNoJob,
        CallerJob::Unreadable => Probe::Failed,
        CallerJob::Limits(_) => start(),
    }
}

/// Start a suspended process of this program with `CREATE_BREAKAWAY_FROM_JOB`, read its job
/// membership, end it and wait until it is gone.
pub fn start_probe() -> Probe {
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(e) => {
            tracing::warn!("survival probe: this program's path is unknown: {e}");
            return Probe::Failed;
        }
    };
    let exe_w: Vec<u16> = {
        use std::os::windows::ffi::OsStrExt;
        exe.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
    };
    let startup = STARTUPINFOW {
        cb: size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut info = PROCESS_INFORMATION::default();
    // SAFETY: every pointer is to a local that outlives the call; no command line, so Windows runs
    // the image with its own path, and the process never gets to run because it starts suspended.
    let created = unsafe {
        CreateProcessW(
            PCWSTR(exe_w.as_ptr()),
            None,
            None,
            None,
            false,
            CREATE_SUSPENDED | CREATE_BREAKAWAY_FROM_JOB | CREATE_NO_WINDOW,
            None,
            PCWSTR::null(),
            &startup,
            &mut info,
        )
    };
    if let Err(e) = created {
        return if LogonFailure::from_error(&e).code == ERROR_ACCESS_DENIED {
            tracing::info!("survival probe: the job around this process refuses breakaway");
            Probe::Refused
        } else {
            tracing::warn!("survival probe: could not start: {e}");
            Probe::Failed
        };
    }
    let probe = EndingProcess {
        process: OwnedHandle(info.hProcess),
        _thread: OwnedHandle(info.hThread),
    };
    let membership = ChildJob::of_process(probe.process.0);
    tracing::info!("survival probe: started with breakaway, found {membership:?}");
    Probe::Started(membership)
}

/// A suspended process that is ended and waited for when this drops, on every way out.
struct EndingProcess {
    process: OwnedHandle,
    _thread: OwnedHandle,
}

impl Drop for EndingProcess {
    fn drop(&mut self) {
        // SAFETY: a live process handle with terminate access (`CreateProcessW` gives full access).
        if let Err(e) = unsafe { TerminateProcess(self.process.0, 1) } {
            tracing::warn!("survival probe: could not end the probe process: {e}");
            return;
        }
        // The process was never resumed and holds nothing, so it ends at once. The wait has no bound:
        // it re-checks nothing but the process, which the kernel ends.
        // SAFETY: the handle from `CreateProcessW` carries SYNCHRONIZE.
        let rc = unsafe { WaitForSingleObject(self.process.0, INFINITE) };
        if rc != WAIT_OBJECT_0 {
            tracing::warn!("survival probe: waiting for the probe process to end gave {rc:?}");
        }
    }
}
