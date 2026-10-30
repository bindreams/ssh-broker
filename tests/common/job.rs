//! A kill-on-close job object: the stand-in for the job sshd keeps its session in. Closing it
//! ends every process still in it, the way sshd ending a session does.
#![allow(dead_code)]

use std::ffi::c_void;

use ssh_broker::winutil::OwnedHandle;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT, JOB_OBJECT_LIMIT_BREAKAWAY_OK,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject,
};
use windows::core::PCWSTR;

pub struct KillOnCloseJob(Option<OwnedHandle>);

impl KillOnCloseJob {
    pub fn create() -> KillOnCloseJob {
        KillOnCloseJob::with_flags(JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
    }

    /// A kill-on-close job that also lets its processes start children outside it
    /// (`JOB_OBJECT_LIMIT_BREAKAWAY_OK`).
    pub fn create_allowing_breakaway() -> KillOnCloseJob {
        KillOnCloseJob::with_flags(JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_BREAKAWAY_OK)
    }

    fn with_flags(flags: JOB_OBJECT_LIMIT) -> KillOnCloseJob {
        // SAFETY: valid arguments; the handle is closed by `OwnedHandle`.
        unsafe {
            let job = OwnedHandle(CreateJobObjectW(None, PCWSTR::null()).expect("CreateJobObjectW"));
            let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            info.BasicLimitInformation.LimitFlags = flags;
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast::<c_void>(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
            .expect("SetInformationJobObject");
            KillOnCloseJob(Some(job))
        }
    }

    /// Put `process` in the job. It should still be suspended.
    pub fn assign(&self, process: HANDLE) {
        let job = self.0.as_ref().expect("the job is already closed");
        // SAFETY: both handles are live and owned by the caller.
        unsafe { AssignProcessToJobObject(job.0, process) }.expect("AssignProcessToJobObject");
    }

    /// Close the job: every process in it ends.
    pub fn close(&mut self) {
        self.0 = None;
    }
}
