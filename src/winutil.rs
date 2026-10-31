//! winutil: shared Windows RAII guards + process-thread attribute-list helper (Windows-only).
//!
//! Used by both `conpty` (the PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE list) and `pipes` (the
//! PROC_THREAD_ATTRIBUTE_HANDLE_LIST list), so the attribute-list create/cleanup is written
//! and reasoned about once.

use crate::shell::StartError;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::{
    GetThreadErrorMode, SEM_FAILCRITICALERRORS, SetThreadErrorMode, THREAD_ERROR_MODE,
};
use windows::Win32::System::Threading::{
    DeleteProcThreadAttributeList, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
    UpdateProcThreadAttribute,
};

/// Owns a `HANDLE`, calling `CloseHandle` on drop (no-op on an invalid handle).
pub struct OwnedHandle(pub HANDLE);

// SAFETY: an `OwnedHandle` is the SOLE owner of its kernel handle (no aliasing — handles
// flow into threads by ownership transfer, never shared). Moving sole ownership to another
// thread, which then closes it exactly once, is sound — the same reasoning as `Box<T>`.
// (Windows kernel handles are process-global, valid from any thread.)
unsafe impl Send for OwnedHandle {}

impl OwnedHandle {
    /// The raw handle as `isize`, for passing to a relay thread (HANDLE is not `Send`).
    pub fn raw(&self) -> isize {
        self.0.0 as isize
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

/// While alive, a program that `CreateProcessW` cannot start (the wrong architecture, a file that is not
/// a program, a blocked one) makes the call fail on this thread. Without it the call raises a message
/// box on the session's desktop and waits for an answer, which nobody gives in a session that is not
/// watched. It is the thread's error mode: the process, and so the programs it starts, are untouched.
/// The flag is added to the mode the thread has, and that mode is what the drop puts back.
pub struct FailCriticalErrors {
    /// The mode to put back; `None` when the mode was not changed.
    restore: Option<THREAD_ERROR_MODE>,
}

impl FailCriticalErrors {
    pub fn enter() -> Self {
        // SAFETY: no pointers.
        let previous = THREAD_ERROR_MODE(unsafe { GetThreadErrorMode() });
        // SAFETY: no pointers.
        let set = unsafe { SetThreadErrorMode(THREAD_ERROR_MODE(previous.0 | SEM_FAILCRITICALERRORS.0), None) };
        match set {
            Ok(()) => FailCriticalErrors {
                restore: Some(previous),
            },
            Err(e) => {
                tracing::warn!("could not switch off the message boxes of a failed start: {e}");
                FailCriticalErrors { restore: None }
            }
        }
    }
}

impl Drop for FailCriticalErrors {
    fn drop(&mut self) {
        if let Some(previous) = self.restore {
            // SAFETY: no pointers.
            let _ = unsafe { SetThreadErrorMode(previous, None) };
        }
    }
}

/// The error of a `CreateProcessW` that failed. The program is at fault unless `cwd` is given and is
/// not a directory, which also fails the call: then the working directory is named and the shell is
/// not blamed. Judged after the failure, so a directory that appears in between blames the program.
pub fn start_error_of_create(error: windows::core::Error, cwd: Option<&std::path::Path>) -> StartError {
    match cwd {
        Some(cwd) if !cwd.is_dir() => StartError::Other(anyhow::anyhow!(
            "the working directory {} is not a directory: {error}",
            cwd.display()
        )),
        _ => StartError::Program(error.into()),
    }
}

/// A failure of anything but `CreateProcessW` while starting a program is not the program's.
impl From<windows::core::Error> for StartError {
    fn from(error: windows::core::Error) -> Self {
        StartError::Other(error.into())
    }
}

/// An anonymous pipe that hands bytes to a child through a handle it inherits (see [`crate::handoff`]).
///
/// Only the read end is inheritable, and a child gets it only by naming it in a
/// `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`. The write end stays with the agent.
pub struct Handoff {
    read: OwnedHandle,
    write: std::fs::File,
}

impl Handoff {
    /// A pipe buffered for `capacity` bytes (0: the default size), so a write of up to that many
    /// returns without a reader.
    pub fn new(capacity: u32) -> windows::core::Result<Handoff> {
        use std::os::windows::io::FromRawHandle;
        use windows::Win32::Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation};
        use windows::Win32::System::Pipes::CreatePipe;
        let (mut read, mut write) = (HANDLE::default(), HANDLE::default());
        // SAFETY: both are valid out pointers.
        unsafe { CreatePipe(&mut read, &mut write, None, capacity)? };
        let read = OwnedHandle(read);
        // SAFETY: `write` is a new handle that nothing else owns.
        let write = unsafe { std::fs::File::from_raw_handle(write.0) };
        // SAFETY: no pointers.
        unsafe { SetHandleInformation(read.0, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT)? };
        Ok(Handoff { read, write })
    }

    /// The read end, to name in the child's handle list; its value is the same in the child.
    pub fn read(&self) -> &OwnedHandle {
        &self.read
    }

    /// Write `bytes`, then close the pipe so the child sees the end of them. Call it after the child
    /// has started: this process's own copy of the read end is closed first, so a child that is gone
    /// makes the write fail instead of wait, and one that is alive reads while this writes.
    pub fn send(self, bytes: &[u8]) -> std::io::Result<()> {
        use std::io::Write;
        let Handoff { read, mut write } = self;
        drop(read);
        write.write_all(bytes)
    }
}

/// `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` (processthreadsapi.h) — restrict the child's inherited handles
/// to exactly those listed. (windows-rs 0.62 doesn't export it as a usable `usize` FFI value; named
/// here with its documented value.)
pub const PROC_THREAD_ATTRIBUTE_HANDLE_LIST: usize = 0x0002_0002;

/// One attribute of an [`AttrList`]: `value` and `size` are passed VERBATIM to
/// `UpdateProcThreadAttribute`; see [`AttrList::new`].
#[derive(Clone, Copy)]
pub struct Attr {
    pub attribute: usize,
    pub value: *const core::ffi::c_void,
    pub size: usize,
}

/// A process-thread attribute list. Holds exactly the attributes it was made with. Frees the list's internal
/// allocations (`DeleteProcThreadAttributeList`) on drop; the backing buffer frees with it.
/// The buffer is `Vec<usize>` so it is pointer-aligned (the list stores pointers internally).
pub struct AttrList {
    _buf: Vec<usize>,
    list: LPPROC_THREAD_ATTRIBUTE_LIST,
}

impl AttrList {
    /// Build a list of `attributes`. Each `value` and `size` are passed VERBATIM to
    /// `UpdateProcThreadAttribute`, so their meaning depends on `attribute`: for some
    /// attributes `value` is a pointer to a `size`-byte buffer (e.g. `HANDLE_LIST` → an
    /// array of `HANDLE`s); for others it is the value encoded directly in the pointer with
    /// `size` describing that value's width (e.g. `PSEUDOCONSOLE` → the HPCON value itself,
    /// `size = size_of::<HPCON>()`). Any buffer a `value` points to must outlive the eventual
    /// `CreateProcessW`.
    ///
    /// # Safety
    /// Every `(attribute, value, size)` must be a valid combination per the Win32 documentation, and
    /// the attributes must be distinct.
    pub unsafe fn new(attributes: &[Attr]) -> windows::core::Result<AttrList> {
        let count = attributes.len() as u32;
        let mut bytes: usize = 0;
        // First call computes the required size (returns an expected error).
        let _ = unsafe { InitializeProcThreadAttributeList(None, count, None, &mut bytes) };
        // Pointer-aligned backing buffer, rounded up to whole `usize`s.
        let words = bytes.div_ceil(std::mem::size_of::<usize>()).max(1);
        let mut buf: Vec<usize> = vec![0usize; words];
        let list = LPPROC_THREAD_ATTRIBUTE_LIST(buf.as_mut_ptr() as *mut _);
        unsafe { InitializeProcThreadAttributeList(Some(list), count, None, &mut bytes)? };
        // Guard NOW so a failure of UpdateProcThreadAttribute still runs the delete.
        let owned = AttrList { _buf: buf, list };
        for Attr { attribute, value, size } in attributes {
            unsafe { UpdateProcThreadAttribute(list, 0, *attribute, Some(*value), *size, None, None)? };
        }
        Ok(owned)
    }

    /// A list of one attribute; see [`AttrList::new`].
    ///
    /// # Safety
    /// As for [`AttrList::new`].
    pub unsafe fn single(
        attribute: usize,
        value: *const core::ffi::c_void,
        size: usize,
    ) -> windows::core::Result<AttrList> {
        unsafe { AttrList::new(&[Attr { attribute, value, size }]) }
    }

    /// The list pointer to store in `STARTUPINFOEXW.lpAttributeList`.
    pub fn as_ptr(&self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.list
    }
}

impl Drop for AttrList {
    fn drop(&mut self) {
        unsafe {
            DeleteProcThreadAttributeList(self.list);
        }
    }
}

/// Turn a `cosca` failure into a Win32 error, keeping the real OS code when there is one.
///
/// Inventing a plausible code instead (this reported `ERROR_INVALID_HANDLE` for every
/// containment failure, whatever actually went wrong) sends whoever reads the log after an
/// incident chasing a cause that was never there.
pub fn win_error_from(e: &cosca::error::Error, context: &str) -> windows::core::Error {
    // Matched, not walked. `Error::Io` is `#[error(transparent)]`, and thiserror forwards
    // `source()` to the *inner* error's source — which for an `io::Error` is `None`. A chain
    // walk therefore never reaches the `io::Error` at all and silently reports a placeholder
    // for every failure, which is the same defect as hardcoding one. The wildcard is required:
    // `cosca::error::Error` is `#[non_exhaustive]`.
    use cosca::error::Error as E;
    let os = match e {
        E::Io(io) => io.raw_os_error().filter(|c| *c != 0),
        // These carry the OS error only when the OS was actually asked something.
        E::Unassessable { source: Some(io), .. } | E::IdentityRecord { source: Some(io), .. } => {
            io.raw_os_error().filter(|c| *c != 0)
        }
        _ => None,
    };
    let hr = os.map(|c| {
        // A negative code is already an encoded HRESULT (an `io::Error` built from one), and
        // widening it a second time would corrupt it; a positive code is a bare Win32 code.
        if c < 0 {
            windows::core::HRESULT(c)
        } else {
            windows::core::HRESULT::from_win32(c as u32)
        }
    });
    windows::core::Error::new(
        hr.unwrap_or(windows::Win32::Foundation::E_FAIL),
        format!("{context}: {e}"),
    )
}

/// Contain a suspended process in a job object, then let it run.
///
/// `process` must have been created `CREATE_SUSPENDED`. That is load-bearing, not tidiness:
/// assignment has to win the race against the process spawning anything, or a descendant is
/// born outside the job and survives teardown. If assignment fails the process is killed
/// rather than resumed — resuming it would produce exactly those unreachable descendants.
///
/// # Safety
/// `process` and `thread` must be the live handles from a successful `CreateProcess*` call.
pub unsafe fn contain_and_resume(process: HANDLE, thread: HANDLE, what: &str) -> windows::core::Result<cosca::Job> {
    use std::os::windows::io::{BorrowedHandle, RawHandle};
    use windows::Win32::System::Threading::{ResumeThread, TerminateProcess};

    // Borrowed for the call only; the caller owns the handle and outlives it.
    let job = match cosca::Job::assign(unsafe { BorrowedHandle::borrow_raw(process.0 as RawHandle) }) {
        Ok(job) => job,
        Err(e) => {
            // Uncontained AND still suspended, so it must not be resumed.
            if let Err(ke) = unsafe { TerminateProcess(process, 1) } {
                // Now also unkillable: say so, or this is a leaked suspended process whose
                // only trace is an unrelated error message.
                tracing::warn!("killing the unassigned {what} also failed: {ke}");
            }
            return Err(win_error_from(&e, &format!("assign the {what} to a job object")));
        }
    };
    if unsafe { ResumeThread(thread) } == u32::MAX {
        let err = windows::core::Error::from_thread();
        if let Err(ke) = job.kill_tree() {
            tracing::warn!("killing the unresumed {what} failed: {ke}");
        }
        return Err(err);
    }
    Ok(job)
}

#[cfg(test)]
#[path = "winutil_tests.rs"]
mod winutil_tests;
