//! winutil: shared Windows RAII guards + process-thread attribute-list helper (Windows-only).
//!
//! Used by both `conpty` (the PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE list) and `pipes` (the
//! PROC_THREAD_ATTRIBUTE_HANDLE_LIST list), so the attribute-list create/cleanup is written
//! and reasoned about once.

use windows::Win32::Foundation::{CloseHandle, HANDLE};
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

/// A process-thread attribute list holding exactly one attribute. Frees the list's internal
/// allocations (`DeleteProcThreadAttributeList`) on drop; the backing buffer frees with it.
/// The buffer is `Vec<usize>` so it is pointer-aligned (the list stores pointers internally).
pub struct AttrList {
    _buf: Vec<usize>,
    list: LPPROC_THREAD_ATTRIBUTE_LIST,
}

impl AttrList {
    /// Build a one-attribute list. `value` and `size` are passed VERBATIM to
    /// `UpdateProcThreadAttribute`, so their meaning depends on `attribute`: for some
    /// attributes `value` is a pointer to a `size`-byte buffer (e.g. `HANDLE_LIST` → an
    /// array of `HANDLE`s); for others it is the value encoded directly in the pointer with
    /// `size` describing that value's width (e.g. `PSEUDOCONSOLE` → the HPCON value itself,
    /// `size = size_of::<HPCON>()`). Any buffer `value` points to must outlive the eventual
    /// `CreateProcessW`.
    ///
    /// # Safety
    /// `(attribute, value, size)` must be a valid combination per the Win32 documentation.
    pub unsafe fn single(
        attribute: usize,
        value: *const core::ffi::c_void,
        size: usize,
    ) -> windows::core::Result<AttrList> {
        let mut bytes: usize = 0;
        // First call computes the required size (returns an expected error).
        let _ = unsafe { InitializeProcThreadAttributeList(None, 1, None, &mut bytes) };
        // Pointer-aligned backing buffer, rounded up to whole `usize`s.
        let words = bytes.div_ceil(std::mem::size_of::<usize>()).max(1);
        let mut buf: Vec<usize> = vec![0usize; words];
        let list = LPPROC_THREAD_ATTRIBUTE_LIST(buf.as_mut_ptr() as *mut _);
        unsafe { InitializeProcThreadAttributeList(Some(list), 1, None, &mut bytes)? };
        // Guard NOW so a failure of UpdateProcThreadAttribute still runs the delete.
        let owned = AttrList { _buf: buf, list };
        unsafe { UpdateProcThreadAttribute(list, 0, attribute, Some(value), size, None, None)? };
        Ok(owned)
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
    let hr = match e {
        cosca::error::Error::Io(io) => io.raw_os_error().map(|c| windows::core::HRESULT::from_win32(c as u32)),
        _ => None,
    };
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
