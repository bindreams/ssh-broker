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

/// Whether the process behind `handle_raw` has already exited.
///
/// The single place this query lives, so its one justified `sleep-ok:` opt-out does not have
/// to be repeated (and kept correct through reformatting) at every call site. A zero timeout
/// is an instantaneous state query: it never blocks and never bets on how long anything takes,
/// which is the thing the hook exists to forbid.
pub fn has_exited(handle_raw: isize) -> bool {
    use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
    use windows::Win32::System::Threading::WaitForSingleObject;
    let h = HANDLE(handle_raw as *mut core::ffi::c_void);
    unsafe { WaitForSingleObject(h, 0) == WAIT_OBJECT_0 } // sleep-ok: zero timeout is a state query
}
