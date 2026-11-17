//! Reading a child's output pipe to its end, on a thread of its own. A child that writes more than a pipe
//! holds blocks until someone reads, so a test that waits for the child before it reads waits forever; with
//! the pipe drained from the start, the wait ends and the test can show what the child said. One source for
//! both homes: the integration tests include it with `#[path]`, and so does the unit tests'
//! `src/test_support.rs`. It needs only `std` and `windows`, so it reads with `ReadFile` itself: the library
//! cannot name itself as `ssh_broker`, so one file cannot call `conpty::read_handle` from both homes.
#![allow(dead_code)]

use std::thread::JoinHandle;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::ReadFile;

/// The bytes that arrive on the read end `raw` of a pipe until it ends (the child, and every other holder
/// of the write end, is gone, or the pipe is closed). The handle stays the caller's: do not close it
/// before the thread is joined.
pub fn drain(raw: isize) -> JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let handle = HANDLE(raw as *mut core::ffi::c_void);
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let mut read = 0u32;
            // SAFETY: `buf` and `read` are live for the call; the handle is the caller's open pipe.
            if unsafe { ReadFile(handle, Some(&mut buf), Some(&mut read), None) }.is_err() || read == 0 {
                return out;
            }
            out.extend_from_slice(&buf[..read as usize]);
        }
    })
}

/// [`drain`]'s bytes as text, for a failure message.
pub fn text_of(output: JoinHandle<Vec<u8>>) -> String {
    String::from_utf8_lossy(&output.join().expect("the drain thread panicked")).into_owned()
}
