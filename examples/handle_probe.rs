//! Test stand-in for the verb's child: given the value of a pipe handle it should have inherited and
//! the value of another handle of its parent that it should not have, it prints `read:<what the pipe
//! held up to its end>`, then `other:invalid` or `other:visible`, and ends with `finished.`. The
//! other handle is a pipe in the parent, and the pipe handle is the only pipe in this process, so a
//! pipe that answers at that value is the parent's. Only Windows has inheritable handles.

#[cfg(windows)]
fn main() {
    use std::io::{Read, Write};
    use std::os::windows::io::{FromRawHandle, RawHandle};
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Pipes::PeekNamedPipe;

    let value = |n: usize| -> usize {
        std::env::args()
            .nth(n)
            .and_then(|a| a.parse().ok())
            .expect("the pipe handle and the other handle, as numbers")
    };
    let (pipe, other) = (value(1), value(2));

    // SAFETY: only a query; the call fails for a value that is not a handle of this process.
    let visible = unsafe { PeekNamedPipe(HANDLE(other as RawHandle), None, 0, None, None, None) }.is_ok();

    // SAFETY: the parent named this handle and nothing else here owns it.
    let mut held = unsafe { std::fs::File::from_raw_handle(pipe as RawHandle) };
    let mut text = String::new();
    held.read_to_string(&mut text).expect("read the pipe to its end");
    println!("read:{text}");
    println!("other:{}", if visible { "visible" } else { "invalid" });
    println!("finished.");
    std::io::stdout().flush().unwrap();
}

#[cfg(not(windows))]
fn main() {
    std::process::exit(2)
}
