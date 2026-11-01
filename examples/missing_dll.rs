//! Test stand-in for a shell that is a real program whose import is missing: it starts, and the
//! loader ends it with `STATUS_DLL_NOT_FOUND` before `main` runs. Only Windows has such an import.

#[cfg(windows)]
#[link(name = "ssh_broker_dll_that_is_not_there", kind = "raw-dylib")]
unsafe extern "system" {
    fn ssh_broker_function_that_is_not_there();
}

#[cfg(windows)]
fn main() {
    // SAFETY: never reached; the loader ends the process first.
    unsafe { ssh_broker_function_that_is_not_there() }
}

#[cfg(not(windows))]
fn main() {
    std::process::exit(2)
}
