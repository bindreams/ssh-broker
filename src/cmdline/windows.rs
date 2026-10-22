//! The process's raw command line.

use ::windows::Win32::System::Environment::GetCommandLineW;

/// The command line exactly as the parent passed it, program name included.
pub fn current() -> String {
    // SAFETY: GetCommandLineW has no preconditions; the returned buffer is owned by the
    // process and lives until it exits, so reading it here is sound.
    let line = unsafe { GetCommandLineW() };
    String::from_utf16_lossy(unsafe { line.as_wide() })
}
