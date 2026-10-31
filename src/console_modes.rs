//! console_modes: the console's raw mode as an RAII guard.
//!
//! `ConsoleModes::enter` puts stdin into raw input (records, not cooked lines; Ctrl+C arrives as a
//! key) and stdout into VT output, and the guard's drop puts both back. The relay (`shim_pty`) and
//! the password prompt (`console_prompt`) share it: the prompt enters it, and a successful logon
//! hands it on to the relay.

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Console::{
    CONSOLE_MODE, DISABLE_NEWLINE_AUTO_RETURN, ENABLE_EXTENDED_FLAGS, ENABLE_MOUSE_INPUT, ENABLE_PROCESSED_OUTPUT,
    ENABLE_VIRTUAL_TERMINAL_PROCESSING, ENABLE_WINDOW_INPUT, GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE,
    STD_OUTPUT_HANDLE, SetConsoleCtrlHandler, SetConsoleMode,
};

/// stdin raw-input mode: window + mouse events as records, extended flags (disables
/// quick-edit). The absolute store implicitly clears PROCESSED/LINE/ECHO input, so Ctrl-C
/// arrives as a KEY record (uc=0x03) rather than a signal. VT-input is intentionally omitted
/// — we read raw `INPUT_RECORD`s and re-encode them ourselves.
pub(crate) const RAW_IN: CONSOLE_MODE =
    CONSOLE_MODE(ENABLE_WINDOW_INPUT.0 | ENABLE_MOUSE_INPUT.0 | ENABLE_EXTENDED_FLAGS.0);
/// stdout bits OR-ed onto the inherited mode: render the agent's VT, and stop CR injection
/// on LF (the agent's stream already carries explicit CR/LF).
pub(crate) const VT_OUT: CONSOLE_MODE =
    CONSOLE_MODE(ENABLE_PROCESSED_OUTPUT.0 | ENABLE_VIRTUAL_TERMINAL_PROCESSING.0 | DISABLE_NEWLINE_AUTO_RETURN.0);

// ── console raw-mode RAII ──────────────────────────────────────────────────────────

/// The Win32 calls `ConsoleModes` drives to apply/restore raw mode, behind a trait so the
/// guard's rollback-on-partial-failure behavior is host-testable without a real console via a
/// fake that fails the SECOND `set_mode` call (`src/console_modes_tests.rs`). `Win32ConsoleOps` is
/// the real implementation the `ConsoleModes` alias below is backed by at runtime.
pub(crate) trait ConsoleOps {
    fn set_mode(&self, handle: HANDLE, mode: CONSOLE_MODE) -> windows::core::Result<()>;
    fn set_ctrl_suppressed(&self, suppress: bool) -> windows::core::Result<()>;
}

pub(crate) struct Win32ConsoleOps;

impl ConsoleOps for Win32ConsoleOps {
    fn set_mode(&self, handle: HANDLE, mode: CONSOLE_MODE) -> windows::core::Result<()> {
        unsafe { SetConsoleMode(handle, mode) }
    }

    fn set_ctrl_suppressed(&self, suppress: bool) -> windows::core::Result<()> {
        unsafe { SetConsoleCtrlHandler(None, suppress) }
    }
}

/// Saves and restores the stdin/stdout console modes (and the Ctrl handler). `is_console` is
/// false when stdin/stdout are not consoles (redirected pipes) — then nothing is changed and
/// Drop is a no-op, and the caller fails open (a non-console can't drive `ReadConsoleInputW`).
///
/// Generic over `ConsoleOps` purely for testability; real callers use the `ConsoleModes` alias
/// below, which is always `Win32ConsoleOps`-backed.
pub(crate) struct ConsoleModesState<Ops: ConsoleOps> {
    ops: Ops,
    pub(crate) stdin: HANDLE,
    pub(crate) stdout: HANDLE,
    in_orig: CONSOLE_MODE,
    out_orig: CONSOLE_MODE,
    pub(crate) is_console: bool,
    // Whether `set_ctrl_suppressed(true)` actually SUCCEEDED. Unlike the two `SetConsoleMode`
    // restores below (writing back a captured value is a harmless no-op even on a path where
    // that particular handle's mode was never actually changed), `SetConsoleCtrlHandler` is an
    // ABSOLUTE state change inherited by child processes, not a value restore — unconditionally
    // clearing it on Drop, on a path where the corresponding suppress call never ran (or
    // failed), would clear an attribute this guard never set (e.g. one the process inherited
    // from sshd). Gating the restore on this flag keeps Drop symmetric with what actually changed.
    ctrl_suppressed: bool,
}

pub(crate) type ConsoleModes = ConsoleModesState<Win32ConsoleOps>;

impl<Ops: ConsoleOps> ConsoleModesState<Ops> {
    /// Applies raw mode via `ops`, constructing the guard NOW, holding the ORIGINAL modes,
    /// before either is changed below. `modes` is then a local variable in scope for the rest of
    /// this function, so if the stdout `set_mode` fails via `?` after the stdin one already
    /// succeeded, Rust drops every local on that early return — running `modes`'s `Drop` and
    /// restoring stdin's mode before this function returns the error.
    pub(crate) fn enter_with(
        ops: Ops,
        stdin: HANDLE,
        stdout: HANDLE,
        in_orig: CONSOLE_MODE,
        out_orig: CONSOLE_MODE,
        is_console: bool,
    ) -> windows::core::Result<Self> {
        let mut modes = ConsoleModesState {
            ops,
            stdin,
            stdout,
            in_orig,
            out_orig,
            is_console,
            ctrl_suppressed: false,
        };
        if is_console {
            modes.ops.set_mode(stdin, RAW_IN)?;
            modes.ops.set_mode(stdout, CONSOLE_MODE(out_orig.0 | VT_OUT.0))?;
            // Suppress Ctrl events as signals to the shim (insurance; the primary path is the
            // cleared ENABLE_PROCESSED_INPUT delivering Ctrl-C as a KEY record). Best-effort:
            // failure here does not fail `enter_with`, it just leaves `ctrl_suppressed` false so
            // Drop does not try to undo a change that never happened — but it must not be silent,
            // for the same reason the Drop-side restores below are logged.
            modes.ctrl_suppressed = match modes.ops.set_ctrl_suppressed(true) {
                Ok(()) => true,
                Err(e) => {
                    tracing::error!("failed to suppress the console Ctrl handler: {e:?}");
                    false
                }
            };
        }
        Ok(modes)
    }
}

impl ConsoleModesState<Win32ConsoleOps> {
    pub(crate) fn enter() -> windows::core::Result<ConsoleModes> {
        crate::ctrl_flag_spike::record("shim, before ConsoleModes::enter");
        let entered = Self::enter_inner();
        crate::ctrl_flag_spike::record("shim, after ConsoleModes::enter");
        entered
    }

    fn enter_inner() -> windows::core::Result<ConsoleModes> {
        unsafe {
            let stdin = GetStdHandle(STD_INPUT_HANDLE)?;
            let stdout = GetStdHandle(STD_OUTPUT_HANDLE)?;
            let mut in_orig = CONSOLE_MODE(0);
            let mut out_orig = CONSOLE_MODE(0);
            let is_console =
                GetConsoleMode(stdin, &mut in_orig).is_ok() && GetConsoleMode(stdout, &mut out_orig).is_ok();
            Self::enter_with(Win32ConsoleOps, stdin, stdout, in_orig, out_orig, is_console)
        }
    }
}

impl<Ops: ConsoleOps> Drop for ConsoleModesState<Ops> {
    fn drop(&mut self) {
        if self.is_console {
            // Restoring a captured value is a harmless no-op even if that particular call never
            // actually changed anything, so these two stay unconditional. A failure here can
            // leave the session in a corrupted terminal state (raw mode, no echo/line input)
            // with nothing left to do about it from this function — but it must not be silent,
            // or that corruption has zero diagnostic trail in the log.
            if let Err(e) = self.ops.set_mode(self.stdin, self.in_orig) {
                tracing::error!("failed to restore stdin console mode: {e:?}");
            }
            if let Err(e) = self.ops.set_mode(self.stdout, self.out_orig) {
                tracing::error!("failed to restore stdout console mode: {e:?}");
            }
            if self.ctrl_suppressed
                && let Err(e) = self.ops.set_ctrl_suppressed(false)
            {
                tracing::error!("failed to restore the console Ctrl handler: {e:?}");
            }
        }
    }
}

#[cfg(test)]
#[path = "console_modes_tests.rs"]
mod console_modes_tests;
