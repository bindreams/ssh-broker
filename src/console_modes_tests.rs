//! Unit tests for `console_modes`: the guard rolls back what it changed. Fake console ops; no console.

// ── ConsoleModes rollback-on-partial-failure ────────────────────────────────────────

/// A fake `ConsoleOps` that fails the SECOND `set_mode` call it ever sees and records every
/// call, so the test can assert exactly what happened rather than merely that something did.
/// `Rc<RefCell<_>>` so the test keeps its own handle to inspect the record after the guard
/// (which owns a clone of this fake) has been dropped.
#[derive(Clone, Default)]
struct FailSecondSetMode {
    set_mode_calls: std::rc::Rc<std::cell::RefCell<Vec<(isize, u32)>>>,
    ctrl_calls: std::rc::Rc<std::cell::RefCell<Vec<bool>>>,
}

impl super::ConsoleOps for FailSecondSetMode {
    fn set_mode(
        &self,
        handle: windows::Win32::Foundation::HANDLE,
        mode: windows::Win32::System::Console::CONSOLE_MODE,
    ) -> windows::core::Result<()> {
        let mut calls = self.set_mode_calls.borrow_mut();
        calls.push((handle.0 as isize, mode.0));
        // Construction makes exactly two `set_mode` calls (stdin, then stdout) before anything
        // else touches this fake, so call #2 overall is deterministically the stdout one.
        if calls.len() == 2 {
            Err(windows::core::Error::new(
                windows::Win32::Foundation::E_FAIL,
                "fake SetConsoleMode failure",
            ))
        } else {
            Ok(())
        }
    }

    fn set_ctrl_suppressed(&self, suppress: bool) -> windows::core::Result<()> {
        self.ctrl_calls.borrow_mut().push(suppress);
        Ok(())
    }
}

/// `enter` must undo the first `SetConsoleMode` change when the second fails, else stdin stays raw (no
/// echo, no line input).
#[test]
fn enter_rolls_back_only_what_it_actually_changed_on_partial_failure() {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Console::CONSOLE_MODE;

    // Two distinct, real (non-dangling) addresses to tell the fake handles apart by value — never
    // dereferenced, `FailSecondSetMode` only ever compares/records `HANDLE.0`.
    static STDIN_MARKER: u8 = 0;
    static STDOUT_MARKER: u8 = 0;
    let ops = FailSecondSetMode::default();
    let stdin = HANDLE(&raw const STDIN_MARKER as *mut core::ffi::c_void);
    let stdout = HANDLE(&raw const STDOUT_MARKER as *mut core::ffi::c_void);
    let in_orig = CONSOLE_MODE(0x1111);
    let out_orig = CONSOLE_MODE(0x2222);

    let result = super::ConsoleModesState::enter_with(ops.clone(), stdin, stdout, in_orig, out_orig, true);

    assert!(
        result.is_err(),
        "the second set_mode call was made to fail, so enter_with must propagate an Err"
    );

    let calls = ops.set_mode_calls.borrow();
    // Two construction calls (stdin succeeds, stdout fails) plus two Drop restores (stdin then
    // stdout) = four, in that order — Drop running at all on this early-return path is the
    // regression this whole test exists to catch.
    assert_eq!(
        calls.len(),
        4,
        "expected 2 construction calls + 2 Drop restore calls, got: {calls:?}"
    );
    assert_eq!(
        calls[0],
        (stdin.0 as isize, super::RAW_IN.0),
        "construction must set stdin to raw mode first"
    );
    assert_eq!(
        calls[2],
        (stdin.0 as isize, in_orig.0),
        "Drop must restore stdin's ORIGINAL mode — this is the exact regression: without \
         constructing the guard before the mutations, this restore never happened at all"
    );
    assert_eq!(
        calls[3],
        (stdout.0 as isize, out_orig.0),
        "Drop must also restore stdout's original mode, even though the mutating call for it \
         is what failed"
    );

    assert!(
        ops.ctrl_calls.borrow().is_empty(),
        "set_ctrl_suppressed(true) was never reached (the stdout set_mode failed first), so \
         Drop must not attempt to restore a suppression that was never applied"
    );
}
