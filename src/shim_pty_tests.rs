//! Unit tests for the `shim_pty` module. Windows-only (the module is `#[cfg(windows)]`), so
//! these compile and run only on a Windows host — in CI, the `Test (windows/amd64)` job.

use super::spawn_contained;

/// The local passthrough must contain its child in a job object, exactly as the relayed path
/// does, so that failing open can never become a way to outlive the session.
///
/// This used to be the property that made a MISCLASSIFIED command harmless: while the shim routed
/// suspected transfers around the relay, a string the client chose decided a security outcome, and
/// naming any binary `scp.exe` was enough to be spawned outside the job object and survive session
/// teardown. That classifier is gone and every command relays now, and `spawn_contained` is what
/// BOTH fail-open arms funnel through — the EXEC passthrough, and (since the interactive arm
/// stopped using the separate, uncontained `exec_local_shell`) the plain `pwsh` an interactive
/// session gets too. So this containment is the sole thing between an unreachable agent and a
/// process that outlives the session the README promises to reap.
///
/// Read that as a statement about the PRODUCTION WIRING, not about this test's reach. This test
/// calls `spawn_contained` directly and therefore gates the spawn, not the wiring: it would stay
/// green if an arm of `run_on` stopped calling it. What keeps the arms honest is that both now go
/// through one `run_local_passthrough` call site, that `fail_open_command` pins the program each
/// selects, and that `tests/fail_open_windows.rs` drives the EXEC arm end to end.
///
/// `cosca::Job` sets `KILL_ON_JOB_CLOSE`, so dropping the job must terminate the child. Before
/// containment was added the child was created with `PROCESS_CREATION_FLAGS(0)` and no job at
/// all, and would simply keep running here — which is exactly what this test would catch.
#[test]
fn the_local_passthrough_child_is_contained_in_a_job() {
    use windows::Win32::Foundation::{STILL_ACTIVE, WAIT_OBJECT_0};
    use windows::Win32::System::Threading::{GetExitCodeProcess, INFINITE, WaitForSingleObject};

    // ~30s of doing nothing, so the child is certainly alive until something kills it.
    // `stdio: None` so it does not inherit the test harness's handles.
    let (process, job) =
        unsafe { spawn_contained("cmd /c ping -n 30 127.0.0.1", None) }.expect("spawn a contained child");

    // Liveness as a state QUERY, never a timed wait. It is not decoration: without it the test
    // passes vacuously if the child failed to start or exited instantly, since the wait below
    // would then return immediately for the wrong reason.
    let mut code = 0u32;
    unsafe { GetExitCodeProcess(process.0, &mut code) }.expect("read the child's exit code");
    assert_eq!(
        code, STILL_ACTIVE.0 as u32,
        "the child must still be running before the job is dropped, or this test proves nothing"
    );

    drop(job); // KILL_ON_JOB_CLOSE fires as the handle closes

    // UNBOUNDED on purpose. Containment makes this exit promptly; if it is broken the test hangs
    // until the CI job's own `timeout-minutes` — a loud failure. A numeric timeout here would be
    // a duration I picked, which is the hazard `no-sleep-sync` exists to catch, and an earlier
    // draft of this test tripped exactly that.
    let rc = unsafe { WaitForSingleObject(process.0, INFINITE) };
    assert_eq!(rc, WAIT_OBJECT_0, "dropping the job must terminate the contained child");
}

/// The interactive fail-open arm must run a plain `pwsh`, and an EXEC command must pass through
/// untouched.
///
/// This is worth pinning because both arms now reach the OS through the SINGLE
/// `run_local_passthrough` call in `run_on` — the program string is the only thing that differs
/// between them, so this is what stops either arm quietly acquiring a DIFFERENT PROGRAM. It does
/// not stop a shell hop: a wrapper applied at that single call site leaves `fail_open_command`
/// untouched and this test green — see the caveat below for what does catch that.
///
/// Being precise about what it does NOT prove, since overclaiming here is a defect this file has
/// already shipped twice: it does not prove containment (that is
/// `the_local_passthrough_child_is_contained_in_a_job`, plus the fact that one call site serves
/// both arms), and it does not prove the absence of a wrapper around the command on the way to
/// `CreateProcessW` (that is `tests/fail_open_windows.rs`, end to end through the binary).
#[test]
fn fail_open_maps_interactive_to_pwsh_and_passes_an_exec_command_through() {
    use crate::shim::FailOpen;
    assert_eq!(super::fail_open_command(&FailOpen::LocalShell), "pwsh -NoLogo");
    let cmd = r#"scp -t "C:\path with spaces\out.bin""#;
    assert_eq!(
        super::fail_open_command(&FailOpen::Passthrough(cmd.to_string())),
        cmd,
        "an EXEC command must reach the spawn byte for byte"
    );
}

// The gate for "an EXEC command reaches the OS verbatim, with no shell re-parsing its quoting"
// deliberately does NOT live here. It cannot: a unit test can only call `spawn_contained`
// directly, which bypasses `run_on` — so the mutation that matters
// (`FailOpen::Passthrough(cmd) => run_local_passthrough(&format!("pwsh -Command {cmd}"))`)
// would leave it green. That property is gated end to end, through the real binary, by
// `tests/fail_open_windows.rs`.

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

/// Regression test for the exact bug this diff fixes: a late `set_mode` failure must still roll
/// back whatever mode was already changed, and must NOT attempt to restore a Ctrl-handler
/// suppression it never actually applied.
///
/// Before the fix, `ConsoleModes::enter` applied both `SetConsoleMode` calls and only
/// constructed the guard on full success — so a failure on the SECOND call left the FIRST
/// change (stdin set to raw mode) live, with no guard ever having existed to undo it: stdin was
/// left raw — no echo, no line input — for the rest of the session. This can't be reproduced
/// through a real console (there is no portable way to make the second of two back-to-back
/// `SetConsoleMode` calls fail while the first succeeds), so this test drives the exact same
/// sequence through a fake `ConsoleOps` instead, which is deterministic and needs no console at
/// all — this is why `ConsoleModesState` is generic over `ConsoleOps` in the first place.
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
