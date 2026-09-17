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
/// selects, and that `tests/fail_open_windows_tests.rs` drives the EXEC arm end to end.
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
/// between them, so this is what stops the interactive arm quietly acquiring a shell hop or a
/// different program.
///
/// Being precise about what it does NOT prove, since overclaiming here is a defect this file has
/// already shipped twice: it does not prove containment (that is
/// `the_local_passthrough_child_is_contained_in_a_job`, plus the fact that one call site serves
/// both arms), and it does not prove the absence of a wrapper around the command on the way to
/// `CreateProcessW` (that is `tests/fail_open_windows_tests.rs`, end to end through the binary).
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
// `tests/fail_open_windows_tests.rs`.
