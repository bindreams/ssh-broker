//! Unit tests for the `shim_pty` module. Windows-only (the module is `#[cfg(windows)]`), so
//! these compile and run only on a Windows host — in CI, the `Test (windows/amd64)` job.

use super::spawn_contained;

/// The local passthrough must contain its child in a job object, exactly as the relayed path
/// does. This is the property that makes a misclassified command harmless.
///
/// Classification reads a string the client chose. While routing carried a containment
/// difference, that string decided a security outcome: naming any binary `scp.exe` was enough to
/// be spawned outside the job object and survive session teardown. sshd itself attaches no such
/// consequence to how a command is classified, and neither should this.
///
/// `cosca::Job` sets `KILL_ON_JOB_CLOSE`, so dropping the job must terminate the child. Before
/// containment was added the child was created with `PROCESS_CREATION_FLAGS(0)` and no job at
/// all, and would simply keep running here — which is exactly what this test would catch.
#[test]
fn the_local_passthrough_child_is_contained_in_a_job() {
    use windows::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows::Win32::System::Threading::WaitForSingleObject;

    // ~30s of doing nothing, so the child is certainly alive until something kills it.
    // `stdio: None` so it does not inherit the test harness's handles.
    let (process, job) =
        unsafe { spawn_contained("cmd /c ping -n 30 127.0.0.1", None) }.expect("spawn a contained child");

    // A zero timeout is a poll of current state, not a sleep.
    assert_eq!(
        unsafe { WaitForSingleObject(process.0, 0) },
        WAIT_TIMEOUT,
        "the child must still be running before the job is dropped, or this test proves nothing"
    );

    drop(job); // KILL_ON_JOB_CLOSE fires as the handle closes

    // Awaiting a process exit, with the timeout as the failure bound reported to a human — not
    // sleep-as-synchronisation. An UNCONTAINED child would still be pinging when this expires.
    assert_eq!(
        unsafe { WaitForSingleObject(process.0, 10_000) },
        WAIT_OBJECT_0,
        "dropping the job must terminate the contained child"
    );
}
