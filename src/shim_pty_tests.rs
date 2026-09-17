//! Unit tests for the `shim_pty` module. Windows-only (the module is `#[cfg(windows)]`), so
//! these compile and run only on a Windows host — in CI, the `Test (windows/amd64)` job.

use super::spawn_contained;

/// The local passthrough must contain its child in a job object, exactly as the relayed path
/// does, so that failing open can never become a way to outlive the session.
///
/// This used to be the property that made a MISCLASSIFIED command harmless: while the shim routed
/// suspected transfers around the relay, a string the client chose decided a security outcome, and
/// naming any binary `scp.exe` was enough to be spawned outside the job object and survive session
/// teardown. That classifier is gone and every command relays now, and `spawn_contained` is now
/// what BOTH fail-open arms funnel through — the EXEC passthrough, and (since the interactive arm
/// stopped using the separate, uncontained `exec_local_shell`) the plain `pwsh` an interactive
/// session gets too. So this containment really is the sole thing between an unreachable agent and
/// a process that outlives the session the README promises to reap, for every local spawn there is
/// — not just for the arm this test happens to invoke directly.
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

/// `spawn_contained` — the function both fail-open arms funnel their command through — must hand
/// `CreateProcessW` the command line BYTE-IDENTICAL to what was passed, with nothing in between
/// re-parsing its quoting. `decide_fail_open` (tested in `shim_tests.rs`) only proves the pure
/// *decision*: that `Some(cmd)` becomes `FailOpen::Passthrough(cmd)` unchanged. It cannot see what
/// actually reaches the OS, because `run_on`/`run_local_passthrough` end in `process::exit` and
/// can't be called in-process here. This test closes that gap on the one platform that can: it
/// spawns `pwsh` printing its OWN raw command line (`[Environment]::CommandLine`, i.e.
/// `GetCommandLineW()`) through the real `spawn_contained` call, and asserts the captured output
/// is byte-identical to the string passed in.
///
/// The payload embeds quoting deliberately, because RE-quoting — not gross mangling — is the
/// failure mode a reinstated shell hop introduces. The mutation this catches: either fail-open arm
/// in `run_on` going back to wrapping its command in another shell layer, e.g.
/// `run_local_passthrough(&format!("pwsh -Command {cmd}"))` (the moral equivalent of the deleted
/// `exec_local_shell(Some(cmd))` route, or of the old `FailOpen::Passthrough(cmd) =>
/// exec_local_shell_with(Some(cmd))` mutation that kept `shim_tests.rs`'s pure-decision test green
/// while destroying this exact property). Any such wrap changes the string `CreateProcessW`
/// receives, so the child's own report of its command line stops matching `cmd` and this
/// assertion fails.
#[test]
fn spawn_contained_passes_the_command_line_to_create_process_w_verbatim() {
    use windows::Win32::Foundation::{HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation};
    use windows::Win32::System::Pipes::CreatePipe;
    use windows::Win32::System::Threading::{GetExitCodeProcess, INFINITE, WaitForSingleObject};

    // Quoted-with-spaces payload: exactly the shape a shell hop would mangle.
    let cmd = r#"pwsh -NoLogo -Command "[Environment]::CommandLine""#;

    unsafe fn pipe() -> (crate::winutil::OwnedHandle, crate::winutil::OwnedHandle) {
        let mut read = HANDLE::default();
        let mut write = HANDLE::default();
        unsafe { CreatePipe(&mut read, &mut write, None, 0) }.expect("create pipe");
        (crate::winutil::OwnedHandle(read), crate::winutil::OwnedHandle(write))
    }

    let (stdout, exit_code) = unsafe {
        let (stdin_read, stdin_write) = pipe(); // child's stdin: nothing sent, closed for EOF
        let (stdout_read, stdout_write) = pipe(); // captured; reused for stderr too
        for h in [stdin_read.0, stdout_write.0] {
            SetHandleInformation(h, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT)
                .expect("mark the child-side handle inheritable");
        }

        let (process, job) = spawn_contained(cmd, Some([stdin_read.0, stdout_write.0, stdout_write.0]))
            .expect("spawn through the real fail-open path");
        // Close OUR copies of the child-side ends now that the child has its own (inherited)
        // copies: keeping the write end open here would keep the pipe alive after the child
        // exits, and the read loop below would then block forever instead of seeing EOF.
        drop(stdin_read);
        drop(stdout_write);
        drop(stdin_write); // nothing to send; drop so the child's stdin reads EOF, not a hang

        WaitForSingleObject(process.0, INFINITE);
        let mut code = 0u32;
        GetExitCodeProcess(process.0, &mut code).expect("read the child's exit code");
        drop(job); // release containment only once the child is provably done

        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = crate::conpty::read_handle(stdout_read.raw(), &mut buf);
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        (out, code)
    };

    assert_eq!(
        exit_code, 0,
        "the probe script must run to completion, or nothing was captured"
    );
    let got = String::from_utf8(stdout).expect("a Windows command line is UTF-16/ASCII-safe here");
    assert_eq!(
        got.trim_end(),
        cmd,
        "the command CreateProcessW actually received must be byte-identical to what fail-open \
         passed — a re-quoting shell hop in between would change it"
    );
}
