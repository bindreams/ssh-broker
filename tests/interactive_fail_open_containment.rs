//! End-to-end test that the INTERACTIVE fail-open arm (`FailOpen::LocalShell`) contains its
//! WHOLE process tree — not just its immediate `pwsh` child — in a job object, through the REAL
//! binary.
//!
//! Windows-only: the shim is `#[cfg(windows)]`. This runs in CI's `Test (windows/amd64)` job.
//!
//! Why an integration test rather than a unit test: `shim_pty::run_on` ends in `process::exit`,
//! so nothing in-process can observe whether it actually routed through
//! `run_local_passthrough` -> `spawn_contained`. The existing unit test
//! `the_local_passthrough_child_is_contained_in_a_job` (`src/shim_pty_tests.rs`) calls
//! `spawn_contained` DIRECTLY, so it gates the spawn helper's own containment but says nothing
//! about whether `run_on`'s `FailOpen::LocalShell` arm still calls it — reverting that arm back
//! to an uncontained `std::process::Command` (its pre-containment shape) leaves that unit test
//! green, since the unit test never goes near `run_on`. Only running the actual binary and
//! driving it into the LocalShell arm traverses the real path and can catch that regression.
#![cfg(windows)]

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use windows::Win32::Foundation::WAIT_OBJECT_0;
use windows::Win32::System::Threading::{
    INFINITE, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, WaitForSingleObject,
};

/// Dropping the shim's job object at session teardown must reap a GRANDCHILD the brokered
/// `pwsh` spawned, not just `pwsh` itself — proving the containment covers the whole tree a
/// fail-open interactive session can grow.
#[test]
fn interactive_fail_open_reaps_a_grandchild_when_the_shim_exits() {
    // No `apply` has run on a CI runner, so there is no agent socket to connect to.
    // `try_relay` fails open (`Ok(None)`) the moment the connect fails, before it ever looks at
    // whether stdio is a real console — so the unreachable agent alone is what routes this run
    // to fail open with `exec = None`, i.e. the INTERACTIVE arm, `FailOpen::LocalShell`.
    let mut child = Command::new(env!("CARGO_BIN_EXE_ssh-broker"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the shim binary");

    let mut stdin = child.stdin.take().expect("stdin was piped");
    let stdout = child.stdout.take().expect("stdout was piped");
    let mut reader = BufReader::new(stdout);

    // This command is also the test's PRECONDITION CHECK, not just a fixture: `decide_fail_open`
    // only reaches `FailOpen::Passthrough` when an EXEC command was given, and this spawn passed
    // none, so the ONLY way anything can be reading commands off this pipe at all is the
    // interactive arm's `pwsh -NoLogo` REPL. A pwsh REPL responding on stdin is therefore itself
    // proof the LocalShell arm ran — do not skip reading the PID line below on the theory that
    // spawning the grandchild is enough; the READ is what proves pwsh (not nothing, not some
    // other path) is on the other end of this pipe.
    //
    // The grandchild's own stdio is explicitly redirected away from inheriting pwsh's (i.e. the
    // shim's, i.e. THIS pipe): `run_local_passthrough` marks the shim's std handles inheritable
    // before spawning pwsh (so pwsh can talk to this test at all), and a bare
    // `[Process]::Start('ping.exe', ...)` would let ping inherit those same handles and become a
    // second, unsynchronized writer into the very pipe the loop below parses — exactly the hazard
    // `the_local_passthrough_child_is_contained_in_a_job` (`src/shim_pty_tests.rs`) avoids for its
    // own child with `stdio: None`. `UseShellExecute = $false` is required before
    // `RedirectStandard*` is honored at all; without it `Process.Start` throws.
    writeln!(
        stdin,
        "$si = [System.Diagnostics.ProcessStartInfo]::new('ping.exe', '-n 3600 127.0.0.1'); \
         $si.UseShellExecute = $false; $si.RedirectStandardOutput = $true; $si.RedirectStandardError = $true; \
         $p = [System.Diagnostics.Process]::Start($si); \
         Write-Output \"GRANDCHILD_PID:$($p.Id)\""
    )
    .expect("write the probe command to the shim's stdin");
    stdin.flush().expect("flush the probe command");

    // Read lines until one CONTAINS the PID marker. This IS the synchronization point: a
    // blocking read that resolves the instant pwsh writes the line — no sleeping, no polling, no
    // numeric timeout.
    //
    // Deliberately a substring search (`find`), not `strip_prefix` on the trimmed line: pwsh
    // -NoLogo writes its `PS <cwd>> ` prompt to stdout with NO trailing newline before it ever
    // reads a line of input. That prompt was already sitting unterminated in the pipe before our
    // `Write-Output` line was even sent, so the first newline-terminated chunk `read_line` ever
    // produces is `PS <cwd>> GRANDCHILD_PID:1234` — the leftover prompt fused onto the front of
    // our output by the very first `\n` in the stream. Requiring the marker as a PREFIX missed
    // that line, and the next `read_line` call would then block forever on the FOLLOWING prompt,
    // itself unterminated and waiting on input this test does not send until after this loop was
    // supposed to have already broken — a hang bounded only by CI's blanket job timeout, not a
    // clean test failure, and one that would occur even with fully correct containment.
    //
    // And deliberately ONLY breaking on an occurrence whose tail actually parses as a `u32`, and
    // deliberately checking EVERY occurrence of the marker in the line rather than just the
    // first: the literal text `GRANDCHILD_PID:` also appears in the COMMAND this test wrote to
    // pwsh's stdin above (inside the `Write-Output` string), and a redirected-stdin `pwsh
    // -NoLogo` transcribes each line it reads back to stdout before executing it. If it does, and
    // that echo is not itself newline-terminated before the real output follows, both occurrences
    // can end up fused onto ONE line — an echoed one (tail `$($p.Id)"`, which does not parse)
    // immediately followed by the real one (tail a number). Stopping at the first occurrence in
    // that line would discard the real PID along with the fake match and then hang forever on the
    // next unterminated prompt, since the marker is only ever emitted once. Scanning every
    // occurrence and taking the first one whose tail parses is robust to that fusion either way,
    // without needing to know for certain whether pwsh actually echoes here.
    let pid: u32 = loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).expect("read the shim's stdout");
        assert_ne!(
            n, 0,
            "the shim closed stdout before printing the grandchild's PID — the interactive \
             fail-open arm never ran (see the precondition note above)"
        );
        let found = line
            .match_indices("GRANDCHILD_PID:")
            .find_map(|(idx, marker)| line[idx + marker.len()..].trim().parse::<u32>().ok());
        if let Some(pid) = found {
            break pid;
        }
    };

    // Open a handle to the grandchild WHILE IT IS STILL ALIVE, before anything below is torn
    // down — so the wait at the end observes real containment rather than a handle that was
    // never valid for a live process in the first place.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE, false, pid) }
        .unwrap_or_else(|e| panic!("OpenProcess({pid}) failed while the grandchild should still be alive: {e}"));
    let handle = ssh_broker::winutil::OwnedHandle(handle); // RAII CloseHandle, mirroring spawn_contained's callers

    // Close the shim's stdin: pwsh sees EOF on its next read and exits, `run_local_passthrough`
    // observes pwsh's exit, `spawn_contained`'s job object is dropped, and `KILL_ON_JOB_CLOSE`
    // reaps every member of the job — including the grandchild, which was never a DIRECT child
    // of the job-assigned process.
    drop(stdin);

    // UNBOUNDED on purpose, mirroring `the_local_passthrough_child_is_contained_in_a_job`'s own
    // discipline: if containment regressed (the LocalShell arm reverting to an uncontained
    // spawn, or the grandchild breaking away from the job), this wait never returns and the CI
    // job's own `timeout-minutes` budget is what surfaces the failure — loudly, not silently. A
    // numeric timeout here would be exactly the duration-I-picked hazard `no-sleep-sync` exists
    // to forbid. `ping -n 3600` (≈ an hour) is chosen to outlast that CI budget, so a regression
    // times out the JOB rather than quietly finishing this wait on its own once ping runs out.
    let rc = unsafe { WaitForSingleObject(handle.0, INFINITE) };
    assert_eq!(
        rc, WAIT_OBJECT_0,
        "the grandchild must be reaped when the shim's job object closes"
    );

    // Let the shim itself finish exiting; its exit code carries no signal for this test (the
    // interactive arm exits however pwsh exited on EOF) — the assertion above is the whole test.
    let _ = child.wait();
}
