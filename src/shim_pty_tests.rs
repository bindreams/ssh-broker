//! Unit tests for the `shim_pty` module. Windows-only (the module is `#[cfg(windows)]`), so
//! these compile and run only on a Windows host — in CI, the `Test (windows/amd64)` job.

use super::spawn_contained;
use crate::shim_offer::NoRescue;

/// The local passthrough must contain its child in a job object, exactly as the relayed path
/// does, so that failing open can never become a way to outlive the session.
///
/// `spawn_contained` is what BOTH fail-open arms funnel through — the EXEC passthrough, and (since
/// the interactive arm stopped using the separate, uncontained `exec_local_shell`) the plain `pwsh`
/// an interactive session gets too. So this containment is the sole thing between an unreachable agent and a
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

/// The fail-open spawn trims leading whitespace for `CreateProcessW`, which rejects it; the
/// relay's spawn does the same (`pipes_tests`).
#[test]
fn the_local_passthrough_spawn_accepts_whitespace_at_the_edges_of_a_command() {
    use windows::Win32::System::Threading::{GetExitCodeProcess, INFINITE, WaitForSingleObject};

    for command in [
        "  cmd.exe /c exit /b 3",
        "\tcmd.exe /c exit /b 3\r\n",
        "\r\ncmd.exe /c exit /b 3",
    ] {
        let (process, _job) =
            unsafe { spawn_contained(command, None) }.unwrap_or_else(|e| panic!("{command:?}: {e:?}"));
        let mut code = 0u32;
        unsafe {
            WaitForSingleObject(process.0, INFINITE);
            GetExitCodeProcess(process.0, &mut code).unwrap();
        }
        assert_eq!(code, 3, "{command:?}");
    }
}

// Where the shim connects, and what it says when it cannot ------------------------------

use crate::socket_loc::{SocketLocation, SocketLocationError};

fn too_long() -> anyhow::Error {
    SocketLocationError::TooLong {
        path: std::path::PathBuf::from(r"C:\very\long\agent.sock"),
        bytes: 120,
        max: 107,
    }
    .into()
}

#[test]
fn unresolvable_socket_location_fails_open_with_the_reason() {
    let mut stderr = Vec::new();
    let relayed = super::try_relay_at(
        Err(too_long()),
        &Some("echo hi".into()),
        &mut stderr,
        None,
        std::io::empty(),
        &mut NoRescue,
    )
    .unwrap();

    assert_eq!(
        relayed, None,
        "an unresolvable location is fail-open, like an unreachable agent"
    );
    let text = String::from_utf8(stderr).unwrap();
    assert!(text.starts_with("ssh-broker: agent unavailable"), "{text}");
    assert!(text.contains("the AF_UNIX limit is 107"), "the reason is named: {text}");
}

#[test]
fn location_error_reaches_stderr_in_pty_mode() {
    // No relay has started and the console has not been touched, so a line on stderr before the
    // fallback shell corrupts nothing. The log is no substitute: for an interactive session it is
    // the only other place the reason goes, and the user does not read it.
    let mut stderr = Vec::new();
    let relayed = super::try_relay_at(
        Err(too_long()),
        &None,
        &mut stderr,
        None,
        std::io::empty(),
        &mut NoRescue,
    )
    .unwrap();

    assert_eq!(relayed, None);
    let text = String::from_utf8(stderr).unwrap();
    assert!(text.contains("agent unavailable"), "{text}");
    assert!(text.contains("the AF_UNIX limit is 107"), "{text}");
}

#[test]
fn unavailable_message_always_begins_with_the_phrase_the_tests_grep_for() {
    assert!(super::unavailable_message(None).starts_with("ssh-broker: agent unavailable"));
    assert!(super::unavailable_message(Some(&"no profile")).starts_with("ssh-broker: agent unavailable"));
    assert!(super::unavailable_message(Some(&"no profile")).contains("no profile"));
}

#[test]
fn connect_failure_in_the_callers_own_dir_fails_open_without_a_reason_on_stderr() {
    // A location that resolves but has no agent behind it: the old behaviour, message unchanged.
    let dir = std::env::temp_dir().join(format!("sb-shim-noagent-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let location = SocketLocation {
        path: dir.join("agent.sock"),
        dir: dir.clone(),
    };
    let mut stderr = Vec::new();
    let relayed = super::try_relay_at(
        Ok(location),
        &Some("echo hi".into()),
        &mut stderr,
        None,
        std::io::empty(),
        &mut NoRescue,
    )
    .unwrap();

    assert_eq!(relayed, None);
    assert_eq!(
        String::from_utf8(stderr).unwrap(),
        "ssh-broker: agent unavailable — falling back to a local shell\n"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn connect_failure_in_pty_mode_writes_nothing_to_stderr() {
    // A connect failure keeps the old rule: stderr would corrupt an interactive stream that the
    // relay may yet use, so the reason goes to the log only.
    let dir = std::env::temp_dir().join(format!("sb-shim-noagent-pty-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let location = SocketLocation {
        path: dir.join("agent.sock"),
        dir: dir.clone(),
    };
    let mut stderr = Vec::new();
    let relayed = super::try_relay_at(Ok(location), &None, &mut stderr, None, std::io::empty(), &mut NoRescue).unwrap();

    assert_eq!(relayed, None);
    assert!(stderr.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A fake agent that answers the first connection's handshake and stdin-EOF marker with `Exit(code)`
/// and returns the handshake it was sent.
fn fake_agent_exiting_with(
    listener: crate::afunix::Listener,
    code: i32,
) -> std::thread::JoinHandle<crate::protocol::Handshake> {
    use crate::afunix;
    use crate::protocol::{ExitCode, FrameKind, FrameReader, Handshake, Stream, read_one_frame, write_frame};
    std::thread::spawn(move || {
        let (mut rx, mut tx) = afunix::split(listener.accept().unwrap()).unwrap();
        let mut frames = FrameReader::new();
        let frame = read_one_frame(&mut rx, &mut frames).unwrap();
        assert_eq!(frame.kind, FrameKind::Handshake);
        // Read the stdin-EOF marker before answering, so nothing the shim sent is unread when
        // this side closes: an unread byte at close can make the peer lose the Exit.
        let eof = read_one_frame(&mut rx, &mut frames).unwrap();
        assert_eq!(
            (eof.kind, eof.payload.as_slice()),
            (FrameKind::Data, &[Stream::Stdin as u8][..])
        );
        write_frame(&mut tx, FrameKind::Exit, &ExitCode(code).encode()).unwrap();
        Handshake::decode(&frame.payload).unwrap()
    })
}

#[test]
fn try_relay_connects_to_the_location_its_provider_names() {
    use crate::afunix::Listener;
    // `run_on` hands `try_relay` the token's profile location. What `try_relay` must do with it
    // is use it and nothing else: a path it worked out from the environment would miss this
    // listener, which sits in a profile no environment variable names.
    let profile = crate::test_support::TempProfile::new("shim-wiring");
    let location = profile.location();
    crate::userdir::ensure_socket_dir(&location, &crate::acl::Sid::current_user().unwrap()).unwrap();
    let listener = Listener::bind(&location.path).unwrap();
    let agent = fake_agent_exiting_with(listener, 7);

    let relayed = super::try_relay(
        &Some("echo hi".into()),
        || Ok(location),
        None,
        std::io::empty(),
        &mut NoRescue,
    )
    .unwrap();

    assert_eq!(
        relayed,
        Some(7),
        "the shim reached the listener at the provided location"
    );
    assert_eq!(agent.join().unwrap().command.as_deref(), Some("echo hi"));
}

// A log that could not be set up -----

#[test]
fn a_failed_log_is_named_where_the_shim_already_explains_a_fallback_for_a_command() {
    let dir = std::env::temp_dir().join(format!("sb-shim-nolog-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let location = SocketLocation {
        path: dir.join("agent.sock"),
        dir: dir.clone(),
    };
    let mut stderr = Vec::new();
    let cause = "the folder belongs to someone else";
    let relayed = super::try_relay_at(
        Ok(location),
        &Some("echo hi".into()),
        &mut stderr,
        Some(cause),
        std::io::empty(),
        &mut NoRescue,
    )
    .unwrap();

    assert_eq!(relayed, None);
    let text = String::from_utf8(stderr).unwrap();
    assert!(text.starts_with("ssh-broker: agent unavailable"), "{text}");
    assert!(text.contains(cause), "the cause of the missing log is named: {text}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_failed_log_adds_nothing_to_an_interactive_fallback_that_prints_nothing_today() {
    // In PTY mode a connect failure writes nothing to stderr (it could corrupt the stream the relay
    // may yet use); a missing log does not change that.
    let dir = std::env::temp_dir().join(format!("sb-shim-nolog-pty-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let location = SocketLocation {
        path: dir.join("agent.sock"),
        dir: dir.clone(),
    };
    let mut stderr = Vec::new();
    let relayed = super::try_relay_at(
        Ok(location),
        &None,
        &mut stderr,
        Some("no log"),
        std::io::empty(),
        &mut NoRescue,
    )
    .unwrap();

    assert_eq!(relayed, None);
    assert!(stderr.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_failed_log_does_not_touch_the_stderr_of_a_relayed_command() {
    // The diagnostics buffer is the shim's own; a relayed command's stderr is the command's.
    use crate::afunix::Listener;
    let profile = crate::test_support::TempProfile::new("shim-nolog-relay");
    let location = profile.location();
    crate::userdir::ensure_socket_dir(&location, &crate::acl::Sid::current_user().unwrap()).unwrap();
    let agent = fake_agent_exiting_with(Listener::bind(&location.path).unwrap(), 0);
    let mut stderr = Vec::new();

    let relayed = super::try_relay_at(
        Ok(location),
        &Some("echo hi".into()),
        &mut stderr,
        Some("no log"),
        std::io::empty(),
        &mut NoRescue,
    )
    .unwrap();

    assert_eq!(relayed, Some(0));
    assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(&stderr));
    agent.join().unwrap();
}

// The rescue: a user with no agent -----

use crate::shim_offer::{Absent, Rescue, Rescued};

/// A rescue that records what it was shown and answers as told.
struct Scripted {
    answer: Option<Rescued>,
    /// Written to stderr before answering, like the notice.
    line: Option<&'static str>,
    /// `(exec, location resolved, connect failed)` per call.
    seen: Vec<(bool, bool, bool)>,
}

impl Scripted {
    fn answering(answer: Rescued) -> Scripted {
        Scripted {
            answer: Some(answer),
            line: None,
            seen: Vec::new(),
        }
    }
}

impl Rescue for Scripted {
    fn rescue(&mut self, absent: &Absent<'_>, stderr: &mut dyn std::io::Write) -> Rescued {
        self.seen
            .push((absent.exec, absent.location.is_ok(), absent.connect.is_err()));
        if let Some(line) = self.line {
            writeln!(stderr, "{line}").unwrap();
        }
        self.answer.take().expect("asked more than once")
    }
}

fn no_agent_location(tag: &str) -> (crate::test_support::TempProfile, SocketLocation) {
    let profile = crate::test_support::TempProfile::new(tag);
    let location = profile.location();
    (profile, location)
}

#[test]
fn a_rescue_is_asked_when_the_connect_fails_and_its_line_comes_before_the_fallback_message() {
    let (_profile, location) = no_agent_location("rescue-plain");
    let mut rescue = Scripted::answering(Rescued::Plain);
    rescue.line = Some("NOTICE");
    let mut stderr = Vec::new();
    let relayed = super::try_relay_at(
        Ok(location),
        &Some("echo hi".into()),
        &mut stderr,
        None,
        std::io::empty(),
        &mut rescue,
    )
    .unwrap();

    assert_eq!(relayed, None);
    assert_eq!(rescue.seen, [(true, true, true)]);
    assert_eq!(
        String::from_utf8(stderr).unwrap(),
        "NOTICE\nssh-broker: agent unavailable — falling back to a local shell\n"
    );
}

#[test]
fn a_rescue_is_shown_a_location_error_and_the_fallback_message_stays() {
    let mut rescue = Scripted::answering(Rescued::Plain);
    let mut stderr = Vec::new();
    let relayed = super::try_relay_at(
        Err(crate::userdir::NoProfile.into()),
        &None,
        &mut stderr,
        None,
        std::io::empty(),
        &mut rescue,
    )
    .unwrap();

    assert_eq!(relayed, None);
    assert_eq!(rescue.seen, [(false, false, true)]);
    let text = String::from_utf8(stderr).unwrap();
    assert!(text.contains("agent unavailable"), "{text}");
    assert!(text.contains("no profile directory"), "{text}");
}

#[test]
fn a_rescue_is_not_asked_when_the_connect_succeeds() {
    use crate::afunix::Listener;
    struct Never;
    impl Rescue for Never {
        fn rescue(&mut self, _: &Absent<'_>, _: &mut dyn std::io::Write) -> Rescued {
            panic!("an agent answered: nothing to rescue")
        }
    }
    let profile = crate::test_support::TempProfile::new("rescue-never");
    let location = profile.location();
    crate::userdir::ensure_socket_dir(&location, &crate::acl::Sid::current_user().unwrap()).unwrap();
    let agent = fake_agent_exiting_with(Listener::bind(&location.path).unwrap(), 5);

    let relayed = super::try_relay_at(
        Ok(location),
        &Some("echo hi".into()),
        &mut Vec::new(),
        None,
        std::io::empty(),
        &mut Never,
    )
    .unwrap();

    assert_eq!(relayed, Some(5));
    agent.join().unwrap();
}

#[test]
fn a_rescue_that_connects_gets_the_session_relayed_through_its_connection() {
    use crate::afunix::Listener;
    // The shim's own location has no agent; the rescue starts one somewhere the shim looks next.
    let (_empty, nowhere) = no_agent_location("rescue-empty");
    let served = crate::test_support::TempProfile::new("rescue-served");
    let at = served.location();
    crate::userdir::ensure_socket_dir(&at, &crate::acl::Sid::current_user().unwrap()).unwrap();
    let agent = fake_agent_exiting_with(Listener::bind(&at.path).unwrap(), 9);
    let socket = crate::afunix::connect(&at.path).unwrap();
    let mut rescue = Scripted::answering(Rescued::Connected { socket, modes: None });

    let relayed = super::try_relay_at(
        Ok(nowhere),
        &Some("echo hi".into()),
        &mut Vec::new(),
        None,
        std::io::empty(),
        &mut rescue,
    )
    .unwrap();

    assert_eq!(relayed, Some(9));
    assert_eq!(agent.join().unwrap().command.as_deref(), Some("echo hi"));
}

#[test]
fn a_rescue_that_finds_the_input_gone_ends_the_shim_with_255_and_runs_nothing() {
    let (_profile, location) = no_agent_location("rescue-gone");
    let mut rescue = Scripted::answering(Rescued::Gone);
    let mut stderr = Vec::new();
    let relayed = super::try_relay_at(Ok(location), &None, &mut stderr, None, std::io::empty(), &mut rescue).unwrap();

    assert_eq!(relayed, Some(255));
    assert!(stderr.is_empty(), "no fallback message: nothing runs");
}

// An agent that ends the connection before it says anything -----

/// A fake agent that takes one connection, reads `frames` frames from it, closes it, and then closes
/// its listener, so that the next connect finds nobody. The shim may connect again before the listener
/// closes; that connection is reset with it, and the shim goes round once more.
fn agent_that_hangs_up(listener: crate::afunix::Listener, frames: usize) -> std::thread::JoinHandle<()> {
    use crate::afunix;
    use crate::protocol::{FrameReader, read_one_frame};
    std::thread::spawn(move || {
        let (mut rx, tx) = afunix::split(listener.accept().unwrap()).unwrap();
        let mut reader = FrameReader::new();
        for _ in 0..frames {
            read_one_frame(&mut rx, &mut reader).unwrap();
        }
        drop((rx, tx));
        drop(listener);
    })
}

fn location_with_listener(
    tag: &str,
) -> (
    crate::test_support::TempProfile,
    SocketLocation,
    crate::afunix::Listener,
) {
    let profile = crate::test_support::TempProfile::new(tag);
    let location = profile.location();
    crate::userdir::ensure_socket_dir(&location, &crate::acl::Sid::current_user().unwrap()).unwrap();
    let listener = crate::afunix::Listener::bind(&location.path).unwrap();
    (profile, location, listener)
}

/// A rescue that must not be asked.
struct Never;

impl Rescue for Never {
    fn rescue(&mut self, _: &Absent<'_>, _: &mut dyn std::io::Write) -> Rescued {
        panic!("the shim asked for a rescue after the agent had ended its connection")
    }
}

#[test]
fn a_command_whose_connection_ends_before_the_agent_answers_says_it_may_have_run_and_is_not_run_locally() {
    // The frames read are none (the connection closes with the handshake unread), or the handshake and
    // the stdin-EOF marker an exec shim sends at once.
    for (tag, frames) in [("hangup-unread", 0), ("hangup-read", 2)] {
        let (_profile, location, listener) = location_with_listener(tag);
        let agent = agent_that_hangs_up(listener, frames);
        let mut stderr = Vec::new();

        let relayed = super::try_relay_at(
            Ok(location),
            &Some("echo hi".into()),
            &mut stderr,
            None,
            std::io::empty(),
            &mut Never,
        )
        .unwrap();
        agent.join().unwrap();

        assert_eq!(relayed, Some(255), "{tag}");
        let text = String::from_utf8(stderr).unwrap();
        assert_eq!(
            text,
            "ssh-broker: the agent ended before it answered; the command may or may not have run
",
            "{tag}"
        );
    }
}

#[test]
fn a_command_is_never_sent_to_an_agent_a_second_time() {
    // The agent may have started the command before it closed the connection, and the agent that
    // answers next could run it again. This agent is still there and would answer.
    use crate::afunix;
    use crate::protocol::{ExitCode, FrameKind, FrameReader, read_one_frame, write_frame};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let (_profile, location, listener) = location_with_listener("never-twice");
    let socket = location.path.clone();
    let stop = std::sync::Arc::new(AtomicBool::new(false));
    let connections = std::sync::Arc::new(AtomicUsize::new(0));
    let agent = std::thread::spawn({
        let (stop, connections) = (std::sync::Arc::clone(&stop), std::sync::Arc::clone(&connections));
        move || {
            loop {
                let conn = listener.accept().unwrap();
                if stop.load(Ordering::SeqCst) {
                    return;
                }
                let nth = connections.fetch_add(1, Ordering::SeqCst) + 1;
                let (mut rx, mut tx) = afunix::split(conn).unwrap();
                read_one_frame(&mut rx, &mut FrameReader::new()).unwrap();
                if nth > 1 {
                    // A second connection would be served: the command would run twice.
                    write_frame(&mut tx, FrameKind::Exit, &ExitCode(0).encode()).unwrap();
                    let _ = tx.shutdown_write();
                }
                drop((rx, tx));
            }
        }
    });

    let relayed = super::try_relay_at(
        Ok(location),
        &Some("echo hi".into()),
        &mut Vec::new(),
        None,
        std::io::empty(),
        &mut Never,
    )
    .unwrap();

    // Only now is the agent told to stop; its next accept is this connection.
    stop.store(true, Ordering::SeqCst);
    drop(afunix::connect(&socket).unwrap());
    agent.join().unwrap();
    assert_eq!(relayed, Some(255));
    assert_eq!(connections.load(Ordering::SeqCst), 1, "the command was sent again");
}

#[test]
fn an_interactive_session_whose_connection_ends_before_the_agent_answers_takes_the_no_agent_path() {
    use super::Interactive;
    use crate::shim::Pumped;
    let (_profile, location, listener) = location_with_listener("hangup-pty");
    let agent = agent_that_hangs_up(listener, 0);
    let mut rescue = Scripted::answering(Rescued::Plain);
    let mut stderr = Vec::new();
    let mut attempts = 0;

    let relayed = super::try_relay_with(
        Ok(location),
        &None,
        &mut stderr,
        None,
        std::io::empty(),
        &mut rescue,
        &mut |_conn, _modes| {
            attempts += 1;
            Ok(Interactive::Pumped(Pumped::closed(anyhow::Error::new(
                std::io::Error::from(std::io::ErrorKind::ConnectionReset),
            ))))
        },
    )
    .unwrap();
    agent.join().unwrap();

    // A connection made before the listener closed is reset with it, which sends the shim round again.
    assert!(attempts >= 1, "the shim never relayed");
    assert_eq!(relayed, None, "the shim fails open as it does for no agent");
    assert_eq!(rescue.seen, [(false, true, true)], "the no-agent path was taken once");
    assert!(stderr.is_empty(), "an interactive fallback prints nothing");
}

#[test]
fn an_interactive_session_goes_round_again_to_an_agent_that_answers_the_second_time() {
    use super::Interactive;
    use crate::relay::Outcome;
    use crate::shim::Pumped;
    let (_profile, location, listener) = location_with_listener("hangup-then-serve");
    let (finished, wait_finished) = std::sync::mpsc::channel::<()>();
    let agent = std::thread::spawn(move || {
        drop(listener.accept().unwrap());
        let second = listener.accept().unwrap();
        wait_finished.recv().ok();
        drop(second);
    });
    let mut attempts = 0;

    let relayed = super::try_relay_with(
        Ok(location),
        &None,
        &mut Vec::new(),
        None,
        std::io::empty(),
        &mut Never,
        &mut |_conn, _modes| {
            attempts += 1;
            Ok(Interactive::Pumped(if attempts == 1 {
                Pumped::closed(anyhow::Error::new(std::io::Error::from(
                    std::io::ErrorKind::ConnectionReset,
                )))
            } else {
                Pumped {
                    outcome: Ok(Outcome::Exited(7)),
                    heard: true,
                }
            }))
        },
    )
    .unwrap();
    finished.send(()).unwrap();
    agent.join().unwrap();

    assert_eq!(attempts, 2);
    assert_eq!(relayed, Some(7));
}

#[test]
fn an_interactive_session_goes_round_for_as_long_as_the_agent_hangs_up_and_answers_in_the_end() {
    // No count ends the loop: an agent that is there and has closed a hundred connections without a
    // byte is still asked again, and the session it then serves is the one relayed.
    use super::Interactive;
    use crate::relay::Outcome;
    use crate::shim::Pumped;
    const HANGUPS: usize = 100;
    let (_profile, location, listener) = location_with_listener("hangup-many");
    let (finished, wait_finished) = std::sync::mpsc::channel::<()>();
    let agent = std::thread::spawn(move || {
        for _ in 0..HANGUPS {
            drop(listener.accept().unwrap());
        }
        let last = listener.accept().unwrap();
        wait_finished.recv().ok();
        drop(last);
    });
    let mut attempts = 0;

    let relayed = super::try_relay_with(
        Ok(location),
        &None,
        &mut Vec::new(),
        None,
        std::io::empty(),
        &mut Never,
        &mut |_conn, _modes| {
            attempts += 1;
            Ok(Interactive::Pumped(if attempts <= HANGUPS {
                Pumped::closed(anyhow::Error::new(std::io::Error::from(
                    std::io::ErrorKind::ConnectionReset,
                )))
            } else {
                Pumped {
                    outcome: Ok(Outcome::Exited(7)),
                    heard: true,
                }
            }))
        },
    )
    .unwrap();

    // Before the agent is joined: a shim that gave up early leaves it waiting for connections.
    assert_eq!(attempts, HANGUPS + 1);
    assert_eq!(relayed, Some(7));
    finished.send(()).unwrap();
    agent.join().unwrap();
}
