//! Unit tests for the `shim_pty` module. Windows-only (the module is `#[cfg(windows)]`), so
//! these compile and run only on a Windows host — in CI, the `Test (windows/amd64)` job.

use super::{LocalChild, start_local, start_with_std_handles};
use crate::acl::Sid;
use crate::cmdline::{Exec, Login};
use crate::shim_offer::NoRescue;
use crate::test_support::asked_policies;

/// A command without a terminal: what `ssh host cmd` sends.
fn exec(command: &str) -> Exec {
    Exec {
        command: command.into(),
        terminal: false,
    }
}

/// A command with a terminal: what `ssh -t host cmd` sends.
fn exec_with_terminal(command: &str) -> Exec {
    Exec {
        command: command.into(),
        terminal: true,
    }
}

/// The local passthrough must contain its child in a job object, exactly as the relayed path
/// does, so that failing open can never become a way to outlive the session.
///
/// `start_local` is what every fail-open session funnels through, a command and a login alike. So
/// this containment is the sole thing between an unreachable agent and a process that outlives the
/// session the README promises to reap.
///
/// Gates the start only; `run_on`'s wiring is covered by `tests/fail_open_windows.rs` and
/// `tests/interactive_fail_open_containment.rs`.
///
/// Fails if the child is not in a job: it would keep running after the job handle drops.
#[test]
fn the_local_passthrough_child_is_contained_in_a_job() {
    use windows::Win32::Foundation::{STILL_ACTIVE, WAIT_OBJECT_0};
    use windows::Win32::System::Threading::{GetExitCodeProcess, INFINITE, WaitForSingleObject};

    // ~30s of doing nothing, so the child is certainly alive until something kills it. Its output
    // goes nowhere, since it shares the harness's standard handles.
    let LocalChild { process, _job } =
        start_local("cmd /c ping -n 30 127.0.0.1 >nul", None).expect("start a contained child");

    // Liveness as a state QUERY, never a timed wait. It is not decoration: without it the test
    // passes vacuously if the child failed to start or exited instantly, since the wait below
    // would then return immediately for the wrong reason.
    let mut code = 0u32;
    unsafe { GetExitCodeProcess(process.0, &mut code) }.expect("read the child's exit code");
    assert_eq!(
        code, STILL_ACTIVE.0 as u32,
        "the child must still be running before the job is dropped, or this test proves nothing"
    );

    drop(_job); // KILL_ON_JOB_CLOSE fires as the handle closes

    // UNBOUNDED on purpose. Containment makes this exit promptly; if it is broken the test hangs
    // until the CI job's own `timeout-minutes` — a loud failure. A numeric timeout here would be
    // a duration I picked, which is the hazard `no-sleep-sync` exists to catch, and an earlier
    // draft of this test tripped exactly that.
    let rc = unsafe { WaitForSingleObject(process.0, INFINITE) };
    assert_eq!(rc, WAIT_OBJECT_0, "dropping the job must terminate the contained child");
}

/// The fail-open start trims leading whitespace for `CreateProcessW`, which rejects it; the
/// relay's start does the same (`pipes_tests`).
#[test]
fn the_local_passthrough_start_accepts_whitespace_at_the_edges_of_a_command() {
    for command in [
        "  cmd.exe /c exit /b 3",
        "\tcmd.exe /c exit /b 3\r\n",
        "\r\ncmd.exe /c exit /b 3",
    ] {
        let child = start_local(command, None).unwrap_or_else(|e| panic!("{command:?}: {e:?}"));
        assert_eq!(child.finish().unwrap(), 3, "{command:?}");
    }
}

// The standard handles of the fail-open start -----

/// A handle value this process has no handle for, as a stale standard handle is (its handle closed after
/// the value was read). No table reaches this.
fn stale_handle() -> windows::Win32::Foundation::HANDLE {
    windows::Win32::Foundation::HANDLE(0x7fff_fff0usize as *mut core::ffi::c_void)
}

/// A shim with no standard handles at all starts its shell: a broken broker must not cost the user their
/// SSH access.
#[test]
fn a_shim_with_no_standard_handles_starts_its_shell() {
    let null = windows::Win32::Foundation::HANDLE::default();
    let child = start_with_std_handles("cmd.exe /c exit 3", [null; 3], None).expect("start with no handles");
    assert_eq!(child.finish().unwrap(), 3);
}

/// A null and a stale standard handle cannot go on the inherit list, and neither stops the shell.
#[test]
fn a_shim_with_a_missing_and_a_stale_standard_handle_still_starts_its_shell() {
    let null = windows::Win32::Foundation::HANDLE::default();
    let child = start_with_std_handles("cmd.exe /c exit 4", [null, stale_handle(), null], None)
        .expect("start with a null and a stale handle");
    assert_eq!(child.finish().unwrap(), 4);
    let child = start_with_std_handles("cmd.exe /c exit 5", [stale_handle(), null, stale_handle()], None)
        .expect("start with the stale handle twice");
    assert_eq!(child.finish().unwrap(), 5);
}

/// A broken shape: stdout is a live pipe and stderr a stale value. The shell starts and what it writes to the
/// live handle arrives.
#[test]
fn a_live_standard_handle_still_carries_the_output_when_another_is_stale() {
    use crate::test_support::{drain, text_of};
    use crate::winutil::OwnedHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Pipes::CreatePipe;

    let (mut read, mut write) = (HANDLE::default(), HANDLE::default());
    // SAFETY: valid out-pointers; both ends are closed by `OwnedHandle`.
    unsafe { CreatePipe(&mut read, &mut write, None, 0) }.expect("create a pipe");
    let (read, write) = (OwnedHandle(read), OwnedHandle(write));
    let null = HANDLE::default();

    let child = start_with_std_handles("cmd.exe /c echo live-stdout", [null, write.0, stale_handle()], None);
    // The child holds its own copy of the write end; this one closes so the pipe ends with the child.
    drop(write);
    let output = drain(read.0.0 as isize);
    let exit = child.map(|child| child.finish());
    let said = text_of(output);
    assert_eq!(
        exit.expect("start with a live stdout and a stale stderr").unwrap(),
        0,
        "it said:
{said}"
    );
    assert!(
        said.contains("live-stdout"),
        "it said:
{said:?}"
    );
}

/// A standard handle that is not on the inherit list is passed to the child as null, and the list has the
/// others: every value the start is handed is valid and inheritable, or null.
#[test]
fn a_standard_handle_that_cannot_be_inherited_is_passed_as_null() {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Pipes::CreatePipe;

    let (mut read, mut write) = (HANDLE::default(), HANDLE::default());
    // SAFETY: valid out-pointers; both ends are closed by `OwnedHandle`.
    unsafe { CreatePipe(&mut read, &mut write, None, 0) }.expect("create a pipe");
    let (_read, write) = (crate::winutil::OwnedHandle(read), crate::winutil::OwnedHandle(write));
    let null = HANDLE::default();

    let (passed, inherit) = super::inheritable_std_handles([null, write.0, stale_handle()]);
    assert_eq!(passed, [null, write.0, null]);
    assert_eq!(inherit, vec![write.0]);
}

// Where the shim connects, and what it says when it cannot ------------------------------

use crate::shim_offer::Folder;
use crate::socket_loc::{SocketLocation, SocketLocationError};

/// The shim's folder at `location`, walked as this account: what `run_on` holds from its first act.
fn folder_of(location: anyhow::Result<SocketLocation>) -> Folder {
    Folder::in_location(location, Sid::current_user())
}

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
        &folder_of(Err(too_long())),
        &Login {
            exec: Some(exec("echo hi")),
            elevation: None,
        },
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
        &folder_of(Err(too_long())),
        &Login {
            exec: None,
            elevation: None,
        },
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
    let location = crate::test_support::location_in(&dir);
    let mut stderr = Vec::new();
    let relayed = super::try_relay_at(
        &folder_of(Ok(location)),
        &Login {
            exec: Some(exec("echo hi")),
            elevation: None,
        },
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
    let location = crate::test_support::location_in(&dir);
    let mut stderr = Vec::new();
    let relayed = super::try_relay_at(
        &folder_of(Ok(location)),
        &Login {
            exec: None,
            elevation: None,
        },
        &mut stderr,
        None,
        std::io::empty(),
        &mut NoRescue,
    )
    .unwrap();

    assert_eq!(relayed, None);
    assert!(stderr.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A stand-in agent (a [`CountingAgent`]) that answers each connection's handshake with `Serving`, reads the
/// stdin-EOF marker that follows, and ends with `Exit(code)`. The handshakes it was sent come on the receiver.
fn fake_agent_exiting_with(
    listener: crate::afunix::Listener,
    socket: &std::path::Path,
    code: i32,
) -> (CountingAgent, mpsc::Receiver<crate::protocol::Handshake>) {
    use crate::protocol::{ExitCode, FrameKind, FrameReader, Handshake, Stream, read_one_frame, write_frame};
    let (handshakes, received) = mpsc::channel();
    let agent = CountingAgent::start(listener, socket, move |_, mut rx, mut tx| {
        let mut frames = FrameReader::new();
        let frame = read_one_frame(&mut rx, &mut frames).unwrap();
        assert_eq!(frame.kind, FrameKind::Handshake);
        // The shim sends no input before this.
        crate::relay::write_serving(&mut tx).unwrap();
        // Read the stdin-EOF marker before answering, so nothing the shim sent is unread when
        // this side closes: an unread byte at close can make the peer lose the Exit.
        let eof = read_one_frame(&mut rx, &mut frames).unwrap();
        assert_eq!(
            (eof.kind, eof.payload.as_slice()),
            (FrameKind::Data, &[Stream::Stdin as u8][..])
        );
        write_frame(&mut tx, FrameKind::Exit, &ExitCode(code).encode()).unwrap();
        // The receiver is dropped by a test that does not look at the handshake.
        let _ = handshakes.send(Handshake::decode(&frame.payload).unwrap());
        After::Keep
    });
    (agent, received)
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
    let listener = Listener::bind(location.path(), crate::socket_loc::Integrity::Medium).unwrap();
    let (agent, handshakes) = fake_agent_exiting_with(listener, location.path(), 7);

    let relayed = super::try_relay(
        &Login {
            exec: Some(exec("echo hi")),
            elevation: None,
        },
        &folder_of(Ok(location)),
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
    assert_eq!(agent.finish(), 1);
    assert_eq!(handshakes.recv().unwrap().command.as_deref(), Some("echo hi"));
}

// A log that could not be set up -----

#[test]
fn a_failed_log_is_named_where_the_shim_already_explains_a_fallback_for_a_command() {
    let dir = std::env::temp_dir().join(format!("sb-shim-nolog-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let location = crate::test_support::location_in(&dir);
    let mut stderr = Vec::new();
    let cause = "the folder belongs to someone else";
    let relayed = super::try_relay_at(
        &folder_of(Ok(location)),
        &Login {
            exec: Some(exec("echo hi")),
            elevation: None,
        },
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
    let location = crate::test_support::location_in(&dir);
    let mut stderr = Vec::new();
    let relayed = super::try_relay_at(
        &folder_of(Ok(location)),
        &Login {
            exec: None,
            elevation: None,
        },
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
    let profile = crate::test_support::TempProfile::new("nolog-relay");
    let location = profile.location();
    crate::userdir::ensure_socket_dir(&location, &crate::acl::Sid::current_user().unwrap()).unwrap();
    let (agent, _) = fake_agent_exiting_with(
        Listener::bind(location.path(), crate::socket_loc::Integrity::Medium).unwrap(),
        location.path(),
        0,
    );
    let mut stderr = Vec::new();

    let relayed = super::try_relay_at(
        &folder_of(Ok(location)),
        &Login {
            exec: Some(exec("echo hi")),
            elevation: None,
        },
        &mut stderr,
        Some("no log"),
        std::io::empty(),
        &mut NoRescue,
    )
    .unwrap();

    assert_eq!(relayed, Some(0));
    assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(&stderr));
    assert_eq!(agent.finish(), 1);
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
            .push((absent.exec, absent.folder.location().is_ok(), absent.connect.is_err()));
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
        &folder_of(Ok(location)),
        &Login {
            exec: Some(exec("echo hi")),
            elevation: None,
        },
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
        &folder_of(Err(crate::userdir::NoProfile.into())),
        &Login {
            exec: None,
            elevation: None,
        },
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
    let (agent, _) = fake_agent_exiting_with(
        Listener::bind(location.path(), crate::socket_loc::Integrity::Medium).unwrap(),
        location.path(),
        5,
    );

    let relayed = super::try_relay_at(
        &folder_of(Ok(location)),
        &Login {
            exec: Some(exec("echo hi")),
            elevation: None,
        },
        &mut Vec::new(),
        None,
        std::io::empty(),
        &mut Never,
    )
    .unwrap();

    assert_eq!(relayed, Some(5));
    assert_eq!(agent.finish(), 1);
}

#[test]
fn a_rescue_that_connects_gets_the_session_relayed_through_its_connection() {
    use crate::afunix::Listener;
    // The shim's own location has no agent; the rescue starts one somewhere the shim looks next.
    let (_empty, nowhere) = no_agent_location("rescue-empty");
    let served = crate::test_support::TempProfile::new("rescue-served");
    let at = served.location();
    crate::userdir::ensure_socket_dir(&at, &crate::acl::Sid::current_user().unwrap()).unwrap();
    let (agent, handshakes) = fake_agent_exiting_with(
        Listener::bind(at.path(), crate::socket_loc::Integrity::Medium).unwrap(),
        at.path(),
        9,
    );
    let socket = crate::afunix::connect(at.path()).unwrap();
    let mut rescue = Scripted::answering(Rescued::Connected { socket, modes: None });

    let relayed = super::try_relay_at(
        &folder_of(Ok(nowhere)),
        &Login {
            exec: Some(exec("echo hi")),
            elevation: None,
        },
        &mut Vec::new(),
        None,
        std::io::empty(),
        &mut rescue,
    )
    .unwrap();

    assert_eq!(relayed, Some(9));
    assert_eq!(agent.finish(), 1);
    assert_eq!(handshakes.recv().unwrap().command.as_deref(), Some("echo hi"));
}

#[test]
fn a_rescue_that_finds_the_input_gone_ends_the_shim_with_255_and_runs_nothing() {
    let (_profile, location) = no_agent_location("rescue-gone");
    let mut rescue = Scripted::answering(Rescued::Gone);
    let mut stderr = Vec::new();
    let relayed = super::try_relay_at(
        &folder_of(Ok(location)),
        &Login {
            exec: None,
            elevation: None,
        },
        &mut stderr,
        None,
        std::io::empty(),
        &mut rescue,
    )
    .unwrap();

    assert_eq!(relayed, Some(255));
    assert!(stderr.is_empty(), "no fallback message: nothing runs");
}

// An agent that ends the connection before it says anything -----

/// A stand-in agent (a [`CountingAgent`]) that takes one connection, reads `frames` frames from it, closes its
/// listener and then the connection, so that the next connect finds nobody: it is an agent that is ending.
fn agent_that_hangs_up(listener: crate::afunix::Listener, socket: &std::path::Path, frames: usize) -> CountingAgent {
    use crate::protocol::{FrameReader, read_one_frame};
    CountingAgent::start(listener, socket, move |_, mut rx, tx| {
        let mut reader = FrameReader::new();
        for _ in 0..frames {
            read_one_frame(&mut rx, &mut reader).unwrap();
        }
        After::Retire(rx, tx)
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
    let listener = crate::afunix::Listener::bind(location.path(), crate::socket_loc::Integrity::Medium).unwrap();
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
    // The frames read are none (the connection closes with the handshake unread), or the handshake, which is
    // all an exec shim sends until the agent answers.
    for (tag, frames) in [("hangup-unread", 0), ("hangup-read", 1)] {
        let (_profile, location, listener) = location_with_listener(tag);
        let agent = agent_that_hangs_up(listener, location.path(), frames);
        let mut stderr = Vec::new();

        let relayed = super::try_relay_at(
            &folder_of(Ok(location)),
            &Login {
                exec: Some(exec("echo hi")),
                elevation: None,
            },
            &mut stderr,
            None,
            std::io::empty(),
            &mut Never,
        )
        .unwrap();
        assert_eq!(agent.finish(), 1, "{tag}");

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
    use crate::protocol::{ExitCode, FrameKind, FrameReader, read_one_frame, write_frame};
    let (_profile, location, listener) = location_with_listener("never-twice");
    let agent = CountingAgent::start(listener, location.path(), |nth, mut rx, mut tx| {
        read_one_frame(&mut rx, &mut FrameReader::new()).unwrap();
        if nth > 1 {
            // A second connection would be served: the command would run twice.
            write_frame(&mut tx, FrameKind::Exit, &ExitCode(0).encode()).unwrap();
            let _ = tx.shutdown_write();
        }
        After::Keep
    });

    let relayed = super::try_relay_at(
        &folder_of(Ok(location)),
        &Login {
            exec: Some(exec("echo hi")),
            elevation: None,
        },
        &mut Vec::new(),
        None,
        std::io::empty(),
        &mut Never,
    )
    .unwrap();

    assert_eq!(relayed, Some(255));
    assert_eq!(agent.finish(), 1, "the command was sent again");
}

#[test]
fn an_interactive_session_whose_connection_ends_before_the_agent_answers_takes_the_no_agent_path() {
    use super::Interactive;
    use crate::shim::Pumped;
    let (_profile, location, listener) = location_with_listener("hangup-pty");
    let mut agent = Some(agent_that_hangs_up(listener, location.path(), 0));
    let mut rescue = Scripted::answering(Rescued::Plain);
    let mut stderr = Vec::new();
    let mut attempts = 0;

    let relayed = super::try_relay_with(
        &folder_of(Ok(location)),
        &Login {
            exec: None,
            elevation: None,
        },
        &mut stderr,
        None,
        std::io::empty(),
        &mut rescue,
        &mut |_conn, _modes, _login| {
            attempts += 1;
            // The pump ends when the agent closes the connection, which it does after its listener.
            let agent = agent.take().expect("one attempt");
            agent.wait_retired();
            assert_eq!(agent.finish(), 1);
            Ok(Interactive::Pumped(Pumped::closed(anyhow::Error::new(
                std::io::Error::from(std::io::ErrorKind::ConnectionReset),
            ))))
        },
    )
    .unwrap();

    assert_eq!(attempts, 1);
    assert_eq!(relayed, None, "the shim fails open as it does for no agent");
    assert_eq!(rescue.seen, [(false, true, true)], "the no-agent path was taken once");
    assert!(stderr.is_empty(), "an interactive fallback prints nothing");
}

#[test]
fn an_interactive_session_goes_round_again_to_an_agent_that_answers_the_second_time() {
    use super::Interactive;
    use crate::relay::Outcome;
    use crate::shim::Pumped;
    let (_profile, location, listener) = location_with_listener("hangup-serve");
    // The first connection is closed without a byte, and the second is held until the agent is finished.
    let mut held = Vec::new();
    let agent = CountingAgent::start(listener, location.path(), move |nth, rx, tx| {
        if nth > 1 {
            held.push((rx, tx));
        }
        After::Keep
    });
    let mut attempts = 0;

    let relayed = super::try_relay_with(
        &folder_of(Ok(location)),
        &Login {
            exec: None,
            elevation: None,
        },
        &mut Vec::new(),
        None,
        std::io::empty(),
        &mut Never,
        &mut |_conn, _modes, _login| {
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
    agent.finish();

    assert_eq!(attempts, 2);
    assert_eq!(relayed, Some(7));
}

/// A stand-in agent (a [`CountingAgent`]) that closes each connection without a byte and keeps its listener
/// until it is finished.
fn agent_that_always_hangs_up(listener: crate::afunix::Listener, socket: &std::path::Path) -> CountingAgent {
    CountingAgent::start(listener, socket, |_, rx, tx| {
        drop((rx, tx));
        After::Keep
    })
}

fn hung_up() -> super::Interactive {
    super::Interactive::Pumped(crate::shim::Pumped::closed(anyhow::Error::new(std::io::Error::from(
        std::io::ErrorKind::ConnectionReset,
    ))))
}

#[test]
fn a_second_connection_that_ends_without_a_byte_is_a_protocol_violation_not_a_reason_to_connect_again() {
    // An agent that follows the protocol closes a connection without a byte only while its listener
    // closes, so the connect after that fails or reaches an agent that answers. This one is still
    // there and hangs up again.
    let (_profile, location, listener) = location_with_listener("hangup-twice");
    let socket = location.path().to_path_buf();
    let agent = agent_that_always_hangs_up(listener, location.path());
    let mut stderr = Vec::new();
    let mut attempts = 0;

    let relayed = super::try_relay_with(
        &folder_of(Ok(location)),
        &Login {
            exec: None,
            elevation: None,
        },
        &mut stderr,
        None,
        std::io::empty(),
        &mut Never,
        &mut |_conn, _modes, _login| {
            attempts += 1;
            // Not a loop limit of the shim: the test fails instead of hanging if the shim never stops.
            assert!(
                attempts <= 2,
                "the shim connected a third time to an agent that hung up twice"
            );
            Ok(hung_up())
        },
    )
    .unwrap();
    agent.finish();

    assert_eq!(attempts, 2);
    assert_eq!(relayed, Some(254));
    assert_eq!(
        String::from_utf8(stderr).unwrap(),
        format!(
            "ssh-broker: the agent at {} closed the connection twice without answering; it may be a different ssh-broker version
",
            socket.display()
        )
    );
}

#[test]
fn a_folder_that_was_missing_at_the_first_act_is_connected_through_when_it_appears_and_counts_the_closes() {
    // The shim's walk found no `AppData` and held nothing. The folders appear, and an agent that keeps
    // hanging up without a byte listens in them: the connect looks again and goes through them, so the
    // second close is a protocol violation and not a reason to connect again.
    let profile = crate::test_support::TempProfile::new("hangup-late");
    let location = profile.location();
    std::fs::remove_dir_all(profile.0.join("AppData")).unwrap();
    let folder = folder_of(Ok(location.clone()));
    assert!(folder.refusal().is_none(), "no folder is not a refused one");
    std::fs::create_dir_all(profile.0.join(r"AppData\Local")).unwrap();
    crate::userdir::ensure_socket_dir(&location, &Sid::current_user().unwrap()).unwrap();
    let agent = agent_that_always_hangs_up(
        crate::afunix::Listener::bind(location.path(), crate::socket_loc::Integrity::Medium).unwrap(),
        location.path(),
    );
    let mut stderr = Vec::new();
    let mut attempts = 0;

    let relayed = super::try_relay_with(
        &folder,
        &Login {
            exec: None,
            elevation: None,
        },
        &mut stderr,
        None,
        std::io::empty(),
        &mut Never,
        &mut |_conn, _modes, _login| {
            attempts += 1;
            assert!(
                attempts <= 2,
                "the shim connected a third time to an agent that hung up twice"
            );
            Ok(hung_up())
        },
    )
    .unwrap();
    agent.finish();

    assert_eq!(attempts, 2);
    assert_eq!(relayed, Some(254));
}

/// A rescue that answers from a list.
struct Answers(std::collections::VecDeque<Rescued>);

impl Rescue for Answers {
    fn rescue(&mut self, _: &Absent<'_>, _: &mut dyn std::io::Write) -> Rescued {
        self.0.pop_front().expect("asked more often than answered")
    }
}

#[test]
fn a_no_byte_close_before_and_after_a_connect_that_failed_are_not_consecutive() {
    // The first agent ends: it hangs up and its listener is gone. The connect after that fails and the
    // rescue starts another agent, which hangs up on its first connection without a byte, too. That is
    // a different agent, not the same one twice.
    use crate::afunix::Listener;
    let (_profile, location, listener) = location_with_listener("hu-first");
    let mut first = Some(agent_that_hangs_up(listener, location.path(), 0));
    let served = crate::test_support::TempProfile::new("hu-served");
    let at = served.location();
    crate::userdir::ensure_socket_dir(&at, &crate::acl::Sid::current_user().unwrap()).unwrap();
    let second = agent_that_always_hangs_up(
        Listener::bind(at.path(), crate::socket_loc::Integrity::Medium).unwrap(),
        at.path(),
    );
    let socket = crate::afunix::connect(at.path()).unwrap();
    let mut rescue = Answers([Rescued::Connected { socket, modes: None }, Rescued::Plain].into());
    let mut attempts = 0;

    let relayed = super::try_relay_with(
        &folder_of(Ok(location)),
        &Login {
            exec: None,
            elevation: None,
        },
        &mut Vec::new(),
        None,
        std::io::empty(),
        &mut rescue,
        &mut |_conn, _modes, _login| {
            attempts += 1;
            // The pump of the first connection ends when the agent closes it, after its listener.
            if let Some(first) = first.take() {
                first.wait_retired();
                assert_eq!(first.finish(), 1);
            }
            Ok(hung_up())
        },
    )
    .unwrap();
    second.finish();

    assert_eq!(attempts, 2);
    assert_eq!(relayed, None, "the last rescue gave up: the shim fails open");
    assert!(rescue.0.is_empty(), "the rescue was asked after each failed connect");
}

// A command with a terminal -----

#[test]
fn a_command_with_a_console_relays_as_a_pty_session_with_the_command() {
    use super::Interactive;
    use crate::relay::Outcome;
    use crate::shim::Pumped;
    let (_profile, location, _listener) = location_with_listener("term-command");
    let mut asked = Vec::new();

    let relayed = super::try_relay_with(
        &folder_of(Ok(location)),
        &Login {
            exec: Some(exec_with_terminal("echo  hi")),
            elevation: None,
        },
        &mut Vec::new(),
        None,
        std::io::empty(),
        &mut Never,
        &mut |_conn, _modes, login| {
            asked.push(login.exec.as_ref().map(|exec| exec.command.clone()));
            Ok(Interactive::Pumped(Pumped {
                outcome: Ok(Outcome::Exited(3)),
                heard: true,
            }))
        },
    )
    .unwrap();

    assert_eq!(relayed, Some(3));
    assert_eq!(
        asked,
        [Some("echo  hi".to_string())],
        "the console relay carries the command"
    );
}

#[test]
fn a_command_without_a_terminal_does_not_take_the_console_relay() {
    let (_profile, location, listener) = location_with_listener("exec-not-pty");
    let (agent, handshakes) = fake_agent_exiting_with(listener, location.path(), 4);

    let relayed = super::try_relay_with(
        &folder_of(Ok(location)),
        &Login {
            exec: Some(exec("echo hi")),
            elevation: None,
        },
        &mut Vec::new(),
        None,
        std::io::empty(),
        &mut Never,
        &mut |_conn, _modes, _login| panic!("a command without a terminal used the console relay"),
    )
    .unwrap();

    assert_eq!(relayed, Some(4));
    assert_eq!(agent.finish(), 1);
    assert_eq!(handshakes.recv().unwrap().command.as_deref(), Some("echo hi"));
}

#[test]
fn a_command_asks_the_agent_for_the_policy_of_its_login() {
    for (n, elevation) in asked_policies().enumerate() {
        let (_profile, location, listener) = location_with_listener(&format!("pol-exec-{n}"));
        let (agent, handshakes) = fake_agent_exiting_with(listener, location.path(), 0);
        let relayed = super::try_relay_with(
            &folder_of(Ok(location)),
            &Login {
                exec: Some(exec("whoami")),
                elevation,
            },
            &mut Vec::new(),
            None,
            std::io::empty(),
            &mut Never,
            &mut |_conn, _modes, _login| panic!("a command without a terminal used the console relay"),
        )
        .unwrap();
        assert_eq!(relayed, Some(0), "{elevation:?}");
        assert_eq!(agent.finish(), 1, "{elevation:?}");
        let handshake = handshakes.recv().unwrap();
        assert_eq!(handshake.elevation, elevation);
        assert_eq!(handshake.command.as_deref(), Some("whoami"), "{elevation:?}");
    }
}

#[test]
fn a_login_with_a_console_reaches_the_console_relay_with_its_policy() {
    use super::Interactive;
    use crate::relay::Outcome;
    use crate::shim::Pumped;
    for (n, elevation) in asked_policies().enumerate() {
        for (tag, exec) in [("login", None), ("term", Some(exec_with_terminal("whoami")))] {
            let (_profile, location, _listener) = location_with_listener(&format!("pol-{tag}-{n}"));
            let mut asked = Vec::new();
            let relayed = super::try_relay_with(
                &folder_of(Ok(location)),
                &Login { exec, elevation },
                &mut Vec::new(),
                None,
                std::io::empty(),
                &mut Never,
                &mut |_conn, _modes, login| {
                    asked.push(login.elevation);
                    Ok(Interactive::Pumped(Pumped {
                        outcome: Ok(Outcome::Exited(3)),
                        heard: true,
                    }))
                },
            )
            .unwrap();
            assert_eq!(relayed, Some(3), "{tag} {elevation:?}");
            assert_eq!(asked, [elevation], "{tag}");
        }
    }
}

#[test]
fn an_unanswered_terminal_command_is_not_sent_again() {
    // The agent may have started the command before it ended the connection. This agent is still
    // listening and would take a second one.
    let (_profile, location, listener) = location_with_listener("terminal-twice");
    let agent = agent_that_always_hangs_up(listener, location.path());
    let mut stderr = Vec::new();
    let mut attempts = 0;

    let relayed = super::try_relay_with(
        &folder_of(Ok(location)),
        &Login {
            exec: Some(exec_with_terminal("echo hi")),
            elevation: None,
        },
        &mut stderr,
        None,
        std::io::empty(),
        &mut Never,
        &mut |_conn, _modes, _login| {
            attempts += 1;
            assert!(attempts <= 1, "the command was sent again");
            Ok(hung_up())
        },
    )
    .unwrap();
    agent.finish();

    assert_eq!(attempts, 1);
    assert_eq!(relayed, Some(255));
    assert_eq!(
        String::from_utf8(stderr).unwrap(),
        "ssh-broker: the agent ended before it answered; the command may or may not have run\n"
    );
}

// An agent that hands the session back -----

/// What a login sees when the agent hands its session back for `cause`.
fn hand_back_line(cause: &str) -> String {
    format!(
        "ssh-broker: agent unavailable — falling back to a local shell (the agent could not prepare an unelevated \
         session: {cause})\n"
    )
}

/// What a stand-in agent does once it has served a connection.
enum After {
    /// Take the next connection.
    Keep,
    /// End. The listener closes first, so that a connect made once this connection is seen to close finds nobody,
    /// and then the connection's halves close.
    Retire(crate::afunix::ConnRx, crate::afunix::ConnTx),
}

/// A stand-in agent that serves each connection with `answer(nth, rx, tx)` on a thread of its own until it
/// retires ([`After::Retire`]) or is finished, and counts the connections.
struct CountingAgent {
    stop: Arc<AtomicBool>,
    connections: Arc<std::sync::atomic::AtomicUsize>,
    /// Set before the listener closes, on a retirement or a stop: a connect refused after it is no fault.
    ending: Arc<AtomicBool>,
    /// Sent once the listener and the connection of a retirement have closed.
    retired: mpsc::Receiver<()>,
    socket: std::path::PathBuf,
    thread: std::thread::JoinHandle<()>,
}

impl CountingAgent {
    fn start(
        listener: crate::afunix::Listener,
        socket: &std::path::Path,
        mut answer: impl FnMut(usize, crate::afunix::ConnRx, crate::afunix::ConnTx) -> After + Send + 'static,
    ) -> CountingAgent {
        use crate::afunix::AcceptError;
        use std::sync::atomic::AtomicUsize;
        let stop = Arc::new(AtomicBool::new(false));
        let connections = Arc::new(AtomicUsize::new(0));
        let ending = Arc::new(AtomicBool::new(false));
        let (retired_tx, retired) = mpsc::channel();
        let thread = std::thread::spawn({
            let (stop, connections, ending) = (Arc::clone(&stop), Arc::clone(&connections), Arc::clone(&ending));
            move || {
                loop {
                    let conn = match listener.accept() {
                        Ok(conn) => conn,
                        // A connection lost while it queued (the sentinel of `finish` may be one) or an
                        // interrupted call serves nobody: the next accept, or the end.
                        Err(AcceptError::Connection(_) | AcceptError::Interrupted(_)) => {
                            if stop.load(Ordering::SeqCst) {
                                break;
                            }
                            continue;
                        }
                        Err(e) => panic!("the stand-in agent could not accept: {e:?}"),
                    };
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let nth = connections.fetch_add(1, Ordering::SeqCst) + 1;
                    let (rx, tx) = crate::afunix::split(conn).unwrap();
                    match answer(nth, rx, tx) {
                        After::Keep => {}
                        After::Retire(rx, tx) => {
                            ending.store(true, Ordering::SeqCst);
                            drop(listener);
                            drop((rx, tx));
                            let _ = retired_tx.send(());
                            return;
                        }
                    }
                }
                // Stopped: the listener closes as this returns, and a connection queued after it is refused.
                ending.store(true, Ordering::SeqCst);
            }
        });
        CountingAgent {
            stop,
            connections,
            ending,
            retired,
            socket: socket.to_path_buf(),
            thread,
        }
    }

    /// Wait until the agent has retired: its listener and the connection that retired it are closed.
    fn wait_retired(&self) {
        self.retired.recv().expect("the stand-in agent ended without retiring");
    }

    /// Stop the agent, which takes the connection this makes as its last, and return how many it served. One
    /// that is queued and not yet accepted when this is called is not served or counted.
    fn finish(self) -> usize {
        self.stop.store(true, Ordering::SeqCst);
        match crate::afunix::connect(&self.socket) {
            Ok(sentinel) => drop(sentinel),
            // An agent that is ending closed its listener first (it retired, or took a connection queued
            // before this one as the last): nothing is waiting to be woken.
            Err(_) if self.ending.load(Ordering::SeqCst) => {}
            Err(e) => {
                // An answer that panicked has closed the listener on its way out; its panic is the cause.
                if self.thread.is_finished() {
                    self.thread.join().unwrap();
                }
                panic!("the stand-in agent's listener refused the connection that stops it: {e:#}");
            }
        }
        self.thread.join().unwrap();
        self.connections.load(Ordering::SeqCst)
    }
}

/// A command without a terminal that the agent hands back is not run by the agent and is not sent again; the
/// shim says why on stderr, falls open (`Ok(None)`), and has read none of its stdin: the shell that runs
/// the command gets it.
#[test]
fn a_command_the_agent_hands_back_falls_open_after_the_cause_with_its_stdin_unread_and_one_connect() {
    use crate::protocol::{FrameReader, read_one_frame};
    use crate::test_support::RecordedInput;
    let (_profile, location, listener) = location_with_listener("handback-exec");
    let agent = CountingAgent::start(listener, location.path(), |_, mut rx, mut tx| {
        let frame = read_one_frame(&mut rx, &mut FrameReader::new()).unwrap();
        assert_eq!(frame.kind, crate::protocol::FrameKind::Handshake);
        crate::relay::write_hand_back(&mut tx, "the token cannot be made").unwrap();
        // Nothing the shim sent is unread (it sent the handshake and, until the answer, nothing else), so
        // closing at once cannot lose the answer. The shim may have gone first.
        let _ = tx.shutdown_write();
        After::Keep
    });
    let (stdin, input_dropped, reads) = RecordedInput::new(b"for the shell that runs the command");
    let mut stderr = Vec::new();

    let relayed = super::try_relay_with(
        &folder_of(Ok(location)),
        &Login {
            exec: Some(exec("echo hi")),
            elevation: None,
        },
        &mut stderr,
        None,
        stdin,
        &mut Never,
        &mut |_conn, _modes, _login| panic!("a command without a terminal used the console relay"),
    )
    .unwrap();

    assert_eq!(relayed, None, "the command falls open");
    assert_eq!(
        String::from_utf8(stderr).unwrap(),
        hand_back_line("the token cannot be made")
    );
    input_dropped.recv().expect("the input is dropped when the relay ends");
    assert_eq!(reads.load(Ordering::SeqCst), 0, "stdin was read");
    assert_eq!(agent.finish(), 1, "the command was sent again");
}

/// The same for a session with a terminal, with and without a command: the relay's answer is the hand-back, so
/// the console has been given back, and nothing connects a second time (a second connect is a second call of the
/// relay).
#[test]
fn a_session_with_a_terminal_the_agent_hands_back_falls_open_after_the_cause_with_one_connect() {
    use super::Interactive;
    use crate::relay::Outcome;
    use crate::shim::Pumped;
    for (n, exec) in [(0, None), (1, Some(exec_with_terminal("whoami")))] {
        // The stand-in console relay does not use the connection, so the listener only has to exist.
        let (_profile, location, _listener) = location_with_listener(&format!("handback-pty-{n}"));
        let mut stderr = Vec::new();
        let mut attempts = 0;

        let relayed = super::try_relay_with(
            &folder_of(Ok(location)),
            &Login { exec, elevation: None },
            &mut stderr,
            None,
            std::io::empty(),
            &mut Never,
            &mut |_conn, _modes, _login| {
                attempts += 1;
                Ok(Interactive::Pumped(Pumped {
                    outcome: Ok(Outcome::HandedBack("the token cannot be made".into())),
                    heard: true,
                }))
            },
        )
        .unwrap();

        assert_eq!(relayed, None, "{n}: falls open");
        assert_eq!(attempts, 1, "{n}");
        assert_eq!(
            String::from_utf8(stderr).unwrap(),
            hand_back_line("the token cannot be made"),
            "{n}"
        );
    }
}

/// An agent that closes every connection without a byte, answer included, is not a hand-back: a command is
/// not run again, and the message is the one it was.
#[test]
fn a_close_without_a_byte_is_not_a_hand_back() {
    let (_profile, location, listener) = location_with_listener("nobyte");
    let agent = agent_that_always_hangs_up(listener, location.path());
    let mut stderr = Vec::new();

    let relayed = super::try_relay_with(
        &folder_of(Ok(location)),
        &Login {
            exec: Some(exec("echo hi")),
            elevation: None,
        },
        &mut stderr,
        None,
        std::io::empty(),
        &mut Never,
        &mut |_conn, _modes, _login| panic!("a command without a terminal used the console relay"),
    )
    .unwrap();
    agent.finish();

    assert_eq!(relayed, Some(255));
    let text = String::from_utf8(stderr).unwrap();
    assert!(text.contains("the agent ended before it answered"), "{text}");
    assert!(!text.contains("falling back"), "{text}");
}

// The input worker of a terminal session -----

use super::Input;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};

/// The worker is started by the answer: before it the write half is held and no thread exists.
#[test]
fn the_input_worker_is_not_started_until_the_answer_and_then_gets_the_write_half() {
    let mut input = Input::Waiting("the write half");
    let mut spawned = Vec::new();
    input
        .start(|tx| {
            spawned.push(tx);
            std::thread::spawn(|| {})
        })
        .unwrap();
    assert_eq!(spawned, ["the write half"]);
    // Started once: a second answer is refused and spawns nothing.
    assert!(input.start(|_| panic!("started twice")).is_err());
    input.end(|| {}, |_| panic!("a started worker is joined, not closed unstarted"));
}

/// Teardown of a worker that was started stops it, then joins it.
#[test]
fn a_started_input_worker_is_stopped_then_joined() {
    let (release, wait_for_stop) = mpsc::channel::<()>();
    let finished = Arc::new(AtomicBool::new(false));
    let mut input = Input::Waiting(());
    input
        .start(|()| {
            let finished = Arc::clone(&finished);
            std::thread::spawn(move || {
                // Ends only when told to stop, as the console read does when woken.
                wait_for_stop.recv().unwrap();
                finished.store(true, Ordering::SeqCst);
            })
        })
        .unwrap();
    let mut stopped = 0;
    input.end(
        || {
            stopped += 1;
            release.send(()).unwrap();
        },
        |()| panic!("a started worker is not closed unstarted"),
    );
    assert_eq!(stopped, 1);
    assert!(finished.load(Ordering::SeqCst), "the worker was not joined");
    // Ended is ended: nothing more happens.
    input.end(|| panic!("stopped twice"), |()| panic!("closed twice"));
}

/// A worker that was never started (a hand-back, a refusal, a failed read) has nothing to stop or join: its
/// write half is closed from here, so the agent sees the client go.
#[test]
fn an_input_worker_that_was_never_started_is_not_stopped_or_joined_and_its_write_half_is_closed() {
    let mut input = Input::Waiting("the write half");
    let mut closed = Vec::new();
    input.end(|| panic!("stopped a worker that never started"), |tx| closed.push(tx));
    assert_eq!(closed, ["the write half"]);
    input.end(|| panic!("stopped twice"), |tx| closed.push(tx));
    assert_eq!(closed.len(), 1, "closed twice");
}

// The root process of a console keeps running through Ctrl+C -----------------------------

/// A shell started under the shim, or under the `console-fallback` verb in a pseudoconsole, shares the
/// console with the process that started it, and a Ctrl+C is raised in every process on the console. The
/// shell answers it itself (cmd.exe clears its line, a running program ends); the process that started the
/// shell must stay, or the session ends with it.
#[test]
fn ctrl_c_and_ctrl_break_are_handled_and_every_other_console_event_is_left_to_the_default() {
    use super::ctrl_handler;
    use windows::Win32::System::Console::{
        CTRL_BREAK_EVENT, CTRL_C_EVENT, CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT,
    };
    for event in [CTRL_C_EVENT, CTRL_BREAK_EVENT] {
        assert!(ctrl_handler(event).as_bool(), "{event}");
    }
    for event in [CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT] {
        assert!(!ctrl_handler(event).as_bool(), "{event}");
    }
}

/// The reason a start failed goes into the warning the user reads, so it must not carry the whole
/// command line, which can be 32 KB of the user's command.
#[test]
fn a_spawn_that_fails_does_not_put_the_command_line_in_its_error() {
    let error = start_local(r"C:\no\such\shell.exe the-command-text-of-the-user", None)
        .map(|_| ())
        .unwrap_err();
    assert!(matches!(error, crate::shell::StartError::Program(_)), "{error:?}");
    assert!(!error.to_string().contains("the-command-text-of-the-user"), "{error}");
}

/// A writer that fails, as a console whose pseudoconsole is gone would.
struct Broken;

impl std::io::Write for Broken {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("the pipe is being closed"))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The notice is the verb's one message to the user; if it cannot be written, the user is told
/// that on the console, and the shell still starts.
#[test]
fn a_notice_is_written_with_a_carriage_return_and_a_failure_to_write_it_is_said() {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    super::show_notice(&mut out, &mut err, "the notice");
    assert_eq!(out, b"the notice\r\n");
    assert!(err.is_empty());

    let (mut out, mut err) = (Vec::new(), Vec::new());
    super::show_notice(&mut out, &mut err, "");
    assert!(out.is_empty() && err.is_empty(), "an empty notice prints nothing");

    let mut err = Vec::new();
    super::show_notice(&mut Broken, &mut err, "the notice");
    let said = String::from_utf8(err).unwrap();
    assert!(
        said.starts_with("ssh-broker: could not show the notice") && said.contains("the pipe is being closed"),
        "{said:?}"
    );
}

// A folder that is refused -----

/// A stand-in profile with its private folder made and a stand-in agent listening in it: the thread
/// returns how many bytes reached the agent first. A shim that connected sends its handshake, and the
/// sentinel the test connects with sends nothing.
fn agent_in_private_folder(
    tag: &str,
) -> (
    crate::test_support::TempProfile,
    SocketLocation,
    std::thread::JoinHandle<usize>,
) {
    use std::io::Read;
    let profile = crate::test_support::TempProfile::new(tag);
    let location = profile.location();
    crate::userdir::ensure_socket_dir(&location, &Sid::current_user().unwrap()).unwrap();
    let listener = crate::afunix::Listener::bind(location.path(), crate::socket_loc::Integrity::Medium).unwrap();
    let agent = std::thread::spawn(move || {
        let mut first = [0u8; 1];
        let (mut rx, _tx) = crate::afunix::split(listener.accept().unwrap()).unwrap();
        rx.read(&mut first).unwrap()
    });
    (profile, location, agent)
}

/// The agent's socket in a folder that is refused, and the stand-in agent behind it.
fn refused_folder_with_an_agent(
    tag: &str,
) -> (
    crate::test_support::TempProfile,
    SocketLocation,
    Folder,
    std::thread::JoinHandle<usize>,
) {
    let (profile, location, agent) = agent_in_private_folder(tag);
    crate::test_support::widen(location.dir());
    let folder = folder_of(Ok(location.clone()));
    (profile, location, folder, agent)
}

/// A shim whose private folder is refused does not connect, even though an agent's socket sits in it. A
/// login with a terminal is told why before it falls back to the plain shell.
#[test]
fn a_shim_with_a_terminal_whose_folder_is_refused_does_not_connect_and_prints_the_folder_refused_line() {
    let (_profile, location, folder, agent) = refused_folder_with_an_agent("ref-pty");
    let mut stderr = Vec::new();

    let relayed = super::try_relay_at(
        &folder,
        &Login {
            exec: None,
            elevation: None,
        },
        &mut stderr,
        None,
        std::io::empty(),
        &mut crate::shim_offer::Prompting::new(Ok(crate::logon::LogonKind::Interactive)),
    )
    .unwrap();

    assert_eq!(relayed, None, "the shim fails open instead of reaching the socket");
    let text = String::from_utf8(stderr).unwrap();
    assert!(text.starts_with("ssh-broker: no session is offered"), "{text}");
    assert!(text.contains(&location.dir().display().to_string()), "{text}");
    drop(crate::afunix::connect(location.path()).unwrap());
    assert_eq!(agent.join().unwrap(), 0, "the shim sent something to the agent");
}

/// A login with a command is told the cause once: by the fail-open line, which carries why the shim has
/// no log. The log and the folder come from the same walk, so that is the folder's refusal.
#[test]
fn a_shim_with_a_command_whose_folder_is_refused_does_not_connect_and_says_why_once_in_the_fail_open_line() {
    let (_profile, location, folder, agent) = refused_folder_with_an_agent("ref-exec");
    let log_failure = format!(
        "{:#}",
        folder.logs().err().expect("the folder is refused, so there is no log")
    );
    let mut stderr = Vec::new();

    let relayed = super::try_relay_at(
        &folder,
        &Login {
            exec: Some(exec("echo hi")),
            elevation: None,
        },
        &mut stderr,
        Some(&log_failure),
        std::io::empty(),
        &mut crate::shim_offer::Prompting::new(Ok(crate::logon::LogonKind::Interactive)),
    )
    .unwrap();

    assert_eq!(relayed, None, "the shim fails open instead of reaching the socket");
    let text = String::from_utf8(stderr).unwrap();
    assert!(text.starts_with("ssh-broker: agent unavailable"), "{text}");
    assert!(!text.contains("no session is offered"), "told twice: {text}");
    assert!(text.contains(&location.dir().display().to_string()), "{text}");
    drop(crate::afunix::connect(location.path()).unwrap());
    assert_eq!(agent.join().unwrap(), 0, "the shim sent something to the agent");
}

/// The log's failure is the first act's: there was no folder then. A folder that is refused when the
/// connect looks again is what the fail-open line of a login with a command names.
#[test]
fn a_shim_with_a_command_whose_folder_is_refused_on_a_later_look_names_that_refusal_in_the_fail_open_line() {
    let profile = crate::test_support::TempProfile::new("ref-later");
    let location = profile.location();
    std::fs::remove_dir_all(profile.0.join("AppData")).unwrap();
    let folder = folder_of(Ok(location.clone()));
    let log_failure = format!("{:#}", folder.logs().err().expect("no folder, so no log"));
    std::fs::create_dir_all(profile.0.join(r"AppData\Local")).unwrap();
    crate::userdir::ensure_socket_dir(&location, &Sid::current_user().unwrap()).unwrap();
    crate::test_support::widen(location.dir());
    let mut stderr = Vec::new();

    let relayed = super::try_relay_at(
        &folder,
        &Login {
            exec: Some(exec("echo hi")),
            elevation: None,
        },
        &mut stderr,
        Some(&log_failure),
        std::io::empty(),
        &mut crate::shim_offer::Prompting::new(Ok(crate::logon::LogonKind::Interactive)),
    )
    .unwrap();

    assert_eq!(relayed, None);
    let text = String::from_utf8(stderr).unwrap();
    assert!(text.starts_with("ssh-broker: agent unavailable"), "{text}");
    assert!(!text.contains("no session is offered"), "told twice: {text}");
    assert!(text.contains("its ACL is not exactly"), "{text}");
    assert!(text.contains(&location.dir().display().to_string()), "{text}");
}

/// The stated limit where the user sees it: another program holds the private folder open with the right
/// to delete it, so the shim cannot hold it. The login is told that, relays nothing and reaches nothing.
#[test]
fn a_shim_whose_folder_is_held_open_by_another_program_says_so_and_does_not_connect() {
    let (_profile, location, agent) = agent_in_private_folder("ref-held");
    let holder = crate::test_support::hold_for_deletion(location.dir());
    let folder = folder_of(Ok(location.clone()));
    let mut stderr = Vec::new();

    let relayed = super::try_relay_at(
        &folder,
        &Login {
            exec: None,
            elevation: None,
        },
        &mut stderr,
        None,
        std::io::empty(),
        &mut crate::shim_offer::Prompting::new(Ok(crate::logon::LogonKind::Interactive)),
    )
    .unwrap();
    drop(holder);

    assert_eq!(relayed, None, "the shim fails open instead of reaching the socket");
    let text = String::from_utf8(stderr).unwrap();
    assert!(text.starts_with("ssh-broker: no session is offered"), "{text}");
    assert!(
        text.contains(&crate::offer::text::folder_held(location.dir())),
        "{text}"
    );
    drop(crate::afunix::connect(location.path()).unwrap());
    assert_eq!(agent.join().unwrap(), 0, "the shim sent something to the agent");
}
