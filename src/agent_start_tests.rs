//! Tests for how the agent starts and keeps serving: the session check, the order of its locks,
//! what it does with a failed log, the accept loop and the home directory. None needs a second
//! session or elevation, and none runs a shell.
use super::*;
use crate::acl::{self, Sid};
use crate::afunix::AcceptError;
use crate::protocol::{ExitCode, FrameKind, FrameReader};
use crate::test_support::TempProfile;
use std::cell::{Cell, RefCell};
use std::os::windows::process::CommandExt;
use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
use windows::Win32::Storage::FileSystem::{
    FILE_NOTIFY_CHANGE_FILE_NAME, FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_CHANGE_SIZE, FindCloseChangeNotification,
    FindFirstChangeNotificationW, FindNextChangeNotification,
};
use windows::Win32::System::Threading::WaitForSingleObject;
use windows::core::PCWSTR;

fn guard() -> tracing_appender::non_blocking::WorkerGuard {
    tracing_appender::non_blocking(std::io::sink()).1
}

// start -----

const ME: &str = "S-1-5-21-1-2-3-1001";

fn background(expect_user: Option<&str>) -> BackgroundArgs {
    BackgroundArgs {
        expect_user: expect_user.map(str::to_string),
    }
}

/// The `Refusal` an error carries, if any.
fn refusal(err: &anyhow::Error) -> Option<Refusal> {
    err.downcast_ref::<Refusal>().copied()
}

#[test]
fn start_refuses_session_zero_before_it_touches_anything() {
    let err = start_with(
        None,
        0,
        ME,
        || -> anyhow::Result<SocketLocation> { panic!("must not look for the profile in session 0") },
        |_| -> anyhow::Result<_> { panic!("must not open a log in session 0") },
        |_, _| panic!("must not serve in session 0"),
    )
    .unwrap_err();
    assert!(format!("{err:#}").contains("session 0"), "{err:#}");
}

#[test]
fn desktop_agent_still_refuses_session_zero_with_65() {
    let err = start_with(
        None,
        0,
        ME,
        || -> anyhow::Result<SocketLocation> { panic!("must not look for the profile") },
        |_| -> anyhow::Result<_> { panic!("must not open a log") },
        |_, _| panic!("must not serve"),
    )
    .unwrap_err();
    assert_eq!(refusal(&err), Some(Refusal::SessionRefused));
    assert_eq!(exit_code_of(&err), 65);
}

#[test]
fn expect_user_mismatch_exits_64_before_touching_the_folder() {
    let args = background(Some("S-1-5-21-1-2-3-9999"));
    let err = start_with(
        Some(&args),
        2,
        ME,
        || -> anyhow::Result<SocketLocation> { panic!("must not look for the profile for another user") },
        |_| -> anyhow::Result<_> { panic!("must not open a log for another user") },
        |_, _| panic!("must not serve another user"),
    )
    .unwrap_err();
    assert_eq!(refusal(&err), Some(Refusal::WrongUser));
    assert_eq!(exit_code_of(&err), 64);
}

#[test]
fn locate_failure_exits_66() {
    let args = background(Some(ME));
    let err = start_with(
        Some(&args),
        2,
        ME,
        || anyhow::bail!("the account has no profile directory"),
        |_| -> anyhow::Result<_> { panic!("must not open a log without a folder") },
        |_, _| panic!("must not serve without a folder"),
    )
    .unwrap_err();
    assert_eq!(refusal(&err), Some(Refusal::NoSocketLocation));
    assert_eq!(exit_code_of(&err), 66);
    assert!(
        format!("{err:#}").contains("no profile directory"),
        "the cause is kept: {err:#}"
    );
}

#[test]
fn folder_refusal_exits_67() {
    let profile = TempProfile::new("start-refused");
    let loc = profile.location();
    // A file where the private folder belongs: nothing can be made safe there.
    std::fs::write(&loc.dir, b"planted").unwrap();
    let args = background(Some(ME));
    let err = start_with(
        Some(&args),
        2,
        ME,
        || Ok(loc.clone()),
        |_| -> anyhow::Result<_> { panic!("must not open a log in a refused folder") },
        |_, _| panic!("must not serve from a refused folder"),
    )
    .unwrap_err();
    assert_eq!(refusal(&err), Some(Refusal::SocketFolderRefused));
    assert_eq!(exit_code_of(&err), 67);
}

#[test]
fn background_agent_is_allowed_in_session_zero() {
    let profile = TempProfile::new("start-bg0");
    let loc = profile.location();
    let served = Cell::new(None);
    let args = background(Some(ME));
    start_with(
        Some(&args),
        0,
        ME,
        || Ok(loc.clone()),
        |_| Ok(guard()),
        |_, session| {
            served.set(Some(session));
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(served.take(), Some(0));
}

#[test]
fn start_makes_the_private_folder_then_serves_that_session_from_it() {
    let profile = TempProfile::new("start-ok");
    let loc = profile.location();
    let served = Cell::new(None);

    start_with(
        None,
        3,
        ME,
        || Ok(loc.clone()),
        |logs| {
            assert_eq!(logs, loc.logs_dir());
            Ok(guard())
        },
        |at, session| {
            assert!(
                acl::verify_dir_acl(&at.dir, &Sid::current_user().unwrap()).unwrap(),
                "the folder is hardened before anything is served from it"
            );
            served.set(Some((at.path.clone(), session)));
            Ok(())
        },
    )
    .unwrap();

    assert_eq!(served.take(), Some((loc.path.clone(), 3)));
}

#[test]
fn start_serves_without_a_log_when_the_log_cannot_be_opened() {
    let profile = TempProfile::new("start-nolog");
    let loc = profile.location();
    let served = Cell::new(false);

    start_with(
        None,
        3,
        ME,
        || Ok(loc.clone()),
        |_| anyhow::bail!("the disk is full"),
        |_, _| {
            served.set(true);
            Ok(())
        },
    )
    .unwrap();

    assert!(served.get(), "a missing log is not a reason to stop serving");
}

#[test]
fn start_returns_the_error_serving_stopped_with() {
    let profile = TempProfile::new("start-err");
    let loc = profile.location();
    let err = start_with(
        None,
        3,
        ME,
        || Ok(loc.clone()),
        |_| Ok(guard()),
        |_, _| anyhow::bail!("listener broke"),
    )
    .unwrap_err();
    assert_eq!(format!("{err:#}"), "listener broke");
    assert_eq!(exit_code_of(&err), 1, "a failure after the log opens is not a refusal");
}

/// A `tracing` writer that keeps what it is given.
#[derive(Clone, Default)]
struct Captured(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn failure_after_the_log_opens_exits_1_and_logs_the_cause() {
    let profile = TempProfile::new("start-logs");
    let loc = profile.location();
    let captured = Captured::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer({
            let captured = captured.clone();
            move || captured.clone()
        })
        .with_ansi(false)
        .finish();
    let err = tracing::subscriber::with_default(subscriber, || {
        start_with(
            None,
            3,
            ME,
            || Ok(loc.clone()),
            |_| Ok(guard()),
            |_, _| anyhow::bail!("the listener broke"),
        )
    })
    .unwrap_err();
    assert_eq!(exit_code_of(&err), 1);
    let logged = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert!(logged.contains("the listener broke"), "{logged}");
}

#[test]
fn a_background_agent_opens_its_log_then_serves_and_signals_nothing_else() {
    let profile = TempProfile::new("start-order");
    let loc = profile.location();
    let events = RefCell::new(Vec::new());
    let args = background(Some(ME));
    start_with(
        Some(&args),
        2,
        ME,
        || Ok(loc.clone()),
        |_| {
            events.borrow_mut().push("log");
            Ok(guard())
        },
        |_, _| {
            events.borrow_mut().push("serve");
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(events.into_inner(), ["log", "serve"]);
}

// the serving marker -----

/// A directory watch on `dir`: signalled by a file being created, resized or written.
struct Watch(HANDLE);

impl Watch {
    fn arm(dir: &Path) -> Watch {
        use std::os::windows::ffi::OsStrExt;
        let dir_w: Vec<u16> = dir.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
        // SAFETY: a NUL-terminated path; the handle is closed in `drop`.
        let handle = unsafe {
            FindFirstChangeNotificationW(
                PCWSTR(dir_w.as_ptr()),
                false,
                FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE,
            )
        }
        .unwrap();
        Watch(handle)
    }

    /// Whether the watch is signalled now: a state check, not a wait.
    fn signalled(&self) -> bool {
        // SAFETY: a valid watch handle.
        let state = unsafe { WaitForSingleObject(self.0, 0) }; // sleep-ok: zero-timeout state check after the write has returned, not a wait
        state == WAIT_OBJECT_0
    }

    /// Re-arm: the next change signals it again, and until then it is not signalled.
    fn rearm(&self) {
        // SAFETY: a valid watch handle.
        unsafe { FindNextChangeNotification(self.0) }.unwrap();
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        // SAFETY: the handle from `arm`.
        let _ = unsafe { FindCloseChangeNotification(self.0) };
    }
}

#[test]
fn mark_listening_changes_the_folder() {
    let profile = TempProfile::new("marker");
    let loc = profile.location();
    std::fs::create_dir_all(&loc.dir).unwrap();
    let watch = Watch::arm(&loc.dir);
    // The folder's own creation may have signalled the watch: consume that, so only the marker can.
    watch.rearm();
    assert!(!watch.signalled(), "nothing has changed since the watch was re-armed");

    mark_listening(&loc).unwrap();
    assert!(watch.signalled(), "the marker write must be a change of the folder");

    watch.rearm();
    mark_listening(&loc).unwrap();
    assert!(watch.signalled(), "a second marker write is a change again");
}

#[test]
fn every_agent_marks_after_bind() {
    let profile = TempProfile::new("marker-order");
    let loc = profile.location();
    let events = RefCell::new(Vec::new());
    let err = run_on_with(
        &loc,
        |path| {
            assert_eq!(path, loc.path);
            events.borrow_mut().push("bind");
            Ok(())
        },
        |at| {
            assert_eq!(at, &loc);
            events.borrow_mut().push("mark");
            Ok(())
        },
        |()| {
            events.borrow_mut().push("accept");
            anyhow::anyhow!("end of loop")
        },
    )
    .unwrap_err();
    assert_eq!(events.into_inner(), ["bind", "mark", "accept"]);
    assert_eq!(format!("{err:#}"), "end of loop");
}

#[test]
fn a_failed_bind_marks_nothing_and_accepts_nothing() {
    let profile = TempProfile::new("marker-bindfail");
    let loc = profile.location();
    let err = run_on_with(
        &loc,
        |_| -> anyhow::Result<()> { anyhow::bail!("not safe to bind") },
        |_| panic!("no marker without a listener"),
        |()| panic!("no accept without a listener"),
    )
    .unwrap_err();
    assert!(format!("{err:#}").contains("not safe to bind"));
}

#[test]
fn a_failed_marker_write_ends_the_agent_before_it_accepts() {
    let profile = TempProfile::new("marker-fail");
    let loc = profile.location();
    let err = run_on_with(
        &loc,
        |_| Ok(()),
        |_| Err(std::io::Error::other("disk full")),
        |()| panic!("a shim cannot be woken, so nothing is accepted"),
    )
    .unwrap_err();
    assert!(format!("{err:#}").contains("disk full"), "{err:#}");
}

// serve -----

/// A user folder with the lock files' directory in place.
fn location_with_dir(tag: &str) -> (TempProfile, SocketLocation) {
    let profile = TempProfile::new(tag);
    let loc = profile.location();
    std::fs::create_dir_all(&loc.dir).unwrap();
    (profile, loc)
}

#[test]
fn serve_returns_ok_at_once_when_another_agent_holds_the_session() {
    let (_profile, loc) = location_with_dir("serve-held");
    let _other = SessionSlot::try_acquire(&loc.sessions_lock_path(), 7).unwrap().unwrap();

    // Neither closure may run: waiting for the user lock here would block behind an agent that
    // may never end, for a session that has an agent already.
    serve_with(
        &loc,
        7,
        |_| panic!("the user lock is taken only after the session slot"),
        |_| panic!("nothing is served by an agent that does not hold the slot"),
        |_| panic!("an agent that holds nothing has nothing to hold on to"),
    )
    .unwrap();
}

#[test]
fn serve_holds_the_session_slot_before_it_takes_the_user_lock_and_both_while_it_serves() {
    let (_profile, loc) = location_with_dir("serve-order");
    let events = RefCell::new(Vec::new());
    let held = RefCell::new(None);

    serve_with(
        &loc,
        7,
        |path| {
            events.borrow_mut().push("user lock");
            assert!(
                SessionSlot::try_acquire(&loc.sessions_lock_path(), 7)
                    .unwrap()
                    .is_none(),
                "the session slot is held before the user lock is asked for"
            );
            UserLock::acquire(path, || ())
        },
        |_| {
            events.borrow_mut().push("serve");
            assert!(
                SessionSlot::try_acquire(&loc.sessions_lock_path(), 7)
                    .unwrap()
                    .is_none()
            );
            assert!(UserLock::try_acquire(&loc.lock_path()).unwrap().is_none());
            Ok(())
        },
        |guard| *held.borrow_mut() = Some(guard),
    )
    .unwrap();

    assert_eq!(events.into_inner(), ["user lock", "serve"]);
    // The process is still ending: a successor that took the locks now would bind while the old
    // agent's listener still answers, and be refused as `AlreadyListening`. The system releases
    // them when the process is gone.
    assert!(
        SessionSlot::try_acquire(&loc.sessions_lock_path(), 7)
            .unwrap()
            .is_none(),
        "the session slot was given up before the process ended"
    );
    assert!(
        UserLock::try_acquire(&loc.lock_path()).unwrap().is_none(),
        "the user lock was given up before the process ended"
    );

    drop(held.into_inner());
    assert!(
        SessionSlot::try_acquire(&loc.sessions_lock_path(), 7)
            .unwrap()
            .is_some(),
        "released with the process"
    );
    assert!(
        UserLock::try_acquire(&loc.lock_path()).unwrap().is_some(),
        "released with the process"
    );
}

#[test]
fn serve_keeps_both_locks_when_the_serving_failed() {
    let (_profile, loc) = location_with_dir("serve-failed");
    let held = RefCell::new(None);

    let err = serve_with(
        &loc,
        7,
        |path| UserLock::acquire(path, || ()),
        |_| anyhow::bail!("the listener is broken"),
        |guard| *held.borrow_mut() = Some(guard),
    )
    .unwrap_err();

    assert!(format!("{err:#}").contains("listener is broken"), "{err:#}");
    assert!(held.borrow().is_some(), "the guards were handed over");
}

#[test]
fn serve_hands_the_slot_and_the_lock_to_the_process_end_and_does_not_drop_them() {
    // `serve` is the one place that passes `hold_until_end`; `serve_with` is tested with its own
    // `hold`. The hold is process-wide and never released, so the locks stay taken in this test
    // process: a session number and folder of their own keep other tests clear of them.
    let (_profile, loc) = location_with_dir("serve-held-to-end");

    serve_in(&loc, 4242, |_| Ok(())).unwrap();

    assert!(
        SessionSlot::try_acquire(&loc.sessions_lock_path(), 4242)
            .unwrap()
            .is_none(),
        "the session slot was dropped when serving ended, not held until the process ends"
    );
    assert!(
        UserLock::try_acquire(&loc.lock_path()).unwrap().is_none(),
        "the user lock was dropped when serving ended, not held until the process ends"
    );
}

// the listener of an ending agent -----

/// A stand-in listener that says when it is closed.
struct Closes(Arc<std::sync::atomic::AtomicBool>);

impl Drop for Closes {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

fn closed(flag: &Arc<std::sync::atomic::AtomicBool>) -> bool {
    flag.load(std::sync::atomic::Ordering::SeqCst)
}

#[test]
fn the_listener_is_closed_when_the_loop_stops_and_not_held_until_the_process_ends() {
    let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let connections = Connections::new();

    let end = serve_until_drained_in(
        Closes(Arc::clone(&flag)),
        &connections,
        || false,
        |_| anyhow::Error::new(Stopped),
    );

    assert!(end.downcast_ref::<Stopped>().is_some(), "{end:#}");
    assert!(closed(&flag), "the listener is still open after the loop stopped");
    assert!(
        !connections.lock().listener_open,
        "the tally still says a loop holds it"
    );
}

#[test]
fn the_listener_is_closed_when_the_loop_fails_too() {
    let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let connections = Connections::new();

    let end = serve_until_drained_in(
        Closes(Arc::clone(&flag)),
        &connections,
        || false,
        |_| anyhow::anyhow!("the listener failed"),
    );

    assert!(format!("{end:#}").contains("the listener failed"), "{end:#}");
    assert!(closed(&flag));
}

// deciding the end -----

/// The accept loop as the end meets it: blocked in `accept` until it is woken, it takes one more
/// connection and counts it, and then returns and closes the listener. The connection stays live until
/// the test releases it. It says what it does on `events`.
fn accepting_loop(
    connections: &Arc<Connections>,
    woken: std::sync::mpsc::Receiver<()>,
    release: std::sync::mpsc::Receiver<()>,
    events: std::sync::mpsc::Sender<&'static str>,
) -> std::thread::JoinHandle<()> {
    let connections = Arc::clone(connections);
    std::thread::spawn(move || {
        if woken.recv().is_err() {
            let _ = events.send("never woken");
            return;
        }
        let late = connections.begin();
        let _ = events.send("counted");
        connections.listener_closed();
        let _ = release.recv();
        let _ = events.send("releasing");
        drop(late);
    })
}

#[test]
fn the_end_is_judged_only_after_the_accept_loop_has_counted_what_it_took_and_closed_the_listener() {
    use std::sync::mpsc;
    let (events, on_event) = mpsc::channel::<&'static str>();
    let connections = Connections::observing_drain({
        let events = events.clone();
        move || {
            let _ = events.send("parked");
        }
    });
    connections.listener_opened();
    let (wake, woken) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let accepting = accepting_loop(&connections, woken, released, events.clone());
    let settler = std::thread::spawn({
        let (connections, events) = (Arc::clone(&connections), events.clone());
        move || {
            let drained = connections.settle(&move || {
                let _ = wake.send(());
            });
            let _ = events.send("settled");
            drained
        }
    });

    let mut seen = Vec::new();
    let mut release = Some(release);
    loop {
        let event = on_event.recv().unwrap();
        seen.push(event);
        // The judge is waiting for the connection the loop took after the flag went up.
        if event == "parked"
            && seen.contains(&"counted")
            && let Some(release) = release.take()
        {
            release.send(()).unwrap();
        }
        if event == "settled" {
            break;
        }
    }
    accepting.join().unwrap();
    let drained = settler.join().unwrap();
    seen.extend(on_event.try_iter());

    let steps: Vec<_> = seen.iter().filter(|event| **event != "parked").collect();
    assert_eq!(
        steps,
        [&"counted", &"releasing", &"settled"],
        "the end was judged before the loop had stopped, or before the connection it took had finished"
    );
    assert_eq!(drained, Drained::Complete);
}

#[test]
fn an_end_with_no_accept_loop_wakes_nothing_and_waits_for_nothing() {
    let connections = Connections::new();
    let drained = connections.settle(&|| panic!("there is no loop to wake"));
    assert_eq!(drained, Drained::Complete);
    assert!(
        connections.is_closing(),
        "the flag is up for any loop that starts later"
    );
}

#[test]
fn a_wake_that_failed_is_logged_and_the_end_does_not_wait_for_the_loop() {
    let connections = Connections::new();
    connections.listener_opened();
    let (log, drained) =
        crate::test_support::logged(|| connections.settle(&|| connections.wake_failed("no thread for it")));
    assert_eq!(drained, Drained::Complete);
    assert!(
        log.contains("could not wake the accept loop: no thread for it"),
        "{log}"
    );
    assert!(log.contains("ending with the listener open"), "{log}");
}

#[test]
fn a_wake_that_fails_on_its_own_thread_ends_the_wait_for_the_loop() {
    let connections = Connections::new();
    connections.listener_opened();
    let (log, drained) = crate::test_support::logged(|| {
        connections.settle(&|| {
            wake_without_blocking(&connections, || anyhow::bail!("the connect was refused"));
        })
    });
    assert_eq!(drained, Drained::Complete);
    assert!(log.contains("the connect was refused"), "{log}");
}

#[test]
fn callers_that_ask_for_the_end_together_get_one_decision() {
    let connections = Connections::new();
    connections.listener_opened();
    let woken = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    // The wake is what closes the listener, as it makes the loop return.
    let wake = {
        let (connections, woken) = (Arc::clone(&connections), Arc::clone(&woken));
        move || {
            woken.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            connections.listener_closed();
        }
    };
    let callers: Vec<_> = (0..4)
        .map(|_| {
            let (connections, wake) = (Arc::clone(&connections), wake.clone());
            std::thread::spawn(move || connections.settle(&wake))
        })
        .collect();
    for caller in callers {
        assert_eq!(caller.join().unwrap(), Drained::Complete);
    }
    assert_eq!(woken.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[test]
fn a_drain_that_gave_up_on_connections_does_not_wait_for_them_a_second_time() {
    let connections = Connections::with_drain_bound(std::time::Duration::from_millis(10));
    let _hung = connections.begin();
    let (log, drained) = crate::test_support::logged(|| connections.settle(&|| {}));
    assert_eq!(drained, Drained::Abandoned { still_live: 1 });
    assert_eq!(log.matches("had not finished").count(), 1, "{log}");
}

#[test]
fn a_loop_that_failed_while_the_agent_ends_still_waits_for_the_drain() {
    let (events, on_event) = std::sync::mpsc::channel();
    let connections = Connections::observing_drain({
        let events = events.clone();
        move || {
            let _ = events.send("parked");
        }
    });
    let other = connections.begin();
    let waiter = std::thread::spawn({
        let connections = Arc::clone(&connections);
        move || {
            let end = finish_stopped(anyhow::anyhow!("the listener failed"), &connections, true);
            let _ = events.send("returned");
            end
        }
    });
    assert_eq!(on_event.recv().unwrap(), "parked", "the waiter did not wait");
    drop(other);
    let next = std::iter::from_fn(|| on_event.recv().ok()).find(|event| *event != "parked");
    assert_eq!(next, Some("returned"));
    assert!(format!("{:#}", waiter.join().unwrap()).contains("the listener failed"));
}

// the exit code -----

/// A write half that fails as told and counts the FINs.
struct Wire {
    written: Vec<u8>,
    write_fails: Option<std::io::ErrorKind>,
    close_fails: Option<std::io::ErrorKind>,
    closed: std::cell::Cell<usize>,
}

impl Wire {
    fn new(write_fails: Option<std::io::ErrorKind>, close_fails: Option<std::io::ErrorKind>) -> Wire {
        Wire {
            written: Vec::new(),
            write_fails,
            close_fails,
            closed: std::cell::Cell::new(0),
        }
    }
}

impl std::io::Write for Wire {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if let Some(kind) = self.write_fails {
            return Err(kind.into());
        }
        self.written.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl HalfClose for Wire {
    fn shutdown_write(&self) -> anyhow::Result<()> {
        self.closed.set(self.closed.get() + 1);
        match self.close_fails {
            Some(kind) => Err(std::io::Error::from(kind).into()),
            None => Ok(()),
        }
    }
}

#[test]
fn the_exit_code_is_sent_and_the_write_half_closed_without_a_word_in_the_log() {
    let mut wire = Wire::new(None, None);
    let (log, ()) = crate::test_support::logged(|| send_exit(&mut wire, 3));
    assert_eq!(log, "");
    let mut reader = FrameReader::new();
    reader.push(&wire.written);
    let frame = reader.next_frame().unwrap().expect("the frame was written");
    assert_eq!(frame.kind, FrameKind::Exit);
    assert_eq!(ExitCode::decode(&frame.payload).unwrap().0, 3);
    assert_eq!(wire.closed.get(), 1);
}

#[test]
fn a_lost_exit_code_is_a_warning_and_the_write_half_is_still_closed() {
    let mut wire = Wire::new(Some(std::io::ErrorKind::PermissionDenied), None);
    let (log, ()) = crate::test_support::logged(|| send_exit(&mut wire, 3));
    assert!(log.contains("WARN"), "{log}");
    assert!(log.contains("could not send the exit code (exit code 3)"), "{log}");
    assert_eq!(wire.closed.get(), 1, "the FIN is sent although the frame was not");
}

#[test]
fn a_write_half_that_cannot_be_closed_is_a_warning() {
    let mut wire = Wire::new(None, Some(std::io::ErrorKind::PermissionDenied));
    let (log, ()) = crate::test_support::logged(|| send_exit(&mut wire, 0));
    assert!(log.contains("WARN"), "{log}");
    assert!(log.contains("could not close the write half (exit code 0)"), "{log}");
}

#[test]
fn a_client_that_has_gone_loses_the_exit_code_quietly() {
    // Routine: the client disconnected first. Not a warning, which is for the unexpected.
    let mut wire = Wire::new(
        Some(std::io::ErrorKind::ConnectionReset),
        Some(std::io::ErrorKind::BrokenPipe),
    );
    let (log, ()) = crate::test_support::logged(|| send_exit(&mut wire, 1));
    assert!(!log.contains("WARN"), "{log}");
}

// closing a pseudoconsole -----

/// A console whose close pushes its pending output into a pipe nobody else reads: the stand-in is a
/// rendezvous channel, which blocks the close at its first chunk until a reader takes it. Without the
/// reader the close would never return and this test would hang.
#[test]
fn a_pseudoconsole_is_closed_while_its_output_is_read() {
    let (pipe_in, pipe_out) = std::sync::mpsc::sync_channel::<usize>(0);
    let read = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    close_while_draining(
        {
            let read = Arc::clone(&read);
            move || {
                let n = pipe_out.recv().unwrap_or(0);
                read.fetch_add(n, std::sync::atomic::Ordering::SeqCst);
                n
            }
        },
        move || {
            for _ in 0..50 {
                pipe_in.send(10).unwrap();
            }
            // Dropping `pipe_in` is the end of the output, as the close ends the real pipe.
        },
    )
    .unwrap();
    assert_eq!(
        read.load(std::sync::atomic::Ordering::SeqCst),
        500,
        "every pending chunk was read before the close returned"
    );
}

// accept loop -----

/// Run the accept loop over a script of outcomes, ending every connection as soon as it is handed
/// over; it ends with a fatal error when the script does.
fn run_script(script: Vec<Result<u32, AcceptError>>) -> (Vec<u32>, anyhow::Error) {
    let mut script = script.into_iter();
    let mut handled = Vec::new();
    let end = serve_connections(
        || {
            script
                .next()
                .unwrap_or_else(|| Err(AcceptError::Fatal(anyhow::anyhow!("end of script"))))
        },
        |conn, _live| {
            handled.push(conn);
            Ok(())
        },
    );
    (handled, end)
}

fn exhausted(code: i32) -> AcceptError {
    AcceptError::Exhausted {
        code,
        source: std::io::Error::from_raw_os_error(code),
    }
}

fn interrupted() -> AcceptError {
    AcceptError::Interrupted(std::io::Error::from_raw_os_error(10004))
}

fn lost() -> AcceptError {
    AcceptError::Connection(anyhow::anyhow!("reset"))
}

#[test]
fn a_connection_lost_in_the_queue_is_dropped_and_the_next_one_served() {
    let (handled, end) = run_script(vec![Ok(1), Err(lost()), Err(lost()), Ok(2)]);
    assert_eq!(handled, [1, 2]);
    assert!(format!("{end:#}").ends_with("end of script"), "{end:#}");
}

#[test]
fn a_broken_listener_ends_the_loop_at_once() {
    let (handled, end) = run_script(vec![
        Ok(1),
        Err(AcceptError::Fatal(anyhow::anyhow!("not listening"))),
        Ok(2),
    ]);
    assert_eq!(handled, [1]);
    assert!(format!("{end:#}").ends_with("not listening"), "{end:#}");
}

#[test]
fn an_interruption_is_retried_however_often_it_comes() {
    // Interrupting a blocking `accept` consumes nothing, so a run of them is not a failing
    // listener and has no count at which it becomes one.
    let mut script: Vec<_> = (0..10_000).map(|_| Err(interrupted())).collect();
    script.push(Ok(1));
    let (handled, end) = run_script(script);
    assert_eq!(handled, [1]);
    assert!(format!("{end:#}").ends_with("end of script"), "{end:#}");
}

#[test]
fn exhaustion_with_no_live_connection_is_fatal_and_names_the_code() {
    // Only one of this agent's own connections ending can free a descriptor or a buffer.
    let (handled, end) = run_script(vec![Err(exhausted(10024)), Ok(1)]);
    assert!(handled.is_empty());
    let text = format!("{end:#}");
    assert!(text.contains("10024"), "{text}");
    assert!(text.contains("no connection"), "{text}");
}

#[test]
fn a_connection_that_ended_before_the_failure_frees_nothing_new() {
    let (handled, end) = run_script(vec![Ok(1), Err(exhausted(10055)), Ok(2)]);
    assert_eq!(handled, [1]);
    assert!(format!("{end:#}").contains("10055"), "{end:#}");
}

#[test]
fn a_connection_that_ended_during_the_failed_accept_is_a_reason_to_try_again() {
    // The resource may have been freed between the failure and the check: that is a connection
    // ending since the attempt began, wherever the check falls.
    let lives = RefCell::new(Vec::new());
    let mut calls = 0;
    let mut handled = Vec::new();
    let end = serve_connections(
        || {
            calls += 1;
            match calls {
                1 => Ok(1),
                2 => {
                    lives.borrow_mut().clear();
                    Err(exhausted(10024))
                }
                3 => Ok(2),
                _ => Err(AcceptError::Fatal(anyhow::anyhow!("end of script"))),
            }
        },
        |conn, live| {
            handled.push(conn);
            lives.borrow_mut().push(live);
            Ok(())
        },
    );
    assert_eq!(handled, [1, 2]);
    assert!(format!("{end:#}").ends_with("end of script"), "{end:#}");
}

#[test]
fn exhaustion_waits_for_a_live_connection_to_end_before_accepting_again() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, mpsc};

    let lives = Arc::new(Mutex::new(Vec::new()));
    let released = Arc::new(AtomicBool::new(false));
    let (waiting, on_waiting) = mpsc::channel::<()>();
    // Ends the connection only once the loop has said that it is blocked waiting for one, so a
    // loop that accepts again without waiting reaches the third accept first and fails it. The
    // flag is raised before the connection ends, so it is up whenever the loop accepts again after
    // waiting for the end.
    let releaser = std::thread::spawn({
        let (lives, released) = (Arc::clone(&lives), Arc::clone(&released));
        move || {
            on_waiting.recv().unwrap();
            released.store(true, Ordering::SeqCst);
            lives.lock().unwrap().clear();
        }
    });

    let mut calls = 0;
    let mut handled = Vec::new();
    let end = serve_connections_observed(
        || {
            calls += 1;
            match calls {
                1 => Ok(1),
                2 => Err(exhausted(10024)),
                3 => {
                    assert!(
                        released.load(Ordering::SeqCst),
                        "accepted again before a connection ended"
                    );
                    Ok(2)
                }
                _ => Err(AcceptError::Fatal(anyhow::anyhow!("end of script"))),
            }
        },
        |conn, live| {
            handled.push(conn);
            lives.lock().unwrap().push(live);
            Ok(())
        },
        || waiting.send(()).unwrap(),
    );
    releaser.join().unwrap();
    assert_eq!(handled, [1, 2]);
    assert!(format!("{end:#}").ends_with("end of script"), "{end:#}");
}

// stopping -----

#[test]
fn the_loop_stops_accepting_once_told_to_and_says_it_stopped() {
    let stop = Cell::new(false);
    let mut accepted = 0;
    let end = serve_connections_with(
        Connections::new(),
        || {
            accepted += 1;
            Ok(accepted)
        },
        |_conn, _live| {
            stop.set(true);
            Ok(())
        },
        || {},
        || stop.get(),
    );
    assert_eq!(accepted, 1, "accepted again after being told to stop");
    assert!(end.downcast_ref::<Stopped>().is_some(), "{end:#}");
}

#[test]
fn a_loop_that_was_stopped_before_it_began_accepts_nothing() {
    let end = serve_connections_with(
        Connections::new(),
        || -> Result<u32, AcceptError> { panic!("nothing is accepted once stopping") },
        |_conn, _live| Ok(()),
        || {},
        || true,
    );
    assert!(end.downcast_ref::<Stopped>().is_some(), "{end:#}");
}

#[test]
fn a_stopped_loop_ends_ok_only_after_every_connection_has_finished() {
    // The waiter says it is about to park, and only then does the connection finish. A waiter that
    // did not wait reports that it returned first.
    let (events, on_event) = std::sync::mpsc::channel();
    let connections = Connections::observing_drain({
        let events = events.clone();
        move || {
            let _ = events.send("parked");
        }
    });
    let other = connections.begin();
    let _logout = connections.begin();
    let _logout_wait = connections.begin_logout();
    let waiter = std::thread::spawn({
        let connections = Arc::clone(&connections);
        move || {
            let end = finish_stopped(anyhow::Error::new(Stopped), &connections, false);
            let _ = events.send("returned");
            end
        }
    });
    assert_eq!(on_event.recv().unwrap(), "parked", "the waiter did not wait");
    drop(other);
    // The wait parks again at every spurious wake-up of its condition variable, so more than one
    // "parked" may be queued; the return is the first event that is not one.
    let next = std::iter::from_fn(|| on_event.recv().ok()).find(|event| *event != "parked");
    assert_eq!(next, Some("returned"));
    let end = waiter.join().unwrap();
    assert!(end.downcast_ref::<Stopped>().is_some(), "{end:#}");
}

#[test]
fn an_error_that_is_not_a_stop_is_still_an_error() {
    let connections = Connections::new();
    let _live = connections.begin();
    let end = finish_stopped(anyhow::anyhow!("the listener failed"), &connections, false);
    assert!(
        format!("{end:#}").contains("the listener failed"),
        "returns without waiting"
    );
}

// the wake -----

#[test]
fn the_wake_runs_on_a_thread_of_its_own_so_the_caller_never_waits_for_it() {
    let (ran_on, on_thread) = std::sync::mpsc::channel();
    wake_without_blocking(&Connections::new(), move || {
        ran_on.send(std::thread::current().id()).unwrap();
        Ok(())
    });
    assert_ne!(
        on_thread.recv().unwrap(),
        std::thread::current().id(),
        "the wake ran on the caller's thread"
    );
}

// threads -----

#[test]
fn a_thread_that_cannot_be_started_hands_the_connection_back_uncounted() {
    let connections = Connections::new();
    let live = connections.begin();
    let before = connections.ended();
    let failed = hand_to_thread(
        7u32,
        live,
        |_work| Err(std::io::Error::other("no thread")),
        |_| panic!("no thread, no handler"),
    )
    .unwrap_err();
    assert_eq!(failed.to_string(), "no thread");
    // Neither live nor ended: it never ran, so it frees nothing that waiting could be for.
    assert_eq!(connections.ended(), before);
    assert!(!connections.wait_for_an_end(before, || {}));
}

#[test]
fn a_thread_that_starts_runs_the_handler_and_ends_the_connection_after_it() {
    let connections = Connections::new();
    let since = connections.ended();
    let (done, handled) = std::sync::mpsc::channel();
    hand_to_thread(
        7u32,
        connections.begin(),
        |work| std::thread::Builder::new().spawn(work).map(drop),
        move |conn| done.send(conn).unwrap(),
    )
    .unwrap();
    assert_eq!(handled.recv().unwrap(), 7);
    assert!(connections.wait_for_an_end(since, || {}));
}

#[test]
fn a_connection_whose_thread_cannot_start_is_dropped_and_the_loop_goes_on_if_one_is_live() {
    let lives = RefCell::new(Vec::new());
    let mut accepted = 0;
    let mut handled = Vec::new();
    let end = serve_connections(
        || {
            accepted += 1;
            match accepted {
                1..=3 => Ok(accepted),
                _ => Err(AcceptError::Fatal(anyhow::anyhow!("end of script"))),
            }
        },
        |conn, live| {
            if conn == 2 {
                // This one's thread fails; connection 1, live, ends meanwhile.
                lives.borrow_mut().clear();
                live.abandon();
                return Err(std::io::Error::other("no thread"));
            }
            handled.push(conn);
            lives.borrow_mut().push(live);
            Ok(())
        },
    );
    assert_eq!(handled, [1, 3]);
    assert!(format!("{end:#}").ends_with("end of script"), "{end:#}");
}

#[test]
fn a_thread_that_cannot_start_with_no_connection_live_is_fatal_and_says_why() {
    let mut accepted = 0;
    let end = serve_connections(
        || {
            accepted += 1;
            Ok(accepted)
        },
        |_conn, live| {
            // What `hand_to_thread` does: the failed connection is neither live nor ended.
            live.abandon();
            Err(std::io::Error::other("no thread"))
        },
    );
    assert_eq!(accepted, 1, "accepted again with nothing that could free a thread");
    let text = format!("{end:#}");
    assert!(text.contains("no thread"), "{text}");
    assert!(text.contains("no connection"), "{text}");
}

#[test]
fn a_connection_handler_that_panics_still_counts_as_ended() {
    // The end is signalled by a guard, so a handler thread that unwinds does not leave the loop
    // waiting for a connection that is already gone.
    let connections = Connections::new();
    let live = connections.begin();
    let before = connections.ended();
    std::thread::spawn(move || {
        let _live = live;
        panic!("handler failed");
    })
    .join()
    .unwrap_err();
    assert!(connections.wait_for_an_end(before, || {}));
}

// home directory -----

#[test]
fn the_home_is_the_profile_when_that_is_a_directory() {
    let profile = TempProfile::new("home-ok");
    assert_eq!(find_home(Ok(profile.0.clone())).unwrap(), profile.0);
}

#[test]
fn a_profile_that_is_not_a_directory_is_no_home_and_says_so() {
    let profile = TempProfile::new("home-missing");
    let gone = profile.0.join("nope");
    let why = find_home(Ok(gone.clone())).unwrap_err();
    assert!(why.contains(&gone.display().to_string()), "{why}");
}

#[test]
fn an_account_with_no_profile_is_no_home_and_says_why() {
    let why = find_home(Err(anyhow::anyhow!("the account has no profile directory"))).unwrap_err();
    assert!(why.contains("no profile directory"), "{why}");
}

const HOME_CHILD_FLAG: &str = "SSH_BROKER_AGENT_HOME_TEST_CHILD";

/// The child half of [`home_comes_from_the_token_not_the_environment`]: not a test of its own, so
/// it is `ignore`d and runs only when the parent asks for it by name. It refuses to run without
/// the flag and prints a marker the parent must find.
#[test]
#[ignore = "run as a child of agent::agent_start_tests::home_comes_from_the_token_not_the_environment"]
fn child_prints_its_home_dir() {
    assert!(
        std::env::var_os(HOME_CHILD_FLAG).is_some(),
        "this test is the child half of a parent test and is not meant to be run alone"
    );
    println!(
        "HOME={}",
        home_dir()
            .expect("the profile of this account is a directory")
            .display()
    );
}

#[test]
fn home_comes_from_the_token_not_the_environment() {
    // The environment is the caller's to set; a home read from %USERPROFILE% would follow a decoy.
    let expected = crate::userdir::current_profile_dir().unwrap();
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "agent::agent_start_tests::child_prints_its_home_dir",
            "--ignored",
            "--nocapture",
        ])
        .env(HOME_CHILD_FLAG, "1")
        .env("USERPROFILE", r"C:\decoy\profile")
        .env("HOMEDRIVE", "C:")
        .env("HOMEPATH", r"\decoy\profile")
        .creation_flags(0x0800_0000)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "child failed: {stdout} {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let line = stdout
        .lines()
        .find_map(|l| l.strip_prefix("HOME="))
        .unwrap_or_else(|| panic!("the child printed no home: {stdout}"));
    assert_eq!(PathBuf::from(line), expected);
}

#[test]
fn a_stopped_loop_ends_although_a_connection_never_finishes() {
    let connections = Connections::with_drain_bound(std::time::Duration::from_millis(10));
    let _hung = connections.begin();
    let end = finish_stopped(anyhow::Error::new(Stopped), &connections, false);
    assert!(end.downcast_ref::<Stopped>().is_some(), "{end:#}");
}
