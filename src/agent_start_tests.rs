//! Tests for how the agent starts and keeps serving: the session check, the order of its locks,
//! what it does with a failed log, the accept loop and the home directory. None needs a second
//! session or elevation, and none runs a shell.
use super::*;
use crate::acl::{self, Sid};
use crate::afunix::AcceptError;
use crate::test_support::TempProfile;
use std::cell::{Cell, RefCell};
use std::os::windows::process::CommandExt;

fn guard() -> tracing_appender::non_blocking::WorkerGuard {
    tracing_appender::non_blocking(std::io::sink()).1
}

// start -----

#[test]
fn start_refuses_session_zero_before_it_touches_anything() {
    let err = start_with(
        0,
        || -> anyhow::Result<SocketLocation> { panic!("must not look for the profile in session 0") },
        |_| -> anyhow::Result<_> { panic!("must not open a log in session 0") },
        |_, _| panic!("must not serve in session 0"),
    )
    .unwrap_err();
    assert!(format!("{err:#}").contains("session 0"), "{err:#}");
}

#[test]
fn start_makes_the_private_folder_then_serves_that_session_from_it() {
    let profile = TempProfile::new("start-ok");
    let loc = profile.location();
    let served = Cell::new(None);

    start_with(
        3,
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
        3,
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
        3,
        || Ok(loc.clone()),
        |_| Ok(guard()),
        |_, _| anyhow::bail!("listener broke"),
    )
    .unwrap_err();
    assert_eq!(format!("{err:#}"), "listener broke");
}

#[test]
fn a_failed_log_setup_is_printed_with_its_cause_and_the_agent_goes_on() {
    let mut stderr = Vec::new();
    let kept = keep_log_or_report(Err(anyhow::anyhow!("the folder belongs to someone else")), &mut stderr);
    let text = String::from_utf8(stderr).unwrap();
    assert!(kept.is_none());
    assert!(text.contains("the folder belongs to someone else"), "{text}");
    assert!(text.contains("without a log"), "{text}");
}

#[test]
fn a_log_that_opened_prints_nothing_and_is_kept() {
    let mut stderr = Vec::new();
    assert!(keep_log_or_report(Ok(guard()), &mut stderr).is_some());
    assert!(stderr.is_empty());
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
    )
    .unwrap();
}

#[test]
fn serve_holds_the_session_slot_before_it_takes_the_user_lock_and_both_while_it_serves() {
    let (_profile, loc) = location_with_dir("serve-order");
    let events = RefCell::new(Vec::new());

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
    )
    .unwrap();

    assert_eq!(events.into_inner(), ["user lock", "serve"]);
    assert!(
        SessionSlot::try_acquire(&loc.sessions_lock_path(), 7)
            .unwrap()
            .is_some(),
        "released"
    );
    assert!(UserLock::try_acquire(&loc.lock_path()).unwrap().is_some(), "released");
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
