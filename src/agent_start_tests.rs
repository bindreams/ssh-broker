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

/// Run the accept loop over a script of outcomes; it ends with a fatal error when the script does.
fn run_script(script: Vec<Result<u32, AcceptError>>) -> (Vec<u32>, anyhow::Error) {
    let mut script = script.into_iter();
    let mut handled = Vec::new();
    let end = serve_connections(
        || {
            script
                .next()
                .unwrap_or_else(|| Err(AcceptError::Fatal(anyhow::anyhow!("end of script"))))
        },
        |conn| handled.push(conn),
    );
    (handled, end)
}

fn transient(code: i32) -> AcceptError {
    AcceptError::Transient {
        code: Some(code),
        source: std::io::Error::from_raw_os_error(code),
    }
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
fn a_transient_failure_is_forgiven_once_and_forgotten_by_the_next_connection() {
    let (handled, end) = run_script(vec![Err(transient(10024)), Ok(1), Err(transient(10024)), Ok(2)]);
    assert_eq!(handled, [1, 2]);
    assert!(format!("{end:#}").ends_with("end of script"), "{end:#}");
}

#[test]
fn the_same_transient_failure_twice_with_no_connection_between_is_a_broken_listener() {
    // Nothing clears, so the loop would spin on warnings: the repeat is fatal, by its kind and
    // not by counting attempts.
    let (handled, end) = run_script(vec![Err(transient(10024)), Err(transient(10024)), Ok(1)]);
    assert!(handled.is_empty());
    let text = format!("{end:#}");
    assert!(text.contains("10024"), "names the failure: {text}");
    assert!(text.contains("again"), "{text}");
}

#[test]
fn alternating_transient_failures_cannot_spin_either() {
    let (_, end) = run_script(vec![
        Err(transient(10024)),
        Err(transient(10055)),
        Err(transient(10024)),
    ]);
    assert!(format!("{end:#}").contains("10024"), "{end:#}");
}

#[test]
fn a_lost_connection_between_two_identical_transient_failures_does_not_clear_them() {
    let (_, end) = run_script(vec![Err(transient(10055)), Err(lost()), Err(transient(10055))]);
    assert!(format!("{end:#}").contains("10055"), "{end:#}");
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
