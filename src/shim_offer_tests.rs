//! Unit tests for `shim_offer`: what the shim does about a missing agent, as decisions. No console,
//! no logon, no account.
use super::*;
use crate::account::LocalAccount;
use std::cell::RefCell;

fn account(kind: AccountKind) -> Option<LocalAccount> {
    Some(LocalAccount {
        name: "alice".into(),
        sid: "S-1-5-21-1-2-3-1001".into(),
        kind,
    })
}

// plan -----

#[test]
fn exec_session_notice_is_one_line_on_stderr() {
    for absence in [Absence::NoAgent, Absence::NoProfileYet] {
        assert_eq!(
            plan(true, true, absence, account(AccountKind::Local), None),
            Plan::Notice { user: "alice".into() }
        );
    }
}

#[test]
fn no_terminal_login_gets_the_notice_and_never_enters_raw_mode() {
    // `plan` is all that runs before the console is touched: a plan that is not `Offer` never reaches
    // `ConsolePrompt::enter`.
    let plan = plan(false, false, Absence::NoAgent, account(AccountKind::Local), None);
    assert_eq!(plan, Plan::Notice { user: "alice".into() });
}

#[test]
fn a_terminal_login_without_a_command_is_offered_the_session() {
    for absence in [Absence::NoAgent, Absence::NoProfileYet] {
        let local = account(AccountKind::Local).unwrap();
        assert_eq!(
            plan(false, true, absence, Some(local.clone()), None),
            Plan::Offer {
                account: local,
                absence
            }
        );
    }
}

#[test]
fn a_non_local_account_is_still_told_why_at_the_terminal() {
    let other = account(AccountKind::NotLocal).unwrap();
    assert_eq!(
        plan(false, true, Absence::NoAgent, Some(other.clone()), None),
        Plan::Offer {
            account: other,
            absence: Absence::NoAgent
        }
    );
}

#[test]
fn a_non_local_account_gets_no_notice_that_names_a_command_it_cannot_use() {
    assert_eq!(
        plan(true, true, Absence::NoAgent, account(AccountKind::NotLocal), None),
        Plan::Nothing
    );
}

#[test]
fn other_absence_changes_nothing_today() {
    for (exec, console) in [(true, true), (false, true), (false, false)] {
        assert_eq!(
            plan(exec, console, Absence::Other, account(AccountKind::Local), None),
            Plan::Nothing,
            "exec={exec} console={console}"
        );
    }
}

#[test]
fn an_unreadable_account_changes_nothing() {
    assert_eq!(plan(false, true, Absence::NoAgent, None, None), Plan::Nothing);
    assert_eq!(plan(true, true, Absence::NoAgent, None, None), Plan::Nothing);
}

const REFUSAL: &str = "make the private folder p/ssh-broker: p/ssh-broker cannot be used as the private folder: its ACL is not exactly Full Control for me. It is left as it is: inspect it, remove it, and it is created again";

#[test]
fn a_refused_private_folder_is_shown_and_no_session_is_offered() {
    for exec in [false, true] {
        for console in [true, false] {
            for absence in [Absence::NoAgent, Absence::NoProfileYet, Absence::Other] {
                for account in [account(AccountKind::Local), account(AccountKind::NotLocal), None] {
                    assert_eq!(
                        plan(exec, console, absence, account, Some(REFUSAL)),
                        Plan::FolderRefused { cause: REFUSAL.into() },
                        "exec={exec} console={console} absence={absence:?}"
                    );
                }
            }
        }
    }
}

// the judgement of the folder -----

use crate::test_support::{TempProfile, junction, widen};

fn me() -> Sid {
    Sid::current_user().unwrap()
}

#[test]
fn a_folder_that_is_usable_or_not_there_yet_is_not_a_refusal() {
    // A first login: nothing is made yet, at any depth.
    let profile = TempProfile::new("fr-first");
    assert!(folder_refusal(&profile.location(), &me()).is_none(), "no folder yet");
    std::fs::remove_dir_all(profile.0.join("AppData")).unwrap();
    assert!(folder_refusal(&profile.location(), &me()).is_none(), "no AppData yet");
    let none = crate::test_support::location_in(&profile.0.join("none"));
    assert!(folder_refusal(&none, &me()).is_none(), "no profile directory yet");

    let usable = TempProfile::new("fr-ok");
    crate::userdir::ensure_socket_dir(&usable.location(), &me()).unwrap();
    assert!(folder_refusal(&usable.location(), &me()).is_none(), "an exact folder");
}

#[test]
fn a_refused_logs_folder_alone_does_not_make_the_private_folder_refused() {
    let profile = TempProfile::new("fr-logs");
    let location = profile.location();
    crate::userdir::ensure_socket_dir(&location, &me()).unwrap();
    widen(&location.logs_dir());

    assert!(folder_refusal(&location, &me()).is_none());
}

#[test]
fn every_failure_of_the_walk_but_a_missing_name_is_a_refusal_with_its_own_text() {
    let missing = {
        let profile = TempProfile::new("fr-miss");
        let root = crate::acl::open_root(&profile.0).unwrap();
        crate::acl::open_dir(&root, "Nothing").err().unwrap()
    };
    assert!(refusal_of(Err(missing)).is_none());
    assert!(refusal_of(Ok(())).is_none());

    // A system error of the walk (access denied at `Local`, an untrusted mount point at a followed
    // link) is not a `Refused`, and is shown all the same.
    for code in [
        windows::Win32::Foundation::ERROR_ACCESS_DENIED,
        windows::Win32::Foundation::ERROR_UNTRUSTED_MOUNT_POINT,
    ] {
        let system = anyhow::Error::from(windows::core::Error::from(windows::core::HRESULT::from_win32(code.0)))
            .context("open p/AppData/Local");
        assert!(!system.is::<crate::acl::Refused>());
        let shown = format!("{:#}", refusal_of(Err(system)).expect("a system error is shown"));
        assert!(shown.starts_with("open p/AppData/Local: "), "{shown}");
    }
}

/// What the rescue of a login for `location` shows, and how it goes on. `log_failure` is why the
/// shim has no log.
fn rescued(location: SocketLocation, exec: bool, log_failure: Option<&str>) -> (Rescued, String) {
    let location = Ok(location);
    let connect = Err(anyhow::anyhow!("a connect that failed for no OS reason"));
    let mut shown = Vec::new();
    let rescued = Prompting.rescue(
        &Absent {
            exec,
            location: &location,
            connect: &connect,
            log_failure,
        },
        &mut shown,
    );
    (rescued, String::from_utf8(shown).unwrap())
}

fn rescued_interactively(location: SocketLocation) -> (Rescued, String) {
    rescued(location, false, None)
}

#[test]
fn a_login_whose_folder_has_the_wrong_acl_is_told_why_and_gets_the_plain_shell_without_a_prompt() {
    let profile = TempProfile::new("rs-acl");
    let location = profile.location();
    crate::userdir::ensure_socket_dir(&location, &me()).unwrap();
    widen(location.dir());

    let (rescued, shown) = rescued_interactively(location.clone());

    assert!(matches!(rescued, Rescued::Plain));
    assert!(shown.starts_with("ssh-broker: no session is offered"), "{shown:?}");
    assert!(shown.contains("its ACL is not exactly"), "{shown:?}");
    assert!(shown.contains(&location.dir().display().to_string()), "{shown:?}");
    assert!(shown.contains("remove"), "the remedy: {shown:?}");
}

#[test]
fn a_login_whose_way_to_the_folder_has_a_link_is_told_why_and_gets_the_plain_shell_without_a_prompt() {
    let profile = TempProfile::new("rs-link");
    let local = profile.0.join(r"AppData\Local");
    let elsewhere = profile.0.join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    std::fs::remove_dir(&local).unwrap();
    junction(&local, &elsewhere);

    let (rescued, shown) = rescued_interactively(profile.location());

    assert!(matches!(rescued, Rescued::Plain));
    assert!(shown.contains("reparse point"), "{shown:?}");
    assert!(
        shown.contains(&local.display().to_string()),
        "the link is named: {shown:?}"
    );
}

// wait_until_serving -----

/// Scripted answers for `wait_until_serving`, recording the order of its calls.
struct Script {
    connects: RefCell<Vec<Option<u32>>>,
    wakes: RefCell<Vec<Woke>>,
    events: RefCell<Vec<&'static str>>,
}

impl Script {
    fn new(connects: Vec<Option<u32>>, wakes: Vec<Woke>) -> Script {
        Script {
            connects: RefCell::new(connects.into_iter().rev().collect()),
            wakes: RefCell::new(wakes.into_iter().rev().collect()),
            events: RefCell::default(),
        }
    }

    fn run(&self) -> Served<u32> {
        wait_until_serving(
            || {
                self.events.borrow_mut().push("connect");
                Ok(self
                    .connects
                    .borrow_mut()
                    .pop()
                    .expect("connected more often than scripted"))
            },
            || {
                self.events.borrow_mut().push("wait");
                Ok(self.wakes.borrow_mut().pop().expect("waited more often than scripted"))
            },
            || {
                self.events.borrow_mut().push("rearm");
                Ok(())
            },
        )
        .unwrap()
    }
}

#[test]
fn a_connect_that_succeeds_at_once_never_waits() {
    let script = Script::new(vec![Some(1)], vec![]);
    assert!(matches!(script.run(), Served::Connected(1)));
    assert_eq!(*script.events.borrow(), ["connect"]);
}

#[test]
fn a_refusal_waits_for_a_change_rearms_first_and_then_connects_again() {
    let script = Script::new(vec![None, None, Some(7)], vec![Woke::Changed, Woke::Changed]);
    assert!(matches!(script.run(), Served::Connected(7)));
    assert_eq!(
        *script.events.borrow(),
        ["connect", "wait", "rearm", "connect", "wait", "rearm", "connect"],
        "the watch is re-armed before every connect that follows a wake, so a change in between is not lost"
    );
}

#[test]
fn an_agent_that_ended_gets_one_more_connect_and_a_serving_peer_is_used() {
    let script = Script::new(vec![None, Some(3)], vec![Woke::AgentExited(0)]);
    assert!(matches!(script.run(), Served::Connected(3)));
    assert_eq!(*script.events.borrow(), ["connect", "wait", "connect"]);
}

#[test]
fn an_agent_that_ended_with_no_peer_serving_reports_its_exit_code() {
    let script = Script::new(vec![None, None], vec![Woke::AgentExited(66)]);
    assert!(matches!(script.run(), Served::Ended { code: 66 }));
}

#[test]
fn a_failing_wait_or_rearm_is_an_error_not_a_hang() {
    let failed = wait_until_serving::<u32>(|| Ok(None), || anyhow::bail!("wait failed"), || Ok(())).unwrap_err();
    assert!(format!("{failed:#}").contains("wait failed"));
    let failed =
        wait_until_serving::<u32>(|| Ok(None), || Ok(Woke::Changed), || anyhow::bail!("rearm failed")).unwrap_err();
    assert!(format!("{failed:#}").contains("rearm failed"));
}

#[test]
fn a_starting_agent_that_is_gone_gets_one_more_connect_and_a_serving_peer_is_used() {
    let script = Script::new(vec![None, Some(3)], vec![Woke::Gone]);
    assert!(matches!(script.run(), Served::Connected(3)));
    assert_eq!(*script.events.borrow(), ["connect", "wait", "connect"]);

    let script = Script::new(vec![None, None], vec![Woke::Gone]);
    assert!(matches!(script.run(), Served::Gone));
}

// wait_while_starting -----

/// Scripted answers for `wait_while_starting`, recording the order of its calls.
struct Starts {
    connects: RefCell<Vec<Option<u32>>>,
    looks: RefCell<Vec<bool>>,
    wakes: RefCell<Vec<Woke>>,
    events: RefCell<Vec<&'static str>>,
}

impl Starts {
    fn new(connects: Vec<Option<u32>>, looks: Vec<bool>, wakes: Vec<Woke>) -> Starts {
        Starts {
            connects: RefCell::new(connects.into_iter().rev().collect()),
            looks: RefCell::new(looks.into_iter().rev().collect()),
            wakes: RefCell::new(wakes.into_iter().rev().collect()),
            events: RefCell::default(),
        }
    }

    fn run(&self) -> Starting<u32> {
        wait_while_starting(
            || {
                self.events.borrow_mut().push("connect");
                Ok(self
                    .connects
                    .borrow_mut()
                    .pop()
                    .expect("connected more often than scripted"))
            },
            || {
                self.events.borrow_mut().push("look");
                Ok(self.looks.borrow_mut().pop().expect("looked more often than scripted"))
            },
            || {
                self.events.borrow_mut().push("wait");
                Ok(self.wakes.borrow_mut().pop().expect("waited more often than scripted"))
            },
            || {
                self.events.borrow_mut().push("rearm");
                Ok(())
            },
        )
        .unwrap()
    }
}

#[test]
fn a_connect_that_succeeds_at_once_looks_for_nothing() {
    let starts = Starts::new(vec![Some(1)], vec![], vec![]);
    assert_eq!(starts.run(), Starting::Served(1));
    assert_eq!(*starts.events.borrow(), ["connect"]);
}

#[test]
fn a_refusal_with_no_agent_anywhere_is_no_agent_and_waits_for_nothing() {
    let starts = Starts::new(vec![None], vec![false], vec![]);
    assert_eq!(starts.run(), Starting::No);
    assert_eq!(*starts.events.borrow(), ["connect", "look"]);
}

#[test]
fn an_agent_process_that_holds_no_lock_yet_is_waited_for_and_then_used() {
    // The look is true on the agent's process alone: nothing here depends on the lock.
    let starts = Starts::new(
        vec![None, None, Some(5)],
        vec![true, true],
        vec![Woke::Changed, Woke::Changed],
    );
    assert_eq!(starts.run(), Starting::Served(5));
    assert_eq!(
        *starts.events.borrow(),
        [
            "connect", "look", "wait", "rearm", "connect", "look", "wait", "rearm", "connect"
        ],
        "the watch is re-armed before every connect that follows a wake"
    );
}

#[test]
fn every_agent_that_ends_is_looked_for_again_before_the_wait_is_given_up() {
    // The first agent ends while a second process is still starting: the wait goes on.
    let starts = Starts::new(
        vec![None, None, Some(9)],
        vec![true, true],
        vec![Woke::Gone, Woke::Changed],
    );
    assert_eq!(starts.run(), Starting::Served(9));
}

#[test]
fn an_agent_that_ended_without_serving_and_left_no_other_is_gone_not_absent() {
    let starts = Starts::new(vec![None, None], vec![true, false], vec![Woke::Gone]);
    assert_eq!(starts.run(), Starting::Gone);
    assert_eq!(*starts.events.borrow(), ["connect", "look", "wait", "connect", "look"]);
}

#[test]
fn a_failing_look_wait_or_rearm_is_an_error_not_a_hang() {
    let failed = wait_while_starting::<u32>(
        || Ok(None),
        || anyhow::bail!("look failed"),
        || Ok(Woke::Gone),
        || Ok(()),
    )
    .unwrap_err();
    assert!(format!("{failed:#}").contains("look failed"));
    let failed =
        wait_while_starting::<u32>(|| Ok(None), || Ok(true), || anyhow::bail!("wait failed"), || Ok(())).unwrap_err();
    assert!(format!("{failed:#}").contains("wait failed"));
    let failed = wait_while_starting::<u32>(
        || Ok(None),
        || Ok(true),
        || Ok(Woke::Changed),
        || anyhow::bail!("rearm failed"),
    )
    .unwrap_err();
    assert!(format!("{failed:#}").contains("rearm failed"));
}

#[test]
fn a_connect_that_fails_for_a_reason_that_waiting_does_not_clear_ends_the_wait_as_an_error() {
    let denied = || -> anyhow::Result<Option<u32>> { anyhow::bail!("access denied") };
    let failed = wait_until_serving(denied, || panic!("waited on an error"), || Ok(())).unwrap_err();
    assert!(format!("{failed:#}").contains("access denied"), "{failed:#}");
    let failed =
        wait_while_starting(denied, || panic!("looked on an error"), || panic!("waited"), || Ok(())).unwrap_err();
    assert!(format!("{failed:#}").contains("access denied"), "{failed:#}");
}

// a folder that is refused -----

/// The error a refused private folder gives the shim's look at it: a junction at `Local`.
fn refusal_of_a_junction_at_local(tag: &str) -> (crate::test_support::TempProfile, anyhow::Error) {
    let profile = crate::test_support::TempProfile::new(tag);
    let local = profile.0.join(r"AppData\Local");
    let elsewhere = profile.0.join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    std::fs::remove_dir(&local).unwrap();
    crate::test_support::junction(&local, &elsewhere);
    let err = Evidence::default()
        .look(
            &profile.location(),
            Path::new(r"C:\no\such\dir\ssh-broker.exe"),
            &Sid::current_user().unwrap(),
        )
        .unwrap_err();
    (profile, err)
}

#[test]
fn an_interactive_login_whose_folder_is_refused_is_told_on_the_terminal_and_gets_the_plain_shell() {
    let (profile, err) = refusal_of_a_junction_at_local("refused-pty");
    let mut shown = Vec::new();

    let rescued = starting_failed(&err, false, None, &mut shown);

    assert!(matches!(rescued, Rescued::Plain));
    let shown = String::from_utf8(shown).unwrap();
    assert!(shown.starts_with("ssh-broker: "), "{shown:?} for {err:#}");
    assert!(
        shown.contains(&profile.0.join(r"AppData\Local").display().to_string()),
        "the link is named: {shown}"
    );
    assert!(shown.contains("remove"), "the remedy: {shown}");
}

#[test]
fn a_folder_that_fails_with_a_system_error_after_it_was_judged_is_told_in_the_same_line() {
    let denied = windows::core::Error::from(windows::core::HRESULT::from_win32(
        windows::Win32::Foundation::ERROR_ACCESS_DENIED.0,
    ));
    let err = anyhow::Error::new(FolderFailed(anyhow::Error::new(denied).context("open p/AppData/Local")));
    let mut shown = Vec::new();

    let rescued = starting_failed(&err, false, None, &mut shown);

    assert!(matches!(rescued, Rescued::Plain));
    let shown = String::from_utf8(shown).unwrap();
    assert!(shown.starts_with("ssh-broker: no session is offered"), "{shown:?}");
    assert!(shown.contains("open p/AppData/Local"), "{shown:?}");
}

/// Why the log of a login cannot be set up in the state of `profile`: what the shim keeps as its
/// `log_failure`.
fn log_failure_of(profile: &crate::test_support::TempProfile) -> String {
    let err = crate::filelog::init_for_location(&profile.location(), &me(), "shim.log").unwrap_err();
    err.to_string()
}

#[test]
fn a_login_with_a_command_is_told_of_a_refused_folder_the_log_did_not_find() {
    // The folder became unusable after the log was set up (or the log failed for another reason).
    let (_profile, err) = refusal_of_a_junction_at_local("refused-exec");
    for log_failure in [None, Some("the disk is full")] {
        let mut shown = Vec::new();

        let rescued = starting_failed(&err, true, log_failure, &mut shown);

        assert!(matches!(rescued, Rescued::Plain));
        assert!(
            String::from_utf8(shown).unwrap().contains("no session is offered"),
            "{log_failure:?}"
        );
    }
}

#[test]
fn a_login_with_a_command_is_not_told_twice_what_the_log_already_says() {
    let (profile, err) = refusal_of_a_junction_at_local("refused-twice");
    let log_failure = log_failure_of(&profile);
    let mut shown = Vec::new();

    starting_failed(&err, true, Some(&log_failure), &mut shown);

    assert!(shown.is_empty(), "{}", String::from_utf8_lossy(&shown));
}

#[test]
fn the_rescue_tells_a_login_with_a_command_of_the_refusal_its_own_walk_found() {
    // Set up the log while the folder is fine; the rescue's walk is the one that finds the link.
    let profile = TempProfile::new("rs-exec");
    let local = profile.0.join(r"AppData\Local");
    let elsewhere = profile.0.join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    std::fs::remove_dir(&local).unwrap();
    junction(&local, &elsewhere);

    for log_failure in [None, Some("the disk is full")] {
        let (rescued, shown) = rescued(profile.location(), true, log_failure);

        assert!(matches!(rescued, Rescued::Plain));
        assert!(shown.contains("no session is offered"), "{log_failure:?}: {shown:?}");
        assert!(shown.contains(&local.display().to_string()), "{shown:?}");
    }
}

#[test]
fn the_rescue_does_not_repeat_to_a_login_with_a_command_what_the_log_already_says() {
    let profile = TempProfile::new("rs-twice");
    let local = profile.0.join(r"AppData\Local");
    let elsewhere = profile.0.join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    std::fs::remove_dir(&local).unwrap();
    junction(&local, &elsewhere);
    let log_failure = log_failure_of(&profile);

    let (rescued, shown) = rescued(profile.location(), true, Some(&log_failure));

    assert!(matches!(rescued, Rescued::Plain));
    assert!(shown.is_empty(), "{shown:?}");
}

#[test]
fn an_account_that_cannot_be_told_is_logged_and_the_folder_is_not_judged() {
    let profile = TempProfile::new("rs-nosid");
    let location = Ok(profile.location());
    let (log, refusal) =
        crate::test_support::logged(|| refusal_for(&location, &Err(anyhow::anyhow!("the token cannot be read"))));
    assert!(refusal.is_none());
    assert!(log.contains("the token cannot be read"), "{log}");
}

/// What `Evidence::look` says about a folder whose lock file `prepare` has made: `prepare` gets the
/// file's path and returns what must stay alive while the look is made.
fn look_at_lock<T>(tag: &str, prepare: impl FnOnce(&Path) -> T) -> anyhow::Error {
    let profile = crate::test_support::TempProfile::new(tag);
    let location = profile.location();
    let user = Sid::current_user().unwrap();
    crate::userdir::ensure_socket_dir(&location, &user).unwrap();
    let _kept = prepare(&location.dir().join(crate::socket_loc::LOCK_FILE_NAME));
    Evidence::default()
        .look(&location, Path::new(r"C:\no\such\dir\ssh-broker.exe"), &user)
        .unwrap_err()
}

#[test]
fn a_lock_file_held_without_sharing_is_not_a_failure_of_the_folder() {
    use std::os::windows::fs::OpenOptionsExt;
    // A scanner holding the file open without sharing: nothing is wrong with the folder.
    let err = look_at_lock("lk-share", |lock| {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(0)
            .open(lock)
            .unwrap()
    });
    assert!(!err.is::<FolderFailed>(), "{err:#}");
    let mut shown = Vec::new();

    starting_failed(&err, false, None, &mut shown);

    assert!(shown.is_empty(), "{}", String::from_utf8_lossy(&shown));
}

#[test]
fn a_lock_file_with_another_name_is_a_failure_of_the_folder() {
    let err = look_at_lock("lk-link", |lock| {
        std::fs::write(lock, b"").unwrap();
        std::fs::hard_link(lock, lock.with_file_name("elsewhere")).unwrap();
    });
    assert!(err.is::<FolderFailed>(), "{err:#}");
}

#[test]
fn a_failure_that_is_not_a_refusal_is_logged_and_not_shown_to_an_interactive_login() {
    let mut shown = Vec::new();
    let (log, rescued) = crate::test_support::logged(|| {
        starting_failed(&anyhow::anyhow!("the process list failed"), false, None, &mut shown)
    });
    assert!(matches!(rescued, Rescued::Plain));
    assert!(shown.is_empty());
    assert!(log.contains("the process list failed"), "{log}");
}

// logs_dir -----

#[test]
fn the_log_folder_is_named_when_the_location_is_known_and_the_failure_is_logged_when_it_is_not() {
    let profile = crate::test_support::TempProfile::new("logs-dir");
    let location = profile.location();
    assert_eq!(logs_dir(Ok(location.clone())), Some(location.logs_dir()));

    let (log, dir) = crate::test_support::logged(|| logs_dir(Err(anyhow::anyhow!("no profile for this token"))));
    assert_eq!(dir, None, "no folder is invented");
    assert!(log.contains("no profile for this token"), "{log}");
}

// connect_if_listening -----

#[test]
fn a_socket_that_is_not_there_is_nobody_listening() {
    let profile = crate::test_support::TempProfile::new("connect-missing");
    let location = profile.location();
    // The folder is missing.
    assert!(connect_if_listening(location.path()).unwrap().is_none());
    // The folder is there and the socket file is not.
    std::fs::create_dir_all(location.dir()).unwrap();
    assert!(connect_if_listening(location.path()).unwrap().is_none());
}

#[test]
fn a_socket_with_nobody_listening_on_it_is_nobody_listening() {
    use socket2::{Domain, SockAddr, Socket, Type};
    let profile = crate::test_support::TempProfile::new("connect-unlistened");
    let location = profile.location();
    std::fs::create_dir_all(location.dir()).unwrap();
    // The file exists and `listen()` has not run, as in the agent's start.
    let socket = Socket::new(Domain::UNIX, Type::STREAM, None).unwrap();
    socket.bind(&SockAddr::unix(location.path()).unwrap()).unwrap();
    assert!(connect_if_listening(location.path()).unwrap().is_none());
}

#[test]
fn a_connect_that_fails_for_any_other_reason_is_an_error_naming_the_path() {
    let long = std::path::PathBuf::from(format!(r"C:\{}\agent.sock", "x".repeat(120)));
    let failed = connect_if_listening(&long).unwrap_err();
    assert!(format!("{failed:#}").contains("too long"), "{failed:#}");
}

// wait_for_agent: the shim's own token and a temporary profile; no account, no logon -----

mod wait_for_agent_on_files {
    use super::*;
    use crate::test_support::TempProfile;
    use std::os::windows::io::AsRawHandle;
    use std::os::windows::process::CommandExt;
    use windows::Win32::System::Threading::CreateEventW;

    /// A handle that is never signalled: an agent that is neither done nor gone.
    fn live_agent() -> crate::winutil::OwnedHandle {
        // SAFETY: an unnamed manual-reset event, not signalled.
        crate::winutil::OwnedHandle(unsafe { CreateEventW(None, true, false, windows::core::PCWSTR::null()) }.unwrap())
    }

    fn marker_exists(location: &SocketLocation) -> anyhow::Result<Option<()>> {
        Ok(location.serving_marker_path().is_file().then_some(()))
    }

    #[test]
    fn a_marker_written_while_the_shim_waits_connects_it() {
        let profile = TempProfile::new("wait-marker");
        let location = profile.location();
        let agent = live_agent();
        let watch = SocketWatch::for_location(&location).unwrap();
        // Whether this thread runs before, during or after the wait, the shim must find the marker.
        let writer = {
            let location = location.clone();
            std::thread::spawn(move || {
                crate::userdir::ensure_socket_dir(&location, &crate::acl::Sid::current_user().unwrap()).unwrap();
                crate::agent_background::mark_listening(&location).unwrap();
            })
        };
        let served = wait_for_agent(watch, agent.0, marker_exists).unwrap();
        writer.join().unwrap();
        assert_eq!(served, Served::Connected(()));
    }

    #[test]
    fn an_agent_that_ends_with_no_marker_is_reported_with_its_exit_code() {
        let profile = TempProfile::new("wait-ended");
        let location = profile.location();
        let mut child = std::process::Command::new("cmd.exe")
            .args(["/c", "exit 3"])
            .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
            .spawn()
            .unwrap();
        let handle = windows::Win32::Foundation::HANDLE(child.as_raw_handle());
        let watch = SocketWatch::for_location(&location).unwrap();
        let served = wait_for_agent(watch, handle, marker_exists).unwrap();
        child.wait().unwrap();
        assert_eq!(served, Served::Ended { code: 3 });
    }

    #[test]
    fn a_marker_already_there_connects_without_waiting() {
        let profile = TempProfile::new("wait-there");
        let location = profile.location();
        crate::userdir::ensure_socket_dir(&location, &crate::acl::Sid::current_user().unwrap()).unwrap();
        crate::agent_background::mark_listening(&location).unwrap();
        let agent = live_agent();
        let watch = SocketWatch::for_location(&location).unwrap();
        assert_eq!(
            wait_for_agent(watch, agent.0, marker_exists).unwrap(),
            Served::Connected(())
        );
    }
}

// after the shim's own agent -----

/// Two first connections start two agents; the one that finds the session's slot taken exits 0 at once,
/// and the winner may not be listening yet. The shim of the loser then waits for the winner and uses it.
#[test]
fn an_own_agent_that_left_while_another_one_starts_is_replaced_by_the_one_that_serves() {
    let served = serve_after_own_agent(Served::Ended { code: 0 }, || Ok(Starting::Served("winner"))).unwrap();
    assert_eq!(served, Served::Connected("winner"));
}

#[test]
fn an_own_agent_that_left_with_no_other_keeps_its_exit_code() {
    for others in [Starting::No, Starting::Gone] {
        let served = serve_after_own_agent(Served::Ended { code: 66 }, || Ok(others)).unwrap();
        assert_eq!(served, Served::Ended::<&str> { code: 66 });
    }
}

#[test]
fn a_lock_holder_that_left_with_no_other_is_still_gone() {
    let served = serve_after_own_agent(Served::Gone, || Ok(Starting::<&str>::No)).unwrap();
    assert_eq!(served, Served::Gone);
}

#[test]
fn an_own_agent_that_serves_is_used_without_looking_for_another() {
    let served = serve_after_own_agent(Served::Connected("mine"), || -> anyhow::Result<Starting<&str>> {
        panic!("nothing else needs to be looked for")
    })
    .unwrap();
    assert_eq!(served, Served::Connected("mine"));
}

#[test]
fn a_failing_look_for_another_agent_is_an_error() {
    let result = serve_after_own_agent(Served::Ended { code: 0 }, || -> anyhow::Result<Starting<&str>> {
        anyhow::bail!("cannot look")
    });
    assert!(result.is_err());
}

// the line about a session that ends with the connection -----

#[test]
fn a_session_that_ends_with_its_connection_says_so_in_one_line() {
    use crate::logon::Survival;
    let line = survival_notice(Survival::EndsWithConnection).expect("the user is told");
    assert_eq!(
        line,
        "ssh-broker: this connection cannot let the Windows session outlive it, so the session ends when you disconnect.\r\n"
    );
    assert_eq!(line.matches('\n').count(), 1, "one line");
}

#[test]
fn a_session_that_may_end_with_its_connection_says_so_in_one_line() {
    use crate::logon::Survival;
    let line = survival_notice(Survival::MayEndWithConnection).expect("the user is told");
    assert_eq!(
        line,
        "ssh-broker: this connection may not let the Windows session outlive it; if so, the session ends when you disconnect.\r\n"
    );
    assert_eq!(line.matches('\n').count(), 1, "one line");
}

#[test]
fn a_session_that_outlives_its_connection_says_nothing() {
    use crate::logon::Survival;
    assert_eq!(survival_notice(Survival::OutlivesConnection), None);
}
