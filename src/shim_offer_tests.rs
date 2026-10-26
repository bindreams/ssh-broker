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
            plan(true, true, absence, account(AccountKind::Local)),
            Plan::Notice { user: "alice".into() }
        );
    }
}

#[test]
fn no_terminal_login_gets_the_notice_and_never_enters_raw_mode() {
    // `plan` is all that runs before the console is touched: a plan that is not `Offer` never reaches
    // `ConsolePrompt::enter`.
    let plan = plan(false, false, Absence::NoAgent, account(AccountKind::Local));
    assert_eq!(plan, Plan::Notice { user: "alice".into() });
}

#[test]
fn a_terminal_login_without_a_command_is_offered_the_session() {
    for absence in [Absence::NoAgent, Absence::NoProfileYet] {
        let local = account(AccountKind::Local).unwrap();
        assert_eq!(
            plan(false, true, absence, Some(local.clone())),
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
        plan(false, true, Absence::NoAgent, Some(other.clone())),
        Plan::Offer {
            account: other,
            absence: Absence::NoAgent
        }
    );
}

#[test]
fn a_non_local_account_gets_no_notice_that_names_a_command_it_cannot_use() {
    assert_eq!(
        plan(true, true, Absence::NoAgent, account(AccountKind::NotLocal)),
        Plan::Nothing
    );
}

#[test]
fn other_absence_changes_nothing_today() {
    for (exec, console) in [(true, true), (false, true), (false, false)] {
        assert_eq!(
            plan(exec, console, Absence::Other, account(AccountKind::Local)),
            Plan::Nothing,
            "exec={exec} console={console}"
        );
    }
}

#[test]
fn an_unreadable_account_changes_nothing() {
    assert_eq!(plan(false, true, Absence::NoAgent, None), Plan::Nothing);
    assert_eq!(plan(true, true, Absence::NoAgent, None), Plan::Nothing);
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
                self.connects
                    .borrow_mut()
                    .pop()
                    .expect("connected more often than scripted")
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
    let failed = wait_until_serving::<u32>(|| None, || anyhow::bail!("wait failed"), || Ok(())).unwrap_err();
    assert!(format!("{failed:#}").contains("wait failed"));
    let failed =
        wait_until_serving::<u32>(|| None, || Ok(Woke::Changed), || anyhow::bail!("rearm failed")).unwrap_err();
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
                self.connects
                    .borrow_mut()
                    .pop()
                    .expect("connected more often than scripted")
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
    let failed =
        wait_while_starting::<u32>(|| None, || anyhow::bail!("look failed"), || Ok(Woke::Gone), || Ok(())).unwrap_err();
    assert!(format!("{failed:#}").contains("look failed"));
    let failed =
        wait_while_starting::<u32>(|| None, || Ok(true), || anyhow::bail!("wait failed"), || Ok(())).unwrap_err();
    assert!(format!("{failed:#}").contains("wait failed"));
    let failed = wait_while_starting::<u32>(
        || None,
        || Ok(true),
        || Ok(Woke::Changed),
        || anyhow::bail!("rearm failed"),
    )
    .unwrap_err();
    assert!(format!("{failed:#}").contains("rearm failed"));
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

    fn marker_exists(location: &SocketLocation) -> Option<()> {
        location.serving_marker_path().is_file().then_some(())
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
