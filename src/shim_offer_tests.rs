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
