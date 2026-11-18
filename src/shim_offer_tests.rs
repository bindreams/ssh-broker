//! Unit tests for `shim_offer`: what the shim does about a missing agent, as decisions. No console,
//! no logon, no account.
use super::*;
use crate::account::{Elevation, LocalAccount};
use crate::protocol::ElevationPolicy;
use crate::socket_loc::Integrity;
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
            plan(
                true,
                true,
                absence,
                account(AccountKind::Local),
                None,
                LogonKind::Interactive
            ),
            Plan::Notice { user: "alice".into() }
        );
    }
}

#[test]
fn no_terminal_login_gets_the_notice_and_never_enters_raw_mode() {
    // `plan` is all that runs before the console is touched: a plan that is not `Offer` never reaches
    // `ConsolePrompt::enter`.
    let plan = plan(
        false,
        false,
        Absence::NoAgent,
        account(AccountKind::Local),
        None,
        LogonKind::Interactive,
    );
    assert_eq!(plan, Plan::Notice { user: "alice".into() });
}

#[test]
fn a_terminal_login_without_a_command_is_offered_the_session() {
    for absence in [Absence::NoAgent, Absence::NoProfileYet] {
        let local = account(AccountKind::Local).unwrap();
        assert_eq!(
            plan(false, true, absence, Some(local.clone()), None, LogonKind::Interactive),
            Plan::Offer {
                account: local,
                absence,
                logon: LogonKind::Interactive
            }
        );
    }
}

#[test]
fn a_non_local_account_is_still_told_why_at_the_terminal() {
    let other = account(AccountKind::NotLocal).unwrap();
    assert_eq!(
        plan(
            false,
            true,
            Absence::NoAgent,
            Some(other.clone()),
            None,
            LogonKind::Interactive
        ),
        Plan::Offer {
            account: other,
            absence: Absence::NoAgent,
            logon: LogonKind::Interactive
        }
    );
}

#[test]
fn a_non_local_account_gets_no_notice_that_names_a_command_it_cannot_use() {
    assert_eq!(
        plan(
            true,
            true,
            Absence::NoAgent,
            account(AccountKind::NotLocal),
            None,
            LogonKind::Interactive
        ),
        Plan::Nothing
    );
}

#[test]
fn other_absence_changes_nothing_today() {
    for (exec, console) in [(true, true), (false, true), (false, false)] {
        assert_eq!(
            plan(
                exec,
                console,
                Absence::Other,
                account(AccountKind::Local),
                None,
                LogonKind::Interactive
            ),
            Plan::Nothing,
            "exec={exec} console={console}"
        );
    }
}

#[test]
fn an_unreadable_account_changes_nothing() {
    assert_eq!(
        plan(false, true, Absence::NoAgent, None, None, LogonKind::Interactive),
        Plan::Nothing
    );
    assert_eq!(
        plan(true, true, Absence::NoAgent, None, None, LogonKind::Interactive),
        Plan::Nothing
    );
}

// stance -----

const AT_HIGH: anyhow::Result<Integrity> = Ok(Integrity::High);
const AT_MEDIUM: anyhow::Result<Integrity> = Ok(Integrity::Medium);

#[test]
fn a_full_token_relays_with_a_batch_logon() {
    assert_eq!(
        stance(None, Ok(Elevation::Full), &AT_HIGH),
        Stance::Relay {
            logon: LogonKind::Batch
        }
    );
}

#[test]
fn a_standard_token_at_medium_relays_with_an_interactive_logon() {
    assert_eq!(
        stance(None, Ok(Elevation::Standard), &AT_MEDIUM),
        Stance::Relay {
            logon: LogonKind::Interactive
        }
    );
}

/// An account that is not an administrator can still hold a full token, and its shim then waits on the
/// elevated folder; the agent the prompt starts has to serve that one, which only a batch logon does.
#[test]
fn a_standard_token_at_high_relays_with_a_batch_logon() {
    assert_eq!(
        stance(None, Ok(Elevation::Standard), &AT_HIGH),
        Stance::Relay {
            logon: LogonKind::Batch
        }
    );
}

#[test]
fn a_filtered_token_gets_the_plain_shell_and_no_relay() {
    assert_eq!(stance(None, Ok(Elevation::Filtered), &AT_MEDIUM), Stance::PlainShell);
    assert_eq!(stance(None, Ok(Elevation::Filtered), &AT_HIGH), Stance::PlainShell);
    // Whatever its level: one that cannot be read does not turn the plain shell into a relay.
    assert_eq!(
        stance(
            None,
            Ok(Elevation::Filtered),
            &Err(anyhow::anyhow!("the level cannot be read"))
        ),
        Stance::PlainShell
    );
}

#[test]
fn an_unreadable_elevation_still_relays_but_offers_nothing_and_keeps_the_cause() {
    assert_eq!(
        stance(None, Err(anyhow::anyhow!("the token cannot be read")), &AT_HIGH),
        Stance::RelayWithoutOffer {
            cause: "the token cannot be read".into()
        }
    );
}

/// The logon kind comes from the integrity level, so a level that cannot be read leaves no kind to offer.
#[test]
fn an_unreadable_integrity_level_still_relays_but_offers_nothing_and_keeps_the_cause() {
    for elevation in [Elevation::Full, Elevation::Standard] {
        assert_eq!(
            stance(None, Ok(elevation), &Err(anyhow::anyhow!("the level cannot be read"))),
            Stance::RelayWithoutOffer {
                cause: "the level cannot be read".into()
            }
        );
    }
}

/// `always` below High is refused at any elevation of the token.
#[test]
fn always_below_high_is_refused_before_anything_connects() {
    for elevation in [Elevation::Standard, Elevation::Filtered] {
        let got = stance(Some(ElevationPolicy::Always), Ok(elevation), &AT_MEDIUM);
        let expected = match elevation {
            Elevation::Filtered => AlwaysRefusal::Filtered,
            _ => AlwaysRefusal::BelowHigh,
        };
        assert_eq!(got, Stance::Refused(expected), "{elevation:?}");
    }
    assert_eq!(
        stance(
            Some(ElevationPolicy::Always),
            Err(anyhow::anyhow!("the token cannot be read")),
            &AT_MEDIUM
        ),
        Stance::Refused(AlwaysRefusal::BelowHigh)
    );
}

#[test]
fn always_at_high_relays_for_a_token_that_can_be_elevated() {
    for elevation in [Elevation::Full, Elevation::Standard] {
        assert_eq!(
            stance(Some(ElevationPolicy::Always), Ok(elevation), &AT_HIGH),
            Stance::Relay {
                logon: LogonKind::Batch
            },
            "{elevation:?}"
        );
    }
    assert_eq!(
        stance(
            Some(ElevationPolicy::Always),
            Err(anyhow::anyhow!("the token cannot be read")),
            &AT_HIGH
        ),
        Stance::RelayWithoutOffer {
            cause: "the token cannot be read".into()
        }
    );
}

/// `always` for a filtered token is refused at every level, readable or not.
#[test]
fn always_for_a_filtered_token_is_refused_at_every_level() {
    for integrity in [AT_MEDIUM, AT_HIGH, Err(anyhow::anyhow!("the level cannot be read"))] {
        assert_eq!(
            stance(Some(ElevationPolicy::Always), Ok(Elevation::Filtered), &integrity),
            Stance::Refused(AlwaysRefusal::Filtered)
        );
    }
}

/// `always` with an unreadable level is refused with the cause.
#[test]
fn always_with_an_unreadable_level_is_refused_with_the_cause() {
    for elevation in [Ok(Elevation::Full), Ok(Elevation::Standard), Err(anyhow::anyhow!("x"))] {
        assert_eq!(
            stance(
                Some(ElevationPolicy::Always),
                elevation,
                &Err(anyhow::anyhow!("the level cannot be read"))
            ),
            Stance::Refused(AlwaysRefusal::LevelUnreadable("the level cannot be read".into()))
        );
    }
}

/// Only `always` is decided here: every other policy, set or not, is stepped down later by the one rule.
#[test]
fn the_other_policies_are_not_refused_at_any_level() {
    for asked in [
        None,
        Some(ElevationPolicy::Never),
        Some(ElevationPolicy::Prompt),
        Some(ElevationPolicy::AutoApprove),
    ] {
        for integrity in [AT_MEDIUM, AT_HIGH] {
            let got = stance(asked, Ok(Elevation::Standard), &integrity);
            assert!(matches!(got, Stance::Relay { .. }), "{asked:?}: {got:?}");
        }
        assert_eq!(stance(asked, Ok(Elevation::Filtered), &AT_MEDIUM), Stance::PlainShell);
    }
}

/// A blank command ends the run, unless the stance is a refusal.
#[test]
fn a_blank_command_ends_the_run_quietly_unless_the_login_is_refused() {
    let cases = [
        (Stance::PlainShell, true),
        (
            Stance::Relay {
                logon: LogonKind::Batch,
            },
            true,
        ),
        (
            Stance::Relay {
                logon: LogonKind::Interactive,
            },
            true,
        ),
        (Stance::RelayWithoutOffer { cause: "x".into() }, true),
        (Stance::Refused(AlwaysRefusal::Filtered), false),
        (Stance::Refused(AlwaysRefusal::BelowHigh), false),
        (Stance::Refused(AlwaysRefusal::LevelUnreadable("x".into())), false),
    ];
    for (stance, ends) in cases {
        assert_eq!(blank_command_ends_run(&stance, true), ends, "{stance:?}, blank");
        assert!(!blank_command_ends_run(&stance, false), "{stance:?}, not blank");
    }
}

/// Each refusal says the sentence of `offer::text` for it.
#[test]
fn each_refusal_says_its_own_sentence() {
    assert_eq!(AlwaysRefusal::BelowHigh.message(), text::always_below_high());
    assert_eq!(AlwaysRefusal::Filtered.message(), text::always_filtered());
    assert_eq!(
        AlwaysRefusal::LevelUnreadable("c".into()).message(),
        text::always_level_unreadable("c")
    );
}

const REFUSAL: &str = "make the private folder p/ssh-broker: p/ssh-broker cannot be used as the private folder: its ACL is not exactly Full Control for me. It is left as it is: inspect it, remove it, and it is created again";

#[test]
fn a_refused_private_folder_is_shown_and_no_session_is_offered() {
    for exec in [false, true] {
        for console in [true, false] {
            for absence in [Absence::NoAgent, Absence::NoProfileYet, Absence::Other] {
                for account in [account(AccountKind::Local), account(AccountKind::NotLocal), None] {
                    assert_eq!(
                        plan(exec, console, absence, account, Some(REFUSAL), LogonKind::Interactive),
                        Plan::FolderRefused { cause: REFUSAL.into() },
                        "exec={exec} console={console} absence={absence:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn an_offer_carries_the_logon_it_is_handed() {
    let local = account(AccountKind::Local).unwrap();
    for absence in [Absence::NoAgent, Absence::NoProfileYet] {
        assert_eq!(
            plan(false, true, absence, Some(local.clone()), None, LogonKind::Batch),
            Plan::Offer {
                account: local.clone(),
                absence,
                logon: LogonKind::Batch
            }
        );
    }
}

#[test]
fn a_batch_logon_without_a_console_gets_the_notice_as_before() {
    assert_eq!(
        plan(
            true,
            true,
            Absence::NoAgent,
            account(AccountKind::Local),
            None,
            LogonKind::Batch
        ),
        Plan::Notice { user: "alice".into() }
    );
}

#[test]
fn a_missing_batch_right_is_told_in_the_prompts_sentence_and_only_for_a_batch_logon() {
    let right = crate::logon::LogonFailure::from_win32(1385);
    let told = start_failure(LogonKind::Batch, "alice", right.clone());
    let StartFailure::Limit { sentence } = told else {
        panic!("{told:?}");
    };
    assert_eq!(
        sentence,
        crate::autologin::batch_right_missing("alice", crate::autologin::FROM_PROMPT)
    );
    // An interactive logon's 1385 is Windows' own to say: the sentence is about a batch job.
    assert!(matches!(
        start_failure(LogonKind::Interactive, "alice", right),
        StartFailure::Windows { .. }
    ));
}

#[test]
fn a_missing_impersonation_right_is_told_for_a_batch_logon_only() {
    let held_by_administrators = crate::logon::LogonFailure::from_win32(1314);
    assert!(held_by_administrators.privilege_not_held());
    let told = start_failure(LogonKind::Batch, "alice", held_by_administrators.clone());
    let StartFailure::Limit { sentence } = told else {
        panic!("{told:?}");
    };
    assert_eq!(sentence, crate::offer::text::impersonate_right_missing("alice"));
    assert!(
        sentence.contains("Impersonate a client after authentication"),
        "{sentence}"
    );
    assert!(
        sentence.contains("a logon at the desktop starts one without it"),
        "the way out is the batch sentence's: {sentence}"
    );
    assert!(
        !sentence.contains("grant"),
        "it does not tell the account to widen its rights"
    );
    // An interactive logon takes no such right: its 1314 is Windows' own to say.
    assert!(matches!(
        start_failure(LogonKind::Interactive, "alice", held_by_administrators),
        StartFailure::Windows { .. }
    ));
}

#[test]
fn another_failure_of_the_batch_logon_is_windows_own_text() {
    let wrong = crate::logon::LogonFailure::from_win32(1326);
    let reason = wrong.reason.clone();
    let StartFailure::Windows { reason: told } = start_failure(LogonKind::Batch, "alice", wrong) else {
        panic!("a wrong password is Windows' to say");
    };
    assert_eq!(told, reason);
}

// the shim's one walk -----

use crate::test_support::{TempProfile, junction, widen};

fn me() -> Sid {
    Sid::current_user().unwrap()
}

/// The shim's folder at `location`, walked as the current user.
fn folder_at(location: SocketLocation) -> Folder {
    Folder::in_location(Ok(location), Ok(me()))
}

#[test]
fn a_folder_that_is_usable_or_not_there_yet_is_not_refused() {
    // A first login: nothing is made yet, at any depth.
    let profile = TempProfile::new("fr-first");
    assert!(folder_at(profile.location()).refusal().is_none(), "no folder yet");
    std::fs::remove_dir_all(profile.0.join("AppData")).unwrap();
    assert!(folder_at(profile.location()).refusal().is_none(), "no AppData yet");
    let none = crate::test_support::location_in(&profile.0.join("none"));
    assert!(folder_at(none).refusal().is_none(), "no profile directory yet");

    let usable = TempProfile::new("fr-ok");
    crate::userdir::ensure_socket_dir(&usable.location(), &me()).unwrap();
    assert!(folder_at(usable.location()).refusal().is_none(), "an exact folder");
}

#[test]
fn a_refused_logs_folder_alone_does_not_make_the_private_folder_refused() {
    let profile = TempProfile::new("fr-logs");
    let location = profile.location();
    crate::userdir::ensure_socket_dir(&location, &me()).unwrap();
    widen(&location.logs_dir());

    let folder = folder_at(location);

    assert!(folder.refusal().is_none());
    assert!(folder.logs().is_err(), "the log is what it costs");
}

#[test]
fn an_account_that_cannot_be_told_is_not_walked_and_the_cause_is_the_logs_failure() {
    let profile = TempProfile::new("rs-nosid");
    let folder = Folder::in_location(Ok(profile.location()), Err(anyhow::anyhow!("the token cannot be read")));
    assert!(folder.refusal().is_none());
    let why = format!("{:#}", folder.logs().err().expect("nothing was walked"));
    assert!(why.contains("the token cannot be read"), "{why}");
    assert!(folder.connect().is_err(), "nothing to connect through");
}

/// What the rescue of a login for `location` shows, and how it goes on. The rescue is handed the
/// folder the shim's one walk found.
fn rescued(location: SocketLocation, exec: bool) -> (Rescued, String) {
    let folder = folder_at(location);
    let connect = Err(anyhow::anyhow!("a connect that failed for no OS reason"));
    let mut shown = Vec::new();
    let rescued = Prompting::new(Ok(LogonKind::Interactive)).rescue(
        &Absent {
            exec,
            folder: &folder,
            connect: &connect,
        },
        &mut shown,
    );
    (rescued, String::from_utf8(shown).unwrap())
}

#[test]
fn the_rescue_of_a_shim_whose_token_cannot_be_read_offers_nothing_and_says_why() {
    let profile = TempProfile::new("rs-no-token");
    let folder = folder_at(profile.location());
    let connect = folder.connect();
    for exec in [false, true] {
        let mut shown = Vec::new();
        let (log, rescued) = crate::test_support::logged(|| {
            Prompting::new(Err("the token cannot be read".into())).rescue(
                &Absent {
                    exec,
                    folder: &folder,
                    connect: &connect,
                },
                &mut shown,
            )
        });
        assert!(matches!(rescued, Rescued::Plain), "exec={exec}");
        assert_eq!(
            String::from_utf8(shown).unwrap(),
            format!(
                "{}
",
                text::elevation_unreadable("the token cannot be read")
            ),
            "exec={exec}"
        );
        assert!(log.contains("the token cannot be read"), "{log}");
    }
}

fn rescued_interactively(location: SocketLocation) -> (Rescued, String) {
    rescued(location, false)
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

// a folder that is looked at again -----

/// The folder of a shim whose first act found no `AppData`, and which has since been made and widened:
/// the walk that looks again refuses it.
fn folder_missing_at_the_first_act_and_refused_since() -> (TempProfile, SocketLocation, Folder) {
    let profile = TempProfile::new("late-ref");
    let location = profile.location();
    std::fs::remove_dir_all(profile.0.join("AppData")).unwrap();
    let folder = folder_at(location.clone());
    assert!(
        folder.refusal().is_none(),
        "control: nothing is refused at the first act"
    );
    std::fs::create_dir_all(profile.0.join(r"AppData\Local")).unwrap();
    crate::userdir::ensure_socket_dir(&location, &me()).unwrap();
    widen(location.dir());
    (profile, location, folder)
}

#[test]
fn a_refusal_found_when_the_folder_is_looked_at_again_is_the_refusal_of_the_folder() {
    let (_profile, location, folder) = folder_missing_at_the_first_act_and_refused_since();

    let err = folder.connect().expect_err("the folder is refused");

    assert!(err.is::<crate::acl::Refused>(), "{err:#}");
    let cause = format!("{:#}", folder.refusal().expect("the refusal found now is the folder's"));
    assert!(cause.contains("its ACL is not exactly"), "{cause}");
    assert!(cause.contains(&location.dir().display().to_string()), "{cause}");
}

#[test]
fn a_login_with_a_terminal_whose_folder_is_refused_on_a_later_look_is_told_the_folder_refused_line() {
    let (_profile, location, folder) = folder_missing_at_the_first_act_and_refused_since();
    let connect = folder.connect();
    let mut shown = Vec::new();

    let rescued = Prompting::new(Ok(LogonKind::Interactive)).rescue(
        &Absent {
            exec: false,
            folder: &folder,
            connect: &connect,
        },
        &mut shown,
    );

    let shown = String::from_utf8(shown).unwrap();
    assert!(matches!(rescued, Rescued::Plain));
    assert!(shown.starts_with("ssh-broker: no session is offered"), "{shown:?}");
    assert!(shown.contains("its ACL is not exactly"), "{shown:?}");
    assert!(shown.contains(&location.dir().display().to_string()), "{shown:?}");
}

#[test]
fn a_folder_missing_again_is_missing_at_the_folder_it_lacks_now() {
    let profile = TempProfile::new("late-miss");
    let location = profile.location();
    std::fs::remove_dir_all(profile.0.join("AppData")).unwrap();
    let folder = folder_at(location.clone());
    std::fs::create_dir_all(profile.0.join(r"AppData\Local")).unwrap();

    let err = folder.connect().expect_err("no folder yet");

    assert!(is_no_agent(&err), "{err:#}");
    assert!(
        format!("{err:#}").contains(&location.dir().display().to_string()),
        "the folder that exists by now is not the one named: {err:#}"
    );
    assert!(folder.refusal().is_none());
}

#[test]
fn a_refusal_of_the_folder_is_shown_as_itself_when_a_connect_to_a_starting_agent_meets_it() {
    let profile = TempProfile::new("lis-ref");
    let location = profile.location();
    crate::userdir::ensure_socket_dir(&location, &me()).unwrap();
    widen(location.dir());
    let refused = crate::userdir::inspect_socket_dir(&location, &me()).err().unwrap();
    let cause = format!("{refused:#}");

    let err = listening(Err(folder_failure(refused)), &location).err().unwrap();

    assert!(err.is::<FolderFailed>(), "{err:#}");
    assert_eq!(format!("{err:#}"), cause);
}

/// What `listening` says of a connect that failed for a reason that is not "no agent": it is an error that
/// names the socket.
#[test]
fn a_connect_that_fails_for_another_reason_than_no_agent_is_an_error_naming_the_socket() {
    let profile = TempProfile::new("lis-other");
    let location = profile.location();

    let err = listening(Err(anyhow::anyhow!("the socket address is not usable")), &location)
        .err()
        .unwrap();

    assert!(!err.is::<FolderFailed>(), "{err:#}");
    let text = format!("{err:#}");
    assert!(text.contains(&location.path().display().to_string()), "{text}");
    assert!(text.contains("the socket address is not usable"), "{text}");
}

/// The folder a shim found missing is looked at again at each connect: refused on one look and usable on
/// the next, it is no longer refused and the connect goes through; and once found, it is not walked again.
#[test]
fn a_folder_refused_on_one_look_and_usable_on_the_next_is_connected_through_and_kept() {
    let (_profile, location, folder) = folder_missing_at_the_first_act_and_refused_since();
    folder.connect().expect_err("the folder is refused");
    assert!(folder.refusal().is_some(), "control: refused on the first look");
    crate::test_support::icacls(location.dir(), &["/remove:g", "*S-1-1-0"]);
    let _listener = crate::afunix::Listener::bind(location.path(), crate::socket_loc::Integrity::Medium).unwrap();

    folder.connect().expect("the folder is usable now");

    assert!(folder.refusal().is_none(), "{:?}", folder.refusal());
    let Walk::Missing(looking) = &folder.walk else {
        panic!("the folder was not missing at the first act")
    };
    let found = looking.folders().unwrap();
    widen(location.dir());
    let again = looking.folders().expect("a folder once found is not walked again");
    assert!(std::ptr::eq(found, again), "the folders kept are the ones used");
    assert!(folder.refusal().is_none(), "a walk that is not made refuses nothing");
}

/// A walk that fails with a system error and not a judgement (access denied at `Local`, by a deny entry on
/// a stand-in) is a refusal of the folder too: no agent serves a folder that cannot be walked.
#[test]
fn a_walk_that_fails_with_a_system_error_is_a_refusal_naming_the_folder_it_could_not_open() {
    let profile = TempProfile::new("sys-err");
    let location = profile.location();
    let local = location.dir().parent().unwrap().to_path_buf();
    let user = format!("*{}", me().to_sddl().unwrap());
    let app_data = local.parent().unwrap().to_path_buf();
    // Attributes of a folder are also read by the right to list its parent, so both are denied.
    crate::test_support::icacls(&app_data, &["/deny", &format!("{user}:(RD)")]);
    crate::test_support::icacls(&local, &["/deny", &format!("{user}:(RA)")]);

    let folder = folder_at(location);
    crate::test_support::icacls(&app_data, &["/remove:d", &user]);
    crate::test_support::icacls(&local, &["/remove:d", &user]);

    let refusal = folder.refusal().expect("a walk that failed is a refusal");
    assert!(refusal.contains(&local.display().to_string()), "{refusal}");
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

    let rescued = starting_failed(&err, &mut shown);

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

    let rescued = starting_failed(&err, &mut shown);

    assert!(matches!(rescued, Rescued::Plain));
    let shown = String::from_utf8(shown).unwrap();
    assert!(shown.starts_with("ssh-broker: no session is offered"), "{shown:?}");
    assert!(shown.contains("open p/AppData/Local"), "{shown:?}");
}

#[test]
fn a_login_with_a_command_is_told_of_a_folder_refused_after_the_log_was_set_up() {
    // The log's walk accepted the folder, so no line of the fail-open says what a later look found.
    let (_profile, err) = refusal_of_a_junction_at_local("refused-exec");
    let mut shown = Vec::new();

    let rescued = starting_failed(&err, &mut shown);

    assert!(matches!(rescued, Rescued::Plain));
    assert!(String::from_utf8(shown).unwrap().contains("no session is offered"));
}

#[test]
fn the_rescue_leaves_a_login_with_a_command_to_the_fail_open_line_that_carries_the_log_s_failure() {
    // The shim walks once, at the link: the log and the folder have the same cause, and the fail-open
    // line says it (`shim_pty`), so the rescue says nothing.
    let profile = TempProfile::new("rs-exec");
    let local = profile.0.join(r"AppData\Local");
    let elsewhere = profile.0.join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    std::fs::remove_dir(&local).unwrap();
    junction(&local, &elsewhere);

    let (rescued, shown) = rescued(profile.location(), true);

    assert!(matches!(rescued, Rescued::Plain));
    assert!(shown.is_empty(), "{shown:?}");
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

    starting_failed(&err, &mut shown);

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
    let (log, rescued) =
        crate::test_support::logged(|| starting_failed(&anyhow::anyhow!("the process list failed"), &mut shown));
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
    assert!(connect_if_listening(&location, &me()).unwrap().is_none());
    // The folder is there and the socket file is not.
    crate::userdir::ensure_socket_dir(&location, &me()).unwrap();
    assert!(connect_if_listening(&location, &me()).unwrap().is_none());
    // A folder above it is missing too.
    std::fs::remove_dir_all(profile.0.join("AppData")).unwrap();
    assert!(connect_if_listening(&location, &me()).unwrap().is_none());
}

#[test]
fn a_socket_with_nobody_listening_on_it_is_nobody_listening() {
    use socket2::{Domain, SockAddr, Socket, Type};
    let profile = crate::test_support::TempProfile::new("unlistened");
    let location = profile.location();
    crate::userdir::ensure_socket_dir(&location, &me()).unwrap();
    // The file exists and `listen()` has not run, as in the agent's start.
    let socket = Socket::new(Domain::UNIX, Type::STREAM, None).unwrap();
    socket.bind(&SockAddr::unix(location.path()).unwrap()).unwrap();
    assert!(connect_if_listening(&location, &me()).unwrap().is_none());
}

#[test]
fn a_listening_socket_in_the_folder_is_connected_to() {
    let profile = crate::test_support::TempProfile::new("connect-listen");
    let location = profile.location();
    crate::userdir::ensure_socket_dir(&location, &me()).unwrap();
    let _listener = crate::afunix::Listener::bind(location.path(), crate::socket_loc::Integrity::Medium).unwrap();

    assert!(connect_if_listening(&location, &me()).unwrap().is_some());
}

/// The wait through the profile-list watch walks before it connects: a listener in a folder that is
/// refused is not connected to, and the refusal is an error that names the folder, not a reason to
/// wait.
#[test]
fn a_listener_in_a_refused_folder_is_not_connected_to_and_the_folder_is_named() {
    let profile = crate::test_support::TempProfile::new("connect-refused");
    let location = profile.location();
    crate::userdir::ensure_socket_dir(&location, &me()).unwrap();
    let _listener = crate::afunix::Listener::bind(location.path(), crate::socket_loc::Integrity::Medium).unwrap();
    crate::test_support::widen(location.dir());

    let failed = connect_if_listening(&location, &me()).expect_err("connected through a folder that is not private");

    assert!(failed.is::<FolderFailed>(), "{failed:#}");
    assert!(
        format!("{failed:#}").contains(&location.dir().display().to_string()),
        "{failed:#}"
    );
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

// the agents a shim waits for -----

/// The folder level of this process, which the agents the test starts inherit, and the other one.
fn own_and_other_level() -> (crate::socket_loc::Integrity, crate::socket_loc::Integrity) {
    use crate::socket_loc::Integrity::{High, Medium};
    let own =
        crate::account::integrity_class(crate::account::integrity_of(crate::winutil::own_token().unwrap().0).unwrap());
    (own, if own == High { Medium } else { High })
}

/// An agent that serves the other folder is no reason to wait: the account's High agent keeps running
/// after the account is taken out of Administrators, and the shim of its next login (Medium) looks in the
/// plain folder, where that agent never serves. In CI the test process is High, so this is that case;
/// on an unelevated host it is the reverse, which is the same rule.
#[test]
fn a_login_does_not_wait_for_an_agent_that_serves_the_folder_of_the_other_level() {
    let (own, other) = own_and_other_level();
    let copy = crate::test_support::NamedCopy::new("wait-level");
    let mut agent = copy.spawn(&["agent", "--background"]);
    let profile = TempProfile::new("wl");
    let user = me();

    let at_other = profile.location_at(other);
    let outcome = await_starting_agent(&at_other, &copy.exe(), &user, || Ok(None)).unwrap();
    assert!(
        matches!(outcome, Starting::No),
        "an agent of the other level is none of this folder's"
    );

    assert!(
        Evidence::default()
            .look(&profile.location_at(own), &copy.exe(), &user)
            .unwrap(),
        "control: the same agent is evidence for the folder of its own level"
    );
    drop(agent.stdin.take());
    agent.wait().unwrap();
}
