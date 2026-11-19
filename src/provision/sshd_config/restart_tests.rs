//! Host tests for the restart of sshd, over the stand-in of `configure_tests`: the service manager is a script of
//! answers, one per call, and a call with no answer left panics, so a test that scripts none shows that nothing
//! was asked. The real service manager is measured by `tests/sshd_config_windows.rs`, which CI runs.
use super::super::configure::configure_tests::Fake;
use super::super::{DROP_IN_NAME, INCLUDE_LINE, drop_in_text, with_line};
use super::*;
use std::cell::RefCell;
use std::rc::Rc;

const INTRO: &str = "apply: restarting sshd; apply waits for the service manager at each step, and after a start for \
                     sshd to listen or exit";
const ELEVATION: &str = "SSH_BROKER_ELEVATION";
const NOT_RUNNING_ADVICE: &str = "Start it at this PC: `net start sshd`.";

/// A machine whose sshd runs.
fn host() -> Fake {
    Fake::with_config("Port 22\r\n")
}

fn exit(win32: u32, specific: u32) -> ExitCodes {
    ExitCodes { win32, specific }
}

fn refused(reply: &str) -> StartReply {
    StartReply::Refused(reply.to_owned())
}

/// What a start that was accepted and then stopped again is called in a sentence.
fn stopped_again(win32: u32, specific: u32) -> String {
    format!("the start was accepted and sshd stopped again (exit codes {win32} and {specific})")
}

fn restart_with(host: &mut Fake, before: &Before) -> (bool, Vec<String>) {
    let mut said = Vec::new();
    let taken = restart(host, &mut |line| said.push(line.to_owned()), before);
    (taken, said)
}

fn run(host: &mut Fake) -> (bool, Vec<String>) {
    restart_with(host, &Before::default())
}

/// What the machine did to the service and to the files, in order.
fn events(host: &Fake) -> Vec<&str> {
    host.events.iter().map(String::as_str).collect()
}

/// A run that changed the drop-in and `sshd_config`, as `configure` leaves the machine: `before` holds what
/// each was, and the machine holds what each is now.
fn changed_by_this_run() -> (Fake, Before) {
    let original = "Port 22\r\n";
    let mut host = Fake::with_config(&format!("Port 22\r\n{INCLUDE_LINE}\r\n"));
    host.drop_in = Some(drop_in_text().into_bytes());
    let before = Before {
        drop_in: None,
        drop_in_changed: true,
        config: Some(original.as_bytes().to_vec()),
    };
    (host, before)
}

// the first state =====

#[test]
fn it_says_once_that_it_waits_for_the_service_manager_before_it_asks_for_anything() {
    let mut host = host();
    host.settles = [Ok(ServiceState::Stopped)].into();
    let (_, said) = run(&mut host);
    assert_eq!(said.first().map(String::as_str), Some(INTRO), "{said:#?}");
    assert_eq!(said.iter().filter(|line| line.as_str() == INTRO).count(), 1);
}

#[test]
fn a_stopped_service_is_not_started_and_reads_the_change_when_it_is() {
    let mut host = host();
    host.settles = [Ok(ServiceState::Stopped)].into();
    let (taken, said) = run(&mut host);
    assert!(taken);
    assert_eq!(
        said,
        [
            INTRO,
            "apply: sshd is not running, so it was not started; it reads the change when it is"
        ]
    );
    assert_eq!(events(&host), ["settled"]);
}

#[test]
fn a_paused_service_is_left_as_it_is_and_the_advice_is_to_resume_it() {
    let mut host = host();
    host.settles = [Ok(ServiceState::Paused)].into();
    let (taken, said) = run(&mut host);
    assert!(!taken);
    assert_eq!(
        said,
        [
            INTRO,
            "apply: the sshd service is paused, so it was not restarted; resume it (`sc continue sshd`) and run \
             `ssh-broker apply` again"
        ]
    );
    assert_eq!(
        events(&host),
        ["settled"],
        "no stop and no start follow a paused first state"
    );
}

/// What the service manager answers a STOP that sshd's control handler did not answer in time.
const NO_ANSWER: &str = "The service did not respond to the start or control request in a timely fashion. (1053)";

/// What is said before the wait for an sshd that did not answer the stop, given the service manager's `reply`.
fn stop_unanswered_line(reply: &str) -> String {
    format!(
        "apply: sshd did not answer the stop in time ({reply}) and the service manager says it is still running; \
         apply waits, with no time limit, for that sshd to exit, and then starts it. To stop waiting, end the \
         task ssh-broker-apply-sshd (`schtasks /End /TN ssh-broker-apply-sshd`, elevated) and run `ssh-broker \
         apply` again; nothing then starts an sshd that exits later. Check sshd at this PC: `sc query sshd`; \
         start it with `net start sshd` if it is stopped."
    )
}

const CAUSE: &str = "the state cannot be read";
const UNSEEN: &str = "whether sshd stopped could not be told (the state cannot be read)";

/// A machine whose stop is not known, answering `starts`.
fn after_an_unknown_stop_with(starts: impl Into<std::collections::VecDeque<StartOutcome>>) -> Fake {
    let mut host = host();
    host.settles = [Ok(ServiceState::Running)].into();
    host.stops = [Ok(StopOutcome::Unknown {
        cause: CAUSE.to_owned(),
    })]
    .into();
    host.starts = starts.into();
    host
}

/// What the run says after a stop whose outcome is not known, with `starts` the answers to its starts.
fn after_an_unknown_stop<const N: usize>(starts: [StartOutcome; N]) -> String {
    let mut host = after_an_unknown_stop_with(starts);
    let (_, said) = run(&mut host);
    said.last().unwrap().clone()
}

/// The clause that says a start was refused and the service then read stopped, as `restart` says it.
fn refused_then_stopped_clause(reply: &str) -> String {
    format!("a start was refused ({reply}), and the service manager then said sshd is stopped")
}

#[test]
fn a_state_that_cannot_be_read_is_never_a_sentence_that_says_sshd_runs_or_does_not() {
    let mut host = host();
    host.settles = [Err("the service manager did not answer".to_owned())].into();
    let (taken, said) = run(&mut host);
    assert!(!taken);
    assert_eq!(
        said,
        [
            INTRO,
            "apply: the sshd service's state cannot be read (the service manager did not answer), so it was not \
             restarted; run `ssh-broker apply` again to restart it"
        ]
    );
    for line in &said {
        assert!(
            !line.contains("running") && !line.contains("accepts") && !line.contains("accept "),
            "a state that was not read is said to be one: {line}"
        );
    }
    assert_eq!(
        events(&host),
        ["settled"],
        "nothing is done to a service whose state was not read"
    );

    // A stop whose outcome is not known is never said to have happened, and its cause is always said.
    let sentences = [
        after_an_unknown_stop([
            StartOutcome::Stopped {
                reply: refused("Access is denied. (5)"),
                exit: exit(1053, 0),
            },
            StartOutcome::Stopped {
                reply: refused("Access is denied. (5)"),
                exit: exit(1053, 0),
            },
        ]),
        after_an_unknown_stop([StartOutcome::Paused(StartReply::Accepted)]),
        after_an_unknown_stop([StartOutcome::Unreadable {
            reply: refused("Access is denied. (5)"),
            cause: "the service manager did not answer".to_owned(),
        }]),
        after_an_unknown_stop([StartOutcome::Serving(refused("Access is denied. (5)"))]),
        after_an_unknown_stop([StartOutcome::Serving(StartReply::Accepted)]),
        after_an_unknown_stop([StartOutcome::Exited {
            reply: refused("Access is denied. (5)"),
            code: 1067,
            unseen: Some("the service manager did not answer".to_owned()),
        }]),
    ];
    for said in &sentences {
        assert!(
            said.contains(UNSEEN),
            "the cause of the unseen stop is not said: {said}"
        );
        assert!(
            !said.contains("was stopped"),
            "an unseen stop is said to have happened: {said}"
        );
    }
    assert_eq!(
        sentences[0],
        format!(
            "apply: sshd is NOT running: {UNSEEN}; {}, and the service manager refused to start it (Access is \
             denied. (5)). {NOT_RUNNING_ADVICE}",
            refused_then_stopped_clause("Access is denied. (5)")
        )
    );
    assert_eq!(
        sentences[1],
        format!("apply: {UNSEEN} and a start was accepted; it is paused. Check it at this PC: `sc query sshd`.")
    );
    assert_eq!(
        sentences[2],
        format!(
            "apply: {UNSEEN} and a start was refused (Access is denied. (5)); its state cannot be read (the \
             service manager did not answer). Check it at this PC: `sc query sshd`."
        )
    );
    assert_eq!(
        sentences[3],
        format!(
            "apply: sshd is running and whether it restarted cannot be told: {UNSEEN}, and a start was refused \
             (Access is denied. (5)); `ssh-broker apply` restarts it if it has not read the change"
        )
    );
    assert_eq!(
        sentences[4],
        format!("apply: sshd restarted; it accepts {ELEVATION} ({UNSEEN}, and the service manager accepted a start)")
    );
    assert_eq!(
        sentences[5],
        format!(
            "apply: sshd is not serving: {UNSEEN}, the service manager refused a start (Access is denied. (5)), \
             and the sshd it reported running exited (code 1067) without being seen to listen (whether the \
             service manager had seen it exit could not be read: the service manager did not answer). Check sshd \
             at this PC: `sc query sshd`; start it with `net start sshd` if it is stopped."
        )
    );

    // A stop that was not answered in time says so first, and then, its outcome unknown, still never says that
    // sshd was stopped.
    let mut unanswered = self::host();
    unanswered.settles = [Ok(ServiceState::Running)].into();
    unanswered.stop_unanswered = Some(NO_ANSWER.to_owned());
    unanswered.stops = [Ok(StopOutcome::Unknown {
        cause: CAUSE.to_owned(),
    })]
    .into();
    unanswered.starts = [StartOutcome::Serving(StartReply::Accepted)].into();
    let (_, said) = run(&mut unanswered);
    assert_eq!(said[1], stop_unanswered_line(NO_ANSWER));
    assert!(
        said.last().unwrap().contains(UNSEEN) && !said.last().unwrap().contains("was stopped"),
        "{said:#?}"
    );

    // A stop that could not be sent says why, and says the running state is the one read before it.
    let mut unsent = self::host();
    unsent.settles = [Ok(ServiceState::Running)].into();
    unsent.stops = [Err(CAUSE.to_owned())].into();
    let (_, said) = run(&mut unsent);
    let last = said.last().unwrap();
    assert!(
        last.contains(CAUSE) && last.contains("no stop was sent") && last.contains("last read as running"),
        "{last}"
    );
    assert!(
        !last.contains("is running") && !last.contains("was stopped") && !last.contains("could not be stopped"),
        "a stop that was not sent is said to have been tried: {last}"
    );
}

#[test]
fn a_start_after_an_unseen_stop_that_stopped_again_says_the_cause_in_every_sentence() {
    let mut host = host();
    host.settles = [Ok(ServiceState::Running)].into();
    host.stops = [Ok(StopOutcome::Unknown {
        cause: CAUSE.to_owned(),
    })]
    .into();
    host.starts = [
        StartOutcome::Stopped {
            reply: StartReply::Accepted,
            exit: exit(1067, 0),
        },
        StartOutcome::Serving(StartReply::Accepted),
    ]
    .into();
    let (taken, said) = run(&mut host);
    assert!(taken);
    assert_eq!(
        said.last().unwrap(),
        &format!(
            "apply: sshd failed to start once ({UNSEEN}; {}); a second start worked and sshd is running. It \
             accepts {ELEVATION}.",
            stopped_again(1067, 0)
        )
    );
}

// the stop =====

#[test]
fn a_stop_sshd_did_not_answer_in_time_is_said_before_the_wait_and_the_restart_goes_on() {
    let mut host = host();
    host.settles = [Ok(ServiceState::Running)].into();
    host.stop_unanswered = Some(NO_ANSWER.to_owned());
    host.stops = [Ok(StopOutcome::Stopped)].into();
    host.starts = [StartOutcome::Serving(StartReply::Accepted)].into();
    let (taken, said) = run(&mut host);
    assert!(taken);
    assert_eq!(
        said,
        [
            INTRO,
            &stop_unanswered_line(NO_ANSWER),
            "apply: sshd was stopped; starting sshd",
            &format!("apply: sshd restarted; it accepts {ELEVATION}")
        ]
    );
    assert_eq!(events(&host), ["settled", "stop", "start"]);
}

#[test]
fn a_wait_that_ended_without_a_stop_seen_is_followed_by_a_line_that_says_so_before_the_start() {
    let mut host = host();
    host.settles = [Ok(ServiceState::Running)].into();
    host.stop_unanswered = Some(NO_ANSWER.to_owned());
    host.stops = [Ok(StopOutcome::Unknown {
        cause: CAUSE.to_owned(),
    })]
    .into();
    host.starts = [StartOutcome::Serving(StartReply::Accepted)].into();
    let (_, said) = run(&mut host);
    assert_eq!(said[1], stop_unanswered_line(NO_ANSWER));
    assert_eq!(said[2], format!("apply: {UNSEEN}; starting sshd"));
}

#[test]
fn nothing_is_said_between_a_stop_that_was_answered_and_the_start() {
    let mut host = host();
    host.settles = [Ok(ServiceState::Running)].into();
    host.stops = [Ok(StopOutcome::Unknown {
        cause: CAUSE.to_owned(),
    })]
    .into();
    host.starts = [StartOutcome::Serving(StartReply::Accepted)].into();
    let (_, said) = run(&mut host);
    assert_eq!(said.len(), 2, "{said:#?}");
}

#[test]
fn a_stop_that_was_not_sent_says_so_with_why_and_that_sshd_was_last_read_as_running() {
    let mut host = host();
    host.settles = [Ok(ServiceState::Running)].into();
    host.stops = [Err("cannot open the process of the sshd service".to_owned())].into();
    let (taken, said) = run(&mut host);
    assert!(!taken);
    assert_eq!(
        said.last().unwrap(),
        &format!(
            "apply: no stop was sent to sshd (cannot open the process of the sshd service), so it was not \
             restarted. Its state was last read as running, before that, with its earlier configuration, so it \
             does not accept {ELEVATION} yet; run `ssh-broker apply` again to restart it"
        )
    );
    assert_eq!(events(&host), ["settled", "stop"]);
}

#[test]
fn a_stop_that_the_service_manager_refused_and_left_sshd_running_starts_nothing() {
    let mut host = host();
    host.settles = [Ok(ServiceState::Running)].into();
    host.stops = [Ok(StopOutcome::NotStopped {
        state: ServiceState::Running,
        refusal: Some("Access is denied.".to_owned()),
    })]
    .into();
    let (taken, said) = run(&mut host);
    assert!(!taken);
    assert_eq!(
        said.last().unwrap(),
        &format!(
            "apply: sshd could not be stopped (Access is denied.) and is running with its earlier configuration, \
             so it does not accept {ELEVATION} yet; run `ssh-broker apply` again to restart it"
        )
    );
    assert_eq!(
        events(&host),
        ["settled", "stop"],
        "no start follows a stop that did not stop"
    );
}

#[test]
fn a_stop_the_service_manager_accepted_and_the_service_did_not_take_is_said_so() {
    let mut host = host();
    host.settles = [Ok(ServiceState::Running)].into();
    host.stops = [Ok(StopOutcome::NotStopped {
        state: ServiceState::Running,
        refusal: None,
    })]
    .into();
    let (taken, said) = run(&mut host);
    assert!(!taken);
    assert_eq!(
        said.last().unwrap(),
        &format!(
            "apply: sshd could not be stopped (the service manager accepted the stop and the service did not stop) \
             and is running with its earlier configuration, so it does not accept {ELEVATION} yet; run \
             `ssh-broker apply` again to restart it"
        )
    );
    assert_eq!(events(&host), ["settled", "stop"]);
}

#[test]
fn a_service_the_stop_left_paused_is_said_to_be_paused_and_nothing_is_started() {
    let mut host = host();
    host.settles = [Ok(ServiceState::Running)].into();
    host.stops = [Ok(StopOutcome::NotStopped {
        state: ServiceState::Paused,
        refusal: None,
    })]
    .into();
    let (taken, said) = run(&mut host);
    assert!(!taken);
    assert!(
        said.last()
            .unwrap()
            .contains("and is paused with its earlier configuration"),
        "{said:#?}"
    );
    assert_eq!(events(&host), ["settled", "stop"]);
}

#[test]
fn a_stop_whose_result_is_not_known_is_followed_by_one_start_decided_without_a_stop_seen() {
    let mut host = host();
    host.settles = [Ok(ServiceState::Running)].into();
    host.stops = [Ok(StopOutcome::Unknown {
        cause: "the state cannot be read".to_owned(),
    })]
    .into();
    host.starts = [StartOutcome::Serving(StartReply::Accepted)].into();
    let (taken, said) = run(&mut host);
    assert!(taken);
    assert_eq!(
        said.last().unwrap(),
        &format!("apply: sshd restarted; it accepts {ELEVATION} ({UNSEEN}, and the service manager accepted a start)")
    );
    assert_eq!(events(&host), ["settled", "stop", "start"]);
}

#[test]
fn a_start_refused_over_a_running_service_after_an_unknown_stop_does_not_say_it_restarted() {
    let mut host = host();
    host.settles = [Ok(ServiceState::Running)].into();
    host.stops = [Ok(StopOutcome::Unknown {
        cause: "the state cannot be read".to_owned(),
    })]
    .into();
    host.starts = [StartOutcome::Serving(refused("the service is already running"))].into();
    let (taken, said) = run(&mut host);
    assert!(!taken);
    assert_eq!(
        said.last().unwrap(),
        &format!(
            "apply: sshd is running and whether it restarted cannot be told: {UNSEEN}, and a start was refused \
             (the service is already running); `ssh-broker apply` restarts it if it has not read the change"
        )
    );
}

// a refused start after a stop that was not seen =====

/// A run that changed the files, whose stop is not known, answering `starts`; and what `restart` said, with
/// the starts and the lines in one sequence (a start is "start").
fn unseen_stop_over_changed_files(
    starts: impl Into<std::collections::VecDeque<StartOutcome>>,
) -> (Fake, bool, Vec<String>) {
    let (mut host, before) = changed_by_this_run();
    let log = Rc::new(RefCell::new(Vec::new()));
    host.said_and_started = Some(Rc::clone(&log));
    host.settles = [Ok(ServiceState::Running)].into();
    host.stops = [Ok(StopOutcome::Unknown {
        cause: CAUSE.to_owned(),
    })]
    .into();
    host.starts = starts.into();
    let taken = restart(&mut host, &mut |line| log.borrow_mut().push(line.to_owned()), &before);
    let log = log.borrow().clone();
    (host, taken, log)
}

/// The files are as `changed_by_this_run` left them: nothing was put back.
fn files_were_not_put_back(host: &Fake) {
    assert_eq!(host.config, format!("Port 22\r\n{INCLUDE_LINE}\r\n").into_bytes());
    assert!(host.drop_in.is_some());
}

#[test]
fn a_refused_start_that_reads_stopped_after_an_unseen_stop_is_followed_by_one_start_more() {
    let (host, taken, log) = unseen_stop_over_changed_files([
        StartOutcome::Stopped {
            reply: refused("An instance of the service is already running. (1056)"),
            exit: exit(1053, 0),
        },
        StartOutcome::Serving(StartReply::Accepted),
    ]);
    assert!(taken, "{log:#?}");
    assert_eq!(events(&host), ["settled", "stop", "start", "start"]);
    let said = format!(
        "apply: {UNSEEN}; {}; starting sshd",
        refused_then_stopped_clause("An instance of the service is already running. (1056)")
    );
    let said_at = log
        .iter()
        .position(|line| *line == said)
        .unwrap_or_else(|| panic!("{log:#?}"));
    let starts: Vec<usize> = (0..log.len()).filter(|i| log[*i] == "start").collect();
    assert!(
        starts[0] < said_at && said_at < starts[1],
        "the line is said after the first start and before the second: {log:#?}"
    );
    assert_eq!(
        log.last().unwrap(),
        &format!("apply: sshd restarted; it accepts {ELEVATION}")
    );
    files_were_not_put_back(&host);
}

#[test]
fn a_refused_start_whose_sshd_exited_and_was_seen_after_an_unseen_stop_is_followed_by_one_start_more() {
    let (host, taken, log) = unseen_stop_over_changed_files([
        exited(refused("An instance of the service is already running. (1056)"), 1067),
        StartOutcome::Serving(StartReply::Accepted),
    ]);
    assert!(taken, "{log:#?}");
    assert_eq!(events(&host), ["settled", "stop", "start", "start"]);
    let said = format!(
        "apply: {UNSEEN}; a start was refused (An instance of the service is already running. (1056)), and the \
         sshd the service manager reported running exited (code 1067); starting sshd"
    );
    let said_at = log
        .iter()
        .position(|line| *line == said)
        .unwrap_or_else(|| panic!("{log:#?}"));
    let starts: Vec<usize> = (0..log.len()).filter(|i| log[*i] == "start").collect();
    assert!(
        starts[0] < said_at && said_at < starts[1],
        "the line is said after the first start and before the second: {log:#?}"
    );
    files_were_not_put_back(&host);
}

#[test]
fn a_second_refusal_after_an_unseen_stop_says_both_replies_and_starts_nothing_more() {
    let (host, taken, log) = unseen_stop_over_changed_files([
        StartOutcome::Stopped {
            reply: refused("the first reply (1056)"),
            exit: exit(1053, 0),
        },
        StartOutcome::Stopped {
            reply: refused("the second reply (5)"),
            exit: exit(1053, 0),
        },
    ]);
    assert!(!taken, "{log:#?}");
    assert_eq!(events(&host), ["settled", "stop", "start", "start"]);
    assert_eq!(
        log.last().unwrap(),
        &format!(
            "apply: sshd is NOT running: {UNSEEN}; {}, and the service manager refused to start it (the second \
             reply (5)). {NOT_RUNNING_ADVICE}",
            refused_then_stopped_clause("the first reply (1056)")
        )
    );
    files_were_not_put_back(&host);
}

/// An unseen stop, a refused start that `refused_clause` says, then an accepted start that ended before sshd
/// listened: the files are put back, a third start follows, and the sentence of that start carries the unseen
/// cause, the refused start and `ended`.
fn an_accepted_second_start_that_ended_after_an_unseen_stop(
    starts: [StartOutcome; 3],
    refused_clause: &str,
    ended: &str,
) {
    let (host, taken, log) = unseen_stop_over_changed_files(starts);
    assert!(!taken, "{log:#?}");
    let events = events(&host);
    let starts: Vec<usize> = (0..events.len()).filter(|i| events[*i] == "start").collect();
    assert_eq!(starts.len(), 3, "{events:?}");
    let put_back_config = events.iter().position(|event| *event == "replace config").unwrap();
    let removed_drop_in = events.iter().position(|event| *event == "remove drop-in").unwrap();
    assert!(
        starts[1] < put_back_config && put_back_config < starts[2] && removed_drop_in < starts[2],
        "the files are put back after the second start and before the third: {events:?}"
    );
    assert_eq!(host.config, b"Port 22\r\n", "sshd_config is what it was");
    assert_eq!(host.drop_in, None, "the drop-in this run made is gone");
    assert_eq!(
        log.last().unwrap(),
        &format!(
            "apply: sshd failed to start with {ELEVATION} accepted ({UNSEEN}; {refused_clause}; {ended}); the \
             original configuration was put back and sshd is running again. It does not accept {ELEVATION}."
        )
    );
}

#[test]
fn an_accepted_second_start_that_settled_stopped_keeps_the_unseen_stop_and_the_refused_start() {
    an_accepted_second_start_that_ended_after_an_unseen_stop(
        [
            StartOutcome::Stopped {
                reply: refused("the first reply (1056)"),
                exit: exit(1053, 0),
            },
            StartOutcome::Stopped {
                reply: StartReply::Accepted,
                exit: exit(1067, 0),
            },
            StartOutcome::Serving(StartReply::Accepted),
        ],
        &refused_then_stopped_clause("the first reply (1056)"),
        &stopped_again(1067, 0),
    );
}

#[test]
fn an_accepted_second_start_whose_sshd_exited_keeps_the_unseen_stop_and_the_refused_start() {
    an_accepted_second_start_that_ended_after_an_unseen_stop(
        [
            exited(refused("the first reply (1056)"), 1067),
            exited(StartReply::Accepted, 255),
            StartOutcome::Serving(StartReply::Accepted),
        ],
        "a start was refused (the first reply (1056)), and the sshd the service manager reported running exited \
         (code 1067)",
        &exited_before_listening(255),
    );
}

// the start =====

fn after_a_stop() -> Fake {
    let mut host = host();
    host.settles = [Ok(ServiceState::Running)].into();
    host.stops = [Ok(StopOutcome::Stopped)].into();
    host
}

#[test]
fn a_start_accepted_that_serves_is_a_restart() {
    let mut host = after_a_stop();
    host.starts = [StartOutcome::Serving(StartReply::Accepted)].into();
    let (taken, said) = run(&mut host);
    assert!(taken);
    assert_eq!(
        said,
        [
            INTRO.to_owned(),
            format!("apply: sshd restarted; it accepts {ELEVATION}")
        ]
    );
    assert_eq!(
        events(&host),
        ["settled", "stop", "start"],
        "nothing is put back or written"
    );
}

#[test]
fn a_start_refused_over_a_service_that_the_service_manager_had_started_again_is_a_restart_when_a_stop_was_seen() {
    let mut host = after_a_stop();
    host.starts = [StartOutcome::Serving(refused(
        "An instance of the service is already running.",
    ))]
    .into();
    let (taken, said) = run(&mut host);
    assert!(taken);
    assert_eq!(
        said.last().unwrap(),
        &format!(
            "apply: sshd restarted (the service manager had started it again: An instance of the service is \
             already running.); it accepts {ELEVATION}"
        )
    );
    assert_eq!(events(&host), ["settled", "stop", "start"]);
}

#[test]
fn a_start_refused_that_settles_stopped_puts_nothing_back_because_sshd_never_ran_the_files() {
    let (mut host, before) = changed_by_this_run();
    host.settles = [Ok(ServiceState::Running)].into();
    host.stops = [Ok(StopOutcome::Stopped)].into();
    host.starts = [StartOutcome::Stopped {
        reply: refused("The service did not respond to the start or control request in a timely fashion."),
        exit: exit(1053, 0),
    }]
    .into();
    let (taken, said) = restart_with(&mut host, &before);
    assert!(!taken);
    assert_eq!(
        said.last().unwrap(),
        "apply: sshd is NOT running: sshd was stopped, and the service manager refused to start it (The service \
         did not respond to the start or control request in a timely fashion.). Start it at this PC: `net start \
         sshd`."
    );
    assert_eq!(
        events(&host),
        ["settled", "stop", "start"],
        "the files are put back only after a start that was accepted and settled stopped"
    );
    assert_eq!(host.config, format!("Port 22\r\n{INCLUDE_LINE}\r\n").into_bytes());
    assert!(host.drop_in.is_some());
}

#[test]
fn a_start_after_which_the_state_cannot_be_read_puts_nothing_back_and_says_nothing_about_running() {
    let (mut host, before) = changed_by_this_run();
    host.settles = [Ok(ServiceState::Running)].into();
    host.stops = [Ok(StopOutcome::Stopped)].into();
    host.starts = [StartOutcome::Unreadable {
        reply: StartReply::Accepted,
        cause: "the service manager did not answer".to_owned(),
    }]
    .into();
    let (taken, said) = restart_with(&mut host, &before);
    assert!(!taken);
    assert_eq!(
        said.last().unwrap(),
        "apply: sshd was stopped and a start was accepted; its state cannot be read (the service manager did not \
         answer). Check it at this PC: `sc query sshd`."
    );
    assert_eq!(
        events(&host),
        ["settled", "stop", "start"],
        "the files are not put back"
    );
}

#[test]
fn a_start_after_which_sshd_is_paused_puts_nothing_back() {
    let (mut host, before) = changed_by_this_run();
    host.settles = [Ok(ServiceState::Running)].into();
    host.stops = [Ok(StopOutcome::Stopped)].into();
    host.starts = [StartOutcome::Paused(refused("the service is paused"))].into();
    let (taken, said) = restart_with(&mut host, &before);
    assert!(!taken);
    assert_eq!(
        said.last().unwrap(),
        "apply: sshd was stopped and a start was refused (the service is paused); it is paused. Check it at this \
         PC: `sc query sshd`."
    );
    assert_eq!(events(&host), ["settled", "stop", "start"]);
}

// a start whose sshd exited before it listened =====

fn exited(reply: StartReply, code: u32) -> StartOutcome {
    StartOutcome::Exited {
        reply,
        code,
        unseen: None,
    }
}

/// What a start that was accepted, and whose sshd exited before it listened, is called in a sentence.
fn exited_before_listening(code: u32) -> String {
    format!("the start was accepted and sshd exited (code {code}) before it listened")
}

/// Everything the flow does after a stop that was seen, for the starts it is given, in order.
fn after_a_stop_with(starts: impl Into<std::collections::VecDeque<StartOutcome>>) -> (bool, Vec<String>) {
    let mut host = after_a_stop();
    host.starts = starts.into();
    run(&mut host)
}

#[test]
fn restarted_is_said_only_after_sshd_listens() {
    let (taken, said) = after_a_stop_with([StartOutcome::Serving(StartReply::Accepted)]);
    assert!(taken);
    assert_eq!(
        said.last().unwrap(),
        &format!("apply: sshd restarted; it accepts {ELEVATION}")
    );

    // Whatever else the start comes to, no line says that sshd restarted, and the run is not a success: sshd
    // listens in none of them.
    let no_listener: [Vec<StartOutcome>; 8] = [
        vec![exited(StartReply::Accepted, 255), exited(StartReply::Accepted, 255)],
        vec![
            exited(StartReply::Accepted, 255),
            StartOutcome::Paused(StartReply::Accepted),
        ],
        vec![exited(refused("Access is denied. (5)"), 1067)],
        vec![
            StartOutcome::Stopped {
                reply: StartReply::Accepted,
                exit: exit(1067, 0),
            },
            exited(StartReply::Accepted, 1),
        ],
        vec![StartOutcome::Stopped {
            reply: refused("Access is denied. (5)"),
            exit: exit(1067, 0),
        }],
        vec![StartOutcome::Paused(StartReply::Accepted)],
        vec![StartOutcome::Unreadable {
            reply: StartReply::Accepted,
            cause: "the service manager did not answer".to_owned(),
        }],
        vec![
            exited(StartReply::Accepted, 255),
            exited(refused("Access is denied. (5)"), 1),
        ],
    ];
    for starts in no_listener {
        let (taken, said) = after_a_stop_with(starts.clone());
        assert!(!taken, "{starts:?}: {said:#?}");
        assert!(
            said.iter().all(|line| !line.contains("restarted")),
            "{starts:?} is said to be a restart: {said:#?}"
        );
    }
}

#[test]
fn an_accepted_start_whose_sshd_exits_before_it_listens_puts_the_files_back() {
    let (mut host, before) = changed_by_this_run();
    host.settles = [Ok(ServiceState::Running)].into();
    host.stops = [Ok(StopOutcome::Stopped)].into();
    host.starts = [
        exited(StartReply::Accepted, 255),
        StartOutcome::Serving(StartReply::Accepted),
    ]
    .into();
    let (taken, said) = restart_with(&mut host, &before);
    assert!(!taken);
    assert_eq!(
        said.last().unwrap(),
        &format!(
            "apply: sshd failed to start with {ELEVATION} accepted ({}); the original configuration was put back \
             and sshd is running again. It does not accept {ELEVATION}.",
            exited_before_listening(255)
        )
    );
    let events = events(&host);
    let second_start = events.iter().rposition(|event| *event == "start").unwrap();
    let put_back_config = events.iter().position(|event| *event == "replace config").unwrap();
    let removed_drop_in = events.iter().position(|event| *event == "remove drop-in").unwrap();
    assert!(
        put_back_config < second_start && removed_drop_in < second_start,
        "{events:?}"
    );
    assert_eq!(host.config, b"Port 22\r\n", "sshd_config is what it was");
    assert_eq!(host.drop_in, None, "the drop-in this run made is gone");
}

#[test]
fn a_refused_start_whose_sshd_exits_puts_nothing_back() {
    let (mut host, before) = changed_by_this_run();
    host.settles = [Ok(ServiceState::Running)].into();
    host.stops = [Ok(StopOutcome::Stopped)].into();
    host.starts = [exited(refused("Access is denied. (5)"), 1067)].into();
    let (taken, said) = restart_with(&mut host, &before);
    assert!(!taken);
    assert_eq!(
        said.last().unwrap(),
        "apply: sshd is not serving: sshd was stopped, the service manager refused a start (Access is denied. \
         (5)), and the sshd it reported running exited (code 1067) without being seen to listen. Check sshd at \
         this PC: `sc query sshd`; start it with `net start sshd` if it is stopped."
    );
    assert_eq!(
        events(&host),
        ["settled", "stop", "start"],
        "a start the service manager refused is no evidence about the files"
    );
    assert_eq!(host.config, format!("Port 22\r\n{INCLUDE_LINE}\r\n").into_bytes());
    assert!(host.drop_in.is_some());
}

#[test]
fn a_start_after_an_unseen_stop_whose_sshd_exited_says_the_cause_in_every_sentence() {
    let mut host = host();
    host.settles = [Ok(ServiceState::Running)].into();
    host.stops = [Ok(StopOutcome::Unknown {
        cause: CAUSE.to_owned(),
    })]
    .into();
    host.starts = [
        exited(StartReply::Accepted, 1067),
        StartOutcome::Serving(StartReply::Accepted),
    ]
    .into();
    let (taken, said) = run(&mut host);
    assert!(taken);
    assert_eq!(
        said.last().unwrap(),
        &format!(
            "apply: sshd failed to start once ({UNSEEN}; {}); a second start worked and sshd is running. It \
             accepts {ELEVATION}.",
            exited_before_listening(1067)
        )
    );
}

// a start that was accepted and then stopped =====

fn first_start_fails(host: &mut Fake) {
    host.settles = [Ok(ServiceState::Running)].into();
    host.stops = [Ok(StopOutcome::Stopped)].into();
    host.starts = [StartOutcome::Stopped {
        reply: StartReply::Accepted,
        exit: exit(1067, 0),
    }]
    .into();
}

#[test]
fn what_this_run_changed_is_put_back_before_the_second_start() {
    let (mut host, before) = changed_by_this_run();
    first_start_fails(&mut host);
    host.starts.push_back(StartOutcome::Serving(StartReply::Accepted));
    let (taken, said) = restart_with(&mut host, &before);
    assert!(!taken);
    assert_eq!(
        said.last().unwrap(),
        &format!(
            "apply: sshd failed to start with {ELEVATION} accepted ({}); the original configuration was put back \
             and sshd is running again. It does not accept {ELEVATION}.",
            stopped_again(1067, 0)
        )
    );
    let events = events(&host);
    let second_start = events.iter().rposition(|event| *event == "start").unwrap();
    let put_back_config = events.iter().position(|event| *event == "replace config").unwrap();
    let removed_drop_in = events.iter().position(|event| *event == "remove drop-in").unwrap();
    assert!(
        put_back_config < second_start && removed_drop_in < second_start,
        "{events:?}"
    );
    assert_eq!(host.config, b"Port 22\r\n", "sshd_config is what it was");
    assert_eq!(host.drop_in, None, "the drop-in this run made is gone");
}

#[test]
fn the_second_start_is_said_before_it_is_waited_for() {
    let (mut host, before) = changed_by_this_run();
    let log = Rc::new(RefCell::new(Vec::new()));
    host.said_and_started = Some(Rc::clone(&log));
    first_start_fails(&mut host);
    host.starts.push_back(StartOutcome::Serving(StartReply::Accepted));
    let taken = restart(&mut host, &mut |line| log.borrow_mut().push(line.to_owned()), &before);
    assert!(!taken);
    let log = log.borrow();
    let again = format!(
        "apply: sshd failed to start with {ELEVATION} accepted ({}); starting it again (the original configuration \
         was put back)",
        stopped_again(1067, 0)
    );
    let said_again = log
        .iter()
        .position(|line| *line == again)
        .unwrap_or_else(|| panic!("{log:#?}"));
    let starts: Vec<usize> = (0..log.len()).filter(|i| log[*i] == "start").collect();
    assert_eq!(starts.len(), 2, "{log:#?}");
    assert!(
        starts[0] < said_again && said_again < starts[1],
        "the line is said after the first start and before the second: {log:#?}"
    );
}

#[test]
fn an_exit_whose_record_could_not_be_read_puts_the_files_back_and_says_why_a_second_start_may_be_refused() {
    let (mut host, before) = changed_by_this_run();
    host.settles = [Ok(ServiceState::Running)].into();
    host.stops = [Ok(StopOutcome::Stopped)].into();
    let reason = "the service manager did not answer";
    host.starts = [
        StartOutcome::Exited {
            reply: StartReply::Accepted,
            code: 255,
            unseen: Some(reason.to_owned()),
        },
        StartOutcome::Stopped {
            reply: refused("An instance of the service is already running. (1056)"),
            exit: exit(1067, 0),
        },
    ]
    .into();
    let (taken, said) = restart_with(&mut host, &before);
    assert!(!taken);
    let first = format!(
        "{} (whether the service manager had seen it exit could not be read: {reason})",
        exited_before_listening(255)
    );
    assert_eq!(
        said.last().unwrap(),
        &format!(
            "apply: sshd is NOT running: it failed to start with {ELEVATION} accepted ({first}), and the service \
             manager refused a second start (An instance of the service is already running. (1056)). The original \
             configuration was put back. {NOT_RUNNING_ADVICE}"
        )
    );
    assert_eq!(host.config, b"Port 22\r\n", "sshd_config is what it was");
    assert_eq!(host.drop_in, None, "the drop-in this run made is gone");
    assert_eq!(events(&host).iter().filter(|event| **event == "start").count(), 2);
}

#[test]
fn a_drop_in_that_had_other_text_gets_that_text_back() {
    let (mut host, mut before) = changed_by_this_run();
    before.drop_in = Some(b"AcceptEnv OTHER\r\n".to_vec());
    before.config = None;
    first_start_fails(&mut host);
    host.starts.push_back(StartOutcome::Serving(StartReply::Accepted));
    let (taken, _) = restart_with(&mut host, &before);
    assert!(!taken);
    assert_eq!(host.drop_in.as_deref(), Some(&b"AcceptEnv OTHER\r\n"[..]));
}

#[test]
fn a_second_start_that_works_when_this_run_changed_nothing_says_sshd_accepts_the_variable() {
    let mut host = host();
    first_start_fails(&mut host);
    host.starts.push_back(StartOutcome::Serving(StartReply::Accepted));
    let (taken, said) = run(&mut host);
    assert!(taken);
    assert_eq!(
        said.last().unwrap(),
        &format!(
            "apply: sshd failed to start once ({}); a second start worked and sshd is running. It accepts \
             {ELEVATION}.",
            stopped_again(1067, 0)
        )
    );
    assert_eq!(
        events(&host),
        ["settled", "stop", "start", "start"],
        "nothing was put back"
    );
}

#[test]
fn a_second_start_refused_over_a_running_service_says_which_configuration_it_read_cannot_be_told() {
    let (mut host, before) = changed_by_this_run();
    first_start_fails(&mut host);
    host.starts.push_back(StartOutcome::Serving(refused(
        "An instance of the service is already running.",
    )));
    let (taken, said) = restart_with(&mut host, &before);
    assert!(!taken);
    assert_eq!(
        said.last().unwrap(),
        &format!(
            "apply: sshd failed to start with {ELEVATION} accepted ({}); sshd is running now, but the service \
             manager refused a second start (An instance of the service is already running.), so which \
             configuration it read cannot be told (the original configuration was put back); run `ssh-broker \
             apply` again",
            stopped_again(1067, 0)
        )
    );
}

#[test]
fn a_second_start_refused_that_settles_stopped_says_sshd_is_not_running_and_how_to_start_it() {
    let (mut host, before) = changed_by_this_run();
    first_start_fails(&mut host);
    host.starts.push_back(StartOutcome::Stopped {
        reply: refused("Access is denied."),
        exit: exit(1067, 0),
    });
    let (taken, said) = restart_with(&mut host, &before);
    assert!(!taken);
    assert_eq!(
        said.last().unwrap(),
        &format!(
            "apply: sshd is NOT running: it failed to start with {ELEVATION} accepted ({}), and the service \
             manager refused a second start (Access is denied.). The original configuration was put back. \
             {NOT_RUNNING_ADVICE}",
            stopped_again(1067, 0)
        )
    );
}

#[test]
fn a_second_start_accepted_that_stops_again_says_both_exit_codes() {
    let mut host = host();
    first_start_fails(&mut host);
    host.starts.push_back(StartOutcome::Stopped {
        reply: StartReply::Accepted,
        exit: exit(1053, 7),
    });
    let (taken, said) = run(&mut host);
    assert!(!taken);
    assert_eq!(
        said.last().unwrap(),
        &format!(
            "apply: sshd is NOT running: it failed to start ({}), and a second start was accepted and sshd \
             stopped again (exit codes 1053 and 7). {NOT_RUNNING_ADVICE}",
            stopped_again(1067, 0)
        )
    );
}

#[test]
fn a_second_start_accepted_whose_sshd_exits_before_it_listens_says_so() {
    let mut host = host();
    first_start_fails(&mut host);
    host.starts.push_back(exited(StartReply::Accepted, 3));
    let (taken, said) = run(&mut host);
    assert!(!taken);
    assert_eq!(
        said.last().unwrap(),
        &format!(
            "apply: sshd is NOT running: it failed to start ({}), and a second start was accepted and sshd exited \
             (code 3) before it listened. {NOT_RUNNING_ADVICE}",
            stopped_again(1067, 0)
        )
    );
}

#[test]
fn a_second_start_refused_whose_sshd_exits_is_the_row_of_a_refused_second_start() {
    let (mut host, before) = changed_by_this_run();
    first_start_fails(&mut host);
    host.starts.push_back(exited(refused("Access is denied."), 3));
    let (taken, said) = restart_with(&mut host, &before);
    assert!(!taken);
    assert_eq!(
        said.last().unwrap(),
        &format!(
            "apply: sshd is NOT running: it failed to start with {ELEVATION} accepted ({}), and the service \
             manager refused a second start (Access is denied.). The original configuration was put back. \
             {NOT_RUNNING_ADVICE}",
            stopped_again(1067, 0)
        )
    );
}

#[test]
fn a_second_start_after_which_the_state_cannot_be_read_does_not_say_sshd_is_not_running() {
    let (mut host, before) = changed_by_this_run();
    first_start_fails(&mut host);
    host.starts.push_back(StartOutcome::Unreadable {
        reply: StartReply::Accepted,
        cause: "the service manager did not answer".to_owned(),
    });
    let (taken, said) = restart_with(&mut host, &before);
    assert!(!taken);
    let last = said.last().unwrap();
    assert!(
        last.contains("its state cannot be read (the service manager did not answer)")
            && last.contains("Check it at this PC: `sc query sshd`.")
            && !last.contains("NOT running"),
        "{last}"
    );
}

#[test]
fn a_second_start_that_leaves_sshd_paused_says_so() {
    let mut host = host();
    first_start_fails(&mut host);
    host.starts.push_back(StartOutcome::Paused(StartReply::Accepted));
    let (taken, said) = run(&mut host);
    assert!(!taken);
    let last = said.last().unwrap();
    assert!(
        last.starts_with("apply: sshd is paused:") && last.contains("Check it at this PC: `sc query sshd`."),
        "{last}"
    );
}

// the put-back =====

#[test]
fn a_file_that_cannot_be_put_back_is_said_and_whether_sshd_read_the_original_is_not() {
    let (mut host, before) = changed_by_this_run();
    host.fail_once_started = Some("remove_drop_in");
    first_start_fails(&mut host);
    host.starts.push_back(StartOutcome::Serving(StartReply::Accepted));
    let (taken, said) = restart_with(&mut host, &before);
    assert!(!taken);
    let last = said.last().unwrap();
    assert!(
        last.contains(&format!(
            "the {DROP_IN_NAME} drop-in could not be put back (remove_drop_in failed)"
        )) && last.contains("which configuration it read cannot be told")
            && !last.contains("It does not accept"),
        "{last}"
    );
    assert_eq!(host.config, b"Port 22\r\n", "what could be put back was");
}

#[test]
fn a_config_that_cannot_be_put_back_leaves_no_candidate_behind() {
    let (mut host, before) = changed_by_this_run();
    host.fail_once_started = Some("replace_config");
    first_start_fails(&mut host);
    host.starts.push_back(StartOutcome::Serving(StartReply::Accepted));
    let (_, said) = restart_with(&mut host, &before);
    assert!(
        said.last()
            .unwrap()
            .contains("sshd_config could not be put back (replace_config failed)"),
        "{said:#?}"
    );
    assert_eq!(host.candidate, None);
    assert_eq!(
        host.config,
        with_line(b"Port 22\r\n", INCLUDE_LINE).unwrap(),
        "the file that could not be replaced is as it was"
    );
}
