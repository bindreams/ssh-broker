//! Host tests for the restart of sshd, over the stand-in of `configure_tests`: the service manager is a script of
//! answers, one per call, and a call with no answer left panics, so a test that scripts none shows that nothing
//! was asked. The real service manager is measured by `tests/sshd_config_windows.rs`, which CI runs.
use super::super::configure::configure_tests::Fake;
use super::super::{DROP_IN_NAME, INCLUDE_LINE, drop_in_text, with_line};
use super::*;

const INTRO: &str = "apply: restarting sshd; apply waits for the service manager at each step";
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
}

// the stop =====

#[test]
fn a_stop_that_was_not_sent_leaves_sshd_running_and_no_start_follows() {
    let mut host = host();
    host.settles = [Ok(ServiceState::Running)].into();
    host.stops = [Err("cannot open the process of the sshd service".to_owned())].into();
    let (taken, said) = run(&mut host);
    assert!(!taken);
    assert_eq!(
        said.last().unwrap(),
        &format!(
            "apply: sshd could not be stopped (cannot open the process of the sshd service) and is running with \
             its earlier configuration, so it does not accept {ELEVATION} yet; run `ssh-broker apply` again to \
             restart it"
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
    host.starts = [StartOutcome::Running(StartReply::Accepted)].into();
    let (taken, said) = run(&mut host);
    assert!(taken);
    assert_eq!(
        said.last().unwrap(),
        &format!("apply: sshd restarted; it accepts {ELEVATION}")
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
    host.starts = [StartOutcome::Running(refused("the service is already running"))].into();
    let (taken, said) = run(&mut host);
    assert!(!taken);
    assert_eq!(
        said.last().unwrap(),
        "apply: sshd is running and whether it restarted cannot be told (the service is already running); \
         `ssh-broker apply` restarts it if it has not read the change"
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
fn a_start_accepted_that_settles_running_is_a_restart() {
    let mut host = after_a_stop();
    host.starts = [StartOutcome::Running(StartReply::Accepted)].into();
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
    host.starts = [StartOutcome::Running(refused(
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
        "apply: sshd is NOT running: it was stopped, and the service manager refused to start it (The service \
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
    host.starts.push_back(StartOutcome::Running(StartReply::Accepted));
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
fn a_drop_in_that_had_other_text_gets_that_text_back() {
    let (mut host, mut before) = changed_by_this_run();
    before.drop_in = Some(b"AcceptEnv OTHER\r\n".to_vec());
    before.config = None;
    first_start_fails(&mut host);
    host.starts.push_back(StartOutcome::Running(StartReply::Accepted));
    let (taken, _) = restart_with(&mut host, &before);
    assert!(!taken);
    assert_eq!(host.drop_in.as_deref(), Some(&b"AcceptEnv OTHER\r\n"[..]));
}

#[test]
fn a_second_start_that_works_when_this_run_changed_nothing_says_sshd_accepts_the_variable() {
    let mut host = host();
    first_start_fails(&mut host);
    host.starts.push_back(StartOutcome::Running(StartReply::Accepted));
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
    host.starts.push_back(StartOutcome::Running(refused(
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
    host.starts.push_back(StartOutcome::Running(StartReply::Accepted));
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
    host.starts.push_back(StartOutcome::Running(StartReply::Accepted));
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
