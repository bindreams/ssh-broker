//! Unit tests for `offer` (pure; runs on the host). The fake records every call.
use super::*;
use crate::password_entry::{Password, PasswordEntry, Step};
use crate::protocol::ElevationPolicy;
use crate::vtinput::KeyEvent;
use std::collections::VecDeque;

const SENTINEL: &str = "hunter2-sentinel";

fn password(text: &str) -> Password {
    let mut entry = PasswordEntry::new();
    for unit in text.encode_utf16() {
        entry.key(&KeyEvent {
            virtual_key_code: 0x41,
            virtual_scan_code: 0,
            unicode_char: unit,
            key_down: true,
            control_key_state: 0,
            repeat_count: 1,
        });
    }
    match entry.key(&KeyEvent {
        virtual_key_code: 0x0D,
        virtual_scan_code: 0,
        unicode_char: 0x0D,
        key_down: true,
        control_key_state: 0,
        repeat_count: 1,
    }) {
        Step::Submit(p) => p,
        _ => panic!("no password typed"),
    }
}

/// What the fake `OfferIo` saw.
#[derive(Default)]
struct Fake {
    steps: VecDeque<Result<Step, Disconnected>>,
    start_result: Option<Result<(), StartFailure>>,
    written: String,
    reads: usize,
    started_with: Vec<Vec<u16>>,
}

impl Fake {
    fn with_steps(steps: Vec<Result<Step, Disconnected>>) -> Fake {
        Fake {
            steps: steps.into(),
            start_result: Some(Ok(())),
            ..Fake::default()
        }
    }
}

impl OfferIo for Fake {
    fn write(&mut self, text: &str) {
        self.written.push_str(text);
    }

    fn read_password(&mut self) -> Result<Step, Disconnected> {
        self.reads += 1;
        self.steps
            .pop_front()
            .expect("the offer read more steps than the test gave")
    }

    fn start_session(&mut self, password: &Password) -> Result<(), StartFailure> {
        self.started_with.push(password.as_wide().to_vec());
        self.start_result.take().expect("a second start_session call")
    }
}

fn run(kind: SessionKind, account: AccountKind, absence: Absence, user: &str, io: &mut Fake) -> Offered {
    offer(kind, account, absence, user, io)
}

fn run_pty(io: &mut Fake) -> Offered {
    run(SessionKind::Pty, AccountKind::Local, Absence::NoAgent, "alice", io)
}

#[test]
fn exec_never_prompts() {
    let mut io = Fake::default();
    let out = run(
        SessionKind::ExecOrNoTerminal,
        AccountKind::Local,
        Absence::NoAgent,
        "alice",
        &mut io,
    );
    assert_eq!(out, Offered::Plain);
    assert_eq!(io.reads, 0);
    assert!(io.started_with.is_empty());
    assert!(io.written.is_empty());
}

#[test]
fn no_terminal_never_prompts() {
    let mut io = Fake::default();
    let out = run(
        SessionKind::ExecOrNoTerminal,
        AccountKind::Local,
        Absence::NoProfileYet,
        "alice",
        &mut io,
    );
    assert_eq!(out, Offered::Plain);
    assert_eq!(io.reads, 0);
}

#[test]
fn other_absence_never_prompts() {
    let mut io = Fake::default();
    let out = run(SessionKind::Pty, AccountKind::Local, Absence::Other, "alice", &mut io);
    assert_eq!(out, Offered::Plain);
    assert_eq!(io.reads, 0);
    assert!(io.started_with.is_empty());
}

#[test]
fn other_absence_writes_no_notice() {
    let mut io = Fake::default();
    run(SessionKind::Pty, AccountKind::Local, Absence::Other, "alice", &mut io);
    assert_eq!(io.written, "");
}

#[test]
fn not_local_account_skips_the_prompt() {
    let mut io = Fake::default();
    let out = run(
        SessionKind::Pty,
        AccountKind::NotLocal,
        Absence::NoAgent,
        "alice",
        &mut io,
    );
    assert_eq!(out, Offered::Plain);
    assert_eq!(io.reads, 0);
    assert!(io.written.contains("alice is not a local account"), "{}", io.written);
    assert!(io.written.contains("ssh-broker#45"), "{}", io.written);
    assert!(io.written.contains(text::COST_LINE.trim_end()), "{}", io.written);
    assert!(!io.written.contains("Enter your Windows password"));
}

#[test]
fn the_prompt_is_the_owners_sentence_then_the_ctrl_c_sentence() {
    let mut io = Fake::with_steps(vec![Ok(Step::Cancel)]);
    run_pty(&mut io);
    assert!(
        io.written.starts_with(
            "ssh-broker: alice has no Windows session on this PC. Enter your Windows password to start one. \
             (The password goes to Windows to sign you in; ssh-broker does not store it.) \
             Press Ctrl+C for a plain shell.\r\n"
        ),
        "{:?}",
        io.written
    );
}

#[test]
fn empty_enter_reprompts_and_never_means_plain() {
    let mut io = Fake::with_steps(vec![Ok(Step::Empty), Ok(Step::Cancel)]);
    let out = run_pty(&mut io);
    assert_eq!(io.reads, 2);
    assert_eq!(out, Offered::Plain);
    assert!(
        io.written
            .contains("empty passwords are not supported yet (ssh-broker#45)")
    );
    assert!(io.started_with.is_empty());
}

#[test]
fn empty_enter_three_times_then_password_starts_one_session() {
    let mut io = Fake::with_steps(vec![
        Ok(Step::Empty),
        Ok(Step::Empty),
        Ok(Step::Empty),
        Ok(Step::Submit(password("pw"))),
    ]);
    let out = run_pty(&mut io);
    assert_eq!(out, Offered::Started);
    assert_eq!(io.started_with, vec![vec![0x70, 0x77]]);
    assert_eq!(io.written.matches("empty passwords are not supported yet").count(), 3);
}

#[test]
fn ctrl_c_gives_plain_with_cost_line() {
    let mut io = Fake::with_steps(vec![Ok(Step::Cancel)]);
    let out = run_pty(&mut io);
    assert_eq!(out, Offered::Plain);
    assert!(io.written.ends_with(text::COST_LINE), "{:?}", io.written);
    assert!(io.started_with.is_empty());
}

#[test]
fn wrong_password_is_one_attempt() {
    let mut io = Fake::with_steps(vec![Ok(Step::Submit(password("wrong")))]);
    io.start_result = Some(Err(StartFailure::Windows {
        reason: "The user name or password is incorrect.".into(),
    }));
    let out = run_pty(&mut io);
    assert_eq!(out, Offered::Plain);
    assert_eq!(io.reads, 1);
    assert_eq!(io.started_with.len(), 1);
    assert!(
        io.written
            .contains("ssh-broker: Windows did not sign you in: The user name or password is incorrect.")
    );
    assert!(io.written.ends_with(text::COST_LINE), "{:?}", io.written);
}

#[test]
fn disconnect_while_prompting_attempts_no_logon() {
    let mut io = Fake::with_steps(vec![Err(Disconnected)]);
    let out = run_pty(&mut io);
    assert_eq!(out, Offered::Gone);
    assert!(io.started_with.is_empty());
}

#[test]
fn disconnect_during_the_logon_is_gone() {
    let mut io = Fake::with_steps(vec![Ok(Step::Submit(password("pw")))]);
    io.start_result = Some(Err(StartFailure::Disconnected));
    assert_eq!(run_pty(&mut io), Offered::Gone);
}

#[test]
fn user_with_space_and_non_ascii_appears_verbatim_in_prompt() {
    let user = "Zoë Müller";
    let mut io = Fake::with_steps(vec![Ok(Step::Cancel)]);
    run(SessionKind::Pty, AccountKind::Local, Absence::NoAgent, user, &mut io);
    assert!(
        io.written
            .starts_with("ssh-broker: Zoë Müller has no Windows session on this PC."),
        "{:?}",
        io.written
    );
}

#[test]
fn password_is_not_in_any_written_text() {
    let mut io = Fake::with_steps(vec![Ok(Step::Submit(password(SENTINEL)))]);
    io.start_result = Some(Err(StartFailure::Windows {
        reason: "The user name or password is incorrect.".into(),
    }));
    run_pty(&mut io);
    assert!(!io.written.contains(SENTINEL), "{:?}", io.written);
}

#[test]
fn every_line_ends_with_crlf() {
    let mut io = Fake::with_steps(vec![Ok(Step::Empty), Ok(Step::Cancel)]);
    run_pty(&mut io);
    assert!(!io.written.replace("\r\n", "").contains('\n'), "{:?}", io.written);
    assert!(io.written.ends_with("\r\n"));
}

#[test]
fn notice_names_the_full_exe_path() {
    let exe = r"C:\ProgramData\ssh-broker\ssh-broker.exe";
    let notice = non_interactive_notice("alice", exe);
    assert!(notice.contains(&format!("run {exe} auto-login on once")), "{notice}");
    assert!(notice.contains("ssh -t"), "{notice}");
    assert!(notice.contains("alice has no Windows session on this PC"), "{notice}");
    assert!(!notice.contains('\n'), "one line, no terminator: {notice:?}");
}

#[test]
fn agent_exit_code_sentences() {
    let logs = std::path::Path::new(r"C:\Users\me\AppData\Local\ssh-broker\logs");
    let line = |code| text::agent_ended(code, Some(logs));
    for code in [64, 65, 66, 67, 68, 69] {
        let sentence = line(code);
        assert!(sentence.starts_with("ssh-broker: "), "{sentence}");
        assert!(sentence.ends_with("\r\n"), "{sentence:?}");
        assert!(
            !sentence.contains("exited with code"),
            "a known code has its own sentence: {sentence}"
        );
    }
    assert!(line(64).contains("different account"));
    assert!(line(66).contains("socket"));
    assert!(line(67).contains("folder"));
    // 67 is any failure to set the folder up, not only an unsafe one.
    assert!(line(67).contains("could not be made or was not safe"), "{}", line(67));
    assert!(line(68).contains("elevated"), "{}", line(68));
    assert_ne!(line(64), line(65));
    assert_ne!(line(66), line(67));
    assert_ne!(line(67), line(68));
    assert!(line(69).contains("elevat"), "{}", line(69));
    assert_ne!(line(68), line(69));
    assert!(line(0).contains("took your session but did not answer"));
    let other = line(1);
    assert!(other.contains("exited with code 1"), "{other}");
    assert!(other.contains(logs.to_str().unwrap()), "{other}");
    assert!(
        line(0xC000_0142).contains("exited with code 3221225794"),
        "{}",
        line(0xC000_0142)
    );
}

#[test]
fn an_exit_code_with_no_known_log_folder_points_at_no_folder() {
    let line = text::agent_ended(1, None);
    assert_eq!(line, "ssh-broker: the agent exited with code 1\r\n");
}

#[test]
fn a_failed_start_line_names_the_reason_once() {
    let line = text::start_failed("the profile cannot be loaded");
    assert_eq!(
        line,
        "ssh-broker: the background session did not start: the profile cannot be loaded\r\n"
    );
}

#[test]
fn a_stated_limit_is_said_in_its_own_sentence_and_the_plain_shell_follows() {
    let mut io = Fake::with_steps(vec![Ok(Step::Submit(password("pw")))]);
    io.start_result = Some(Err(StartFailure::Limit {
        sentence: "ssh-broker: alice may not log on as a batch job.".into(),
    }));
    let out = run_pty(&mut io);
    assert_eq!(out, Offered::Plain);
    assert_eq!(io.started_with.len(), 1, "one attempt");
    assert!(
        io.written.ends_with(&format!(
            "ssh-broker: alice may not log on as a batch job.\r\n{}",
            text::COST_LINE
        )),
        "{:?}",
        io.written
    );
    assert!(!io.written.contains("Windows did not sign you in"), "{}", io.written);
}

#[test]
fn a_failure_of_our_own_is_not_blamed_on_windows() {
    let mut io = Fake::with_steps(vec![Ok(Step::Submit(password("pw")))]);
    io.start_result = Some(Err(StartFailure::Internal {
        reason: "could not make the ready event".into(),
    }));
    let out = run_pty(&mut io);
    assert_eq!(out, Offered::Plain);
    assert!(
        io.written
            .contains("ssh-broker: the background session did not start: could not make the ready event"),
        "{}",
        io.written
    );
    assert!(!io.written.contains("Windows did not sign you in"), "{}", io.written);
    assert!(io.written.ends_with(text::COST_LINE));
}

#[test]
fn the_missing_impersonation_right_is_one_unbroken_sentence() {
    assert_eq!(
        text::impersonate_right_missing("alice"),
        "ssh-broker: this login is elevated, and starting an elevated session for alice from a password needs the \
         right \"Impersonate a client after authentication\", which this login does not hold (a logon at the desktop \
         starts one without it; SSH logins use it while it runs)."
    );
}

// The sentences of `elevate` -----

#[test]
fn the_elevate_sentences_are_each_whole() {
    assert_eq!(
        text::elevation_not_hosted(),
        "ssh-broker: this shell is not hosted by ssh-broker, so nothing can be elevated from it (a session of an agent \
         from before this version has no session id: end it and log in again).\r\n"
    );
    assert_eq!(
        text::elevation_never(),
        "ssh-broker: this login asked that nothing be elevated (SSH_BROKER_ELEVATION=never).\r\n"
    );
    assert_eq!(
        text::elevation_already_elevated(),
        "ssh-broker: this session is already elevated: run the command in it.\r\n"
    );
    assert_eq!(
        text::elevation_consent_not_built(),
        "ssh-broker: this login asks before elevating, and asking is not built yet: log in with \
         SSH_BROKER_ELEVATION=auto-approve to run a command elevated without a question.\r\n"
    );
    assert_eq!(
        text::elevation_in_progress(),
        "ssh-broker: another elevation is in progress in this session.\r\n"
    );
    assert_eq!(
        text::elevation_cannot_start("the system cannot find the file"),
        "ssh-broker: the command could not be started elevated: the system cannot find the file\r\n"
    );
    assert_eq!(
        text::elevation_needs_high_agent(),
        "ssh-broker: elevate needs an account whose agent runs at High, and this account's agent does not.\r\n"
    );
    assert_eq!(
        text::elevation_needs_a_terminal(),
        "ssh-broker: --terminal needs a session with a terminal, and this one has none: log in with ssh -t, or leave \
         out --terminal to run the command with its output here and its input closed.\r\n"
    );
    assert_eq!(
        text::elevation_end_unread("sink failed: gone"),
        "ssh-broker: the command ran, and its end could not be read: sink failed: gone\r\n"
    );
    assert_eq!(
        text::elevation_answer_unreadable("protocol error: x"),
        "ssh-broker: the agent's answer could not be read (protocol error: x); the command may or may not have run.\r\n"
    );
    assert_eq!(
        text::agent_ended_unanswered(),
        "ssh-broker: the agent ended before it answered; the command may or may not have run"
    );
    assert_eq!(
        text::elevate_usage(),
        "usage: ssh-broker elevate [--terminal] <command> [arguments]"
    );
}

#[test]
fn every_elevate_refusal_is_one_prefixed_line_ending_in_crlf() {
    for line in [
        text::elevation_not_hosted(),
        text::elevation_never(),
        text::elevation_already_elevated(),
        text::elevation_consent_not_built(),
        text::elevation_in_progress(),
        text::elevation_cannot_start("why"),
        text::elevation_needs_high_agent(),
        text::elevation_needs_a_terminal(),
        text::elevation_end_unread("why"),
        text::elevation_answer_unreadable("why"),
    ] {
        assert!(line.starts_with("ssh-broker: ") && line.ends_with("\r\n"), "{line:?}");
        assert_eq!(line.matches('\n').count(), 1, "{line:?}");
    }
}

// The sentences of the elevation policy -----

#[test]
fn an_unknown_elevation_value_is_named_with_the_four_words_and_nothing_was_run() {
    assert_eq!(
        text::unknown_elevation("Always"),
        "ssh-broker: SSH_BROKER_ELEVATION is \"Always\", which is none of never, prompt, auto-approve or always \
         (lower case, nothing around it). Nothing was run."
    );
    assert!(!text::unknown_elevation("x").contains('\n'), "the shim ends the line");
}

/// One sentence for the shim's fail-open and for the agent's reply (`fail_connection` writes
/// `ssh-broker: {what}: {cause}` and a line break itself), so that it is never prefixed twice.
#[test]
fn always_below_high_is_the_line_the_agents_reply_shares() {
    assert_eq!(
        text::always_below_high(),
        "ssh-broker: this login asked for SSH_BROKER_ELEVATION=always, and this account's sessions cannot be elevated \
         here: its agent does not run at High. Nothing was run.\r\n"
    );
    assert_eq!(
        text::always_below_high(),
        format!(
            "ssh-broker: {}: {}\r\n",
            text::ALWAYS_BELOW_HIGH_WHAT,
            text::ALWAYS_BELOW_HIGH_CAUSE
        )
    );
    assert_eq!(text::always_below_high().matches("ssh-broker: ").count(), 1);
    assert!(!text::always_below_high().contains("administrator"));
}

/// The sentence for a session whose token cannot be made, for a login that asked for a level, says that a login
/// that asked for none is not refused, and says nothing of `always`, whose refusal has sentences of its own.
#[test]
fn an_unavailable_unelevated_session_says_a_login_that_set_nothing_is_not_refused_and_the_cause() {
    for asked in [
        ElevationPolicy::Never,
        ElevationPolicy::Prompt,
        ElevationPolicy::AutoApprove,
    ] {
        assert_eq!(
            text::unelevated_unavailable(Some(asked), "the token cannot be made"),
            "ssh-broker: could not prepare an unelevated session, so nothing was run (a login that leaves \
             SSH_BROKER_ELEVATION unset is not refused): the token cannot be made",
            "{asked:?}"
        );
        assert_eq!(
            text::unelevated_unavailable(Some(asked), "c"),
            format!("ssh-broker: {}: c", text::UNELEVATED_UNAVAILABLE_WHAT)
        );
    }
}

/// A login that asked for `always` is never told to ask for `always`: what cannot be read is whether it
/// can be given.
#[test]
fn an_unreadable_level_for_always_says_so_and_never_tells_it_to_ask_for_always() {
    let sentence = text::unelevated_unavailable(Some(ElevationPolicy::Always), "the level cannot be read");
    assert_eq!(
        sentence,
        "ssh-broker: this login asked for SSH_BROKER_ELEVATION=always, and it cannot be told whether an elevated \
         session can be given, so nothing was run: the level cannot be read"
    );
    assert_eq!(
        text::always_level_unreadable("the level cannot be read"),
        format!("{sentence}\r\n")
    );
    assert!(!sentence.contains("set it to always"), "{sentence}");
}

/// A login whose own token is an administrator's with elevation removed cannot be given an elevated session,
/// whatever level its shim has.
#[test]
fn always_for_a_filtered_login_says_why_it_cannot_be_given() {
    assert_eq!(
        text::always_filtered(),
        "ssh-broker: this login asked for SSH_BROKER_ELEVATION=always, and its own token is an administrator's with \
         elevation removed, so it cannot be given an elevated session. Nothing was run.\r\n"
    );
}

/// A login that set nothing and could not be stepped down is told what it has, and why. Only the shim says it: the
/// agent hands such a login back. `always` is not among the levels that are refused instead, since at High it
/// runs elevated as asked.
#[test]
fn the_fallback_notice_says_the_session_has_sshds_token_and_which_values_are_refused_instead() {
    assert_eq!(
        text::unelevated_fallback("the token cannot be made"),
        "ssh-broker: could not prepare an unelevated session (the token cannot be made), so this session has the \
         token sshd gave this login, which for an administrator is elevated. A login that sets \
         SSH_BROKER_ELEVATION to never, prompt or auto-approve is refused instead."
    );
    assert!(!text::unelevated_fallback("c").contains('\n'));
}

/// The sentences about the filtered login and the elevated agent do not send anyone to an elevated prompt for
/// an ordinary SSH login.
#[test]
fn the_filtered_sentences_do_not_call_an_ordinary_ssh_login_the_way_to_an_elevated_agent() {
    assert_eq!(
        text::FILTERED_SHIM_NOTICE,
        "ssh-broker: this login is an administrator's with elevation removed and cannot reach the account's agent, \
         which runs elevated, so this runs without DPAPI, a loaded profile or symlink traversal."
    );
    // True of an administrator and of an account Windows splits without making it one, so it says neither.
    assert_eq!(
        text::ELEVATED_AGENT_LOOKS_ELSEWHERE,
        "this account's agent serves elevated processes: run this from an elevated prompt or from an SSH login \
         that asked for SSH_BROKER_ELEVATION=always"
    );
    assert!(!text::ELEVATED_AGENT_LOOKS_ELSEWHERE.contains("ordinary SSH login"));
    assert_eq!(
        text::agent_ended(68, None),
        "ssh-broker: the agent refused to run: its token is an administrator's with elevation removed, and an \
         administrator's agent runs elevated or not at all.\r\n"
    );
}
