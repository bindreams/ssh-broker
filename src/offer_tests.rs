//! Unit tests for `offer` (pure; runs on the host). The fake records every call.
use super::*;
use crate::password_entry::{Password, PasswordEntry, Step};
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
    for code in [64, 65, 66, 67] {
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
    assert_ne!(line(64), line(65));
    assert_ne!(line(66), line(67));
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
