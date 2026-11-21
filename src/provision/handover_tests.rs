//! Host tests for what `install` says about the previous sshd shell before it replaces it (pure: no registry,
//! no file).

use std::cell::Cell;
use std::path::Path;

use super::{Handover, Stream, Written, hand_over, remove_arguments, replace_shell, say_to, show_to};
use crate::provision::registry::{SshdShell, SshdShellReading};
use crate::provision::system_config::{ConfigKind, CreateOutcome, Decision, Skip, decide};
use crate::shell::config::ShellBlock;
use crate::test_support::{ClosedStream, Said, recording, states_facts_only};

const PWSH7: &str = r"C:\Program Files\PowerShell\7\pwsh.exe";
const CONFIG: &str = r"C:\ProgramData\ssh-broker\config.yaml";

fn previous() -> SshdShell {
    SshdShell {
        shell: Some(PWSH7.into()),
        command_option: Some("-NoLogo -c".into()),
        arguments: Some("-NoProfile".into()),
        escape_arguments: false,
    }
}

/// A handover for the tests that stand in for `carry` and look at its order, not at what it proves. The
/// field is private to `handover`, which this module is inside.
fn a_handover() -> Handover {
    Handover(())
}

fn block() -> ShellBlock {
    ShellBlock {
        start: vec![PWSH7.into()],
        without_command: None,
        with_command: None,
        escaping: None,
    }
}

/// Run `hand_over` for `previous` and return the notices it showed.
fn shown_for(
    previous: &SshdShell,
    decision: Decision,
    create: impl FnOnce(&ShellBlock) -> anyhow::Result<CreateOutcome>,
) -> Vec<String> {
    let mut notices = Vec::new();
    let _ = hand_over(Path::new(CONFIG), previous, decision, create, &mut |text| {
        notices.push(text.to_owned());
        Written(())
    });
    notices
}

/// Run `hand_over` for the foreign `previous()` and return the notices it showed.
fn shown(decision: Decision, create: impl FnOnce(&ShellBlock) -> anyhow::Result<CreateOutcome>) -> Vec<String> {
    shown_for(&previous(), decision, create)
}

fn holds_every_previous_value(text: &str) {
    for part in [
        CONFIG,
        PWSH7,
        "-NoLogo -c",
        "-NoProfile",
        "escape arguments = no",
        "install replaces DefaultShell next",
    ] {
        assert!(text.contains(part), "{part}: {text}");
    }
    before_the_flip(text);
    states_facts_only(text);
}

/// What `hand_over` prints comes before the flip, which can still fail: it may say what `install` does
/// next, never that `DefaultShell` was replaced or changed.
fn before_the_flip(text: &str) {
    for past in ["replaced", "changed", "restored", "is now", "has been"] {
        assert!(!text.contains(past), "{past}: {text}");
    }
}

#[test]
fn a_config_created_by_someone_else_in_between_prints_the_previous_values() {
    let notices = shown(Decision::Write(block()), |_| Ok(CreateOutcome::FileExists));
    assert_eq!(notices.len(), 1, "{notices:?}");
    holds_every_previous_value(&notices[0]);
    assert!(notices[0].contains(&format!("{CONFIG} exists")), "{}", notices[0]);
}

/// The config is the record of what was carried; stdout carries only `install`'s step lines and its last line.
#[test]
fn a_written_config_says_nothing() {
    let notices = shown(Decision::Write(block()), |_| Ok(CreateOutcome::Created));
    assert_eq!(notices, Vec::<String>::new());
}

/// No notice begins with the verb's name, and what `remove_arguments` says rather than shows is on stderr.
#[test]
fn no_notice_begins_with_the_verb_and_what_is_said_is_on_stderr() {
    let mut texts = shown(Decision::Write(block()), |_| Err(anyhow::anyhow!("disk full")));
    texts.extend(shown(Decision::Write(block()), |_| Ok(CreateOutcome::FileExists)));
    texts.extend(shown(Decision::Skip(Skip::NotAFile), |_| unreachable!()));
    for (read, config_is_file, remove_fails) in [
        (Ok(Some("-NoLogo")), Ok(ConfigKind::File), true),
        (Ok(Some("-NoLogo")), Ok(ConfigKind::Missing), false),
        (Err("i/o error"), Ok(ConfigKind::File), false),
    ] {
        let (events, said) = removal(read, config_is_file, remove_fails);
        texts.extend(events.into_iter().filter_map(|event| match event {
            Event::Shown(text) => Some(text),
            Event::Removed => None,
        }));
        for (stream, text) in said {
            assert_eq!(stream, Stream::Err, "{text}");
            texts.push(text);
        }
    }
    assert!(texts.len() >= 6, "{texts:?}");
    for text in texts {
        assert!(!text.to_ascii_lowercase().starts_with("install:"), "{text}");
        assert!(!text.starts_with("install "), "{text}");
    }
}

/// A line to a stream that cannot be written (an `install` over an SSH connection that has gone) is lost, on
/// either stream, and the lines that can be written go to the stream they name.
#[test]
fn a_line_to_a_closed_stream_is_lost_without_a_panic_and_the_others_are_written() {
    say_to(&mut ClosedStream, &mut ClosedStream, Stream::Out, "a line");
    say_to(&mut ClosedStream, &mut ClosedStream, Stream::Err, "a line");

    let (mut out, mut err) = (Vec::new(), Vec::new());
    say_to(&mut out, &mut err, Stream::Out, "to stdout");
    say_to(&mut out, &mut err, Stream::Err, "to stderr");
    assert_eq!((out, err), (b"to stdout\n".to_vec(), b"to stderr\n".to_vec()));

    // Stdout closed, stderr open: the stdout line is lost and the stderr lines are written.
    let mut err = Vec::new();
    say_to(&mut ClosedStream, &mut err, Stream::Out, "lost");
    say_to(&mut ClosedStream, &mut err, Stream::Err, "first");
    say_to(&mut ClosedStream, &mut err, Stream::Out, "lost again");
    say_to(&mut ClosedStream, &mut err, Stream::Err, "second");
    assert_eq!(err, b"first\nsecond\n");

    // Stderr closed, stdout open: the stderr line is lost and the stdout lines are written.
    let mut out = Vec::new();
    say_to(&mut out, &mut ClosedStream, Stream::Err, "lost");
    say_to(&mut out, &mut ClosedStream, Stream::Out, "first");
    say_to(&mut out, &mut ClosedStream, Stream::Err, "lost again");
    say_to(&mut out, &mut ClosedStream, Stream::Out, "second");
    assert_eq!(out, b"first\nsecond\n");
}

/// A notice that keeps a value is written to the writer it is given, as a line.
#[test]
fn a_notice_is_written_as_a_line() {
    let mut err = Vec::new();
    show_to(&mut err, "the values");
    assert_eq!(err, b"the values\n");
}

/// A notice that cannot be written does not return, so what it announces is not done: `eprintln!` ends the
/// process the same way.
#[test]
#[should_panic(expected = "failed printing to stderr")]
fn a_notice_that_cannot_be_written_does_not_return() {
    show_to(&mut ClosedStream, "the values");
}

#[test]
fn a_config_that_cannot_be_written_prints_the_previous_values_and_the_cause() {
    let notices = shown(Decision::Write(block()), |_| Err(anyhow::anyhow!("disk full")));
    assert_eq!(notices.len(), 1, "{notices:?}");
    holds_every_previous_value(&notices[0]);
    assert!(notices[0].contains("could not write"), "{}", notices[0]);
    assert!(notices[0].contains("disk full"), "{}", notices[0]);
}

#[test]
fn every_skip_that_loses_the_previous_shell_prints_the_previous_values_without_creating() {
    for skip in [
        Skip::FileExists,
        Skip::NotAFile,
        Skip::PreviousMissing("there is no such file".into()),
        Skip::Unchecked("cannot tell whether the config exists".into()),
    ] {
        let created = Cell::new(false);
        let notices = shown(Decision::Skip(skip.clone()), |_| {
            created.set(true);
            Ok(CreateOutcome::Created)
        });
        assert!(!created.get(), "{skip:?}");
        assert_eq!(notices.len(), 1, "{skip:?}: {notices:?}");
        holds_every_previous_value(&notices[0]);
    }
}

/// A directory at the config path, from the check through the decision to what is printed: nothing is
/// created, and the one line says the path is not a file, with every previous value.
#[test]
fn a_config_path_that_is_not_a_file_prints_that_and_the_previous_values_without_creating() {
    let decision = decide(
        &previous(),
        Ok(ConfigKind::Other),
        &|| Ok(vec![]),
        &|_, path| Ok(path.to_path_buf()),
        &|_| false,
    );
    let created = Cell::new(false);
    let notices = shown(decision, |_| {
        created.set(true);
        Ok(CreateOutcome::Created)
    });
    assert!(!created.get());
    assert_eq!(notices.len(), 1, "{notices:?}");
    holds_every_previous_value(&notices[0]);
    assert!(
        notices[0].contains(&format!("{CONFIG} is not a file")),
        "{}",
        notices[0]
    );
}

/// The path turned into a non-file between the check and the create: the create says so and the line is the same.
#[test]
fn a_config_path_that_turns_into_a_non_file_before_the_create_prints_that() {
    let notices = shown(Decision::Write(block()), |_| Ok(CreateOutcome::NotAFile));
    assert_eq!(notices.len(), 1, "{notices:?}");
    holds_every_previous_value(&notices[0]);
    assert!(notices[0].contains("is not a file"), "{}", notices[0]);
}

/// What is carried is judged from the previous shell itself, whatever the decision says: ssh-broker's
/// own shell, or none, loses nothing and says nothing (and nothing is created for it).
#[test]
fn a_previous_shell_that_is_ssh_broker_or_unset_says_nothing_whatever_the_decision() {
    let own = |shell: Option<&str>| SshdShell {
        shell: shell.map(str::to_owned),
        ..previous()
    };
    for shell in [
        Some(r"C:\ProgramData\ssh-broker\ssh-broker.exe"),
        Some(r"C:\ProgramData\ssh-broker\ssh-broker"),
        None,
    ] {
        for decision in [
            Decision::Skip(Skip::NothingToCarry),
            Decision::Skip(Skip::FileExists),
            Decision::Skip(Skip::Unchecked("cannot tell".into())),
            Decision::Write(block()),
        ] {
            let created = Cell::new(false);
            let notices = shown_for(&own(shell), decision, |_| {
                created.set(true);
                Ok(CreateOutcome::Created)
            });
            assert_eq!((notices, created.get()), (vec![], false), "{shell:?}");
        }
    }
}

/// A decision that claims there is nothing to carry cannot make a foreign shell vanish unseen: its values
/// are printed.
#[test]
fn a_nothing_to_carry_skip_for_a_foreign_shell_prints_the_previous_values() {
    let notices = shown(Decision::Skip(Skip::NothingToCarry), |_| Ok(CreateOutcome::Created));
    assert_eq!(notices.len(), 1, "{notices:?}");
    assert!(notices[0].contains(PWSH7), "{}", notices[0]);
}

/// The proof is only given for a shell that has nothing to carry: a foreign one gets none, whoever asks.
#[test]
fn nothing_to_carry_is_proven_only_for_ssh_broker_or_no_shell() {
    assert!(Handover::nothing_to_carry(&previous()).is_none());
    assert!(Handover::nothing_to_carry(&SshdShell::none()).is_some());
    for own in [
        r"C:\ProgramData\ssh-broker\ssh-broker.exe",
        r"C:\ProgramData\ssh-broker\ssh-broker",
    ] {
        let shell = SshdShell {
            shell: Some(own.into()),
            ..previous()
        };
        assert!(Handover::nothing_to_carry(&shell).is_some(), "{own}");
    }
}

fn reading() -> SshdShellReading {
    SshdShellReading {
        shell: Ok(Some(PWSH7.into())),
        command_option: Ok(Some("-NoLogo -c".into())),
        arguments: Ok(Some("-NoProfile".into())),
        escape_arguments: Ok(false),
    }
}

/// The owner's rule (7/7): the flip never happens unless the previous values were carried or printed. A
/// value that cannot be read can be neither, so `install` stops before the flip and says which, and what
/// was read.
#[test]
fn an_unreadable_previous_shell_stops_before_the_flip() {
    let mut unreadable = reading();
    unreadable.command_option = Err("access denied".into());
    let (carried, flipped) = (Cell::new(false), Cell::new(false));
    let result = replace_shell(
        || unreadable.into_shell(r"HKLM\SOFTWARE\OpenSSH"),
        |_| {
            carried.set(true);
            a_handover()
        },
        |_| {
            flipped.set(true);
            Ok(())
        },
    );
    let text = format!("{:#}", result.unwrap_err());
    assert!(
        !carried.get() && !flipped.get(),
        "carried {carried:?}, flipped {flipped:?}"
    );
    for part in [
        "DefaultShellCommandOption (access denied)",
        "DefaultShell was not changed",
        &format!("DefaultShell = \"{PWSH7}\""),
        "DefaultShellArguments = \"-NoProfile\"",
        "DefaultShellEscapeArguments = off",
    ] {
        assert!(text.contains(part), "{part}: {text}");
    }
    // Nothing was written, so the text may say so; it must not say the shell was replaced.
    assert!(!text.contains("replaced"), "{text}");
    states_facts_only(&text);
}

#[test]
fn a_readable_previous_shell_is_carried_and_then_flipped() {
    let order = std::cell::RefCell::new(Vec::new());
    let flipped = replace_shell(
        || reading().into_shell("location"),
        |previous| {
            assert_eq!(previous.shell.as_deref(), Some(PWSH7));
            order.borrow_mut().push("carry");
            a_handover()
        },
        |_| {
            order.borrow_mut().push("flip");
            Ok(7)
        },
    )
    .unwrap();
    assert_eq!((flipped, order.into_inner()), (7, vec!["carry", "flip"]));
}

/// The error is printed after the failed write, when `DefaultShell` is as the registry held it: the
/// error says so, with the cause, and does not say it was replaced.
#[test]
fn a_failed_flip_is_the_error_and_says_the_default_shell_was_not_changed() {
    let error = replace_shell(
        || reading().into_shell("location"),
        |_| a_handover(),
        |_| -> anyhow::Result<()> { anyhow::bail!("write failed") },
    )
    .unwrap_err();
    assert!(error.to_string().starts_with("DefaultShell was not changed"), "{error}");
    let text = format!("{error:#}");
    assert!(text.contains("write failed"), "{text}");
    assert!(!text.contains("replaced"), "{text}");
    states_facts_only(&text);
}

fn unreadable_arguments(shell: &str) -> SshdShellReading {
    let mut reading = reading();
    reading.shell = Ok(Some(shell.into()));
    reading.arguments = Err("i/o error".into());
    reading
}

/// Nothing is lost by replacing ssh-broker with itself, so an unreadable other value does not stop `install`
/// (it must still reach the removal of `DefaultShellArguments`); with a foreign shell it does.
#[test]
fn an_unreadable_value_stops_the_flip_only_for_a_shell_that_is_not_ssh_broker() {
    for (shell, goes_on) in [
        (r"C:\ProgramData\ssh-broker\ssh-broker.exe", true),
        (r"C:\ProgramData\ssh-broker\ssh-broker", true),
        (PWSH7, false),
    ] {
        let (carried, flipped) = (Cell::new(false), Cell::new(false));
        let result = replace_shell(
            || unreadable_arguments(shell).into_shell("location"),
            |_| {
                carried.set(true);
                a_handover()
            },
            |_| {
                flipped.set(true);
                Ok(())
            },
        );
        assert_eq!(result.is_ok(), goes_on, "{shell}: {result:?}");
        assert_eq!((carried.get(), flipped.get()), (goes_on, goes_on), "{shell}");
    }
}

// the removal of DefaultShellArguments =====

const KEY: &str = r"SOFTWARE\OpenSSH";

/// What `remove_arguments` showed and did, in order: the notice with the value, and the removal.
#[derive(Debug, PartialEq, Eq)]
enum Event {
    Shown(String),
    Removed,
}

/// Run `remove_arguments` and return what happened, in order, and the lines it said. `remove_fails` makes the
/// removal fail.
fn removal(
    read: Result<Option<&str>, &str>,
    config_is_file: Result<ConfigKind, &str>,
    remove_fails: bool,
) -> (Vec<Event>, Said) {
    let events = std::cell::RefCell::new(Vec::new());
    let said = std::cell::RefCell::new(Vec::new());
    remove_arguments(
        Path::new(CONFIG),
        KEY,
        read.map(|v| v.map(str::to_owned)).map_err(str::to_owned),
        || config_is_file.map_err(str::to_owned),
        |_shown| {
            events.borrow_mut().push(Event::Removed);
            if remove_fails {
                anyhow::bail!("access denied");
            }
            Ok(())
        },
        &mut recording(&said),
        &mut |text| {
            events.borrow_mut().push(Event::Shown(text.to_owned()));
            Written(())
        },
    );
    (events.into_inner(), said.into_inner())
}

/// The owner's rule (7/7), applied to the value that is deleted: the text with the value is emitted
/// before the delete runs. A removal that worked says nothing more: stdout carries only `install`'s step lines
/// and its last line.
#[test]
fn the_arguments_are_printed_before_they_are_removed_and_a_removal_that_worked_says_nothing_more() {
    let (events, said) = removal(Ok(Some("-NoLogo")), Ok(ConfigKind::File), false);
    let [Event::Shown(before), Event::Removed] = &events[..] else {
        panic!("{events:?}");
    };
    assert_eq!(
        before,
        r#"removing DefaultShellArguments ("-NoLogo") from HKLM\SOFTWARE\OpenSSH"#
    );
    states_facts_only(before);
    assert_eq!(said, []);
}

#[test]
fn a_failed_removal_was_announced_first_and_says_the_cause() {
    let (events, said) = removal(Ok(Some("-NoLogo")), Ok(ConfigKind::File), true);
    let [Event::Shown(before), Event::Removed] = &events[..] else {
        panic!("{events:?}");
    };
    assert!(before.contains("-NoLogo"), "{before}");
    let [(Stream::Err, after)] = &said[..] else {
        panic!("{said:?}");
    };
    for part in ["could not remove DefaultShellArguments", "access denied"] {
        assert!(after.contains(part), "{part}: {after}");
    }
    states_facts_only(after);
}

#[test]
fn arguments_that_are_not_removed_are_never_removed_and_a_value_that_is_set_is_said() {
    for (read, config_is_file) in [
        (Err("i/o error"), Ok(ConfigKind::File)),
        (Err("i/o error"), Ok(ConfigKind::Missing)),
        (Ok(Some("-NoLogo")), Ok(ConfigKind::Missing)),
        (Ok(Some("-NoLogo")), Ok(ConfigKind::Other)),
        (Ok(Some("-NoLogo")), Err("cannot tell")),
    ] {
        let (events, said) = removal(read, config_is_file, false);
        assert_eq!(events, [], "{read:?} {config_is_file:?}");
        let [(Stream::Err, text)] = &said[..] else {
            panic!("{read:?} {config_is_file:?}: {said:?}");
        };
        states_facts_only(text);
    }
}

#[test]
fn no_arguments_say_nothing_and_remove_nothing() {
    assert_eq!(removal(Ok(None), Ok(ConfigKind::File), false), (vec![], vec![]));
}
