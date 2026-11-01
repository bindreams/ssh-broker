//! Host tests for what `apply` says about the previous sshd shell before it replaces it (pure: no registry,
//! no file).

use std::cell::Cell;
use std::path::Path;

use super::{Handover, Stream, hand_over, remove_arguments, replace_shell};
use crate::provision::registry::{SshdShell, SshdShellReading};
use crate::provision::system_config::{ConfigKind, CreateOutcome, Decision, Skip, decide};
use crate::shell::config::ShellBlock;
use crate::test_support::states_facts_only;

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

/// Run `hand_over` for `previous` and return what was said.
fn said_for(
    previous: &SshdShell,
    decision: Decision,
    create: impl FnOnce(&ShellBlock) -> anyhow::Result<CreateOutcome>,
) -> Vec<(Stream, String)> {
    let mut lines = Vec::new();
    let _ = hand_over(Path::new(CONFIG), previous, decision, create, &mut |stream, text| {
        lines.push((stream, text.to_owned()))
    });
    lines
}

/// Run `hand_over` for the foreign `previous()` and return what was said.
fn said(
    decision: Decision,
    create: impl FnOnce(&ShellBlock) -> anyhow::Result<CreateOutcome>,
) -> Vec<(Stream, String)> {
    said_for(&previous(), decision, create)
}

fn holds_every_previous_value(text: &str) {
    for part in [
        CONFIG,
        PWSH7,
        "-NoLogo -c",
        "-NoProfile",
        "escape arguments = no",
        "apply replaces DefaultShell next",
    ] {
        assert!(text.contains(part), "{part}: {text}");
    }
    before_the_flip(text);
    states_facts_only(text);
}

/// What `hand_over` prints comes before the flip, which can still fail: it may say what `apply` does
/// next, never that `DefaultShell` was replaced or changed.
fn before_the_flip(text: &str) {
    for past in ["replaced", "changed", "restored", "is now", "has been"] {
        assert!(!text.contains(past), "{past}: {text}");
    }
}

#[test]
fn a_config_created_by_someone_else_in_between_prints_the_previous_values() {
    let lines = said(Decision::Write(block()), |_| Ok(CreateOutcome::FileExists));
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0].0, Stream::Err);
    holds_every_previous_value(&lines[0].1);
    assert!(lines[0].1.contains(&format!("{CONFIG} exists")), "{}", lines[0].1);
}

#[test]
fn a_written_config_says_so_on_stdout_and_prints_no_warning() {
    let lines = said(Decision::Write(block()), |_| Ok(CreateOutcome::Created));
    assert_eq!(
        lines,
        vec![(
            Stream::Out,
            format!("apply: wrote {CONFIG} from the shell sshd used before ({PWSH7})")
        )]
    );
    before_the_flip(&lines[0].1);
}

#[test]
fn a_config_that_cannot_be_written_prints_the_previous_values_and_the_cause() {
    let lines = said(Decision::Write(block()), |_| Err(anyhow::anyhow!("disk full")));
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0].0, Stream::Err);
    holds_every_previous_value(&lines[0].1);
    assert!(lines[0].1.contains("could not write"), "{}", lines[0].1);
    assert!(lines[0].1.contains("disk full"), "{}", lines[0].1);
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
        let lines = said(Decision::Skip(skip.clone()), |_| {
            created.set(true);
            Ok(CreateOutcome::Created)
        });
        assert!(!created.get(), "{skip:?}");
        assert_eq!(lines.len(), 1, "{skip:?}: {lines:?}");
        assert_eq!(lines[0].0, Stream::Err, "{skip:?}");
        holds_every_previous_value(&lines[0].1);
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
    let lines = said(decision, |_| {
        created.set(true);
        Ok(CreateOutcome::Created)
    });
    assert!(!created.get());
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0].0, Stream::Err);
    holds_every_previous_value(&lines[0].1);
    assert!(
        lines[0].1.contains(&format!("{CONFIG} is not a file")),
        "{}",
        lines[0].1
    );
}

/// The path turned into a non-file between the check and the create: the create says so and the line is the same.
#[test]
fn a_config_path_that_turns_into_a_non_file_before_the_create_prints_that() {
    let lines = said(Decision::Write(block()), |_| Ok(CreateOutcome::NotAFile));
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0].0, Stream::Err);
    holds_every_previous_value(&lines[0].1);
    assert!(lines[0].1.contains("is not a file"), "{}", lines[0].1);
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
            let lines = said_for(&own(shell), decision, |_| {
                created.set(true);
                Ok(CreateOutcome::Created)
            });
            assert_eq!((lines, created.get()), (vec![], false), "{shell:?}");
        }
    }
}

/// A decision that claims there is nothing to carry cannot make a foreign shell vanish unseen: its values
/// are printed.
#[test]
fn a_nothing_to_carry_skip_for_a_foreign_shell_prints_the_previous_values() {
    let lines = said(Decision::Skip(Skip::NothingToCarry), |_| Ok(CreateOutcome::Created));
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0].0, Stream::Err);
    assert!(lines[0].1.contains(PWSH7), "{}", lines[0].1);
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
/// value that cannot be read can be neither, so `apply` stops before the flip and says which, and what
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

/// Nothing is lost by replacing ssh-broker with itself, so an unreadable other value does not stop `apply`
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

#[derive(Debug, PartialEq, Eq)]
enum Event {
    Said(Stream, String),
    Removed,
}

/// Run `remove_arguments` and return what happened, in order. `remove_fails` makes the removal fail.
fn removal(
    read: Result<Option<&str>, &str>,
    config_is_file: Result<ConfigKind, &str>,
    remove_fails: bool,
) -> Vec<Event> {
    let events = std::cell::RefCell::new(Vec::new());
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
        &mut |stream, text| events.borrow_mut().push(Event::Said(stream, text.to_owned())),
    );
    events.into_inner()
}

/// The owner's rule (7/7), applied to the value that is deleted: the text with the value is emitted
/// before the delete runs, and the delete is confirmed after it.
#[test]
fn the_arguments_are_printed_before_they_are_removed_and_the_removal_is_confirmed_after() {
    let events = removal(Ok(Some("-NoLogo")), Ok(ConfigKind::File), false);
    let [Event::Said(first, before), Event::Removed, Event::Said(second, after)] = &events[..] else {
        panic!("{events:?}");
    };
    assert_eq!((*first, *second), (Stream::Err, Stream::Out));
    assert!(
        before.contains("removing DefaultShellArguments") && before.contains("-NoLogo"),
        "{before}"
    );
    assert!(
        after.contains("removed DefaultShellArguments") && after.contains("-NoLogo"),
        "{after}"
    );
    states_facts_only(before);
    states_facts_only(after);
}

#[test]
fn a_failed_removal_was_announced_first_and_says_the_cause() {
    let events = removal(Ok(Some("-NoLogo")), Ok(ConfigKind::File), true);
    let [Event::Said(_, before), Event::Removed, Event::Said(Stream::Err, after)] = &events[..] else {
        panic!("{events:?}");
    };
    assert!(before.contains("-NoLogo"), "{before}");
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
        let events = removal(read, config_is_file, false);
        let [Event::Said(Stream::Err, text)] = &events[..] else {
            panic!("{read:?} {config_is_file:?}: {events:?}");
        };
        states_facts_only(text);
    }
}

#[test]
fn no_arguments_say_nothing_and_remove_nothing() {
    assert_eq!(removal(Ok(None), Ok(ConfigKind::File), false), vec![]);
}
