//! Host tests for what `apply` says about the previous sshd shell before it replaces it (pure: no registry,
//! no file).

use std::cell::Cell;
use std::path::Path;

use super::{Stream, hand_over, hand_over_unreadable};
use crate::provision::registry::SshdShell;
use crate::provision::system_config::{Decision, Skip};
use crate::shell::config::ShellBlock;

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

fn block() -> ShellBlock {
    ShellBlock {
        start: vec![PWSH7.into()],
        without_command: None,
        with_command: None,
        escaping: None,
    }
}

/// Run `hand_over` and return what was said.
fn said(decision: Decision, create: impl FnOnce(&ShellBlock) -> anyhow::Result<bool>) -> Vec<(Stream, String)> {
    let mut lines = Vec::new();
    let _ = hand_over(Path::new(CONFIG), &previous(), decision, create, &mut |stream, text| {
        lines.push((stream, text.to_owned()))
    });
    lines
}

fn holds_every_previous_value(text: &str) {
    for part in [
        CONFIG,
        PWSH7,
        "-NoLogo -c",
        "-NoProfile",
        "escape arguments = no",
        "DefaultShell is replaced all the same",
    ] {
        assert!(text.contains(part), "{part}: {text}");
    }
}

#[test]
fn a_config_created_by_someone_else_in_between_prints_the_previous_values() {
    let lines = said(Decision::Write(block()), |_| Ok(false));
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0].0, Stream::Err);
    holds_every_previous_value(&lines[0].1);
    assert!(lines[0].1.contains("is already there"), "{}", lines[0].1);
}

#[test]
fn a_written_config_says_so_on_stdout_and_prints_no_warning() {
    let lines = said(Decision::Write(block()), |_| Ok(true));
    assert_eq!(
        lines,
        vec![(
            Stream::Out,
            format!("apply: wrote {CONFIG} from the shell sshd used before ({PWSH7})")
        )]
    );
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
        Skip::PreviousMissing("there is no such file".into()),
        Skip::Unchecked("cannot tell whether the config exists".into()),
    ] {
        let created = Cell::new(false);
        let lines = said(Decision::Skip(skip.clone()), |_| {
            created.set(true);
            Ok(true)
        });
        assert!(!created.get(), "{skip:?}");
        assert_eq!(lines.len(), 1, "{skip:?}: {lines:?}");
        assert_eq!(lines[0].0, Stream::Err, "{skip:?}");
        holds_every_previous_value(&lines[0].1);
    }
}

#[test]
fn a_skip_that_replaces_nothing_says_nothing() {
    for skip in [Skip::PreviousIsSshBroker, Skip::NoPreviousShell] {
        assert_eq!(said(Decision::Skip(skip.clone()), |_| Ok(true)), vec![], "{skip:?}");
    }
}

#[test]
fn an_unreadable_previous_shell_prints_the_cause() {
    let mut lines = Vec::new();
    let _ = hand_over_unreadable(&anyhow::anyhow!("access denied"), &mut |stream, text| {
        lines.push((stream, text.to_owned()))
    });
    assert_eq!(
        lines,
        vec![(
            Stream::Err,
            "apply: could not read the shell sshd uses now, so it is not carried into config.yaml: access denied"
                .to_owned()
        )]
    );
}
