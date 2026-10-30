//! Host tests for what `apply` carries from the previous sshd shell into the system config (pure;
//! runs on any platform, no registry).

use std::path::{Path, PathBuf};

use super::{Decision, Skip, SshdClass, carried_block, classify, create_once_at, decide, render};
use crate::provision::registry::SshdShell;
use crate::shell::Escaping;
use crate::shell::config::{ShellBlock, parse};

const PWSH7: &str = r"C:\Program Files\PowerShell\7\pwsh.exe";
const TOOLS_PWSH: &str = r"C:\tools\pwsh.exe";

fn sshd(shell: &str) -> SshdShell {
    SshdShell {
        shell: Some(shell.into()),
        command_option: None,
        arguments: None,
        escape_arguments: true,
    }
}

fn carried(prev: &SshdShell) -> ShellBlock {
    carried_block(prev, false)
}

// classify =====

#[test]
fn classify_follows_sshds_order_and_substrings() {
    for (path, class) in [
        (r"C:\Windows\System32\cmd.exe", SshdClass::Cmd),
        ("c:/windows/system32/CMD.EXE", SshdClass::Cmd),
        (
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            SshdClass::PowerShell,
        ),
        (PWSH7, SshdClass::PowerShell),
        (r"C:\Program Files\Git\bin\bash.exe", SshdClass::Bash),
        (r"C:\cygwin64\bin\zsh.exe", SshdClass::Cygwin),
        (r"C:\Program Files\OpenSSH\ssh-shellhost.exe", SshdClass::ShellHost),
        (TOOLS_PWSH, SshdClass::Other),
        (r"C:\Windows\SysWOW64\cmd.exe", SshdClass::Other),
        (r"C:\Windows\System32\powershell\cmd.exe", SshdClass::PowerShell),
        (r"C:\x\system32\cmd\powershell.exe", SshdClass::Cmd),
        (r"C:\tools\bash.exe", SshdClass::Bash),
        (r"C:\tools\notbash.exe", SshdClass::Other),
    ] {
        assert_eq!(classify(path), class, "{path}");
    }
}

// carried_block =====

#[test]
fn only_values_that_differ_from_the_default_are_carried() {
    // No companion values: the shell alone.
    assert_eq!(
        carried(&sshd(TOOLS_PWSH)),
        ShellBlock {
            start: vec![TOOLS_PWSH.into()],
            ..ShellBlock::default()
        }
    );
    assert_eq!(
        carried(&sshd(PWSH7)).escaping,
        None,
        "PowerShell class is escaped, as msvc is"
    );

    // `-c` is the default for another program; `-Command` is not.
    let mut prev = sshd(TOOLS_PWSH);
    prev.command_option = Some("-c".into());
    assert_eq!(carried(&prev).with_command, None);
    prev.command_option = Some("-Command".into());
    assert_eq!(carried(&prev).with_command, Some(vec!["-Command".into()]));

    // A cmd-class path that is not the system cmd.exe: sshd runs it `/c` and unescaped, which
    // differs from the default for another program.
    let copy = carried(&sshd(r"C:\Windows\System32\cmd.exe"));
    assert_eq!(copy.with_command, Some(vec!["/c".into()]));
    assert_eq!(copy.escaping, Some(Escaping::Cmd));
    // The system cmd.exe itself matches its defaults and carries nothing but the start.
    let system = carried_block(&sshd(r"C:\Windows\System32\cmd.exe"), true);
    assert_eq!((system.with_command, system.escaping), (None, None));

    // Empty values count as absent.
    let mut prev = sshd(TOOLS_PWSH);
    prev.command_option = None;
    prev.arguments = None;
    assert_eq!(carried(&prev).without_command, None);
}

#[test]
fn arguments_are_split_as_a_command_line() {
    let with = |arguments: &str| {
        let mut prev = sshd(TOOLS_PWSH);
        prev.arguments = Some(arguments.into());
        carried(&prev).without_command
    };
    assert_eq!(
        with("-NoLogo -NoProfile"),
        Some(vec!["-NoLogo".into(), "-NoProfile".into()])
    );
    assert_eq!(
        with(r#"-File "C:\my dir\a.ps1""#),
        Some(vec!["-File".into(), r"C:\my dir\a.ps1".into()])
    );
    assert_eq!(with("-NoLogo"), Some(vec!["-NoLogo".into()]));
    assert_eq!(with("   "), None, "only blanks is no arguments");
}

#[test]
fn the_escape_flag_applies_only_to_the_other_class() {
    let off = |shell: &str| {
        let mut prev = sshd(shell);
        prev.escape_arguments = false;
        carried(&prev).escaping
    };
    assert_eq!(off(TOOLS_PWSH), Some(Escaping::Cmd));
    for shell in [PWSH7, r"C:\Program Files\Git\bin\bash.exe", r"C:\cygwin64\bin\zsh.exe"] {
        assert_eq!(off(shell), None, "{shell}: escaped whatever the flag says");
    }
    assert_eq!(
        carried(&sshd(TOOLS_PWSH)).escaping,
        None,
        "flag on: msvc is the default"
    );
    // ShellHost is never escaped, and its default (another program) is msvc.
    assert_eq!(carried(&sshd(r"C:\x\ssh-shellhost.exe")).escaping, Some(Escaping::Cmd));
}

// decide =====

#[test]
fn decide_table() {
    let exists = |_: &Path| true;
    let missing = |_: &Path| false;
    let not_system = |_: &Path| false;

    for own in [
        r"C:\ProgramData\ssh-broker\ssh-broker.exe",
        r"D:\other\SSH-Broker.EXE",
        "c:/x/ssh-broker.exe",
        "ssh-broker.exe",
    ] {
        assert_eq!(
            decide(&sshd(own), false, &exists, &not_system),
            Decision::Skip(Skip::PreviousIsSshBroker),
            "{own}"
        );
    }

    let none = SshdShell {
        shell: None,
        command_option: Some("-x".into()),
        arguments: None,
        escape_arguments: false,
    };
    assert_eq!(
        decide(&none, false, &exists, &not_system),
        Decision::Skip(Skip::NoPreviousShell)
    );

    assert_eq!(
        decide(&sshd(PWSH7), true, &exists, &not_system),
        Decision::Skip(Skip::FileExists)
    );
    assert_eq!(
        decide(&sshd(PWSH7), false, &missing, &not_system),
        Decision::Skip(Skip::PreviousMissing)
    );
    match decide(&sshd(PWSH7), false, &exists, &not_system) {
        Decision::Write(block) => assert_eq!(block.start, [PWSH7]),
        other => panic!("{other:?}"),
    }
    // The identity of the shell decides which defaults it is compared with.
    let system_cmd = |p: &Path| p == Path::new(r"C:\Windows\System32\cmd.exe");
    match decide(&sshd(r"C:\Windows\System32\cmd.exe"), false, &exists, &system_cmd) {
        Decision::Write(block) => assert_eq!((block.with_command, block.escaping), (None, None)),
        other => panic!("{other:?}"),
    }
}

// the written file =====

#[test]
fn the_written_yaml_parses_back_to_the_carried_block() {
    let mut blocks = Vec::new();
    for shell in [
        PWSH7,
        r"C:\Program Files (x86)\My Shell\sh.exe",
        r#"C:\a "quoted" dir\sh.exe"#,
        "C:\\Users\\Ünï cödé\\sh.exe",
    ] {
        let mut prev = sshd(shell);
        prev.command_option = Some("-Command".into());
        prev.arguments = Some(r#"-NoLogo -File "C:\a b\x.ps1""#.into());
        prev.escape_arguments = false;
        blocks.push(carried(&prev));
        blocks.push(carried(&sshd(shell)));
    }
    for block in blocks {
        let text = render(&block).unwrap();
        assert_eq!(parse(text.as_bytes()).unwrap(), Some(block), "{text}");
    }
}

// create_once =====

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> TempDir {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("sb-sysconfig-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn create_once_never_replaces_an_existing_file_and_leaves_no_partial_file() {
    let dir = TempDir::new("once");
    let target = dir.0.join("config.yaml");
    let first = ShellBlock {
        start: vec!["a.exe".into()],
        ..ShellBlock::default()
    };
    let second = ShellBlock {
        start: vec!["b.exe".into()],
        ..ShellBlock::default()
    };

    assert!(create_once_at(&target, &first).unwrap());
    let written = std::fs::read(&target).unwrap();
    assert_eq!(parse(&written).unwrap(), Some(first));
    assert_eq!(names(&dir.0), ["config.yaml"], "no temp file is left");

    assert!(!create_once_at(&target, &second).unwrap(), "a file was there");
    assert_eq!(std::fs::read(&target).unwrap(), written, "the file is untouched");
    assert_eq!(names(&dir.0), ["config.yaml"]);
}

#[test]
fn create_once_leaves_a_file_with_other_content_alone() {
    let dir = TempDir::new("other");
    let target = dir.0.join("config.yaml");
    std::fs::write(&target, "# mine\nshell: pwsh.exe\n").unwrap();
    let block = ShellBlock {
        start: vec!["b.exe".into()],
        ..ShellBlock::default()
    };
    assert!(!create_once_at(&target, &block).unwrap());
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "# mine\nshell: pwsh.exe\n");
}

#[test]
fn a_failure_before_the_move_leaves_the_target_absent_and_says_so() {
    let dir = TempDir::new("fail");
    let target = dir.0.join("config.yaml");
    // The temp name is taken by a directory, so the file cannot be written.
    std::fs::create_dir_all(dir.0.join(format!("config.yaml.tmp-{}", std::process::id()))).unwrap();
    let block = ShellBlock {
        start: vec!["b.exe".into()],
        ..ShellBlock::default()
    };
    assert!(create_once_at(&target, &block).is_err());
    assert!(!target.exists());
}

#[test]
fn a_directory_in_the_way_is_not_replaced() {
    let dir = TempDir::new("dir");
    let target = dir.0.join("config.yaml");
    std::fs::create_dir_all(&target).unwrap();
    let block = ShellBlock {
        start: vec!["b.exe".into()],
        ..ShellBlock::default()
    };
    assert!(!create_once_at(&target, &block).unwrap());
    assert!(target.is_dir());
    assert_eq!(names(&dir.0), ["config.yaml"]);
}
