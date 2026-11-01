//! Host tests for what `apply` carries from the previous sshd shell into the system config (pure;
//! runs on any platform, no registry).

use std::path::{Path, PathBuf};

use super::{
    ArgumentsPlan, ConfigKind, CreateOutcome, Decision, Skip, SshdClass, arguments_left, arguments_not_removed,
    arguments_removed, arguments_removing, arguments_unreadable, carried_block, classify, config_is_file,
    create_once_at, decide, image_dir, not_written, nothing_to_carry, plan_arguments, remove_temp, render, skip_notice,
    sshd_search_dirs,
};
use crate::provision::registry::SshdShell;
use crate::shell::Escaping;
use crate::shell::config::{ShellBlock, parse};
use crate::shell::test_host::TestHost;
use crate::test_support::states_facts_only;

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

    // Empty and blank values: no arguments, and an option of no words is carried as no words, as sshd pastes nothing.
    for blank in ["", "   "] {
        let mut prev = sshd(TOOLS_PWSH);
        prev.command_option = Some(blank.into());
        prev.arguments = Some(blank.into());
        let block = carried(&prev);
        assert_eq!(block.without_command, None, "{blank:?}");
        assert_eq!(block.with_command, Some(vec![]), "{blank:?}");
    }
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

// not_written =====

/// `apply` replaces `DefaultShell` even when it cannot write the config, so the message holds every
/// value of the shell it replaces.
#[test]
fn the_message_for_a_config_that_could_not_be_written_holds_every_carried_value() {
    let prev = SshdShell {
        shell: Some(PWSH7.into()),
        command_option: Some("-NoLogo -c".into()),
        arguments: Some("-NoProfile".into()),
        escape_arguments: false,
    };
    let text = not_written(
        Path::new(r"C:\ProgramData\ssh-broker\config.yaml"),
        &prev,
        "Access is denied.",
    );
    for part in [
        r"C:\ProgramData\ssh-broker\config.yaml",
        "Access is denied.",
        PWSH7,
        "-NoLogo -c",
        "-NoProfile",
        "escape arguments = no",
    ] {
        assert!(text.contains(part), "{part}: {text}");
    }
    assert!(!text.contains("escape arguments = yes"), "{text}");
    states_facts_only(&text);

    // Values sshd does not have are said so, not left out.
    let text = not_written(Path::new("c.yaml"), &sshd(PWSH7), "x");
    assert!(
        text.contains("DefaultShellCommandOption") && text.contains("DefaultShellArguments"),
        "{text}"
    );
    assert!(text.contains("not set"), "{text}");
    assert!(text.contains("escape arguments = yes"), "{text}");
}

// decide =====

#[test]
fn decide_table() {
    let exists = |_: &[PathBuf], p: &Path| Ok(p.to_path_buf());
    let missing = |_: &[PathBuf], _: &Path| Err("there is no such file".to_string());
    let not_system = |_: &Path| false;
    let dirs = || Ok(Vec::<PathBuf>::new());

    for own in [
        r"C:\ProgramData\ssh-broker\ssh-broker.exe",
        r"D:\other\SSH-Broker.EXE",
        "c:/x/ssh-broker.exe",
        "ssh-broker.exe",
        // sshd runs these as ssh-broker.exe: `CreateProcess` appends `.exe` to a name with no extension.
        r"C:\ProgramData\ssh-broker\ssh-broker",
        "c:/x/SSH-Broker",
        "ssh-broker",
    ] {
        assert_eq!(
            decide(&sshd(own), Ok(ConfigKind::Missing), &dirs, &exists, &not_system),
            Decision::Skip(Skip::NothingToCarry),
            "{own}"
        );
    }
    // A name with another extension is another file.
    for other in [
        r"C:\x\ssh-broker.cmd",
        r"C:\x\ssh-broker.bak",
        r"C:\x\ssh-broker.exe.bak",
    ] {
        assert_ne!(
            decide(&sshd(other), Ok(ConfigKind::Missing), &dirs, &exists, &not_system),
            Decision::Skip(Skip::NothingToCarry),
            "{other}"
        );
    }

    let none = SshdShell {
        shell: None,
        command_option: Some("-x".into()),
        arguments: None,
        escape_arguments: false,
    };
    assert_eq!(
        decide(&none, Ok(ConfigKind::Missing), &dirs, &exists, &not_system),
        Decision::Skip(Skip::NothingToCarry)
    );

    assert_eq!(
        decide(&sshd(PWSH7), Ok(ConfigKind::File), &dirs, &exists, &not_system),
        Decision::Skip(Skip::FileExists)
    );
    assert_eq!(
        decide(&sshd(PWSH7), Ok(ConfigKind::Missing), &dirs, &missing, &not_system),
        Decision::Skip(Skip::PreviousMissing("there is no such file".into()))
    );
    match decide(&sshd(PWSH7), Ok(ConfigKind::Missing), &dirs, &exists, &not_system) {
        Decision::Write(block) => assert_eq!(block.start, [PWSH7]),
        other => panic!("{other:?}"),
    }
    // The identity of the shell decides which defaults it is compared with.
    let system_cmd = |p: &Path| p == Path::new(r"C:\Windows\System32\cmd.exe");
    match decide(
        &sshd(r"C:\Windows\System32\cmd.exe"),
        Ok(ConfigKind::Missing),
        &dirs,
        &exists,
        &system_cmd,
    ) {
        Decision::Write(block) => assert_eq!((block.with_command, block.escaping), (None, None)),
        other => panic!("{other:?}"),
    }
}

/// What `apply` could not find out is not a reason to say nothing: the config that may or may not be
/// there, or the directories to look for the shell in, make the shell not carried, and the decision
/// says so. A shell that is replaced by nothing, or a config that is there anyway, does not wait on them.
#[test]
fn decide_reports_what_it_could_not_find_out_unless_nothing_depends_on_it() {
    let exists = |_: &[PathBuf], p: &Path| Ok(p.to_path_buf());
    let not_system = |_: &Path| false;
    let no_dirs = || Err::<Vec<PathBuf>, String>("no system directory".into());
    let no_config: Result<ConfigKind, String> = Err("cannot tell whether c.yaml exists".into());

    assert_eq!(
        decide(&sshd(PWSH7), no_config.clone(), &|| Ok(vec![]), &exists, &not_system),
        Decision::Skip(Skip::Unchecked("cannot tell whether c.yaml exists".into()))
    );
    assert_eq!(
        decide(&sshd(PWSH7), Ok(ConfigKind::Missing), &no_dirs, &exists, &not_system),
        Decision::Skip(Skip::Unchecked("no system directory".into()))
    );
    // A config that is there decides first; and with no previous shell, or ssh-broker's own, nothing is replaced.
    assert_eq!(
        decide(&sshd(PWSH7), Ok(ConfigKind::File), &no_dirs, &exists, &not_system),
        Decision::Skip(Skip::FileExists)
    );
    assert_eq!(
        decide(
            &sshd(r"C:\x\ssh-broker.exe"),
            no_config.clone(),
            &no_dirs,
            &exists,
            &not_system
        ),
        Decision::Skip(Skip::NothingToCarry)
    );
    let none = SshdShell {
        shell: None,
        command_option: None,
        arguments: None,
        escape_arguments: true,
    };
    assert_eq!(
        decide(&none, no_config, &no_dirs, &exists, &not_system),
        Decision::Skip(Skip::NothingToCarry)
    );
}

/// A directory (or anything not a file) at the config path cannot hold the config: the decision says so,
/// without trying to write it or looking for the shell.
#[test]
fn decide_skips_a_config_path_that_is_not_a_file() {
    let never_dirs = || -> Result<Vec<PathBuf>, String> { panic!("looked for the directories") };
    let never_find = |_: &[PathBuf], _: &Path| -> Result<PathBuf, String> { panic!("looked for the shell") };
    assert_eq!(
        decide(&sshd(PWSH7), Ok(ConfigKind::Other), &never_dirs, &never_find, &|_| {
            false
        }),
        Decision::Skip(Skip::NotAFile)
    );
    // With nothing to carry, nothing is said about the path.
    assert_eq!(
        decide(
            &sshd(r"C:\x\ssh-broker.exe"),
            Ok(ConfigKind::Other),
            &never_dirs,
            &never_find,
            &|_| false
        ),
        Decision::Skip(Skip::NothingToCarry)
    );
}

/// The directories to look for the shell in are looked up only when the decision gets that far: with no
/// previous shell, ssh-broker's own, or a config that is there (or not known to be), finding them, and
/// saying that it failed, would be noise about something that does not matter.
#[test]
fn decide_looks_up_the_directories_only_when_it_needs_them() {
    let calls = std::cell::Cell::new(0);
    let dirs = || {
        calls.set(calls.get() + 1);
        Ok(Vec::<PathBuf>::new())
    };
    let exists = |_: &[PathBuf], p: &Path| Ok(p.to_path_buf());
    let none = SshdShell {
        shell: None,
        command_option: None,
        arguments: None,
        escape_arguments: false,
    };
    decide(&none, Ok(ConfigKind::Missing), &dirs, &exists, &|_| false);
    decide(
        &sshd(r"C:\x\ssh-broker.exe"),
        Ok(ConfigKind::Missing),
        &dirs,
        &exists,
        &|_| false,
    );
    decide(&sshd(PWSH7), Ok(ConfigKind::File), &dirs, &exists, &|_| false);
    decide(&sshd(PWSH7), Err("cannot tell".into()), &dirs, &exists, &|_| false);
    assert_eq!(
        calls.get(),
        0,
        "looked the directories up for a decision that does not use them"
    );
    decide(&sshd(PWSH7), Ok(ConfigKind::Missing), &dirs, &exists, &|_| false);
    assert_eq!(calls.get(), 1);
}

/// A bare `DefaultShell` is found where sshd found it, which a session (it searches `PATH` only)
/// may not: the config names the file that was found, so it starts the shell sshd started. The
/// carried options are still judged by the name sshd was given.
#[test]
fn a_bare_shell_is_carried_as_the_file_sshd_found() {
    let found = |_: &[PathBuf], _: &Path| Ok(PathBuf::from(r"C:\Program Files\OpenSSH\powershell7.exe"));
    let mut prev = sshd("powershell7");
    prev.command_option = Some("-Command".into());
    match decide(&prev, Ok(ConfigKind::Missing), &|| Ok(vec![]), &found, &|_| false) {
        Decision::Write(block) => {
            assert_eq!(block.start, [r"C:\Program Files\OpenSSH\powershell7.exe"]);
            assert_eq!(block.with_command, Some(vec!["-Command".to_string()]));
        }
        other => panic!("{other:?}"),
    }
    // A path is carried as written.
    match decide(
        &sshd(r"C:\x\pwsh"),
        Ok(ConfigKind::Missing),
        &|| Ok(vec![]),
        &found,
        &|_| false,
    ) {
        Decision::Write(block) => assert_eq!(block.start, [r"C:\x\pwsh"]),
        other => panic!("{other:?}"),
    }
}

// the previous shell is missing =====

/// `apply` replaces `DefaultShell` whenever it does not carry the shell, so each way of not carrying it
/// says so with every value of the shell it replaces, as the message for a config it cannot write does.
/// Nothing is said when nothing is replaced.
#[test]
fn every_skip_that_replaces_a_shell_without_carrying_it_holds_every_previous_value() {
    let prev = SshdShell {
        shell: Some(PWSH7.into()),
        command_option: Some("-NoLogo -c".into()),
        arguments: Some("-NoProfile".into()),
        escape_arguments: false,
    };
    let config = Path::new(r"C:\ProgramData\ssh-broker\config.yaml");
    for (skip, cause) in [
        (Skip::FileExists, "config.yaml exists"),
        (Skip::NotAFile, "config.yaml is not a file"),
        (
            Skip::PreviousMissing("there is no such file".into()),
            "there is no such file",
        ),
        (
            Skip::Unchecked("cannot tell whether the config exists".into()),
            "cannot tell whether the config exists",
        ),
    ] {
        let text = skip_notice(config, &prev, &skip);
        for part in [
            r"C:\ProgramData\ssh-broker\config.yaml",
            cause,
            PWSH7,
            "-NoLogo -c",
            "-NoProfile",
            "escape arguments = no",
            "DefaultShellCommandOption",
            "DefaultShellArguments",
            "apply replaces DefaultShell next",
        ] {
            assert!(text.contains(part), "{skip:?}: {part}: {text}");
        }
        // An earlier `apply` may have carried the shell into the config that is there: the notice says
        // what this `apply` does, not that the shell is nowhere.
        assert!(!text.contains("is not carried"), "{skip:?}: {text}");
        assert!(!text.contains("escape arguments = yes"), "{skip:?}: {text}");
        states_facts_only(&text);
        // It is printed before the flip, which can still fail.
        for past in ["replaced", "changed", "restored", "is now", "has been"] {
            assert!(!text.contains(past), "{skip:?}: {past}: {text}");
        }
    }
}

/// A config path that holds a directory is said to hold no file: "exists" and "never rewritten" say
/// something else.
#[test]
fn the_notice_for_a_config_path_that_is_not_a_file_says_so() {
    let text = skip_notice(Path::new(CONFIG), &sshd(PWSH7), &Skip::NotAFile);
    assert!(text.contains(&format!("{CONFIG} is not a file")), "{text}");
    for part in ["never rewritten", "already there", "exists"] {
        assert!(!text.contains(part), "{part}: {text}");
    }
    let text = skip_notice(Path::new(CONFIG), &sshd(PWSH7), &Skip::FileExists);
    assert!(text.contains(&format!("{CONFIG} exists")), "{text}");
    assert!(!text.contains("is not a file"), "{text}");
}

/// A shell that is set and not ssh-broker's has something to carry: a skip that claims otherwise is wrong,
/// and the notice still holds every value.
#[test]
fn a_nothing_to_carry_skip_for_a_shell_that_has_something_to_carry_prints_the_values() {
    let prev = sshd(PWSH7);
    let text = skip_notice(Path::new(CONFIG), &prev, &Skip::NothingToCarry);
    assert!(text.contains(PWSH7) && text.contains("DefaultShellArguments"), "{text}");
    states_facts_only(&text);
}

#[test]
fn nothing_to_carry_is_no_shell_or_ssh_broker_itself() {
    let none = SshdShell {
        shell: None,
        ..sshd(PWSH7)
    };
    assert!(nothing_to_carry(&none));
    for own in [r"C:\ProgramData\ssh-broker\ssh-broker.exe", "ssh-broker"] {
        assert!(nothing_to_carry(&sshd(own)), "{own}");
    }
    assert!(!nothing_to_carry(&sshd(PWSH7)));
}

// sshd's search =====

const SSHD_IMAGE: &str = r"C:\Program Files\OpenSSH\sshd.exe";

#[test]
fn the_image_directory_is_read_from_a_service_image_path_in_any_form() {
    for (image, dir) in [
        (SSHD_IMAGE, Some(r"C:\Program Files\OpenSSH")),
        (
            r#""C:\Program Files\OpenSSH\sshd.exe""#,
            Some(r"C:\Program Files\OpenSSH"),
        ),
        (
            r#""C:\Program Files\OpenSSH\sshd.exe" -f "C:\x y\sshd_config""#,
            Some(r"C:\Program Files\OpenSSH"),
        ),
        (
            r"C:\Program Files\OpenSSH\SSHD.EXE -d",
            Some(r"C:\Program Files\OpenSSH"),
        ),
        (
            r"C:\Windows\System32\OpenSSH\sshd.exe",
            Some(r"C:\Windows\System32\OpenSSH"),
        ),
        (r"D:/ssh/sshd.exe", Some("D:/ssh")),
        ("sshd.exe", None),
        ("", None),
        ("  ", None),
    ] {
        assert_eq!(image_dir(image), dir.map(PathBuf::from), "{image:?}");
    }
}

/// The directories `CreateProcess` looks in before `PATH`, in its order: the program's own
/// directory, then the working directory (a service's is the system directory), the system
/// directory and the Windows directory.
#[test]
fn sshd_searches_its_own_directory_the_system_directory_and_the_windows_directory_first() {
    let host = TestHost::new();
    assert_eq!(
        sshd_search_dirs(&host, Some(SSHD_IMAGE)).unwrap(),
        [
            PathBuf::from(r"C:\Program Files\OpenSSH"),
            PathBuf::from(r"C:\Windows\System32"),
            PathBuf::from(r"C:\Windows"),
        ]
    );
    assert_eq!(
        sshd_search_dirs(&host, None).unwrap(),
        [PathBuf::from(r"C:\Windows\System32"), PathBuf::from(r"C:\Windows")]
    );
    let mut host = TestHost::new();
    host.no_system_dir = true;
    assert!(sshd_search_dirs(&host, Some(SSHD_IMAGE)).is_err());
}

#[test]
fn a_bare_shell_is_found_in_sshds_order() {
    use crate::shell::resolve_program_in;
    let host = TestHost::new()
        .with_file(r"C:\Program Files\OpenSSH\only-sshd.exe", "MZ")
        .with_file(r"C:\Windows\System32\only-system.exe", "MZ")
        .with_file(r"C:\Windows\only-windows.exe", "MZ")
        .with_program("only-path", r"C:\tools\only-path.exe")
        .with_file(r"C:\Program Files\OpenSSH\both.exe", "MZ")
        .with_program("both", r"C:\tools\both.exe")
        .with_file(r"C:\Windows\System32\sys-and-win.exe", "MZ")
        .with_file(r"C:\Windows\sys-and-win.exe", "MZ");
    let dirs = sshd_search_dirs(&host, Some(SSHD_IMAGE)).unwrap();
    for (name, want) in [
        ("only-sshd", r"C:\Program Files\OpenSSH\only-sshd.exe"),
        ("only-system.exe", r"C:\Windows\System32\only-system.exe"),
        ("only-windows", r"C:\Windows\only-windows.exe"),
        ("only-path", r"C:\tools\only-path.exe"),
        ("both", r"C:\Program Files\OpenSSH\both.exe"),
        ("sys-and-win", r"C:\Windows\System32\sys-and-win.exe"),
    ] {
        assert_eq!(
            resolve_program_in(&host, &dirs, name),
            Ok(PathBuf::from(want)),
            "{name}"
        );
    }
    assert!(resolve_program_in(&host, &dirs, "nonesuch").is_err());
    // A search of PATH alone, as a session does, does not find what only sshd's directory holds.
    assert!(crate::shell::resolve_program(&host, "only-sshd").is_err());
}

// the written file =====

#[test]
fn the_written_yaml_parses_back_to_the_carried_block() {
    let mut blocks = Vec::new();
    for shell in [
        PWSH7,
        r"C:\Program Files (x86)\My Shell\sh.exe",
        r#"C:\a "quoted" dir\sh.exe"#,
        "D:\\Profiles\\Ünï cödé\\sh.exe",
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

    assert_eq!(create_once_at(&target, &first).unwrap(), CreateOutcome::Created);
    let written = std::fs::read(&target).unwrap();
    assert_eq!(parse(&written).unwrap(), Some(first));
    assert_eq!(names(&dir.0), ["config.yaml"], "no temp file is left");

    assert_eq!(
        create_once_at(&target, &second).unwrap(),
        CreateOutcome::FileExists,
        "a file was there"
    );
    assert_eq!(std::fs::read(&target).unwrap(), written, "the file is untouched");
    assert_eq!(names(&dir.0), ["config.yaml"]);
}

/// A temp file that cannot be removed stays in the install directory; the log says which and why.
#[test]
fn a_temp_file_that_cannot_be_removed_is_logged_and_one_that_is_gone_is_not() {
    use std::os::windows::fs::OpenOptionsExt;
    let dir = TempDir::new("temp-removal");
    let temp = dir.0.join("config.yaml.tmp-1");
    std::fs::write(&temp, "x").unwrap();
    // Opened without FILE_SHARE_DELETE, so the removal is refused while it is held.
    let held = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(&temp)
        .unwrap();
    let (log, ()) = crate::test_support::logged(|| remove_temp(&temp));
    assert!(log.contains("WARN") && log.contains("config.yaml.tmp-1"), "{log}");
    drop(held);
    assert!(temp.exists());

    let (log, ()) = crate::test_support::logged(|| remove_temp(&temp));
    assert_eq!(log, "");
    assert!(!temp.exists());
    let (log, ()) = crate::test_support::logged(|| remove_temp(&temp));
    assert_eq!(log, "", "a file that is not there is removed already");
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
    assert_eq!(create_once_at(&target, &block).unwrap(), CreateOutcome::FileExists);
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
    assert_eq!(create_once_at(&target, &block).unwrap(), CreateOutcome::NotAFile);
    assert!(target.is_dir());
    assert_eq!(names(&dir.0), ["config.yaml"]);
}

#[test]
fn a_command_option_with_several_words_is_split_like_the_arguments() {
    let with = |shell: &str, system_cmd: bool, option: &str| {
        let mut prev = sshd(shell);
        prev.command_option = Some(option.into());
        carried_block(&prev, system_cmd).with_command
    };
    assert_eq!(
        with(r"C:\Windows\System32\cmd.exe", true, "/d /c"),
        Some(vec!["/d".into(), "/c".into()])
    );
    assert_eq!(
        with(TOOLS_PWSH, false, "-NoProfile -Command"),
        Some(vec!["-NoProfile".into(), "-Command".into()])
    );
    assert_eq!(
        with(TOOLS_PWSH, false, r#"-File "C:\my dir\run.ps1" -c"#),
        Some(vec!["-File".into(), r"C:\my dir\run.ps1".into(), "-c".into()])
    );
    // The default option is still not written.
    assert_eq!(with(TOOLS_PWSH, false, "-c"), None);
}

// the texts printed after the flip =====

/// `apply` prints these once `DefaultShell` is ssh-broker, so none says the shell is unchanged or is
/// still to be replaced.
fn after_the_flip(text: &str) {
    for before in [
        "unchanged",
        "not changed",
        "not replaced",
        "replaces DefaultShell",
        "about to",
    ] {
        assert!(!text.contains(before), "{before}: {text}");
    }
}

const CONFIG: &str = r"C:\ProgramData\ssh-broker\config.yaml";
const KEY: &str = r"SOFTWARE\OpenSSH";

#[test]
fn the_arguments_left_text_names_the_value_the_key_and_why() {
    let text = arguments_left(KEY, "\"-NoLogo\"", "there is no config");
    assert_eq!(
        text,
        r#"apply: left DefaultShellArguments ("-NoLogo") under HKLM\SOFTWARE\OpenSSH: there is no config"#
    );
    states_facts_only(&text);
    after_the_flip(&text);
}

#[test]
fn the_arguments_unreadable_text_names_the_key_and_the_cause() {
    let text = arguments_unreadable(KEY, "i/o error");
    assert_eq!(
        text,
        r"apply: left DefaultShellArguments under HKLM\SOFTWARE\OpenSSH: it could not be read (i/o error)"
    );
    states_facts_only(&text);
    after_the_flip(&text);
}

#[test]
fn the_arguments_removing_text_names_the_value_and_the_key() {
    let text = arguments_removing(KEY, "\"-NoLogo\"");
    assert_eq!(
        text,
        r#"apply: removing DefaultShellArguments ("-NoLogo") from HKLM\SOFTWARE\OpenSSH"#
    );
    states_facts_only(&text);
}

#[test]
fn the_arguments_removed_text_names_the_value_and_the_key() {
    let text = arguments_removed(KEY, "\"-NoLogo\"");
    assert_eq!(
        text,
        r#"apply: removed DefaultShellArguments ("-NoLogo") from HKLM\SOFTWARE\OpenSSH"#
    );
    states_facts_only(&text);
    after_the_flip(&text);
}

#[test]
fn the_arguments_not_removed_text_names_the_value_the_key_and_the_cause() {
    let text = arguments_not_removed(KEY, "\"-NoLogo\"", "access denied");
    assert_eq!(
        text,
        r#"apply: could not remove DefaultShellArguments ("-NoLogo") from HKLM\SOFTWARE\OpenSSH: access denied"#
    );
    states_facts_only(&text);
    after_the_flip(&text);
}

// the DefaultShellArguments left or removed after the flip =====

const NO_LONGER_THERE: &str = "there is no";

fn plan(arguments: Result<Option<&str>, &str>, config: Result<ConfigKind, &str>) -> ArgumentsPlan {
    plan_arguments(
        Path::new(CONFIG),
        KEY,
        arguments.map(|a| a.map(str::to_owned)).map_err(str::to_owned),
        || config.map_err(str::to_owned),
    )
}

#[test]
fn no_arguments_to_pass_on_is_nothing_to_do_and_the_config_is_not_looked_at() {
    let plan = plan_arguments(Path::new(CONFIG), KEY, Ok(None), || panic!("the config is not needed"));
    assert_eq!(plan, ArgumentsPlan::Nothing);
}

#[test]
fn arguments_that_are_read_and_have_a_config_to_go_to_are_removed_with_the_value_shown() {
    assert_eq!(
        plan(Ok(Some("-NoLogo")), Ok(ConfigKind::File)),
        ArgumentsPlan::Remove("\"-NoLogo\"".to_owned())
    );
}

/// A value that could not be read is neither carried nor shown, so it is never deleted: whatever the config
/// is, it is left, and the text gives the cause.
#[test]
fn arguments_that_could_not_be_read_are_never_removed_and_the_cause_is_said() {
    for config in [
        Ok(ConfigKind::File),
        Ok(ConfigKind::Missing),
        Ok(ConfigKind::Other),
        Err("cannot tell"),
    ] {
        let ArgumentsPlan::Leave(text) = plan(Err("i/o error"), config) else {
            panic!("{config:?}: removed or ignored a value it could not read");
        };
        for part in ["left DefaultShellArguments", "could not be read", "i/o error", KEY] {
            assert!(text.contains(part), "{config:?}: {part}: {text}");
        }
        // It cannot say what sshd does with a value nobody could read.
        assert!(!text.contains("passes"), "{config:?}: {text}");
        states_facts_only(&text);
        after_the_flip(&text);
    }
}

#[test]
fn arguments_with_no_config_are_left_and_the_text_says_there_is_none() {
    let ArgumentsPlan::Leave(text) = plan(Ok(Some("-NoLogo")), Ok(ConfigKind::Missing)) else {
        panic!("removed a value with no config to hold it");
    };
    for part in ["-NoLogo", CONFIG, NO_LONGER_THERE] {
        assert!(text.contains(part), "{part}: {text}");
    }
    assert!(!text.contains("is not a file"), "{text}");
    states_facts_only(&text);
}

/// Something else is at the path (a directory): the text does not say there is nothing there.
#[test]
fn arguments_with_something_that_is_not_a_file_at_the_config_path_are_left_and_the_text_says_so() {
    let ArgumentsPlan::Leave(text) = plan(Ok(Some("-NoLogo")), Ok(ConfigKind::Other)) else {
        panic!("removed a value although the config path holds no file");
    };
    for part in ["-NoLogo", &format!("{CONFIG} is not a file")] {
        assert!(text.contains(part), "{part}: {text}");
    }
    assert!(!text.contains(NO_LONGER_THERE), "{text}");
    states_facts_only(&text);
}

/// A check that failed does not know the config is absent: the value is left and the text says it cannot
/// tell, with the cause, not that there is no config.
#[test]
fn arguments_with_a_config_that_could_not_be_checked_are_left_and_the_text_says_it_cannot_tell() {
    let ArgumentsPlan::Leave(text) = plan(
        Ok(Some("-NoLogo")),
        Err("cannot tell whether the config exists: i/o error"),
    ) else {
        panic!("removed a value although the config could not be checked");
    };
    for part in ["-NoLogo", "cannot tell whether the config exists: i/o error"] {
        assert!(text.contains(part), "{part}: {text}");
    }
    assert!(!text.contains(NO_LONGER_THERE), "{text}");
    states_facts_only(&text);
}

// config_is_file -----

#[test]
fn a_config_that_is_a_file_is_known_to_be_one_and_one_that_is_not_there_is_known_to_be_absent() {
    let dir = TempDir::new("is_file");
    let config = dir.0.join("config.yaml");
    assert_eq!(config_is_file(&config), Ok(ConfigKind::Missing));
    std::fs::write(&config, "").unwrap();
    assert_eq!(config_is_file(&config), Ok(ConfigKind::File));
}

/// A directory at the path holds no config, and is not "absent" either: the loader cannot read it, so nothing
/// is carried into it, and the notice must not say there is nothing there.
#[test]
fn a_directory_at_the_config_path_is_not_a_config() {
    let dir = TempDir::new("is_file_dir");
    let config = dir.0.join("config.yaml");
    std::fs::create_dir(&config).unwrap();
    assert_eq!(config_is_file(&config), Ok(ConfigKind::Other));
}

/// A path the file system cannot answer for is an error that is not "absent": a NUL in the name is refused
/// by the OS on every platform.
#[test]
fn a_config_that_cannot_be_checked_says_it_cannot_tell() {
    let cause = config_is_file(Path::new("config\0.yaml")).unwrap_err();
    assert!(cause.starts_with("cannot tell whether config"), "{cause}");
    assert!(cause.contains(" is a file: "), "{cause}");
}

// a link at the config path -----

/// A config path that is a symlink to a file that is not there. Needs symlink creation rights (an
/// elevated administrator or Developer Mode).
fn dangling_config(tag: &str) -> (TempDir, PathBuf) {
    let dir = TempDir::new(tag);
    let config = dir.0.join("config.yaml");
    std::os::windows::fs::symlink_file(dir.0.join("gone.yaml"), &config)
        .expect("create a file symlink: needs an elevated administrator or Developer Mode");
    (dir, config)
}

/// The name exists and the target does not: the name is taken, so nothing can be written there, and no
/// config is in it.
#[test]
fn a_dangling_link_at_the_config_path_is_not_a_config() {
    let (_dir, config) = dangling_config("link-dangling");
    assert_eq!(config_is_file(&config), Ok(ConfigKind::Other));
}

#[test]
fn a_link_to_a_file_at_the_config_path_is_a_config() {
    let dir = TempDir::new("link-file");
    let (target, config) = (dir.0.join("real.yaml"), dir.0.join("config.yaml"));
    std::fs::write(&target, "").unwrap();
    std::os::windows::fs::symlink_file(&target, &config)
        .expect("create a file symlink: needs an elevated administrator or Developer Mode");
    assert_eq!(config_is_file(&config), Ok(ConfigKind::File));
}

#[test]
fn create_once_over_a_dangling_link_says_the_path_is_not_a_file_and_writes_nothing() {
    let (dir, config) = dangling_config("link-create");
    let block = ShellBlock {
        start: vec!["b.exe".into()],
        ..ShellBlock::default()
    };
    assert_eq!(create_once_at(&config, &block).unwrap(), CreateOutcome::NotAFile);
    assert_eq!(names(&dir.0), ["config.yaml"], "no temp file is left");
    assert!(!dir.0.join("gone.yaml").exists());
}

/// One run asks the question once per use, and every answer is the same: for a dangling link the decision
/// and the arguments plan both say the path is not a file, and neither says a config exists or is absent.
#[test]
fn one_run_over_a_dangling_link_says_the_path_is_not_a_file_everywhere() {
    let (_dir, config) = dangling_config("link-run");
    let kind = || config_is_file(&config);
    let skip = match decide(
        &sshd(PWSH7),
        kind(),
        &|| Ok(vec![]),
        &|_, p| Ok(p.to_path_buf()),
        &|_| false,
    ) {
        Decision::Skip(skip) => skip,
        other => panic!("{other:?}"),
    };
    assert_eq!(skip, Skip::NotAFile);
    let notice = skip_notice(&config, &sshd(PWSH7), &skip);
    let ArgumentsPlan::Leave(left) = plan_arguments(&config, KEY, Ok(Some("-NoLogo".into())), kind) else {
        panic!("removed a value although the config path holds no file");
    };
    for text in [&notice, &left] {
        assert!(text.contains(&format!("{} is not a file", config.display())), "{text}");
        assert!(!text.contains("exists") && !text.contains("there is no"), "{text}");
    }
}
