//! Host tests for what `apply` carries from the previous sshd shell into the system config (pure;
//! runs on any platform, no registry).

use std::path::{Path, PathBuf};

use super::{
    Decision, Skip, SshdClass, carried_block, classify, create_once_at, decide, image_dir, not_written,
    previous_missing, remove_temp, render, sshd_search_dirs,
};
use crate::provision::registry::SshdShell;
use crate::shell::Escaping;
use crate::shell::config::{ShellBlock, parse};
use crate::shell::test_host::TestHost;

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
    let exists = |p: &Path| Ok(p.to_path_buf());
    let missing = |_: &Path| Err("there is no such file".to_string());
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
        Decision::Skip(Skip::PreviousMissing("there is no such file".into()))
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

/// A bare `DefaultShell` is found where sshd found it, which a session (it searches `PATH` only)
/// may not: the config names the file that was found, so it starts the shell sshd started. The
/// carried options are still judged by the name sshd was given.
#[test]
fn a_bare_shell_is_carried_as_the_file_sshd_found() {
    let found = |_: &Path| Ok(PathBuf::from(r"C:\Program Files\OpenSSH\powershell7.exe"));
    let mut prev = sshd("powershell7");
    prev.command_option = Some("-Command".into());
    match decide(&prev, false, &found, &|_| false) {
        Decision::Write(block) => {
            assert_eq!(block.start, [r"C:\Program Files\OpenSSH\powershell7.exe"]);
            assert_eq!(block.with_command, Some(vec!["-Command".to_string()]));
        }
        other => panic!("{other:?}"),
    }
    // A path is carried as written.
    match decide(&sshd(r"C:\x\pwsh"), false, &found, &|_| false) {
        Decision::Write(block) => assert_eq!(block.start, [r"C:\x\pwsh"]),
        other => panic!("{other:?}"),
    }
}

// the previous shell is missing =====

/// `apply` replaces `DefaultShell` all the same, so the message for a shell it cannot carry holds
/// every value of it, as the message for a config it cannot write does.
#[test]
fn the_message_for_a_previous_shell_that_is_missing_holds_every_previous_value() {
    let prev = SshdShell {
        shell: Some(PWSH7.into()),
        command_option: Some("-NoLogo -c".into()),
        arguments: Some("-NoProfile".into()),
        escape_arguments: false,
    };
    let text = previous_missing(
        Path::new(r"C:\ProgramData\ssh-broker\config.yaml"),
        &prev,
        "there is no such file",
    );
    for part in [
        r"C:\ProgramData\ssh-broker\config.yaml",
        "there is no such file",
        PWSH7,
        "-NoLogo -c",
        "-NoProfile",
        "escape arguments = no",
        "DefaultShellCommandOption",
        "DefaultShellArguments",
    ] {
        assert!(text.contains(part), "{part}: {text}");
    }
    assert!(!text.contains("escape arguments = yes"), "{text}");
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

    assert!(create_once_at(&target, &first).unwrap());
    let written = std::fs::read(&target).unwrap();
    assert_eq!(parse(&written).unwrap(), Some(first));
    assert_eq!(names(&dir.0), ["config.yaml"], "no temp file is left");

    assert!(!create_once_at(&target, &second).unwrap(), "a file was there");
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
