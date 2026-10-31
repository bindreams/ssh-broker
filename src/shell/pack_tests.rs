//! Host tests for defaults and the spawn line (pure; runs on any platform).

use std::path::PathBuf;

use super::{
    Session, Source, StartError, built_in_plan, defaults, effective, plan, render, resolve_program, resolve_program_in,
    start_or_fall_back,
};
use crate::cmdline::split_args;
use crate::shell::test_host::{SYSTEM_CMD, TestHost};
use crate::shell::{Escaping, Origin};

const PWSH: &str = r"C:\Program Files\PowerShell\7\pwsh.exe";

fn pwsh_host() -> TestHost {
    TestHost::new()
        .with_program("pwsh.exe", PWSH)
        .with_user_config("shell: pwsh.exe\n")
}

fn command(text: &str) -> Session<'_> {
    Session::Command { text, terminal: false }
}

fn line(host: &TestHost, session: &Session<'_>) -> String {
    plan(host, session).expect("a plan").command_line
}

// defaults =====

#[test]
fn the_system_cmd_gets_cmd_escaping_and_slash_c() {
    let d = defaults(true);
    assert_eq!((d.escaping, d.with_command), (Escaping::Cmd, vec!["/c".to_string()]));
    let e = effective(&TestHost::new()).unwrap();
    assert_eq!(e.escaping, Escaping::Cmd);
    assert_eq!(e.with_command, ["/c"]);
    assert!(e.without_command.is_empty());
    assert_eq!(e.program, PathBuf::from(SYSTEM_CMD));
    assert_eq!(e.origin, Origin::Default);
    assert_eq!(e.why.escaping, Source::SystemCmd);
    assert_eq!(e.why.start, Source::BuiltIn);
}

#[test]
fn any_other_program_gets_msvc_and_dash_c() {
    let d = defaults(false);
    assert_eq!((d.escaping, d.with_command), (Escaping::Msvc, vec!["-c".to_string()]));
    let e = effective(&pwsh_host()).unwrap();
    assert_eq!(
        (e.escaping, e.with_command.clone()),
        (Escaping::Msvc, vec!["-c".to_string()])
    );
    assert_eq!(e.why.escaping, Source::OtherProgram);
    assert_eq!(e.program, PathBuf::from(PWSH));
}

#[test]
fn a_copy_of_cmd_exe_and_syswow64_are_other_programs() {
    for path in [r"C:\tools\cmd.exe", r"C:\Windows\SysWOW64\cmd.exe"] {
        let host = TestHost::new()
            .with_program("cmd.exe", path)
            .with_user_config("shell: cmd.exe\n");
        let e = effective(&host).unwrap();
        assert_eq!(e.escaping, Escaping::Msvc, "{path}");
        assert_eq!(e.with_command, ["-c"], "{path}");
    }
}

#[test]
fn cmd_exe_in_any_spelling_that_is_the_same_file_is_the_system_cmd() {
    let mut host = TestHost::new()
        .with_program("cmd", r"c:\windows\system32\CMD.EXE")
        .with_user_config("shell: cmd\n");
    host.system_cmd_aliases
        .push(PathBuf::from(r"c:\windows\system32\CMD.EXE"));
    let e = effective(&host).unwrap();
    assert_eq!((e.escaping, e.with_command), (Escaping::Cmd, vec!["/c".to_string()]));
}

// effective =====

#[test]
fn explicit_append_values_override_the_defaults() {
    let host = TestHost::new()
        .with_program("pwsh.exe", PWSH)
        .with_user_config(
            "shell: {start: [pwsh.exe, -NoLogo], append: {with-command: [-Command], without-command: [-NoExit]}, escaping: cmd}\n",
        );
    let e = effective(&host).unwrap();
    assert_eq!(e.start, ["pwsh.exe", "-NoLogo"]);
    assert_eq!(e.with_command, ["-Command"]);
    assert_eq!(e.without_command, ["-NoExit"]);
    assert_eq!(e.escaping, Escaping::Cmd);
    let user = Source::User(PathBuf::from(crate::shell::test_host::USER_CONFIG));
    assert_eq!(e.why.start, user);
    assert_eq!(e.why.with_command, user);
    assert_eq!(e.why.without_command, user);
    assert_eq!(e.why.escaping, user);
}

#[test]
fn an_explicit_empty_with_command_stays_empty() {
    let host = TestHost::new()
        .with_program("pwsh.exe", PWSH)
        .with_user_config("shell: {start: pwsh.exe, append: {with-command: []}}\n");
    assert!(effective(&host).unwrap().with_command.is_empty());
    assert_eq!(line(&host, &command("echo hi")), format!(r#""{PWSH}" "echo hi""#));
}

// plan =====

#[test]
fn interactive_is_start_plus_without_command() {
    let host = TestHost::new()
        .with_program("pwsh.exe", PWSH)
        .with_user_config("shell: {start: [pwsh.exe, -NoLogo], append: {without-command: [-NoExit, \"a b\"]}}\n");
    assert_eq!(
        line(&host, &Session::Interactive),
        format!(r#""{PWSH}" -NoLogo -NoExit "a b""#)
    );
    assert_eq!(line(&TestHost::new(), &Session::Interactive), SYSTEM_CMD);
}

#[test]
fn cmd_packing_wraps_the_command_in_quotes_unescaped() {
    let host = TestHost::new();
    assert_eq!(
        line(&host, &command(r#"echo "a b""#)),
        format!(r#"{SYSTEM_CMD} /c "echo "a b"""#)
    );
    assert_eq!(line(&host, &command("whoami")), format!(r#"{SYSTEM_CMD} /c "whoami""#));
}

#[test]
fn msvc_packing_is_one_argument_in_cosca_s_quoting() {
    let host = pwsh_host();
    let got = line(&host, &command(r#"echo "a b" \"#));
    assert_eq!(split_args(&got), [PWSH, "-c", r#"echo "a b" \"#], "{got}");
    assert_eq!(got, crate::cmdline::join_args(&[PWSH, "-c", r#"echo "a b" \"#]));
}

#[test]
fn a_terminal_command_is_appended_as_is() {
    let session = Session::Command {
        text: r#"echo  "a  b" \"#,
        terminal: true,
    };
    assert_eq!(
        line(&TestHost::new(), &session),
        format!(r#"{SYSTEM_CMD} /c echo  "a  b" \"#)
    );
    assert_eq!(line(&pwsh_host(), &session), format!(r#""{PWSH}" -c echo  "a  b" \"#));
}

#[test]
fn the_program_is_one_quoted_argument() {
    let program = r"C:\Program Files (x86)\x y\pwsh.exe";
    let host = TestHost::new()
        .with_program("p", program)
        .with_user_config("shell: {start: [p, \"-Some Arg\", \"-q\"]}\n");
    let got = line(&host, &command("echo hi"));
    assert_eq!(got, format!(r#""{program}" "-Some Arg" -q -c "echo hi""#));
    assert_eq!(got.matches("Program Files (x86)").count(), 1);
    assert_eq!(split_args(&got), [program, "-Some Arg", "-q", "-c", "echo hi"]);
}

#[test]
fn a_program_given_by_absolute_path_is_used_as_is() {
    let host = TestHost::new()
        .with_program("unused", PWSH)
        .with_user_config(&format!("shell: '{PWSH}'\n"));
    assert_eq!(effective(&host).unwrap().program, PathBuf::from(PWSH));
}

/// `CreateProcess` appends `.exe` to a name without an extension, and sshd starts `DefaultShell` that
/// way, so an absolute `C:\...\pwsh` is the file `C:\...\pwsh.exe`.
#[test]
fn an_absolute_path_without_an_extension_is_the_exe_it_names() {
    let bare = r"C:\Program Files\PowerShell\7\pwsh";
    let host = TestHost::new().with_bytes(PWSH, b"MZ");
    assert_eq!(resolve_program(&host, bare), Ok(PathBuf::from(PWSH)));

    // The session's check and its line go through it.
    let host = host.with_user_config(&format!("shell: '{bare}'\n"));
    let e = effective(&host).unwrap();
    assert_eq!(e.program, PathBuf::from(PWSH));
    assert!(e.problem.is_none(), "{:?}", e.problem);
    assert_eq!(split_args(&line(&host, &command("echo hi"))), [PWSH, "-c", "echo hi"]);
}

#[test]
fn exe_is_not_appended_to_an_absolute_path_that_has_an_extension_or_a_trailing_dot() {
    let host = TestHost::new()
        .with_bytes(r"C:\x\tool.7.exe", b"MZ")
        .with_bytes(r"C:\x\tool.exe", b"MZ");
    for name in [r"C:\x\tool.7", r"C:\x\tool."] {
        assert_eq!(
            resolve_program(&host, name),
            Err("there is no such file".to_string()),
            "{name}"
        );
    }
    assert_eq!(
        resolve_program(&host, r"C:\x\nonesuch"),
        Err("there is no such file".to_string())
    );
}

#[test]
fn leading_whitespace_is_trimmed_and_trailing_kept() {
    let host = pwsh_host();
    assert_eq!(
        split_args(&line(&host, &command(" \t\r\n echo a \t "))),
        [PWSH, "-c", "echo a \t "]
    );
    assert_eq!(
        line(&TestHost::new(), &command("  echo a   ")),
        format!(r#"{SYSTEM_CMD} /c "echo a   ""#)
    );
    let terminal = Session::Command {
        text: "  echo a  ",
        terminal: true,
    };
    assert_eq!(line(&TestHost::new(), &terminal), format!("{SYSTEM_CMD} /c echo a  "));
}

#[test]
fn a_command_that_makes_the_line_too_long_is_an_error_not_a_truncation() {
    let host = pwsh_host();
    let prefix = crate::cmdline::join_args(&[PWSH, "-c", ""]).encode_utf16().count() - 2;
    // A line of exactly 32,766 units plus the NUL is the most CreateProcessW takes.
    let fits = "a".repeat(32_766 - prefix);
    let got = line(&host, &command(&fits));
    assert_eq!(got.encode_utf16().count(), 32_766);
    let too_long = "a".repeat(32_766 - prefix + 1);
    let error = plan(&host, &command(&too_long)).expect_err("too long");
    assert!(error.to_string().contains("32,767"), "{error}");
    for terminal in [false, true] {
        let session = Session::Command {
            text: &"echo ".repeat(10_000),
            terminal,
        };
        assert!(plan(&TestHost::new(), &session).is_err());
        assert!(plan(&host, &session).is_err());
    }
}

#[test]
fn a_command_with_a_nul_is_an_error_not_a_truncation() {
    assert!(plan(&pwsh_host(), &command("echo a\0b")).is_err());
}

// fallback =====

#[test]
fn an_unresolvable_program_falls_back_to_cmd_exe_with_a_problem() {
    for (value, reason) in [
        ("nonesuch.exe", "PATH"),
        (r"sub\pwsh.exe", "absolute"),
        (r"C:\no\such\pwsh.exe", "file"),
        (r"C:\Windows", "file"),
        ("C:pwsh.exe", "absolute"),
        ("", "empty"),
    ] {
        let host = TestHost::new()
            .with_entry(r"C:\Windows", crate::shell::test_host::Entry::Dir)
            .with_user_config(&format!("shell: {{start: [{value:?}]}}\n"));
        let e = effective(&host).unwrap();
        assert_eq!(e.program, PathBuf::from(SYSTEM_CMD), "{value:?}");
        assert_eq!(e.origin, Origin::Default, "{value:?}");
        let problem = e.problem.expect(value);
        assert_eq!(problem.file, PathBuf::from(crate::shell::test_host::USER_CONFIG));
        assert_eq!(problem.value.as_deref(), Some(value));
        assert!(problem.reason.contains(reason), "{value:?}: {}", problem.reason);
    }
}

#[test]
fn the_fallback_block_uses_the_built_in_defaults() {
    let host = TestHost::new().with_user_config(
        "shell: {start: [nonesuch.exe, -x], append: {with-command: [-Command], without-command: [-NoExit]}, escaping: msvc}\n",
    );
    let e = effective(&host).unwrap();
    assert_eq!(e.start, [SYSTEM_CMD]);
    assert_eq!(e.escaping, Escaping::Cmd);
    assert_eq!(e.with_command, ["/c"]);
    assert!(e.without_command.is_empty());
    assert_eq!(
        line(&host, &command("echo hi")),
        format!(r#"{SYSTEM_CMD} /c "echo hi""#)
    );
}

#[test]
fn a_broken_file_reports_its_problem_through_effective_and_plan() {
    let host = TestHost::new().with_user_config("shell: {strt: x}\n");
    let p = plan(&host, &Session::Interactive).unwrap();
    assert!(p.effective.problem.is_some());
    assert_eq!(p.command_line, SYSTEM_CMD);
}

#[test]
fn even_the_built_in_cmd_exe_missing_is_an_error() {
    let mut host = TestHost::new();
    host.entries.clear();
    assert!(effective(&host).is_err());
    assert!(plan(&host, &Session::Interactive).is_err());
}

#[test]
fn the_built_in_cmd_exe_is_the_system_cmd_even_when_the_identity_probe_fails() {
    let mut host = TestHost::new().with_user_config(
        "shell: nonesuch.exe
",
    );
    host.probe_fails = true;
    let e = effective(&host).unwrap();
    assert_eq!(
        (e.escaping, e.with_command.clone()),
        (Escaping::Cmd, vec!["/c".to_string()])
    );
    assert_eq!(
        line(&host, &command("echo hi")),
        format!(r#"{SYSTEM_CMD} /c "echo hi""#)
    );
}

// a shell that exists and cannot start =====

const OS_ERROR: &str = "%1 is not a valid Win32 application. (os error 193)";

/// A spawn that refuses `refused` and records every line it is given.
fn spawner<'a>(
    refused: &'a str,
    tried: &'a std::cell::RefCell<Vec<String>>,
) -> impl FnMut(&str) -> Result<(), StartError> + 'a {
    move |line| {
        tried.borrow_mut().push(line.to_string());
        if line.contains(refused) {
            return Err(StartError::Program(anyhow::anyhow!("{OS_ERROR}")));
        }
        Ok(())
    }
}

#[test]
fn a_shell_that_cannot_start_is_replaced_by_cmd_exe_with_a_problem_naming_the_os_error() {
    let host = pwsh_host();
    for session in [
        Session::Interactive,
        command("echo hi"),
        Session::Command {
            text: "echo hi",
            terminal: true,
        },
    ] {
        let first = plan(&host, &session).unwrap();
        let tried = std::cell::RefCell::new(Vec::new());
        let mut warned = None;
        start_or_fall_back(&host, &session, &first, spawner("pwsh.exe", &tried), |replacement| {
            // The warning comes before the replacement starts.
            assert_eq!(tried.borrow().len(), 1);
            warned = Some(replacement.clone());
        })
        .unwrap();
        let replacement = warned.expect("the built-in cmd.exe is started instead");
        assert_eq!(
            *tried.borrow(),
            [first.command_line.clone(), replacement.command_line.clone()]
        );
        assert!(
            replacement.command_line.starts_with(SYSTEM_CMD),
            "{}",
            replacement.command_line
        );
        let problem = replacement.effective.problem.as_ref().expect("a problem");
        assert_eq!(problem.file, PathBuf::from(crate::shell::test_host::USER_CONFIG));
        assert_eq!(problem.value.as_deref(), Some("pwsh.exe"));
        assert!(problem.reason.contains(OS_ERROR), "{}", problem.reason);
        let notice = replacement.notice().unwrap();
        assert!(
            notice.contains("pwsh.exe") && notice.contains("os error 193"),
            "{notice}"
        );
    }
}

/// A failure the shell did not cause (a bad working directory, no pseudoconsole) is reported as itself: the
/// shell is not blamed, and cmd.exe would meet the same failure.
#[test]
fn a_failure_the_shell_did_not_cause_is_reported_as_itself_and_not_replaced() {
    let host = pwsh_host();
    let first = plan(&host, &Session::Interactive).unwrap();
    let mut calls = 0;
    let error = start_or_fall_back(
        &host,
        &Session::Interactive,
        &first,
        |_| -> Result<(), StartError> {
            calls += 1;
            Err(StartError::Other(anyhow::anyhow!("no such working directory")))
        },
        |_| panic!("the shell was not at fault"),
    )
    .unwrap_err();
    assert_eq!(calls, 1);
    assert!(format!("{error:#}").contains("no such working directory"), "{error:#}");
}

/// The built-in shell whatever the config says, for a session whose planned shell is out of reach.
#[test]
fn the_built_in_plan_is_cmd_exe_whatever_the_config_says() {
    for host in [pwsh_host(), TestHost::new().with_user_config("shell: {strt: x}\n")] {
        let plan = built_in_plan(&host, &Session::Interactive, None).unwrap();
        assert_eq!(plan.command_line, SYSTEM_CMD);
        assert_eq!(plan.notice(), None);
        let plan = built_in_plan(&host, &command("echo hi"), None).unwrap();
        assert_eq!(plan.command_line, format!(r#"{SYSTEM_CMD} /c "echo hi""#));
    }
}

#[test]
fn a_replacement_packs_the_session_for_cmd_exe() {
    let host = pwsh_host();
    let session = command("echo hi");
    let first = plan(&host, &session).unwrap();
    let tried = std::cell::RefCell::new(Vec::new());
    start_or_fall_back(&host, &session, &first, spawner("pwsh.exe", &tried), |_| {}).unwrap();
    assert_eq!(tried.borrow()[1], format!(r#"{SYSTEM_CMD} /c "echo hi""#));
}

#[test]
fn a_shell_that_starts_is_started_once_and_nothing_warns() {
    let host = pwsh_host();
    let first = plan(&host, &Session::Interactive).unwrap();
    let tried = std::cell::RefCell::new(Vec::new());
    start_or_fall_back(&host, &Session::Interactive, &first, spawner("never", &tried), |_| {
        panic!("nothing to warn about")
    })
    .unwrap();
    assert_eq!(tried.borrow().len(), 1);
}

#[test]
fn the_built_in_cmd_exe_that_cannot_start_is_an_error_after_one_try() {
    for host in [
        TestHost::new(),
        TestHost::new().with_user_config("shell: nonesuch.exe\n"),
    ] {
        let first = plan(&host, &Session::Interactive).unwrap();
        let tried = std::cell::RefCell::new(Vec::new());
        let error = start_or_fall_back(&host, &Session::Interactive, &first, spawner("cmd.exe", &tried), |_| {
            panic!("no replacement exists")
        })
        .unwrap_err();
        assert!(format!("{error:#}").contains(OS_ERROR), "{error:#}");
        assert_eq!(tried.borrow().len(), 1, "{:?}", tried.borrow());
    }
}

#[test]
fn when_the_replacement_cannot_start_either_the_error_is_the_replacement_s() {
    let host = pwsh_host();
    let first = plan(&host, &Session::Interactive).unwrap();
    let mut calls = 0;
    let error = start_or_fall_back(
        &host,
        &Session::Interactive,
        &first,
        |_| -> Result<(), StartError> {
            calls += 1;
            Err(StartError::Program(anyhow::anyhow!("attempt {calls}")))
        },
        |_| {},
    )
    .unwrap_err();
    assert_eq!(calls, 2);
    assert!(format!("{error:#}").contains("attempt 2"), "{error:#}");
}

// the corpus =====

#[test]
fn the_command_corpus_reaches_the_shell_exactly() {
    let host = TestHost::new()
        .with_program("pwsh.exe", PWSH)
        .with_user_config("shell: {start: [pwsh.exe, -NoLogo]}\n");
    let mut failures = Vec::new();
    for text in crate::command_corpus::CORPUS {
        let want_command = crate::shim::spawn_line(text);
        let got = line(&host, &command(text));
        if split_args(&got) != [PWSH, "-NoLogo", "-c", want_command] {
            failures.push(format!("{text:?} -> {got:?}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn the_command_corpus_under_cmd_is_wrapped_and_otherwise_unchanged() {
    let host = TestHost::new();
    for text in crate::command_corpus::CORPUS {
        let want = format!(r#"{SYSTEM_CMD} /c "{}""#, crate::shim::spawn_line(text));
        assert_eq!(line(&host, &command(text)), want, "{text:?}");
    }
}

// render =====

#[test]
fn render_shows_every_value_with_its_origin() {
    // A user shell with a default `with-command`.
    let host = TestHost::new()
        .with_program("pwsh.exe", PWSH)
        .with_user_config("shell: {start: [pwsh.exe, -NoLogo], append: {without-command: [-NoExit]}}\n");
    let text = render(&effective(&host).unwrap());
    let user = format!("user: {}", crate::shell::test_host::USER_CONFIG);
    let want = format!(
        "shell:\n\
         \x20 start:  # {user}\n\
         \x20 - pwsh.exe\n\
         \x20 - -NoLogo\n\
         \x20 append:\n\
         \x20   without-command:  # {user}\n\
         \x20   - -NoExit\n\
         \x20   with-command:  # any other program\n\
         \x20   - -c\n\
         \x20 escaping: msvc  # any other program\n\
         # program: {PWSH}"
    );
    assert_eq!(text, want);

    // The built-in: the system cmd.exe and its defaults.
    let text = render(&effective(&TestHost::new()).unwrap());
    assert!(
        text.contains(&format!("start:  # built-in\n  - {SYSTEM_CMD}\n")),
        "{text}"
    );
    assert!(text.contains("escaping: cmd  # the system cmd.exe\n"), "{text}");
    assert!(
        text.contains("with-command:  # the system cmd.exe\n    - /c\n"),
        "{text}"
    );
    assert!(text.contains("without-command: []  # the system cmd.exe\n"), "{text}");
    assert!(text.ends_with(&format!("# program: {SYSTEM_CMD}")), "{text}");

    // The system layer, and a value with a space.
    let host = TestHost::new()
        .with_program("p", PWSH)
        .with_system_config("shell: {start: [p, \"a b\"]}\n");
    let text = render(&effective(&host).unwrap());
    assert!(
        text.contains(&format!(
            "start:  # system: {}\n  - p\n  - a b\n",
            crate::shell::test_host::SYSTEM_CONFIG
        )),
        "{text}"
    );
}

#[test]
fn render_shows_the_problem_and_the_fallback() {
    let host = TestHost::new().with_user_config("shell: nonesuch.exe\n");
    let text = render(&effective(&host).unwrap());
    assert!(
        text.contains("start:  # built-in\n  - C:\\Windows\\System32\\cmd.exe\n"),
        "{text}"
    );
    let warning = text.lines().last().unwrap();
    assert!(
        warning.starts_with("# warning: cannot use the shell from ")
            && warning.contains("(nonesuch.exe)")
            && warning.ends_with("using the built-in cmd.exe"),
        "{text}"
    );
}

#[test]
fn a_missing_system_directory_is_an_error_not_a_panic() {
    let mut host = TestHost::new();
    host.no_system_dir = true;
    let error = effective(&host).unwrap_err();
    assert!(format!("{error:#}").contains("GetSystemDirectoryW"), "{error:#}");
    assert!(plan(&host, &Session::Interactive).is_err());

    // A configured shell needs no system directory until it must be replaced.
    let mut host = pwsh_host();
    host.no_system_dir = true;
    assert_eq!(effective(&host).unwrap().program, PathBuf::from(PWSH));
    let first = plan(&host, &Session::Interactive).unwrap();
    let error = start_or_fall_back(
        &host,
        &Session::Interactive,
        &first,
        |_| -> Result<(), StartError> { Err(StartError::Program(anyhow::anyhow!("{OS_ERROR}"))) },
        |_| panic!("nothing to replace it with"),
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains(OS_ERROR), "{error:#}");
}

// verify's output is a config =====

/// Strings a list item can be: every one must come back from `parse` as itself.
const ITEMS: &[&str] = &[
    r"C:\Program Files\PowerShell\7\pwsh.exe",
    "C:",
    "a:",
    "-c:",
    "-c",
    "/c",
    "-NoLogo",
    "a,b",
    "{x}",
    "[y]",
    "a: b",
    "k:v",
    "#hash",
    "a #b",
    "true",
    "False",
    "null",
    "~",
    "yes",
    "123",
    "-5",
    "1e3",
    ".5",
    ".inf",
    "0x1F",
    "",
    " ",
    " lead and trail ",
    "tab\there",
    "new\nline",
    " leading space\nthen a second line",
    "carriage\rreturn",
    "del\u{7f}",
    "bell\u{7}",
    "nel\u{85}",
    "ls\u{2028}",
    "bom\u{feff}x",
    "q\"uote",
    "'single'",
    r"back\slash",
    "trail\\",
    "\u{e9}\u{65e5}\u{672c}\u{8a9e}",
    "\u{1f600}",
    "&anchor",
    "*alias",
    "!tag",
    "|pipe",
    ">fold",
    "%percent",
    "@at",
    "`tick",
    "- dash",
    "? q",
    "---",
    "...",
    "<<",
    "=",
];

fn effective_of(start: &[&str], without: &[&str], with: &[&str], escaping: Escaping) -> super::Effective {
    let owned = |items: &[&str]| items.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    super::Effective {
        program: PathBuf::from(r"C:\a #b: c\prog.exe"),
        start: owned(start),
        without_command: owned(without),
        with_command: owned(with),
        escaping,
        why: super::Why {
            start: Source::User(PathBuf::from(r"C:\Users\me\.config\ssh-broker\config.yaml")),
            without_command: Source::SystemCmd,
            with_command: Source::OtherProgram,
            escaping: Source::BuiltIn,
        },
        origin: Origin::Default,
        problem: None,
    }
}

/// What `verify` prints is a config the parser reads back as the values it shows, whatever the
/// strings are, because the YAML library renders the values and everything else is a comment.
#[test]
fn what_render_prints_parses_back_to_the_same_values() {
    let mut cases: Vec<Vec<&str>> = ITEMS.iter().map(|item| vec!["prog", *item]).collect();
    cases.push(ITEMS.to_vec());
    for items in cases {
        for escaping in [Escaping::Cmd, Escaping::Msvc] {
            let effective = effective_of(&items, &items, &items, escaping);
            let text = render(&effective);
            let parsed = crate::shell::config::parse(text.as_bytes())
                .unwrap_or_else(|e| panic!("{items:?} rendered as\n{text}\ndoes not parse: {}", e.reason))
                .unwrap_or_else(|| panic!("{text}\nhas no shell block"));
            assert_eq!(parsed.start, effective.start, "{text}");
            assert_eq!(
                parsed.without_command.as_ref(),
                Some(&effective.without_command),
                "{text}"
            );
            assert_eq!(parsed.with_command.as_ref(), Some(&effective.with_command), "{text}");
            assert_eq!(parsed.escaping, Some(escaping), "{text}");
        }
    }
}

/// Empty lists, a program path that would end a plain scalar, and a warning of several lines
/// leave the output a config.
#[test]
fn a_program_a_warning_and_empty_lists_do_not_break_the_config() {
    let mut effective = effective_of(&["p"], &[], &[], Escaping::Cmd);
    effective.problem = Some(crate::shell::Problem {
        file: PathBuf::from(r"C:\x.yaml"),
        value: Some("a: b\n#c".into()),
        reason: "line one\nline two: x\r\n- three".into(),
    });
    let text = render(&effective);
    let parsed = crate::shell::config::parse(text.as_bytes())
        .unwrap_or_else(|e| panic!("{text}\ndoes not parse: {}", e.reason))
        .unwrap();
    assert_eq!(
        (parsed.start, parsed.without_command, parsed.with_command),
        (vec!["p".to_string()], Some(vec![]), Some(vec![]))
    );
    assert!(text.contains(r"program: C:\a #b: c\prog.exe"), "{text}");
    assert!(text.contains("warning: "), "{text}");
}

/// Characters a YAML comment cannot hold as they are: every C0 control (NUL included), DEL, every C1
/// control (NEL included), the Unicode line and paragraph separators, and the two non-characters the
/// YAML reader rejects.
fn comment_hostile_chars() -> Vec<char> {
    let mut chars: Vec<char> = (0u32..0x20)
        .chain([0x7f])
        .chain(0x80..0xa0)
        .filter_map(char::from_u32)
        .collect();
    chars.extend(['\u{2028}', '\u{2029}', '\u{fffe}', '\u{ffff}']);
    chars
}

/// Every comment `render` writes (the source labels, `# program:`, `# warning:`) reads back as a
/// comment, whatever it holds: a hostile character in a path, a `start` value or an error reason
/// leaves the whole output a config with the values shown. Each character goes through every
/// comment alone, and all of them together go through at once.
#[test]
fn a_comment_holding_any_character_leaves_the_output_a_config() {
    let hostile = comment_hostile_chars();
    let mut texts: Vec<String> = hostile.iter().map(|c| format!("x{c}y: z # w")).collect();
    texts.push(hostile.iter().collect());
    texts.push(" a\nb".into());
    for text in texts {
        let mut effective = effective_of(&["prog", "arg"], &["-i"], &["-c"], Escaping::Msvc);
        effective.program = PathBuf::from(format!(r"C:\{text}\prog.exe"));
        effective.why.start = Source::User(PathBuf::from(format!(r"C:\{text}\config.yaml")));
        effective.why.without_command = Source::System(PathBuf::from(format!(r"C:\{text}\system.yaml")));
        effective.problem = Some(crate::shell::Problem {
            file: PathBuf::from(format!(r"C:\{text}\bad.yaml")),
            value: Some(text.clone()),
            reason: text.clone(),
        });
        let rendered = render(&effective);
        let parsed = crate::shell::config::parse(rendered.as_bytes())
            .unwrap_or_else(|e| panic!("{text:?} rendered as\n{rendered:?}\ndoes not parse: {}", e.reason))
            .unwrap_or_else(|| panic!("{rendered:?}\nhas no shell block"));
        assert_eq!(parsed.start, effective.start, "{rendered:?}");
        assert_eq!(
            parsed.without_command.as_ref(),
            Some(&effective.without_command),
            "{rendered:?}"
        );
        assert_eq!(
            parsed.with_command.as_ref(),
            Some(&effective.with_command),
            "{rendered:?}"
        );
        assert_eq!(parsed.escaping, Some(Escaping::Msvc), "{rendered:?}");
        // Nothing is left raw that could end a comment or the stream; the line ends are the output's own.
        assert!(
            rendered.chars().all(|c| c == '\n' || !hostile.contains(&c)),
            "{rendered:?}"
        );
    }
}

#[test]
fn a_terminal_command_keeps_a_leading_line_break_as_stock_sshd_does() {
    // The line is `"shell" -c <text>`, so only a space or tab before the text is a separator that can go.
    for (text, want) in [
        ("\r\nx\r\n", "\r\nx\r\n"),
        ("\nx", "\nx"),
        ("  \r\nx", "\r\nx"),
        ("\t x", "x"),
        (" \r\n x", "\r\n x"),
    ] {
        let session = Session::Command { text, terminal: true };
        assert_eq!(
            line(&TestHost::new(), &session),
            format!("{SYSTEM_CMD} /c {want}"),
            "{text:?}"
        );
    }
}

// resolve_program =====

/// A file that cannot be examined is not a file that is missing: the reason is the system's.
#[test]
fn a_file_that_cannot_be_examined_is_reported_with_the_systems_reason() {
    let denied = "Access is denied. (os error 5)";
    let host = TestHost::new().with_entry(
        r"C:\locked\sh.exe",
        crate::shell::test_host::Entry::Unreadable("Access is denied. (os error 5)"),
    );
    let reason = resolve_program(&host, r"C:\locked\sh.exe").unwrap_err();
    assert!(reason.contains(denied), "{reason}");
    // The same for the `.exe` a path without an extension may mean.
    let reason = resolve_program(&host, r"C:\locked\sh").unwrap_err();
    assert!(reason.contains(denied), "{reason}");
    // A name that is merely absent still reads as missing.
    assert_eq!(
        resolve_program(&host, r"C:\locked\none.exe").unwrap_err(),
        "there is no such file"
    );
}

#[test]
fn the_given_directories_are_searched_in_order_before_path() {
    let host = TestHost::new()
        .with_program("sh", r"C:\on-path\sh.exe")
        .with_program("other", r"C:\on-path\other.exe")
        .with_file(r"C:\second\sh.exe", "MZ")
        .with_file(r"C:\first\sh.exe", "MZ");
    let dirs = [PathBuf::from(r"C:\first"), PathBuf::from(r"C:\second")];
    assert_eq!(
        resolve_program_in(&host, &dirs, "sh"),
        Ok(PathBuf::from(r"C:\first\sh.exe"))
    );
    assert_eq!(
        resolve_program_in(&host, &dirs[1..], "sh"),
        Ok(PathBuf::from(r"C:\second\sh.exe"))
    );
    // Nothing in the directories: PATH, as for a session.
    assert_eq!(
        resolve_program_in(&host, &dirs, "other"),
        Ok(PathBuf::from(r"C:\on-path\other.exe"))
    );
    assert_eq!(resolve_program_in(&host, &[], "sh"), resolve_program(&host, "sh"));
    assert_eq!(
        resolve_program_in(&host, &dirs, "nonesuch"),
        Err("not found on PATH".to_string())
    );
    // A name with a separator is a path: the directories do not matter.
    assert_eq!(
        resolve_program_in(&host, &dirs, r"C:\first\sh.exe"),
        Ok(PathBuf::from(r"C:\first\sh.exe"))
    );
}
