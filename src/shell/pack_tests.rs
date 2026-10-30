//! Host tests for defaults and the spawn line (pure; runs on any platform).

use std::path::PathBuf;

use super::{Session, Source, defaults, effective, flow_list, plan, render, start_or_fall_back};
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
) -> impl FnMut(&str) -> anyhow::Result<()> + 'a {
    move |line| {
        tried.borrow_mut().push(line.to_string());
        if line.contains(refused) {
            anyhow::bail!("{OS_ERROR}");
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
        |_| -> anyhow::Result<()> {
            calls += 1;
            anyhow::bail!("attempt {calls}")
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
         \x20 start: [pwsh.exe, -NoLogo]  ({user})\n\
         \x20 append:\n\
         \x20   without-command: [-NoExit]  ({user})\n\
         \x20   with-command: [-c]  (any other program)\n\
         \x20 escaping: msvc  (any other program)\n\
         program: {PWSH}"
    );
    assert_eq!(text, want);

    // The built-in: the system cmd.exe and its defaults.
    let text = render(&effective(&TestHost::new()).unwrap());
    assert!(text.contains(&format!("start: [{SYSTEM_CMD}]  (built-in)")), "{text}");
    assert!(text.contains("escaping: cmd  (the system cmd.exe)"), "{text}");
    assert!(text.contains("with-command: [/c]  (the system cmd.exe)"), "{text}");
    assert!(text.contains("without-command: []  (the system cmd.exe)"), "{text}");
    assert!(text.ends_with(&format!("program: {SYSTEM_CMD}")), "{text}");

    // The system layer, and a value with a space.
    let host = TestHost::new()
        .with_program("p", PWSH)
        .with_system_config("shell: {start: [p, \"a b\"]}\n");
    let text = render(&effective(&host).unwrap());
    assert!(
        text.contains(&format!(
            r#"start: [p, "a b"]  (system: {})"#,
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
        text.contains("start: [C:\\Windows\\System32\\cmd.exe]  (built-in)"),
        "{text}"
    );
    let warning = text.lines().last().unwrap();
    assert!(
        warning.starts_with("warning: cannot use the shell from ")
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
        |_| -> anyhow::Result<()> { anyhow::bail!("{OS_ERROR}") },
        |_| panic!("nothing to replace it with"),
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains(OS_ERROR), "{error:#}");
}

// verify's lists are YAML =====

#[test]
fn a_rendered_list_parses_back_to_the_same_items() {
    let items: Vec<String> = [
        r"C:\Program Files\PowerShell\7\pwsh.exe",
        r"C:\a\b.exe",
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
        "tab\there",
        "new\nline",
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
        "two\\\\",
        "é日本語",
        "😀",
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
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    for item in &items {
        let list = flow_list(std::slice::from_ref(item));
        let parsed = crate::shell::config::parse(format!("shell: {{start: {list}}}").as_bytes())
            .unwrap_or_else(|e| panic!("{item:?} rendered as {list} does not parse: {}", e.reason))
            .unwrap();
        assert_eq!(parsed.start, std::slice::from_ref(item), "{item:?} rendered as {list}");
    }
    let list = flow_list(&items);
    let parsed = crate::shell::config::parse(format!("shell: {{start: {list}}}").as_bytes())
        .unwrap()
        .unwrap();
    assert_eq!(parsed.start, items);
}

#[test]
fn a_quoted_item_escapes_only_what_yaml_needs() {
    assert_eq!(flow_list(&["a b,[c]".into()]), r#"["a b,[c]"]"#);
    assert_eq!(flow_list(&["q\"\\".into()]), r#"["q\"\\"]"#);
    assert_eq!(flow_list(&["x\t\u{7f}".into()]), r#"["x\t\u007F"]"#);
}

#[test]
fn common_items_are_not_quoted() {
    assert_eq!(
        flow_list(&[
            "pwsh.exe".into(),
            "-NoLogo".into(),
            "/c".into(),
            r"C:\Windows\System32\cmd.exe".into()
        ]),
        r"[pwsh.exe, -NoLogo, /c, C:\Windows\System32\cmd.exe]"
    );
}
