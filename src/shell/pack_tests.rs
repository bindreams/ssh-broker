//! Host tests for defaults and the spawn line (pure; runs on any platform).

use std::path::PathBuf;

use super::{Session, Source, defaults, effective, plan};
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
