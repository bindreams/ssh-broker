//! Host tests for argv dispatch (pure; runs on any platform).
//!
//! Each case is a whole command line, as sshd's `DefaultShell` launch produces it; the argv
//! `route` receives is derived from it the way the C runtime would.

use super::{AgentArgs, AutoLoginArgs, BackgroundArgs, ProbeLink, Route, Toggle, Verb, route};
use crate::cmdline::{Encoding, RawExec, resolve_exec, split_args};

fn route_line(line: &str) -> Route {
    let args = split_args(line);
    route(&args[1..], line)
}

/// The `-c` route that carries `tail`, the text after `-c` as written.
fn tail(tail: &str) -> Route {
    Route::Shim {
        exec: Some(RawExec::Tail(tail.into())),
    }
}

/// The command `line` carries once sshd's form is `encoding`: routed, then decoded.
fn command_as(line: &str, encoding: Encoding) -> Option<String> {
    let Route::Shim { exec } = route_line(line) else {
        panic!("{line:?} must select the shim");
    };
    exec.map(|exec| resolve_exec(exec, || encoding).command)
}

/// A line whose form does not matter: commands with nothing sshd would escape.
fn command(line: &str) -> Option<String> {
    command_as(line, Encoding::Escaped)
}

fn some(command: &str) -> Option<String> {
    Some(command.to_string())
}

#[test]
fn bare_is_interactive_shim() {
    assert_eq!(route_line("ssh-broker.exe"), Route::Shim { exec: None });
}

/// Routing keeps the text after `-c` as written; which form it is in is decided later.
#[test]
fn dash_c_routes_the_raw_tail() {
    assert_eq!(route_line("ssh-broker.exe -c echo"), tail("echo"));
    assert_eq!(route_line(r#"ssh-broker.exe -c "echo hi""#), tail(r#""echo hi""#));
    assert_eq!(route_line("ssh-broker.exe -c echo  two"), tail("echo  two"));
}

/// `-c` was given, so it is an exec request even when the command is empty (the shell runs
/// nothing for `-c ""`). Only a line with no `-c` at all is an interactive session.
#[test]
fn dash_c_with_an_empty_command_is_an_empty_exec() {
    assert_eq!(route_line("ssh-broker.exe -c"), tail(""));
    assert_eq!(route_line("ssh-broker.exe -c "), tail(""));
    for encoding in [Encoding::Verbatim, Encoding::Escaped] {
        assert_eq!(command_as("ssh-broker.exe -c", encoding), some(""), "{encoding:?}");
        assert_eq!(command_as("ssh-broker.exe -c ", encoding), some(""), "{encoding:?}");
    }
    assert_eq!(command_as(r#"ssh-broker.exe -c """#, Encoding::Escaped), some(""));
}

#[test]
fn agent_alone_is_a_desktop_agent() {
    assert_eq!(
        route_line("ssh-broker.exe agent"),
        Route::Agent(AgentArgs { background: None })
    );
}

fn background(expect_user: Option<&str>) -> Route {
    Route::Agent(AgentArgs {
        background: Some(BackgroundArgs {
            expect_user: expect_user.map(str::to_string),
        }),
    })
}

#[test]
fn agent_background_flags_parse() {
    assert_eq!(route_line("ssh-broker.exe agent --background"), background(None));
    assert_eq!(
        route_line("ssh-broker.exe agent --background --expect-user S-1-5-21-1-2-3-1001"),
        background(Some("S-1-5-21-1-2-3-1001"))
    );
}

#[test]
fn the_ready_event_flag_is_gone() {
    // The shim passes no named event.
    assert_eq!(
        route_line("ssh-broker.exe agent --background --ready-event ev --expect-user S-1-5-18"),
        Route::Usage(Verb::Agent)
    );
}

#[test]
fn agent_unknown_flag_is_not_the_shim() {
    for line in [
        "ssh-broker.exe agent --expect-user S-1-5-18",
        "ssh-broker.exe agent --bogus",
        "ssh-broker.exe agent stray",
        "ssh-broker.exe agent --background --bogus",
        "ssh-broker.exe agent --background --expect-user",
        "ssh-broker.exe agent --background --expect-user a --expect-user b",
        "ssh-broker.exe agent --background --background",
        "ssh-broker.exe agent --background stray",
    ] {
        assert_eq!(route_line(line), Route::Usage(Verb::Agent), "{line}");
    }
}

#[test]
fn logout_routes() {
    assert_eq!(route_line("ssh-broker.exe logout"), Route::Logout);
}

#[test]
fn logout_takes_no_arguments() {
    assert_eq!(route_line("ssh-broker.exe logout now"), Route::Usage(Verb::Logout));
}

#[test]
fn route_elevate_takes_the_rest_of_the_arguments_and_a_dash_c_login_stays_the_shim() {
    assert_eq!(
        route_line("ssh-broker.exe elevate cmd /c whoami"),
        Route::Elevate {
            terminal: false,
            command: "cmd /c whoami".into()
        }
    );
    assert_eq!(
        route_line(r#"ssh-broker.exe elevate "C:\Program Files\x.exe" "a b" --help"#),
        Route::Elevate {
            terminal: false,
            command: r#""C:\Program Files\x.exe" "a b" --help"#.into()
        },
        "the arguments are the command's, whatever they look like"
    );
    assert_eq!(
        route_line("ssh-broker.exe elevate"),
        Route::Usage(Verb::Elevate),
        "no command is a usage line"
    );
    assert_eq!(command("ssh-broker.exe -c \"elevate x\""), some("elevate x"));
    assert_eq!(command("ssh-broker.exe -c elevate"), some("elevate"));
}

#[test]
fn elevate_terminal_is_a_flag_only_as_the_first_argument_after_the_verb() {
    assert_eq!(
        route_line("ssh-broker.exe elevate --terminal cmd /k"),
        Route::Elevate {
            terminal: true,
            command: "cmd /k".into()
        }
    );
    assert_eq!(
        route_line("ssh-broker.exe elevate cmd --terminal"),
        Route::Elevate {
            terminal: false,
            command: "cmd --terminal".into()
        },
        "after the command's first word it is the command's own argument"
    );
    assert_eq!(
        route_line("ssh-broker.exe elevate --terminal --terminal"),
        Route::Elevate {
            terminal: true,
            command: "--terminal".into()
        },
        "only the first one is the flag"
    );
    assert_eq!(
        route_line("ssh-broker.exe elevate --terminal"),
        Route::Usage(Verb::Elevate),
        "the flag alone has no command"
    );
}

/// The command is the text after the verb (and the flag) as typed, not argv joined again: argv has lost the quotes
/// and the runs of spaces that decide what the command does.
#[test]
fn elevate_carries_the_line_as_written_not_argv() {
    assert_eq!(
        route_line(r#"ssh-broker.exe elevate cmd /c echo "a&whoami""#),
        Route::Elevate {
            terminal: false,
            command: r#"cmd /c echo "a&whoami""#.into()
        }
    );
    assert_eq!(
        route_line(r#""C:\Program Files\ssh-broker.exe" elevate --terminal  p   "a  b"  \"c\""#),
        Route::Elevate {
            terminal: true,
            command: r#"p   "a  b"  \"c\""#.into()
        }
    );
}

/// argv's program name is partly quoted, or empty: the text after `elevate` is still cut from where argv put it. The
/// argv after argv[0] is written out for each line, as the runtime gives it, not derived from the line.
#[test]
fn the_programs_own_name_may_be_partly_quoted() {
    let args = |args: &[&str]| args.iter().map(|a| (*a).to_owned()).collect::<Vec<_>>();
    assert_eq!(
        route(
            &args(&["elevate", "whoami"]),
            r#"C:\tools\"my bin"\ssh-broker.exe elevate whoami"#
        ),
        Route::Elevate {
            terminal: false,
            command: "whoami".into()
        }
    );
    assert_eq!(
        route(
            &args(&["elevate", "whoami", "/all"]),
            r#"C:\"a b"\"c d"\ssh-broker.exe elevate whoami /all"#
        ),
        Route::Elevate {
            terminal: false,
            command: "whoami /all".into()
        }
    );
    // A line that starts with a blank has an empty argv[0]: `elevate` is the first argument.
    assert_eq!(
        route(&args(&["elevate", "whoami"]), " elevate whoami"),
        Route::Elevate {
            terminal: false,
            command: "whoami".into()
        }
    );
}

#[test]
fn a_flag_name_is_not_a_flag_value() {
    assert_eq!(
        route_line("ssh-broker.exe agent --background --expect-user --expect-user x"),
        Route::Usage(Verb::Agent)
    );
}

#[test]
fn auto_login_on_off_account_and_invalid() {
    let args = |toggle, account: Option<&str>| {
        Route::AutoLogin(Some(AutoLoginArgs {
            toggle,
            account: account.map(str::to_string),
        }))
    };
    assert_eq!(route_line("ssh-broker.exe auto-login on"), args(Toggle::On, None));
    assert_eq!(route_line("ssh-broker.exe auto-login off"), args(Toggle::Off, None));
    assert_eq!(
        route_line(r#"ssh-broker.exe auto-login on "Zoe Muller""#),
        args(Toggle::On, Some("Zoe Muller"))
    );
    assert_eq!(
        route_line("ssh-broker.exe auto-login off alice"),
        args(Toggle::Off, Some("alice"))
    );
    for line in [
        "ssh-broker.exe auto-login",
        "ssh-broker.exe auto-login maybe",
        "ssh-broker.exe auto-login on a b",
        "ssh-broker.exe auto-login --on",
    ] {
        assert_eq!(route_line(line), Route::AutoLogin(None), "{line}");
    }
}

/// `ssh host logout` arrives as `-c logout`, like every other verb name.
#[test]
fn a_c_flag_after_a_verb_is_still_exec() {
    assert_eq!(command("ssh-broker.exe -c logout"), some("logout"));
    assert_eq!(command("ssh-broker.exe -c \"auto-login on\""), some("auto-login on"));
    assert_eq!(command("ssh-broker.exe -c agent"), some("agent"));
}

#[test]
fn apply_and_doctor_verbs() {
    assert_eq!(route_line("ssh-broker.exe apply"), Route::Apply);
    assert_eq!(route_line("ssh-broker.exe doctor"), Route::Doctor);
    assert_eq!(
        route_line("ssh-broker.exe doctor-probe"),
        Route::DoctorProbe(ProbeLink::NoJunction)
    );
}

/// `verify` and `verify-probe` are unknown words, which the shim takes.
#[test]
fn verify_is_not_a_verb() {
    for word in ["verify", "verify-probe"] {
        assert_eq!(
            route_line(&format!("ssh-broker.exe {word}")),
            Route::Shim { exec: None }
        );
    }
}

/// The hidden verb of the task that sets sshd up takes no arguments; any other shape is a usage error,
/// never the shim.
#[test]
fn apply_sshd_is_a_hidden_verb_that_takes_no_arguments() {
    let args = |args: &[&str]| args.iter().map(|a| (*a).to_owned()).collect::<Vec<_>>();
    assert_eq!(route_line("ssh-broker.exe apply-sshd"), Route::ApplySshd);
    assert_eq!(
        route(&args(&["apply-sshd", "now"]), "ignored"),
        Route::Usage(Verb::ApplySshd)
    );
}

/// The hidden probe takes the directory of the junction it makes or the one it follows, which `doctor`
/// names: it runs the two probes of an administrator's session with them. Any other shape is a usage
/// error, never the shim and never a probe that ignored what it was told.
#[test]
fn doctor_probe_takes_the_directory_to_make_a_junction_in_or_to_follow() {
    let args = |args: &[&str]| args.iter().map(|a| (*a).to_owned()).collect::<Vec<_>>();
    let dir = r"C:\Users\me\AppData\Local\Temp\sb-junction-1-2";
    assert_eq!(
        route(&args(&["doctor-probe", "--make-junction", dir]), "ignored"),
        Route::DoctorProbe(ProbeLink::Make(dir.into()))
    );
    assert_eq!(
        route(&args(&["doctor-probe", "--follow", dir]), "ignored"),
        Route::DoctorProbe(ProbeLink::Follow(dir.into()))
    );
    for bad in [
        vec!["doctor-probe", "--follow"],
        vec!["doctor-probe", "--make-junction"],
        vec!["doctor-probe", "--follow", "--make-junction"],
        vec!["doctor-probe", "--follow", "a", "b"],
        vec!["doctor-probe", "--make-junction", "a", "b"],
        vec!["doctor-probe", "--make-junction", "--follow", "a"],
        vec!["doctor-probe", "now"],
    ] {
        assert_eq!(
            route(&args(&bad), "ignored"),
            Route::Usage(Verb::DoctorProbe),
            "{bad:?}"
        );
    }
}

/// The hidden verb of a terminal session's fallback shell takes the value of the pipe handle it
/// inherited, and `--login` before it for a session without a command; any other shape is a usage
/// error, never the shim.
#[test]
fn console_fallback_takes_the_value_of_its_handle() {
    let args = |args: &[&str]| args.iter().map(|a| (*a).to_owned()).collect::<Vec<_>>();
    assert_eq!(
        route(&args(&["console-fallback", "1234"]), "ignored"),
        Route::ConsoleFallback {
            handle: 1234,
            login: false
        }
    );
    assert_eq!(
        route(&args(&["console-fallback", "--login", "88"]), "ignored"),
        Route::ConsoleFallback {
            handle: 88,
            login: true
        }
    );
    for args in [
        vec!["console-fallback"],
        vec!["console-fallback", "a notice", "cmd.exe"],
        vec!["console-fallback", "C:/a b/file"],
        vec!["console-fallback", "-1"],
        // A NULL handle is never valid; a sign is not part of a handle's value; a value that does not
        // fit is not one.
        vec!["console-fallback", "0"],
        vec!["console-fallback", "00"],
        vec!["console-fallback", "+5"],
        vec!["console-fallback", "-0"],
        vec!["console-fallback", "18446744073709551616"],
        vec!["console-fallback", "99999999999999999999999999"],
        vec!["console-fallback", "--login", "0"],
        vec!["console-fallback", "--login", "+5"],
        vec!["console-fallback", ""],
        vec!["console-fallback", " 5"],
        vec!["console-fallback", "--login"],
        vec!["console-fallback", "--login", "x"],
        vec!["console-fallback", "12", "--login"],
    ] {
        let args: Vec<String> = args.into_iter().map(str::to_owned).collect();
        assert_eq!(route(&args, "ignored"), Route::Usage(Verb::ConsoleFallback), "{args:?}");
    }
}

/// `ssh host agent` arrives as `-c agent`, so argv[1] is `-c` and no verb can collide with a
/// client command, whatever the command is called.
#[test]
fn a_command_named_like_a_verb_is_still_shim_exec() {
    for verb in [
        "agent",
        "apply",
        "doctor",
        "doctor-probe",
        "console-fallback",
        "logout",
        "elevate",
        "auto-login",
    ] {
        assert_eq!(command(&format!("ssh-broker.exe -c {verb}")), some(verb));
        assert_eq!(
            command(&format!(r#"ssh-broker.exe -c "{verb} --x y""#)),
            some(&format!("{verb} --x y"))
        );
    }
}

/// Every `-c` command is relayed whole, whatever program it names. A command that a classifier
/// would pick out, such as `sftp-server.exe` or `scp`, takes the same route and reaches the shim
/// intact. A reintroduced classifier that diverts or rewrites one fails here.
#[test]
fn every_dash_c_command_routes_to_the_relay_with_its_text_intact() {
    for text in [
        "scp -t /x",
        "scp.exe -f /x",
        "sftp-server.exe -l INFO",
        "internal-sftp",
        r"C:\Program Files\OpenSSH\sftp-server.exe -l INFO",
        r#""C:\Program Files\OpenSSH\sftp-server.exe" -l INFO"#,
        "git status",
        "cmd /c exit 3",
        "ssh-broker.exe agent",
        r"C:\a b\ssh-broker.exe doctor",
    ] {
        assert_eq!(
            command_as(&format!("ssh-broker.exe -c {text}"), Encoding::Verbatim),
            some(text),
            "{text}"
        );
    }
}

/// The command is relayed as the client sent it, edges included: the string the shim sends is
/// the string the client wrote. (`shim::spawn_line` trims only its leading edge, for `CreateProcessW`.)
#[test]
fn a_command_keeps_the_whitespace_at_its_edges() {
    assert_eq!(command(r#"ssh-broker.exe -c "  scp -t /x  ""#), some("  scp -t /x  "));
    assert_eq!(command(r#"ssh-broker.exe -c "   ""#), some("   "));
    assert_eq!(
        command_as("ssh-broker.exe -c \t\r\n x \r\n", Encoding::Verbatim),
        some("\t\r\n x \r\n"),
        "one separator after -c is sshd's; the rest is the command"
    );
}

/// `CreateProcessW(NULL, cmdline)` resolves an unquoted program path with spaces by prefix
/// widening, so the shim must hand it the command line untouched: no tokenizing, no
/// re-quoting. sshd's `Subsystem sftp <path>` takes the rest of the line verbatim, and the path
/// is commonly unquoted.
///
/// Pins `route` only: that the string it returns is this one. What the relay and the fail-open
/// do with the string is pinned by `agent_program_path_tests` and `tests/fail_open_windows.rs`.
#[test]
fn dash_c_keeps_an_unquoted_spaced_program_path_verbatim() {
    let text = r"C:\Program Files\OpenSSH\sftp-server.exe -l INFO";
    // A PTY session: the command is appended to the line unquoted.
    assert_eq!(
        command_as(&format!("ssh-broker.exe -c {text}"), Encoding::Verbatim),
        some(text)
    );
    // A non-PTY session: sshd passes the command as one quoted argument.
    assert_eq!(command(&format!(r#"ssh-broker.exe -c "{text}""#)), some(text));
}

#[test]
fn dash_c_keeps_a_quoted_program_path_verbatim() {
    let text = r#""C:\Program Files\OpenSSH\sftp-server.exe" -l INFO"#;
    assert_eq!(
        command_as(&format!("ssh-broker.exe -c {text}"), Encoding::Verbatim),
        some(text)
    );
    // As one escaped argument.
    assert_eq!(
        command(r#"ssh-broker.exe -c "\"C:\Program Files\OpenSSH\sftp-server.exe\" -l INFO""#),
        some(text)
    );
}

/// A PTY session appends the command unquoted, so the C runtime's argv has lost its quotes and
/// collapsed its spaces. The command must come from the raw line.
#[test]
fn a_verbatim_command_keeps_its_quotes_empty_argument_and_double_space() {
    let text = r#""C:\a b\p.exe" "x y" "" end  of  line"#;
    assert_eq!(
        command_as(&format!("ssh-broker.exe -c {text}"), Encoding::Verbatim),
        some(text)
    );
}

/// A non-PTY session passes the command as one escaped argument; unescaping it must restore the
/// command exactly.
#[test]
fn an_escaped_single_argument_keeps_its_quotes_empty_argument_and_double_space() {
    assert_eq!(
        command(r#"ssh-broker.exe -c "\"C:\a b\p.exe\" \"x y\" \"\" end  of  line""#),
        some(r#""C:\a b\p.exe" "x y" "" end  of  line"#)
    );
}

/// The raw line always shows the `-c` argv reports, because both come from the same command
/// line. If it does not, argv is all there is: `route` asserts in a debug build and, in release,
/// returns the joined argv for `resolve_exec` to log.
#[test]
#[should_panic(expected = "no `-c`")]
fn a_raw_line_without_dash_c_is_a_bug_that_asserts_in_debug() {
    route(&["-c".into(), "a b".into(), "c".into()], "");
}
