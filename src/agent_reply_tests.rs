//! Tests that the agent answers every connection it cannot serve with a frame the shim prints, and
//! closes none of them without a byte while it is alive. No shell is started: the starters of the
//! hooks fail on purpose, and the connections are AF_UNIX pairs in a temp dir.
use super::*;
use crate::afunix::{ConnTx, Whole};
use crate::protocol::{ElevationPolicy, FrameKind, Handshake, Launch, Mode, Stream, write_frame};
use crate::relay::{Outcome, TestSink, pump_decode, write_data};
use crate::shell::test_host::{TestHost, USER_CONFIG};
use crate::socket_loc::StepDown;
use crate::winutil::UnelevatedToken;

/// What a client saw: how the session ended and what the agent wrote to its stderr and to its terminal.
struct Answer {
    outcome: Outcome,
    stderr: String,
    stdout: String,
}

/// Connect a client that runs `send`, let the agent handle the server side with `hooks`, and return
/// what the client was told and what the handler returned. The client closes after the reply, which
/// is what the agent waits for.
fn answered(tag: &str, hooks: Hooks, send: impl FnOnce(&mut ConnTx) + Send + 'static) -> (Answer, anyhow::Result<()>) {
    let (server, client, dir) = crate::test_support::raw_socket_pair(tag);
    let agent = std::thread::spawn(move || handle_connection_in(server, hooks, &Control::standalone()));
    let (mut rx, mut tx) = afunix::split(client).unwrap();
    send(&mut tx);
    let mut sink = TestSink::default();
    let outcome = pump_decode(&mut rx, &mut FrameReader::new(), &mut sink).expect("the reply was lost");
    drop((rx, tx));
    let result = agent.join().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    (
        Answer {
            outcome,
            stderr: String::from_utf8(sink.stderr).unwrap(),
            stdout: String::from_utf8(sink.stdout).unwrap(),
        },
        result,
    )
}

fn handshake(mode: Mode, command: &str) -> impl FnOnce(&mut ConnTx) + Send + 'static {
    let hs = Handshake {
        mode,
        command: Some(command.to_owned()),
        ..Handshake::pty_default()
    };
    move |tx| {
        write_frame(tx, FrameKind::Handshake, &hs.encode().unwrap()).unwrap();
        write_data(tx, Stream::Stdin, b"").unwrap();
    }
}

fn failing_starters() -> Hooks {
    Hooks {
        start_exec: |_, _, _| Err(StartError::Program(anyhow::anyhow!("the system cannot find the file"))),
        start_pty: |_, _, _, _, _, _| Err(StartError::Program(anyhow::anyhow!("the system cannot find the file"))),
        ..Hooks::production()
    }
}

#[test]
fn a_command_that_cannot_be_started_is_answered_with_the_cause_and_255() {
    let (answer, result) = answered("exec-spawn", failing_starters(), handshake(Mode::Exec, "nosuchprogram"));
    assert_eq!(answer.outcome, Outcome::Exited(255));
    assert_eq!(
        answer.stderr,
        "ssh-broker: the agent could not start the command: the system cannot find the file\r\n"
    );
    assert!(format!("{:#}", result.unwrap_err()).contains("cannot find the file"));
}

#[test]
fn a_shell_that_cannot_be_started_is_answered_with_the_cause_and_255() {
    let (answer, result) = answered("pty-spawn", failing_starters(), handshake(Mode::Pty, "pwsh.exe"));
    assert_eq!(answer.outcome, Outcome::Exited(255));
    assert_eq!(
        answer.stderr,
        "ssh-broker: the agent could not start the shell: the system cannot find the file\r\n"
    );
    assert!(result.is_err());
}

#[test]
fn a_first_frame_that_is_not_a_handshake_is_answered_with_254() {
    let (answer, result) = answered("not-handshake", Hooks::production(), |tx| {
        write_data(tx, Stream::Pty, b"oops").unwrap();
    });
    assert_eq!(answer.outcome, Outcome::Exited(254));
    assert!(
        answer
            .stderr
            .starts_with("ssh-broker: the agent could not read the request: "),
        "{}",
        answer.stderr
    );
    assert!(answer.stderr.contains("not a handshake"), "{}", answer.stderr);
    assert!(result.is_err());
}

#[test]
fn a_handshake_that_cannot_be_decoded_is_answered_with_254() {
    let (answer, result) = answered("junk-handshake", Hooks::production(), |tx| {
        write_frame(tx, FrameKind::Handshake, b"not a handshake").unwrap();
    });
    assert_eq!(answer.outcome, Outcome::Exited(254));
    assert!(
        answer
            .stderr
            .starts_with("ssh-broker: the agent could not read the request: "),
        "{}",
        answer.stderr
    );
    assert!(result.is_err());
}

#[test]
fn a_frame_cut_short_is_answered_not_dropped() {
    // The header promises more than comes: the client then closes its write half and waits.
    let (answer, _result) = answered("cut-short", Hooks::production(), |tx| {
        use std::io::Write;
        tx.write_all(&[FrameKind::Handshake as u8, 100, 0, 0, 0, 1, 2, 3])
            .unwrap();
        tx.shutdown_write().unwrap();
    });
    assert_eq!(answer.outcome, Outcome::Exited(254));
    assert!(
        answer.stderr.contains("could not read the request"),
        "{}",
        answer.stderr
    );
}

#[test]
fn a_connection_that_cannot_be_split_is_answered_on_the_socket_itself() {
    let hooks = Hooks {
        split: |socket| Err((Whole::of(socket), anyhow::anyhow!("no handle to duplicate"))),
        ..Hooks::production()
    };
    let (answer, result) = answered("no-split", hooks, handshake(Mode::Exec, "echo"));
    assert_eq!(answer.outcome, Outcome::Exited(255));
    assert_eq!(
        answer.stderr,
        "ssh-broker: the agent could not set up the connection: no handle to duplicate\r\n"
    );
    assert!(result.is_err());
}

#[test]
fn a_client_that_connects_and_leaves_without_a_byte_is_not_a_fault() {
    // The wake that ends the accept loop is such a client.
    let (server, client, dir) = crate::test_support::raw_socket_pair("left");
    drop(client);
    let result = handle_connection_in(server, Hooks::production(), &Control::standalone());
    assert!(result.is_ok(), "{:#}", result.unwrap_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_client_that_leaves_in_the_middle_of_a_frame_is_still_a_bad_request() {
    // It sent something, so it is not the wake: the log keeps the fault.
    let (server, client, dir) = crate::test_support::raw_socket_pair("left-midway");
    let (_rx, mut tx) = afunix::split(client).unwrap();
    std::io::Write::write_all(&mut tx, &[FrameKind::Handshake as u8, 100, 0, 0, 0, 1]).unwrap();
    tx.shutdown_both().unwrap();
    let result = handle_connection_in(server, Hooks::production(), &Control::standalone());
    assert!(result.is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_handler_that_panics_answers_its_connection_with_255_before_it_closes() {
    let hooks = Hooks {
        start_pty: |_, _, _, _, _, _| panic!("the starter failed"),
        ..Hooks::production()
    };
    let (server, client, dir) = crate::test_support::raw_socket_pair("panic-reply");
    let agent = std::thread::spawn(move || serve_connection(server, hooks, &Control::standalone()));
    let (mut rx, mut tx) = afunix::split(client).unwrap();
    handshake(Mode::Pty, "pwsh.exe")(&mut tx);
    let mut sink = TestSink::default();
    let outcome = pump_decode(&mut rx, &mut FrameReader::new(), &mut sink).expect("the reply was lost");
    drop((rx, tx));
    let handler = agent.join();
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(outcome, Outcome::Exited(255));
    assert_eq!(
        String::from_utf8(sink.stderr).unwrap(),
        "ssh-broker: the agent failed while serving this connection: the handler panicked\r\n"
    );
    assert!(handler.is_err(), "the panic is not swallowed");
}

#[test]
fn a_handler_that_does_not_panic_adds_nothing_to_its_reply() {
    // A desktop agent answers a logout request and returns without closing anything itself: the
    // connection ends with the handler, and no second reply is behind the first.
    let (server, client, dir) = crate::test_support::raw_socket_pair("no-panic-reply");
    let agent = std::thread::spawn(move || serve_connection(server, Hooks::production(), &Control::standalone()));
    let (mut rx, mut tx) = afunix::split(client).unwrap();
    // Nothing after the handshake: unread input at the agent's close would reset the connection.
    let logout = Handshake {
        mode: Mode::Logout,
        ..Handshake::pty_default()
    };
    write_frame(&mut tx, FrameKind::Handshake, &logout.encode().unwrap()).unwrap();
    let mut sink = TestSink::default();
    let outcome = pump_decode(&mut rx, &mut FrameReader::new(), &mut sink).expect("the reply was lost");
    let mut rest = Vec::new();
    std::io::Read::read_to_end(&mut rx, &mut rest).unwrap();
    drop((rx, tx));
    let result = agent.join().unwrap();
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(outcome, Outcome::Exited(2));
    assert!(result.is_ok());
    assert!(rest.is_empty(), "bytes after the reply: {rest:?}");
}

#[test]
fn a_connection_refused_at_accept_is_answered_with_255_not_dropped() {
    // The system hands out a connection the agent must not give to a shell: its peer is told why.
    let (server, client, dir) = crate::test_support::raw_socket_pair("refused");
    let connections = Connections::new();
    let control = Arc::new(Control::standalone());
    let mut script = Some(AcceptError::Refused {
        socket: server,
        cause: anyhow::anyhow!("the connection is inheritable by child processes"),
    });
    let end = accept_loop_with(
        || {
            Err(script
                .take()
                .unwrap_or_else(|| AcceptError::Fatal(anyhow::anyhow!("end of script"))))
        },
        &connections,
        &control,
        || false,
    );
    assert!(format!("{end:#}").ends_with("end of script"), "{end:#}");

    let (mut rx, tx) = afunix::split(client).unwrap();
    let mut sink = TestSink::default();
    let outcome = pump_decode(&mut rx, &mut FrameReader::new(), &mut sink).expect("the reply was lost");
    drop((rx, tx));
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(outcome, Outcome::Exited(255));
    assert_eq!(
        String::from_utf8(sink.stderr).unwrap(),
        "ssh-broker: the agent could not use the connection: the connection is inheritable by child processes\r\n"
    );
}

// Which line a handshake starts -----

/// `command` as a `Launch::Shell` request in `mode`.
fn shell_request(mode: Mode, command: Option<&str>) -> impl FnOnce(&mut ConnTx) + Send + 'static {
    let hs = Handshake {
        mode,
        command: command.map(str::to_owned),
        launch: Launch::Shell,
        ..Handshake::pty_default()
    };
    move |tx| {
        write_frame(tx, FrameKind::Handshake, &hs.encode().unwrap()).unwrap();
        write_data(tx, Stream::Stdin, b"").unwrap();
    }
}

fn with_host(host: TestHost) -> Hooks {
    Hooks {
        shell_host: Box::new(host),
        ..failing_starters()
    }
}

#[test]
fn a_request_without_the_command_it_needs_is_answered_with_254_and_starts_nothing() {
    for (tag, mode, launch) in [
        ("exec-shell", Mode::Exec, Launch::Shell),
        ("exec-direct", Mode::Exec, Launch::Direct),
        ("pty-direct", Mode::Pty, Launch::Direct),
    ] {
        let hs = Handshake {
            mode,
            launch,
            ..Handshake::pty_default()
        };
        let (answer, result) = answered(tag, failing_starters(), move |tx| {
            write_frame(tx, FrameKind::Handshake, &hs.encode().unwrap()).unwrap();
            write_data(tx, Stream::Stdin, b"").unwrap();
        });
        assert_eq!(answer.outcome, Outcome::Exited(254), "{tag}");
        assert!(
            answer
                .stderr
                .starts_with("ssh-broker: the agent could not read the request: "),
            "{tag}: {}",
            answer.stderr
        );
        assert!(answer.stderr.contains("needs a command"), "{tag}: {}", answer.stderr);
        assert!(result.is_err(), "{tag}");
    }
}

#[test]
fn a_command_too_long_for_a_command_line_is_answered_with_255_and_starts_nothing() {
    let long = "x".repeat(40_000);
    let (answer, result) = answered(
        "too-long",
        with_host(TestHost::new()),
        shell_request(Mode::Exec, Some(&long)),
    );
    assert_eq!(answer.outcome, Outcome::Exited(255));
    assert!(answer.stderr.contains("32,767"), "{}", answer.stderr);
    assert!(
        !answer.stderr.contains("could not start"),
        "a starter was reached: {}",
        answer.stderr
    );
    assert!(result.is_err());
}

#[test]
fn a_broken_config_shows_one_warning_before_anything_else() {
    let host = TestHost::new().with_user_config("shell: {strt: pwsh.exe}\n");
    let (answer, _result) = answered("warn-exec", with_host(host), shell_request(Mode::Exec, Some("echo hi")));
    let warning = format!("ssh-broker: cannot use the shell from {USER_CONFIG}");
    assert!(answer.stderr.starts_with(&warning), "{}", answer.stderr);
    assert_eq!(
        answer.stderr.matches("cannot use the shell").count(),
        1,
        "{}",
        answer.stderr
    );
    assert!(
        answer.stderr.contains("using the built-in cmd.exe\n"),
        "{}",
        answer.stderr
    );
    // The starter fails on purpose after it: the failure reply follows the warning.
    assert!(
        answer.stderr.contains("could not start the command"),
        "{}",
        answer.stderr
    );
}

#[test]
fn a_working_config_shows_no_warning() {
    let host = TestHost::new();
    let (answer, _result) = answered("no-warn", with_host(host), shell_request(Mode::Exec, Some("echo hi")));
    assert!(!answer.stderr.contains("cannot use the shell"), "{}", answer.stderr);
}

// The elevation policy of a login -----

/// A `Launch::Shell` request in `mode` that asked for `elevation`.
fn request_for(
    mode: Mode,
    command: Option<&str>,
    elevation: ElevationPolicy,
) -> impl FnOnce(&mut ConnTx) + Send + 'static {
    request_asking(mode, command, Some(elevation))
}

/// A `Launch::Shell` request in `mode` from a login that asked for `elevation` (`None`: it set nothing).
fn request_asking(
    mode: Mode,
    command: Option<&str>,
    elevation: Option<ElevationPolicy>,
) -> impl FnOnce(&mut ConnTx) + Send + 'static {
    let hs = Handshake {
        mode,
        command: command.map(str::to_owned),
        launch: Launch::Shell,
        elevation,
        ..Handshake::pty_default()
    };
    move |tx| {
        write_frame(tx, FrameKind::Handshake, &hs.encode().unwrap()).unwrap();
        write_data(tx, Stream::Stdin, b"").unwrap();
    }
}

/// The three starts a session can be given a token at: a command on pipes, a shell, and the line a shell
/// that cannot be used falls back to.
const REQUESTS: [(&str, Mode, Option<&str>); 3] = [
    ("exec", Mode::Exec, Some("whoami")),
    ("pty", Mode::Pty, None),
    ("pty-command", Mode::Pty, Some("whoami")),
];

/// A login that asked for a level the agent cannot prepare is refused, and the refusal names both ways out.
#[test]
fn agent_refuses_a_login_that_asked_when_the_token_cannot_be_made_and_names_both_ways_out() {
    for (tag, mode, command) in REQUESTS {
        let hooks = Hooks {
            make_unelevated: |_| Err(anyhow::anyhow!("the token cannot be made")),
            start_exec: |_, _, _| panic!("a command was started for a session with no token"),
            start_pty: |_, _, _, _, _, _| panic!("a shell was started for a session with no token"),
            ..Hooks::production()
        };
        let (answer, result) = answered(
            &format!("no-token-{tag}"),
            hooks,
            request_for(mode, command, ElevationPolicy::Prompt),
        );
        assert_eq!(answer.outcome, Outcome::Exited(255), "{tag}");
        assert_eq!(
            answer.stderr,
            format!(
                "{}\r\n",
                crate::offer::text::unelevated_unavailable(Some(ElevationPolicy::Prompt), "the token cannot be made")
            ),
            "{tag}"
        );
        assert!(
            answer.stderr.contains("leaves SSH_BROKER_ELEVATION unset") && answer.stderr.contains("sets it to always"),
            "{tag}"
        );
        assert!(result.is_err(), "{tag}");
    }
}

/// A login that asked for `always` whose level the agent cannot read is told that, and never to ask for `always`.
#[test]
fn agent_refuses_always_with_an_unreadable_level_and_does_not_tell_it_to_ask_for_always() {
    let hooks = Hooks {
        make_unelevated: |_| Err(anyhow::anyhow!("the level cannot be read")),
        start_exec: |_, _, _| panic!("a command was started for a refused login"),
        start_pty: |_, _, _, _, _, _| panic!("a shell was started for a refused login"),
        ..Hooks::production()
    };
    let (answer, result) = answered(
        "unreadable-always",
        hooks,
        request_for(Mode::Exec, Some("whoami"), ElevationPolicy::Always),
    );
    assert_eq!(answer.outcome, Outcome::Exited(255));
    assert_eq!(
        answer.stderr,
        format!(
            "{}\r\n",
            crate::offer::text::unelevated_unavailable(Some(ElevationPolicy::Always), "the level cannot be read")
        )
    );
    assert!(!answer.stderr.contains("sets it to always"), "{}", answer.stderr);
    assert!(result.is_err());
}

/// An agent below High cannot give `always`: it answers with the one sentence, exit 255, and starts nothing.
#[test]
fn agent_refuses_always_below_high_with_the_sentence_and_starts_nothing() {
    for (tag, mode, command) in REQUESTS {
        let hooks = Hooks {
            // The rule with the level fixed below High.
            make_unelevated: |policy| {
                crate::account::step_down(
                    policy,
                    || Ok(crate::socket_loc::Integrity::Medium),
                    || -> anyhow::Result<UnelevatedToken> { panic!("a token was made below High") },
                )
            },
            start_exec: |_, _, _| panic!("a command was started for a refused login"),
            start_pty: |_, _, _, _, _, _| panic!("a shell was started for a refused login"),
            ..Hooks::production()
        };
        let (answer, result) = answered(
            &format!("refused-{tag}"),
            hooks,
            request_for(mode, command, ElevationPolicy::Always),
        );
        assert_eq!(answer.outcome, Outcome::Exited(255), "{tag}");
        assert_eq!(
            answer.stderr,
            crate::offer::text::always_below_high(),
            "{tag}: one `ssh-broker: ` prefix and one line break"
        );
        assert!(result.is_err(), "{tag}");
    }
}

/// The policies the maker of `an_account_login_makes_no_token` was called with.
static MADE_FOR: std::sync::Mutex<Vec<Option<ElevationPolicy>>> = std::sync::Mutex::new(Vec::new());

/// The agent hands the login's policy to the maker, once, and starts with no token when it answers `Own`.
#[test]
fn the_agent_asks_for_the_token_once_with_the_policy_of_the_login() {
    let hooks = Hooks {
        make_unelevated: |policy| {
            MADE_FOR.lock().unwrap().push(policy);
            Ok(StepDown::Own)
        },
        ..failing_starters()
    };
    let (answer, _result) = answered(
        "asks-once",
        hooks,
        request_for(Mode::Exec, Some("whoami"), ElevationPolicy::AutoApprove),
    );
    assert_eq!(
        *MADE_FOR.lock().unwrap(),
        [Some(ElevationPolicy::AutoApprove)],
        "the maker was called once, with the login's policy"
    );
    assert!(
        answer.stderr.contains("could not start the command"),
        "{}",
        answer.stderr
    );
}

/// The starts of the tests below: `(starter, the shell inherits a handle from the verb, it was given a token)`.
static STARTS: std::sync::Mutex<Vec<(&'static str, bool, bool)>> = std::sync::Mutex::new(Vec::new());

/// An agent at High, whatever the level of the test process: the rule with the level fixed, and a real token.
fn at_high(tag: &str, policy: ElevationPolicy, host: TestHost, mode: Mode, command: Option<&str>) {
    let recording = Hooks {
        shell_host: Box::new(host),
        make_unelevated: |policy| {
            crate::account::step_down(
                policy,
                || Ok(crate::socket_loc::Integrity::High),
                crate::winutil::UnelevatedToken::of_this_process,
            )
        },
        start_exec: |_, _, token| {
            STARTS.lock().unwrap().push(("exec", false, token.is_some()));
            Err(StartError::Program(anyhow::anyhow!("recorded")))
        },
        start_pty: |_, _, _, _, read, token| {
            STARTS.lock().unwrap().push(("pty", read.is_some(), token.is_some()));
            Err(StartError::Program(anyhow::anyhow!("recorded")))
        },
        ..Hooks::production()
    };
    let _ = answered(tag, recording, request_for(mode, command, policy));
}

/// The tests that read [`STARTS`] hold this for their whole run: the starters are plain function pointers and
/// record into the one list.
static STARTS_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The starts recorded since the last call.
fn taken_starts() -> Vec<(&'static str, bool, bool)> {
    std::mem::take(&mut *STARTS.lock().unwrap())
}

#[test]
fn agent_gives_prompt_never_and_auto_approve_the_stepped_down_token_at_high() {
    let _serial = STARTS_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    taken_starts();
    let broken = || TestHost::new().with_user_config("shell: {strt: x}\n");
    for (n, policy) in [
        ElevationPolicy::Never,
        ElevationPolicy::Prompt,
        ElevationPolicy::AutoApprove,
    ]
    .into_iter()
    .enumerate()
    {
        at_high(
            &format!("stepped-exec-{n}"),
            policy,
            TestHost::new(),
            Mode::Exec,
            Some("whoami"),
        );
        at_high(&format!("stepped-pty-{n}"), policy, TestHost::new(), Mode::Pty, None);
        // A shell that cannot be used is started through the `console-fallback` verb first, and that start is
        // given the token too.
        at_high(&format!("stepped-verb-{n}"), policy, broken(), Mode::Pty, None);
        assert_eq!(
            taken_starts(),
            [
                ("exec", false, true),
                ("pty", false, true),
                // The verb's start, then the line the agent falls back to when the verb cannot be started.
                ("pty", true, true),
                ("pty", false, true),
            ],
            "{policy:?}"
        );
    }
}

#[test]
fn agent_gives_always_its_own_token_at_high() {
    let _serial = STARTS_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    taken_starts();
    let broken = || TestHost::new().with_user_config("shell: {strt: x}\n");
    at_high(
        "own-exec",
        ElevationPolicy::Always,
        TestHost::new(),
        Mode::Exec,
        Some("whoami"),
    );
    at_high("own-pty", ElevationPolicy::Always, TestHost::new(), Mode::Pty, None);
    at_high("own-verb", ElevationPolicy::Always, broken(), Mode::Pty, None);
    assert_eq!(
        taken_starts(),
        [
            ("exec", false, false),
            ("pty", false, false),
            ("pty", true, false),
            ("pty", false, false),
        ]
    );
}

// A login that set nothing and cannot be stepped down -----

/// The agent at High whose unelevated token cannot be made: the one rule, with a maker that fails.
fn at_high_without_a_token(tag: &str, host: TestHost, mode: Mode, command: Option<&str>) -> Answer {
    let recording = Hooks {
        shell_host: Box::new(host),
        make_unelevated: |asked| {
            crate::account::step_down(
                asked,
                || Ok(crate::socket_loc::Integrity::High),
                || -> anyhow::Result<UnelevatedToken> { Err(anyhow::anyhow!("the token cannot be made")) },
            )
        },
        start_exec: |_, _, token| {
            STARTS.lock().unwrap().push(("exec", false, token.is_some()));
            Err(StartError::Program(anyhow::anyhow!("recorded")))
        },
        start_pty: |_, _, _, _, read, token| {
            STARTS.lock().unwrap().push(("pty", read.is_some(), token.is_some()));
            Err(StartError::Program(anyhow::anyhow!("recorded")))
        },
        ..Hooks::production()
    };
    answered(tag, recording, request_asking(mode, command, None)).0
}

/// The notice of a login that set nothing, as the agent says it.
fn the_fallback_notice() -> String {
    crate::offer::text::unelevated_fallback("the token cannot be made", crate::offer::text::FallbackToken::Agent)
}

/// A login that set nothing is not refused when its session cannot be stepped down: it is served with the
/// agent's own token, and the notice is the first thing it sees, on stderr.
#[test]
fn agent_serves_a_command_that_set_nothing_with_its_own_token_and_the_notice_first() {
    let _serial = STARTS_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    taken_starts();
    let answer = at_high_without_a_token("fallback-exec", TestHost::new(), Mode::Exec, Some("whoami"));
    assert_eq!(taken_starts(), [("exec", false, false)], "started once, with no token");
    assert!(
        answer.stderr.starts_with(&format!("{}\n", the_fallback_notice())),
        "{}",
        answer.stderr
    );
    assert_eq!(
        answer.stderr.matches("could not prepare an unelevated session").count(),
        1
    );
}

/// The same for a terminal: the notice is printed from inside the pseudoconsole by the `console-fallback` verb,
/// which clears nothing after it, and when the verb cannot start it is the first data on the terminal.
#[test]
fn agent_serves_a_terminal_that_set_nothing_with_its_own_token_and_the_notice_first() {
    let _serial = STARTS_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    for (tag, command) in [("fallback-pty", None), ("fallback-pty-command", Some("whoami"))] {
        taken_starts();
        let answer = at_high_without_a_token(tag, TestHost::new(), Mode::Pty, command);
        assert_eq!(
            taken_starts(),
            // The verb's start, then the line the agent falls back to when the verb cannot be started.
            [("pty", true, false), ("pty", false, false)],
            "{tag}"
        );
        assert!(
            answer.stdout.starts_with(&format!("{}\r\n", the_fallback_notice())),
            "{tag}: {}",
            answer.stdout
        );
    }
}

/// The notice comes before the warning for a shell that cannot be used, once each.
#[test]
fn agent_says_the_fallback_notice_before_the_warning_for_a_broken_shell() {
    let _serial = STARTS_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    taken_starts();
    let host = TestHost::new().with_user_config("shell: {strt: x}\n");
    let answer = at_high_without_a_token("fallback-broken", host, Mode::Exec, Some("whoami"));
    taken_starts();
    let notice = format!("{}\n", the_fallback_notice());
    assert!(answer.stderr.starts_with(&notice), "{}", answer.stderr);
    assert!(
        answer.stderr[notice.len()..].starts_with(&format!("ssh-broker: cannot use the shell from {USER_CONFIG}")),
        "{}",
        answer.stderr
    );
}
