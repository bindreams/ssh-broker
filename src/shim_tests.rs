//! Cross-platform tests for the shim relay logic: the EXEC relay (over the in-memory
//! duplex transport), the fail-open decision, and the pure helpers. The Windows console
//! PTY path (raw mode, `ReadConsoleInputW`) is exercised on a real Windows host end-to-end.
use super::{
    ExecOutSink, Fallback, MouseModeSniffer, XtwinopsFilter, decide_fallback, fail_open, is_blank_command,
    make_handshake, map_outcome, size_to_resize, spawn_line,
};
use crate::protocol::{
    ExitCode, FrameKind, FrameReader, Handshake, Launch, Mode, Resize, Stream, read_one_frame, write_frame,
};
use crate::relay::{FrameSink, Outcome, TestSink, duplex, write_data};
use std::io::Write;

#[test]
fn exec_shim_relays_streams_and_exit() {
    let (server, client) = duplex();
    let (mut srx, mut stx) = server.split(); // fake agent end
    let (crx, ctx) = client.split(); // shim end: read agent output on crx, write on ctx

    let agent = std::thread::spawn(move || {
        // Read the handshake the shim sends first.
        let mut fr = FrameReader::new();
        let frame = read_one_frame(&mut srx, &mut fr).unwrap();
        assert_eq!(frame.kind, FrameKind::Handshake);
        let hs = Handshake::decode(&frame.payload).unwrap();
        assert_eq!(hs.mode, Mode::Exec);
        assert_eq!(hs.command.as_deref(), Some("whatever"));
        // Emit stdout, then stderr (kept on a separate stream), then the exit code.
        write_data(&mut stx, Stream::Stdout, b"OUT").unwrap();
        write_data(&mut stx, Stream::Stderr, b"ERR").unwrap();
        write_frame(&mut stx, FrameKind::Exit, &ExitCode(2).encode()).unwrap();
        // stx drops here → the shim sees EXIT then EOF.
    });

    let hs = Handshake {
        mode: Mode::Exec,
        command: Some("whatever".into()),
        ..Handshake::pty_default()
    };
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = super::run_exec_on(crx, ctx, &hs, &mut out, &mut err, std::io::empty()).unwrap();
    agent.join().unwrap();

    assert_eq!(code, 2);
    assert_eq!(out, b"OUT");
    assert_eq!(err, b"ERR");
}

/// The EXEC relay must be byte-transparent. Every command now rides the relay — there is no local
/// route and no classifier — so this property is what makes `scp` and `sftp` work at all, rather
/// than the throughput detail it would have been if transfers were routed around it. Until this
/// test the claim was only ever asserted in prose.
///
/// The claim entered the tree with `40c30b2`, whose message has no body and which bundled two
/// changes. The only defect actually measured there was sftp *hanging* — `std::io::stdout()` is a
/// `LineWriter`, so newline-less output sat in the buffer — and the fix for that is the per-frame
/// flush, which applies to every relayed command. Nothing tested byte-transparency itself, so the
/// premise could diverge silently. This is that test; `verify`'s probe covers the same property
/// end to end, on a real child, real pipes and a real socket.
///
/// Payload: all 256 byte values, so NUL, `0xFF`, a lone CR, a lone LF and invalid UTF-8 are all
/// present. The agent writes it in deliberately awkward chunks — 1 byte, then a chunk ending
/// exactly on a 256 boundary, then the remainder — so no frame aligns with the value cycle and
/// reassembly across frames is exercised rather than assumed.
#[test]
fn exec_relay_is_byte_clean_from_the_agent() {
    let payload: Vec<u8> = (0..=255u8).cycle().take(1024).collect();
    let chunks: Vec<Vec<u8>> = vec![payload[..1].to_vec(), payload[1..257].to_vec(), payload[257..].to_vec()];

    let (server, client) = duplex();
    let (mut srx, mut stx) = server.split();
    let (crx, ctx) = client.split();

    let expect = payload.clone();
    let agent = std::thread::spawn(move || {
        let mut fr = FrameReader::new();
        let _ = read_one_frame(&mut srx, &mut fr).unwrap(); // consume the handshake
        for c in &chunks {
            write_data(&mut stx, Stream::Stdout, c).unwrap();
        }
        // The same bytes on stderr: proves the streams stay separate AND that both stay clean.
        write_data(&mut stx, Stream::Stderr, &expect).unwrap();
        write_frame(&mut stx, FrameKind::Exit, &ExitCode(0).encode()).unwrap();
    });

    let hs = Handshake {
        mode: Mode::Exec,
        command: Some("x".into()),
        ..Handshake::pty_default()
    };
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = super::run_exec_on(crx, ctx, &hs, &mut out, &mut err, std::io::empty()).unwrap();
    agent.join().unwrap();

    assert_eq!(code, 0);
    assert_eq!(out, payload, "stdout must round-trip every byte value unchanged");
    assert_eq!(err, payload, "stderr must round-trip too, and not merge into stdout");
}

/// The upstream half of the same premise: bytes the client sends — an `sftp put`, an `scp`
/// upload — must reach the agent unchanged. This direction carries a hazard the downstream one
/// does not: `forward_stdin` signals end-of-input with an EMPTY `Stdin` frame rather than by
/// closing the connection (closing would make the agent treat it as a disconnect and kill the
/// child), so a reader that took a zero-length payload for data would corrupt an upload.
///
/// Same adversarial payload as the downstream test: all 256 byte values.
#[test]
fn exec_relay_is_byte_clean_to_the_agent() {
    let payload: Vec<u8> = (0..=255u8).cycle().take(1024).collect();

    let (server, client) = duplex();
    let (mut srx, mut stx) = server.split();
    let (crx, ctx) = client.split();

    let agent = std::thread::spawn(move || {
        let mut fr = FrameReader::new();
        let _ = read_one_frame(&mut srx, &mut fr).unwrap(); // consume the handshake
        let mut got = Vec::new();
        loop {
            let frame = read_one_frame(&mut srx, &mut fr).unwrap();
            assert_eq!(frame.kind, FrameKind::Data);
            assert_eq!(
                frame.payload[0],
                Stream::Stdin as u8,
                "only stdin flows upstream in EXEC"
            );
            let bytes = &frame.payload[1..];
            if bytes.is_empty() {
                break; // the stdin-EOF marker — NOT a zero-length write
            }
            got.extend_from_slice(bytes);
        }
        write_frame(&mut stx, FrameKind::Exit, &ExitCode(0).encode()).unwrap();
        got
    });

    let hs = Handshake {
        mode: Mode::Exec,
        command: Some("x".into()),
        ..Handshake::pty_default()
    };
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = super::run_exec_on(crx, ctx, &hs, &mut out, &mut err, std::io::Cursor::new(payload.clone())).unwrap();
    let got = agent.join().unwrap();

    assert_eq!(code, 0);
    assert_eq!(got, payload, "stdin must round-trip every byte value unchanged");
}

#[test]
fn exec_shim_dead_agent_is_255_not_command_failure() {
    // The agent dies after spawning the child but before writing EXIT (e.g. crash). The shim
    // must NOT report exit 1 — that would be indistinguishable from a real command failure.
    let (server, client) = duplex();
    let (mut srx, mut stx) = server.split();
    let (crx, ctx) = client.split();

    let agent = std::thread::spawn(move || {
        let mut fr = FrameReader::new();
        let _ = read_one_frame(&mut srx, &mut fr).unwrap(); // consume handshake
        write_data(&mut stx, Stream::Stdout, b"partial output").unwrap();
        // Drop stx WITHOUT an EXIT frame → the shim sees PeerClosed.
    });

    let hs = Handshake {
        mode: Mode::Exec,
        command: Some("x".into()),
        ..Handshake::pty_default()
    };
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = super::run_exec_on(crx, ctx, &hs, &mut out, &mut err, std::io::empty()).unwrap();
    agent.join().unwrap();
    assert_eq!(code, 255, "a dead agent (no EXIT frame) must map to 255");
}

#[test]
fn exec_shim_truncated_stream_is_254() {
    // A frame cut mid-way (truncation) is a protocol error → exit 254, distinct from both a
    // clean failure and a clean disconnect.
    use std::io::Write;
    let (server, client) = duplex();
    let (mut srx, mut stx) = server.split();
    let (crx, ctx) = client.split();

    let agent = std::thread::spawn(move || {
        let mut fr = FrameReader::new();
        let _ = read_one_frame(&mut srx, &mut fr).unwrap();
        // Write an incomplete frame header (the header is 5 bytes) then drop.
        stx.write_all(&[2u8, 5, 0]).unwrap();
    });

    let hs = Handshake {
        mode: Mode::Exec,
        command: Some("x".into()),
        ..Handshake::pty_default()
    };
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = super::run_exec_on(crx, ctx, &hs, &mut out, &mut err, std::io::empty()).unwrap();
    agent.join().unwrap();
    assert_eq!(code, 254, "a truncated frame must map to 254");
}

#[test]
fn size_event_maps_to_resize_frame() {
    assert_eq!(size_to_resize(120, 40), Resize { cols: 120, rows: 40 });
}

/// The leading `BOUNDARY` characters are trimmed (`CreateProcessW` fails on a line that starts
/// with one). Nothing else is: a Unicode space is part of an argument.
#[test]
fn spawn_line_trims_the_leading_boundary_characters() {
    assert_eq!(spawn_line("  cmd /c x"), "cmd /c x");
    assert_eq!(spawn_line("\t\r\n scp -t /p"), "scp -t /p");
    assert_eq!(spawn_line("\u{a0}scp -t /p\u{a0}"), "\u{a0}scp -t /p\u{a0}");
    assert_eq!(spawn_line("a  b"), "a  b");
}

/// Trailing space and tab reach the program: `cmd /c echo a   ` prints `a   `.
#[test]
fn spawn_line_keeps_trailing_spaces_and_tabs() {
    assert_eq!(spawn_line("cmd /c echo a   "), "cmd /c echo a   ");
    assert_eq!(spawn_line("  cmd /c echo a \t"), "cmd /c echo a \t");
    assert_eq!(spawn_line("whoami "), "whoami ");
}

/// Nothing trailing is trimmed, whatever the shape of the line: a trailing line break fails like a
/// misspelled program (`CreateProcessW` reports `ERROR_FILE_NOT_FOUND`), by design. Which shapes
/// `CreateProcessW` would run as sent depends on the files on disk, so no string rule can tell
/// them apart.
#[test]
fn spawn_line_keeps_trailing_line_breaks_in_every_shape() {
    // arguments
    assert_eq!(spawn_line("scp -t /p\r\n"), "scp -t /p\r\n");
    assert_eq!(spawn_line("scp -t /p \t\r\n"), "scp -t /p \t\r\n");
    // bare program name
    assert_eq!(spawn_line("whoami\n"), "whoami\n");
    assert_eq!(spawn_line("\r\n whoami\r\n"), "whoami\r\n");
    assert_eq!(spawn_line("whoami\r\n\r\n"), "whoami\r\n\r\n");
    // quoted program name
    assert_eq!(spawn_line("\"whoami\"\n"), "\"whoami\"\n");
    assert_eq!(spawn_line("\"C:\\tools\\prog.exe\"\r\n"), "\"C:\\tools\\prog.exe\"\r\n");
    assert_eq!(spawn_line("\r\n\"whoami\"\n"), "\"whoami\"\n");
    // unclosed quote
    assert_eq!(spawn_line("\"whoami\n"), "\"whoami\n");
    assert_eq!(spawn_line(" \"whoami\r\n"), "\"whoami\r\n");
    // unquoted spaced path, with and without arguments
    assert_eq!(spawn_line("C:\\Sp Dir\\p.exe\n"), "C:\\Sp Dir\\p.exe\n");
    assert_eq!(spawn_line("C:\\Sp Dir\\p.exe /?\r\n"), "C:\\Sp Dir\\p.exe /?\r\n");
}

#[test]
fn exec_out_sink_flushes_each_frame() {
    // The bug that hung sftp: streaming/binary output (no newlines) must reach the client
    // immediately, not sit in a LineWriter buffer until a newline or process exit.
    #[derive(Default)]
    struct FlushSpy {
        bytes: Vec<u8>,
        flushes: usize,
    }
    impl std::io::Write for FlushSpy {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.bytes.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }
    let mut sink = ExecOutSink {
        out: FlushSpy::default(),
        err: FlushSpy::default(),
    };
    sink.on_data(Stream::Stdout, b"binary-no-newline").unwrap();
    sink.on_data(Stream::Stderr, b"err-no-newline").unwrap();
    assert_eq!(sink.out.bytes, b"binary-no-newline");
    assert_eq!(sink.out.flushes, 1, "stdout must flush after each frame");
    assert_eq!(sink.err.bytes, b"err-no-newline");
    assert_eq!(sink.err.flushes, 1, "stderr must flush after each frame");
}

#[test]
fn fail_open_when_agent_unreachable() {
    assert_eq!(decide_fallback(true), Fallback::LocalShellWithWarning);
    assert_eq!(decide_fallback(false), Fallback::Relay);
}

// ── fail_open (the line it runs, and what it says first) ───────────────────────────

use crate::cmdline::Exec;
use crate::shell::test_host::{SYSTEM_CMD, TestHost, USER_CONFIG};

const PWSH: &str = r"C:\Program Files\PowerShell\7\pwsh.exe";

fn pwsh_host() -> TestHost {
    TestHost::new()
        .with_program("pwsh.exe", PWSH)
        .with_user_config("shell: pwsh.exe\n")
}

fn exec(command: &str, terminal: bool) -> Option<Exec> {
    Some(Exec {
        command: command.into(),
        terminal,
    })
}

/// Run `fail_open` with a `run` that records the line and returns `code`; returns what it saw.
fn failed_open(host: &TestHost, exec: &Option<Exec>, code: anyhow::Result<i32>) -> (i32, Option<String>, String) {
    let mut stderr = Vec::new();
    let mut line = None;
    let got = fail_open(host, exec, &mut stderr, |l| {
        line = Some(l.to_owned());
        code
    });
    (got, line, String::from_utf8(stderr).unwrap())
}

#[test]
fn fail_open_runs_the_planned_line_for_commands_and_for_the_interactive_session() {
    let host = pwsh_host();
    let cmd = r#"scp -t "C:\path with spaces\out.bin""#;
    let (code, line, stderr) = failed_open(&host, &exec(cmd, false), Ok(7));
    assert_eq!(code, 7);
    assert_eq!(
        line.as_deref(),
        Some(crate::cmdline::join_args(&[PWSH, "-c", cmd]).as_str()),
        "a command goes to the shell as one argument, not as a program"
    );
    assert_eq!(stderr, "");

    let (_, line, _) = failed_open(&host, &exec("echo  hi", true), Ok(0));
    assert_eq!(
        line.as_deref(),
        Some(format!(r#""{PWSH}" -c echo  hi"#).as_str()),
        "a terminal appends as is"
    );

    let (_, line, _) = failed_open(&host, &None, Ok(0));
    assert_eq!(line.as_deref(), Some(format!(r#""{PWSH}""#).as_str()));

    let (_, line, _) = failed_open(&TestHost::new(), &exec("echo hi", false), Ok(0));
    assert_eq!(line, Some(format!(r#"{SYSTEM_CMD} /c "echo hi""#)));
}

#[test]
fn the_fallback_warning_precedes_the_child_on_stderr() {
    let host = TestHost::new().with_user_config("shell: {strt: x}\n");
    for exec in [exec("echo hi", false), None] {
        let mut events = Vec::new();
        let mut stderr = Vec::new();
        fail_open(&host, &exec, &mut stderr, |_line| {
            events.push("child");
            Ok(0)
        });
        let text = String::from_utf8(stderr).unwrap();
        assert!(text.starts_with("ssh-broker: cannot use the shell from "), "{text:?}");
        assert!(
            text.contains(USER_CONFIG) && text.ends_with("using the built-in cmd.exe\n"),
            "{text:?}"
        );
        assert_eq!(text.matches("cannot use the shell").count(), 1);
        assert_eq!(events, ["child"]);
    }
}

#[test]
fn a_warning_is_written_before_the_run_closure_is_called() {
    use std::cell::RefCell;
    struct Spy<'a>(&'a RefCell<Vec<String>>);
    impl Write for Spy<'_> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0
                .borrow_mut()
                .push(format!("stderr:{}", String::from_utf8_lossy(bytes).trim_end()));
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let events = RefCell::new(Vec::new());
    let host = TestHost::new().with_user_config("shell: nonesuch.exe\n");
    fail_open(&host, &None, &mut Spy(&events), |_| {
        events.borrow_mut().push("run".into());
        Ok(0)
    });
    let events = events.into_inner();
    assert!(
        events
            .first()
            .is_some_and(|e| e.starts_with("stderr:ssh-broker: cannot use the shell")),
        "{events:?}"
    );
    assert_eq!(events.last().map(String::as_str), Some("run"), "{events:?}");
}

#[test]
fn a_fail_open_that_cannot_run_exits_255_and_says_why_for_a_command_only() {
    let host = pwsh_host();
    let (code, _, stderr) = failed_open(&host, &exec("echo hi", false), Err(anyhow::anyhow!("access denied")));
    assert_eq!(code, 255);
    assert_eq!(stderr, "ssh-broker: could not run the command locally: access denied\n");
    // An interactive session's failure goes to the log only.
    let (code, _, stderr) = failed_open(&host, &None, Err(anyhow::anyhow!("access denied")));
    assert_eq!((code, stderr.as_str()), (255, ""));

    let too_long = "x".repeat(40_000);
    let (code, line, stderr) = failed_open(&host, &exec(&too_long, false), Ok(0));
    assert_eq!(code, 255);
    assert_eq!(line, None, "nothing was started");
    assert!(stderr.contains("32,767"), "{stderr}");
}

#[test]
fn xtwinops_filter_passes_plain_text_through() {
    let mut f = XtwinopsFilter::new();
    assert_eq!(f.filter(b"hello world"), b"hello world");
}

#[test]
fn xtwinops_filter_strips_window_manipulation() {
    let mut f = XtwinopsFilter::new();
    // CSI 8 ; 50 ; 100 t  (resize-window report) must be removed; surrounding text kept.
    assert_eq!(f.filter(b"a\x1b[8;50;100tb"), b"ab");
}

#[test]
fn xtwinops_filter_preserves_other_csi() {
    let mut f = XtwinopsFilter::new();
    // SGR colour sequences end in 'm', not 't' — must pass through untouched.
    assert_eq!(f.filter(b"\x1b[31mred\x1b[0m"), b"\x1b[31mred\x1b[0m");
}

#[test]
fn xtwinops_filter_handles_sequence_split_across_reads() {
    let mut f = XtwinopsFilter::new();
    // An XTWINOPS sequence split mid-way: first chunk yields nothing (held), the second
    // completes the dropped sequence and emits the trailing byte.
    assert_eq!(f.filter(b"X\x1b[8;50"), b"X");
    assert_eq!(f.filter(b";100tY"), b"Y");

    // A non-XTWINOPS CSI split across reads is reassembled and emitted in full.
    let mut g = XtwinopsFilter::new();
    assert_eq!(g.filter(b"\x1b[3"), b"");
    assert_eq!(g.filter(b"1m!"), b"\x1b[31m!");
}

#[test]
fn xtwinops_filter_passes_non_csi_escape_through() {
    let mut f = XtwinopsFilter::new();
    // ESC not followed by '[' (here an OSC introducer) is not a CSI — pass it through.
    assert_eq!(f.filter(b"\x1b]0;title\x07"), b"\x1b]0;title\x07");
}

// ── map_outcome (pure exit-code policy) ────────────────────────────────────────────

#[test]
fn map_outcome_exit_code_policy() {
    // A clean exit propagates verbatim (incl. high-bit NTSTATUS, bit-preserved).
    assert_eq!(map_outcome(Ok(Outcome::Exited(7))), 7);
    assert_eq!(map_outcome(Ok(Outcome::Exited(0))), 0);
    // A dead/abrupt peer is never 0; protocol errors get a distinct nonzero.
    assert_eq!(map_outcome(Ok(Outcome::PeerClosed)), 255);
    assert_eq!(
        map_outcome(Err(crate::relay::PumpError::Protocol(anyhow::anyhow!(
            "truncated frame"
        )))),
        254
    );
}

// ── make_handshake (pure field mapping) ────────────────────────────────────────────

#[test]
fn no_command_is_pty_without_a_command() {
    let hs = make_handshake(&None, false, Launch::Shell, "screen-256color".into(), 100, 30);
    assert_eq!(hs.mode, Mode::Pty);
    assert_eq!(hs.command, None);
    assert_eq!(hs.launch, Launch::Shell);
    assert_eq!((hs.cols, hs.rows), (100, 30));
    assert_eq!(hs.term, "screen-256color");
    assert!(hs.cwd.is_empty()); // agent uses the session-1 default cwd
    assert!(hs.env.is_empty()); // nothing forwarded in v1
    assert_eq!(hs.version, crate::protocol::PROTOCOL_VERSION);
}

#[test]
fn a_command_without_a_terminal_is_exec() {
    let hs = make_handshake(&Some("git status".into()), false, Launch::Shell, "xterm".into(), 80, 24);
    assert_eq!(hs.mode, Mode::Exec);
    assert_eq!(hs.command.as_deref(), Some("git status"));
}

#[test]
fn a_command_with_a_terminal_is_a_pty_handshake_with_the_command() {
    let hs = make_handshake(&Some("git status".into()), true, Launch::Shell, "xterm".into(), 120, 40);
    assert_eq!(hs.mode, Mode::Pty);
    assert_eq!(hs.command.as_deref(), Some("git status"));
    assert_eq!((hs.cols, hs.rows), (120, 40));
}

#[test]
fn the_launch_is_carried_as_given() {
    for launch in [Launch::Shell, Launch::Direct] {
        assert_eq!(make_handshake(&None, false, launch, String::new(), 0, 0).launch, launch);
    }
}

// ── MouseModeSniffer (pure; gates mouse forwarding) ────────────────────────────────

#[test]
fn sniffer_requires_both_tracking_and_sgr() {
    let mut s = MouseModeSniffer::new();
    assert!(!s.forward_mouse());
    s.observe(b"\x1b[?1000h"); // tracking on, SGR still off
    assert!(s.tracking_on());
    assert!(!s.sgr_on());
    assert!(!s.forward_mouse());
    s.observe(b"\x1b[?1006h"); // SGR on → now both
    assert!(s.forward_mouse());
}

#[test]
fn sniffer_multi_param_single_csi() {
    let mut s = MouseModeSniffer::new();
    s.observe(b"\x1b[?1002;1006h"); // button-drag tracking + SGR in one sequence
    assert!(s.forward_mouse());
}

#[test]
fn sniffer_disable_one_tracking_mode_keeps_another() {
    let mut s = MouseModeSniffer::new();
    s.observe(b"\x1b[?1000h\x1b[?1002h\x1b[?1006h");
    assert!(s.forward_mouse());
    s.observe(b"\x1b[?1000l"); // disable click-tracking; button-drag (1002) still on
    assert!(s.tracking_on());
    assert!(s.forward_mouse());
    s.observe(b"\x1b[?1002l"); // now no tracking modes remain
    assert!(!s.tracking_on());
    assert!(!s.forward_mouse());
}

#[test]
fn sniffer_handles_sequence_split_across_reads() {
    let mut s = MouseModeSniffer::new();
    s.observe(b"\x1b[?100");
    s.observe(b"0h\x1b[?10");
    s.observe(b"06h");
    assert!(s.forward_mouse());
}

#[test]
fn sniffer_ignores_unrelated_sequences() {
    let mut s = MouseModeSniffer::new();
    // SGR colour and XTWINOPS must not flip any mouse flag.
    s.observe(b"\x1b[31mred\x1b[0m\x1b[8;50;100t");
    assert!(!s.tracking_on());
    assert!(!s.sgr_on());
    // A non-private CSI ending in 'h' (e.g. SM, no '?') must not be read as a mode set.
    s.observe(b"\x1b[4h");
    assert!(!s.tracking_on());
}

// ── focus-tracking mode (?1004) ────────────────────────────────────────────────────

#[test]
fn sniffer_focus_set_and_clear() {
    let mut s = MouseModeSniffer::new();
    assert!(!s.focus_on());
    s.observe(b"\x1b[?1004h"); // focus reporting on
    assert!(s.focus_on());
    s.observe(b"\x1b[?1004l"); // focus reporting off
    assert!(!s.focus_on());
}

#[test]
fn sniffer_focus_combined_with_mouse_in_one_csi() {
    let mut s = MouseModeSniffer::new();
    s.observe(b"\x1b[?1002;1004;1006h"); // button-drag tracking + focus + SGR in one sequence
    assert!(s.focus_on());
    assert!(s.tracking_on());
    assert!(s.sgr_on());
    assert!(s.forward_mouse());
}

#[test]
fn sniffer_focus_handles_sequence_split_across_reads() {
    let mut s = MouseModeSniffer::new();
    s.observe(b"\x1b[?100");
    s.observe(b"4h");
    assert!(s.focus_on());
}

#[test]
fn sniffer_focus_independent_of_mouse_flags() {
    // ?1004 must not flip mouse tracking/sgr, and mouse modes must not flip focus.
    let mut s = MouseModeSniffer::new();
    s.observe(b"\x1b[?1004h");
    assert!(s.focus_on());
    assert!(!s.tracking_on());
    assert!(!s.sgr_on());
    assert!(!s.forward_mouse());

    let mut t = MouseModeSniffer::new();
    t.observe(b"\x1b[?1000h\x1b[?1006h"); // mouse tracking + SGR
    assert!(t.forward_mouse());
    assert!(!t.focus_on());
}

/// A blank exec (empty, or only space, tab, CR and LF) runs nothing, as the shell does for
/// `-c ""`. The set is spelled out here so a change to `BOUNDARY` shows up as a failure.
#[test]
fn a_blank_command_is_empty_or_only_space_tab_cr_lf() {
    for blank in ["", " ", "\t", "\r", "\n", "\r\n", " \t\r\n "] {
        assert!(is_blank_command(blank), "{blank:?}");
    }
    // A Unicode space is part of an argument (see `BOUNDARY`), so it is not blank.
    for not_blank in ["\u{a0}", "cmd", " cmd ", "\0", "\u{b}", "\u{c}"] {
        assert!(!is_blank_command(not_blank), "{not_blank:?}");
    }
}

// The agent that never answers, and the input of a command -----

use super::{PumpError, Pumped, Started, peer_gone, start_exec_input};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};

/// A connection that hands what is written to it to the test, a write at a time.
struct Wire(mpsc::Sender<Vec<u8>>);

impl std::io::Write for Wire {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .send(bytes.to_vec())
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn wire() -> (Wire, mpsc::Receiver<Vec<u8>>) {
    let (tx, rx) = mpsc::channel();
    (Wire(tx), rx)
}

/// The next `n` frames written to a connection, as `(kind, payload)`. Blocks until they arrive.
fn frames(from: &mpsc::Receiver<Vec<u8>>, n: usize) -> Vec<(FrameKind, Vec<u8>)> {
    let mut fr = FrameReader::new();
    let mut got = Vec::new();
    while got.len() < n {
        while let Some(frame) = fr.next_frame().unwrap() {
            got.push((frame.kind, frame.payload));
        }
        if got.len() < n {
            fr.push(&from.recv().expect("the connection closed before the frames came"));
        }
    }
    got
}

fn exec_handshake() -> Handshake {
    make_handshake(&Some("sort".into()), false, Launch::Shell, "xterm".into(), 80, 24)
}

fn stdin_data(payload: &[u8]) -> (FrameKind, Vec<u8>) {
    let mut p = vec![Stream::Stdin as u8];
    p.extend_from_slice(payload);
    (FrameKind::Data, p)
}

/// Input that is read once the test lets it: ends at EOF, and says when the reader has dropped it, which
/// the forwarder does as it returns.
struct Stdin {
    data: std::io::Cursor<Vec<u8>>,
    dropped: mpsc::Sender<()>,
}

impl std::io::Read for Stdin {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        std::io::Read::read(&mut self.data, buf)
    }
}

impl Drop for Stdin {
    fn drop(&mut self) {
        let _ = self.dropped.send(());
    }
}

/// A connection that says when it is closed.
struct Tracked(Arc<AtomicBool>, Wire);

impl std::io::Write for Tracked {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        std::io::Write::write(&mut self.1, bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for Tracked {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[test]
fn the_handshake_goes_first_and_the_input_follows_with_the_end_marker() {
    let (conn, from_conn) = wire();
    let (dropped, _) = mpsc::channel();
    let stdin = Stdin {
        data: std::io::Cursor::new(
            b"b
a
"
            .to_vec(),
        ),
        dropped,
    };
    let _keep = match start_exec_input(conn, &exec_handshake(), stdin).unwrap() {
        Started::Ready(keep) => keep,
        Started::Closed(e) => panic!("{e:#}"),
    };
    let sent = frames(&from_conn, 3);
    assert_eq!(sent[0].0, FrameKind::Handshake);
    assert_eq!(
        sent[1],
        stdin_data(
            b"b
a
"
        )
    );
    assert_eq!(sent[2], stdin_data(b""), "the end of input is a marker, not a close");
}

#[test]
fn the_connection_stays_open_after_the_end_of_input_until_the_session_is_over() {
    // The agent takes a close of the socket for a disconnect and kills the command, so the write half
    // is held by the caller, not by the thread that forwards the input and ends with it.
    let closed = Arc::new(AtomicBool::new(false));
    let (conn, from_conn) = wire();
    let (dropped, forwarder_returned) = mpsc::channel();
    let stdin = Stdin {
        data: std::io::Cursor::new(Vec::new()),
        dropped,
    };
    let keep = match start_exec_input(Tracked(Arc::clone(&closed), conn), &exec_handshake(), stdin).unwrap() {
        Started::Ready(keep) => keep,
        Started::Closed(e) => panic!("{e:#}"),
    };
    assert_eq!(frames(&from_conn, 2)[1], stdin_data(b""));
    forwarder_returned
        .recv()
        .expect("the forwarder returns once stdin has ended");
    assert!(
        !closed.load(Ordering::SeqCst),
        "the connection was closed with the end of the input"
    );
    drop(keep);
    assert!(closed.load(Ordering::SeqCst), "and it closes when the session is over");
}

#[test]
fn a_handshake_to_a_peer_that_has_gone_is_reported_not_raised() {
    let (gone, from_gone) = wire();
    drop(from_gone);
    match start_exec_input(gone, &exec_handshake(), std::io::empty()).unwrap() {
        Started::Closed(e) => assert_eq!(peer_gone(&e), Some(std::io::ErrorKind::BrokenPipe)),
        Started::Ready(_) => panic!("the peer had gone"),
    }
}

#[test]
fn a_handshake_that_fails_for_another_reason_is_an_error() {
    struct Denied;
    impl std::io::Write for Denied {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::PermissionDenied.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    assert!(start_exec_input(Denied, &exec_handshake(), std::io::empty()).is_err());
}

#[test]
fn only_a_connection_that_ended_without_a_byte_from_the_agent_is_unanswered() {
    use std::io::ErrorKind::{ConnectionReset, PermissionDenied};
    let transport = |kind| Err(PumpError::Transport(std::io::Error::from(kind)));
    let protocol = || Err(PumpError::Protocol(anyhow::anyhow!("bad frame")));
    let cases: [(&str, Result<Outcome, PumpError>, bool, bool); 7] = [
        ("closed, silent", Ok(Outcome::PeerClosed), false, true),
        ("reset, silent", transport(ConnectionReset), false, true),
        ("closed after a byte", Ok(Outcome::PeerClosed), true, false),
        ("reset after a byte", transport(ConnectionReset), true, false),
        ("exited", Ok(Outcome::Exited(0)), true, false),
        ("another transport failure", transport(PermissionDenied), false, false),
        ("protocol error", protocol(), true, false),
    ];
    for (name, outcome, heard, unanswered) in cases {
        assert_eq!(Pumped { outcome, heard }.no_answer(), unanswered, "{name}");
    }
}

#[test]
fn the_pump_notes_whether_the_agent_sent_a_byte() {
    let mut silent: &[u8] = b"";
    let pumped = super::pump_heard(&mut silent, &mut FrameReader::new(), &mut TestSink::default());
    assert!(!pumped.heard && pumped.no_answer());

    let mut exit = Vec::new();
    write_frame(&mut exit, FrameKind::Exit, &ExitCode(3).encode()).unwrap();
    let pumped = super::pump_heard(&mut exit.as_slice(), &mut FrameReader::new(), &mut TestSink::default());
    assert!(pumped.heard && !pumped.no_answer());
    assert_eq!(pumped.code(), 3);
}
