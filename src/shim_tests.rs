//! Cross-platform tests for the shim relay logic: the EXEC relay (over the in-memory
//! duplex transport), the fail-open decision, and the pure helpers. The Windows console
//! PTY path (raw mode, `ReadConsoleInputW`) is exercised on a real Windows host end-to-end.
use super::{
    ExecOutSink, Fallback, MouseModeSniffer, XtwinopsFilter, decide_fallback, is_transfer_command, make_handshake,
    map_outcome, size_to_resize, split_command,
};
use crate::protocol::{ExitCode, FrameKind, FrameReader, Handshake, Mode, Resize, Stream, read_one_frame, write_frame};
use crate::relay::{FrameSink, Outcome, duplex, write_data};

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

// ── is_transfer_command (route sftp/scp locally, not through the agent) ──────────────

/// `ssh host " "` is a genuine exec request; only `ssh host ""` degrades to interactive
/// (measured against a stock sshd). Mapping a blank command to `None` would hand the caller an
/// interactive REPL on the SSH channel instead of running its no-op.
#[test]
fn normalize_exec_trims_but_keeps_a_blank_command_an_exec() {
    assert_eq!(super::normalize_exec(Some("  cmd  ".into())), Some("cmd".into()));
    assert_eq!(
        super::normalize_exec(Some(" ".into())),
        Some(String::new()),
        "stays an exec"
    );
    assert_eq!(super::normalize_exec(None), None);
}

#[test]
fn detects_sftp_and_scp_transfers() {
    // The sftp subsystem (the dominant path) — bare name, full path, internal-sftp.
    assert!(is_transfer_command("sftp-server.exe"));
    assert!(is_transfer_command(r"C:\Windows\System32\OpenSSH\sftp-server.exe"));
    assert!(is_transfer_command("sftp-server.exe -l ERROR")); // with args
    assert!(is_transfer_command("internal-sftp"));
    // A quoted path with spaces (a "C:\Program Files\OpenSSH\…" install) must still be detected
    // — split_whitespace would shatter it and re-hang sftp.
    assert!(is_transfer_command(r#""C:\Program Files\OpenSSH\sftp-server.exe""#));
    assert!(is_transfer_command(
        r#""C:\Program Files\OpenSSH\sftp-server.exe" -l ERROR"#
    ));
    // The rcp protocol's `-t`/`-f`, wherever it falls in the argument list.
    assert!(is_transfer_command("scp -t /tmp/x"));
    assert!(is_transfer_command("scp -p -f /tmp/x"));
    // Both shapes below are what an OpenSSH 10.3 client actually sends, measured rather than
    // assumed, and both were missed while the flag had to sit immediately before the last
    // token. A remote path containing a space is the ordinary case on Windows.
    assert!(is_transfer_command("scp -t -- -dst"), "a path starting with a dash");
    assert!(is_transfer_command("scp -f -- -src"), "the fetch direction");
    assert!(is_transfer_command("scp -r -p -t /my dir/with spaces/"));
    // Windows separates arguments on space and tab only, so a stray CR/LF stays glued to the
    // program name; the scan this replaced split on any whitespace and caught these.
    assert!(
        is_transfer_command("sftp-server.exe\r"),
        "a trailing CR must not hide a transfer"
    );
    assert!(is_transfer_command("\nsftp-server.exe"), "nor a leading LF");
    // An attached value carries its own argument, so the `-t` after it is a real flag. Matching
    // on a token's last character got this backwards and ate the `-t`.
    assert!(is_transfer_command("scp -oStrictHostKeyChecking=no -t /p"));
    assert!(
        is_transfer_command("scp -i key -t /p"),
        "`-i` consumed `key`, so `-t` is a flag"
    );
}

#[test]
fn does_not_misdetect_normal_commands() {
    // A user running scp on the remote host to a THIRD host wants session-1 parity, not a
    // local transfer.
    assert!(!is_transfer_command("scp file other-host:/path"));

    // A `-t`/`-f` that is an option's argument, or an operand, must NOT be misdetected.
    assert!(!is_transfer_command("scp -- -t host:/p")); // `-t` is an operand, not a flag
    assert!(!is_transfer_command("scp -i -t file host:/p")); // `-t` is `-i`'s argument
    assert!(!is_transfer_command("scp -o -f a host:/p")); // `-f` is `-o`'s argument
    assert!(!is_transfer_command("scp -if /tmp/x")); // `f` clustered behind a value-taking `-i`

    assert!(!is_transfer_command("pwsh -c Get-ChildItem"));
    assert!(!is_transfer_command("git status"));
    assert!(!is_transfer_command("sftp-something-else.exe")); // not sftp-server
    assert!(!is_transfer_command(""));
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
fn make_handshake_pty_fields() {
    let hs = make_handshake(&None, "screen-256color".into(), 100, 30);
    assert_eq!(hs.mode, Mode::Pty);
    assert_eq!(hs.command, None);
    assert_eq!((hs.cols, hs.rows), (100, 30));
    assert_eq!(hs.term, "screen-256color");
    assert!(hs.cwd.is_empty()); // agent uses the session-1 default cwd
    assert!(hs.env.is_empty()); // nothing forwarded in v1
    assert_eq!(hs.version, crate::protocol::PROTOCOL_VERSION);
}

#[test]
fn make_handshake_exec_fields() {
    let hs = make_handshake(&Some("git status".into()), "xterm".into(), 80, 24);
    assert_eq!(hs.mode, Mode::Exec);
    assert_eq!(hs.command.as_deref(), Some("git status"));
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

/// The UTF-16 round trip around `cosca::quote::windows::split_wide` is this module's own code,
/// so it gets its own test; the splitter's fidelity to `CommandLineToArgvW` is verified by
/// cosca's differential suite against the real OS parser and is not re-tested here.
#[test]
fn split_command_round_trips_utf16_through_the_splitter() {
    assert_eq!(split_command(r#"prog "a b" c"#), vec!["prog", "a b", "c"]);
    // Not a re-test of cosca's differential suite (see above) — these pin the specific
    // divergences this module's routing depends on, so a splitter swap that reintroduced the
    // old scan's behaviour fails here instead of silently misrouting. Every expectation below
    // was measured against the splitter, not reasoned out.
    //
    // A backslash run is only special immediately before a quote; elsewhere it stays literal.
    assert_eq!(
        split_command(r#"p "a\\b""#),
        vec!["p", r"a\\b"],
        "not before a quote: literal"
    );
    assert_eq!(split_command(r##"p "a\"b""##), vec!["p", r#"a"b"#], "an escaped quote");
    // argv[0] is parsed by a DIFFERENT rule: no backslash-escaping at all. The input must
    // contain a quote to discriminate — a bare backslash run is literal under both rules, so
    // an assertion built on one passes even if argv[0] were parsed by the argv[1..] rule.
    assert_eq!(
        split_command(r##"a\"b c"##),
        vec![r#"a\"b"#, "c"],
        "argv[0] keeps the escape"
    );
    assert_eq!(
        split_command(r##"p a\"b c"##),
        vec!["p", r#"a"b"#, "c"],
        "argv[1..] unescapes"
    );
    // shell32's mod-3 rule for a run of bare quotes inside a quoted region.
    assert_eq!(
        split_command(r##"p "a""""##),
        vec!["p", r#"a""#],
        "three quotes yield one"
    );
    // The exact divergence documented on `split_command`: the old scan produced `C:\dir\`.
    assert_eq!(
        split_command(r##"scp -t "C:\dir\"""##),
        vec!["scp", "-t", r#"C:\dir""#],
        "an escaped quote inside a path operand"
    );
    // Non-ASCII survives the &str -> UTF-16 -> String round trip intact.
    assert_eq!(
        split_command("prog \u{e9}t\u{e9} \u{1f600}"),
        vec!["prog", "\u{e9}t\u{e9}", "\u{1f600}"]
    );
    assert!(
        split_command("   ").is_empty(),
        "whitespace-only input yields no tokens"
    );
}
