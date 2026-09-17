//! Cross-platform tests for the shim relay logic: the EXEC relay (over the in-memory
//! duplex transport), the fail-open decision, and the pure helpers. The Windows console
//! PTY path (raw mode, `ReadConsoleInputW`) is exercised on a real Windows host end-to-end.
use super::{
    ExecOutSink, FailOpen, Fallback, MouseModeSniffer, XtwinopsFilter, decide_fail_open, decide_fallback,
    make_handshake, map_outcome, size_to_resize,
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

/// `ssh host " "` is a genuine exec request; only `ssh host ""` degrades to interactive
/// (measured against a stock client — `ssh.c` sends a shell request only for an empty
/// command buffer, so sshd never sees an empty exec). Mapping a blank command to `None` would hand the caller an
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

/// `BOUNDARY` is deliberately narrower than Rust's `trim`: only the separators this pipeline
/// treats as meaningful. A Unicode space is part of an argument, not padding around one.
#[test]
fn boundary_is_narrower_than_unicode_whitespace() {
    assert_eq!(
        super::normalize_exec(Some("\u{a0}scp -t /p".into())),
        Some("\u{a0}scp -t /p".into())
    );
    assert_eq!(
        super::normalize_exec(Some("\r\n scp -t /p \t".into())),
        Some("scp -t /p".into())
    );
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

/// Fail-open dispatch: a command runs DIRECTLY, and only an interactive session gets a shell.
///
/// Rationale, recorded so this is never "simplified" back: `pwsh -Command` re-parses its
/// argument, so putting an EXEC command through a shell re-quotes it and mangles a binary
/// stream — which is exactly what an `sftp`/`scp` session landing on the fail-open path is. An
/// earlier `exec_local_shell(Some(cmd))` route did precisely that. Now that nothing is routed
/// around the relay, fail-open is the ONLY local execution left, so if it silently regains shell
/// semantics there is no second path left to notice. `run_on` ends in `process::exit`, which is
/// why the choice lives in a pure function rather than being asserted where it is made.
#[test]
fn fail_open_runs_a_command_directly_and_only_interactive_gets_a_shell() {
    // The command must survive verbatim: re-quoting is the failure mode being guarded against,
    // and spaces plus backslashes are what a shell would mangle first.
    let cmd = r#"scp -t "C:\path with spaces\out.bin""#;
    assert_eq!(
        decide_fail_open(Some(cmd.to_string())),
        FailOpen::Passthrough(cmd.to_string()),
        "an EXEC command must run directly, byte for byte, never through a re-quoting shell"
    );
    assert_eq!(
        decide_fail_open(None),
        FailOpen::LocalShell,
        "an interactive session carries no command to run, so it gets pwsh"
    );
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
