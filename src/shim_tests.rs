//! Cross-platform tests for the shim relay logic: the EXEC relay (over the in-memory
//! duplex transport), the fail-open decision, and the pure helpers. The Windows console
//! PTY path (raw mode, `ReadConsoleInputW`) is exercised on winhost / in Phase 8.
use crate::protocol::{
    ExitCode, FrameKind, FrameReader, Handshake, Mode, Resize, Stream, read_one_frame, write_frame,
};
use crate::relay::{Outcome, duplex, write_data};
use super::{
    Fallback, MouseModeSniffer, XtwinopsFilter, decide_fallback, make_handshake, map_outcome,
    size_to_resize,
};

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

    let hs = Handshake { mode: Mode::Exec, command: Some("x".into()), ..Handshake::pty_default() };
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

    let hs = Handshake { mode: Mode::Exec, command: Some("x".into()), ..Handshake::pty_default() };
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
    assert_eq!(map_outcome(Err(anyhow::anyhow!("truncated frame"))), 254);
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
