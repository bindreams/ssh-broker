//! Unit tests for the `relay` module (sibling-file style per project conventions).
use super::*;
use crate::protocol::{ExitCode, FrameHeader, FrameKind, FrameReader, Resize, Stream, write_frame};
use std::io::{Read, Write};
use std::thread;

#[test]
fn inmem_duplex_moves_bytes() {
    let (mut a, mut b) = duplex();
    // Writer on its own thread, so the test is robust to the transport's buffering.
    let t = thread::spawn(move || {
        a.write_all(b"ping").unwrap();
    });
    let mut buf = [0u8; 4];
    b.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"ping");
    t.join().unwrap();
}

#[test]
fn duplex_reader_sees_eof_when_peer_dropped() {
    let (a, mut b) = duplex();
    drop(a); // peer's write half gone
    let mut got = Vec::new();
    b.read_to_end(&mut got).unwrap(); // relies on a clean Ok(0) EOF
    assert!(got.is_empty());
}

#[test]
fn split_halves_carry_bytes_and_eof() {
    // Mirrors the relay's real use: each connection end is split into (rx, tx) for two
    // independent threads.
    let (a, b) = duplex();
    let (mut a_rx, _a_tx) = a.split();
    let (_b_rx, mut b_tx) = b.split();
    let t = thread::spawn(move || {
        b_tx.write_all(b"hello").unwrap();
        // b_tx drops here -> a_rx hits EOF after draining "hello"
    });
    let mut got = Vec::new();
    a_rx.read_to_end(&mut got).unwrap();
    assert_eq!(got, b"hello");
    t.join().unwrap();
}

#[test]
fn data_and_exit_roundtrip() {
    let (tx, mut rx) = duplex();
    let writer = thread::spawn(move || {
        let mut tx = tx;
        write_data(&mut tx, Stream::Stdout, b"out").unwrap();
        write_frame(&mut tx, FrameKind::Exit, &ExitCode(7).encode()).unwrap();
    });
    let mut fr = FrameReader::new();
    let mut sink = TestSink::default();
    let outcome = pump_decode(&mut rx, &mut fr, &mut sink).unwrap();
    writer.join().unwrap();
    assert_eq!(outcome, Outcome::Exited(7));
    assert_eq!(sink.stdout, b"out");
    assert!(sink.stderr.is_empty());
}

#[test]
fn exit_propagates_high_bit_code() {
    let (tx, mut rx) = duplex();
    let writer = thread::spawn(move || {
        let mut tx = tx;
        write_frame(&mut tx, FrameKind::Exit, &ExitCode(0xC000_0142u32 as i32).encode()).unwrap();
    });
    let mut fr = FrameReader::new();
    let mut sink = TestSink::default();
    let outcome = pump_decode(&mut rx, &mut fr, &mut sink).unwrap();
    writer.join().unwrap();
    assert_eq!(outcome, Outcome::Exited(0xC000_0142u32 as i32));
}

#[test]
fn peer_closed_without_exit_is_distinct_from_exit_zero() {
    // EOF with no EXIT frame must surface as PeerClosed, NOT Exited(0) — a dead agent
    // must not look like a successful command.
    let (tx, mut rx) = duplex();
    let writer = thread::spawn(move || {
        let mut tx = tx;
        write_data(&mut tx, Stream::Stdout, b"partial").unwrap();
        // no EXIT frame; tx drops -> EOF
    });
    let mut fr = FrameReader::new();
    let mut sink = TestSink::default();
    let outcome = pump_decode(&mut rx, &mut fr, &mut sink).unwrap();
    writer.join().unwrap();
    assert_eq!(outcome, Outcome::PeerClosed);
    assert_eq!(sink.stdout, b"partial");
}

#[test]
fn stderr_stream_kept_separate() {
    let (tx, mut rx) = duplex();
    let writer = thread::spawn(move || {
        let mut tx = tx;
        write_data(&mut tx, Stream::Stdout, b"O").unwrap();
        write_data(&mut tx, Stream::Stderr, b"E").unwrap();
        write_frame(&mut tx, FrameKind::Exit, &ExitCode(0).encode()).unwrap();
    });
    let mut fr = FrameReader::new();
    let mut sink = TestSink::default();
    pump_decode(&mut rx, &mut fr, &mut sink).unwrap();
    writer.join().unwrap();
    assert_eq!(sink.stdout, b"O");
    assert_eq!(sink.stderr, b"E");
}

#[test]
fn resize_frame_dispatched() {
    let (tx, mut rx) = duplex();
    let writer = thread::spawn(move || {
        let mut tx = tx;
        write_frame(&mut tx, FrameKind::Resize, &Resize { cols: 120, rows: 40 }.encode()).unwrap();
        write_frame(&mut tx, FrameKind::Exit, &ExitCode(0).encode()).unwrap();
    });
    let mut fr = FrameReader::new();
    let mut sink = TestSink::default();
    let outcome = pump_decode(&mut rx, &mut fr, &mut sink).unwrap();
    writer.join().unwrap();
    assert_eq!(outcome, Outcome::Exited(0));
    assert_eq!(sink.resizes, vec![Resize { cols: 120, rows: 40 }]);
}

#[test]
fn pump_decode_errors_on_truncation_at_eof() {
    // A correct peer always closes on a frame boundary. EOF with a partial frame still
    // buffered means the stream was cut mid-frame — that is a truncation error, NOT a
    // clean PeerClosed.
    let (tx, mut rx) = duplex();
    let writer = thread::spawn(move || {
        let mut tx = tx;
        // Header claims 10 payload bytes; only 2 are sent, then EOF.
        let header = FrameHeader { kind: FrameKind::Data, len: 10 }.encode();
        tx.write_all(&header).unwrap();
        tx.write_all(&[Stream::Stdout as u8, b'x']).unwrap();
        // tx drops here -> EOF mid-frame
    });
    let mut fr = FrameReader::new();
    let mut sink = TestSink::default();
    let result = pump_decode(&mut rx, &mut fr, &mut sink);
    writer.join().unwrap();
    assert!(
        result.is_err(),
        "truncated stream must error, got {result:?} instead of a truncation error"
    );
}

#[test]
fn pump_decode_errors_on_handshake_midstream() {
    let (tx, mut rx) = duplex();
    let writer = thread::spawn(move || {
        let mut tx = tx;
        // A HANDSHAKE frame is illegal once the stream is running.
        write_frame(&mut tx, FrameKind::Handshake, b"\x00").unwrap();
    });
    let mut fr = FrameReader::new();
    let mut sink = TestSink::default();
    let result = pump_decode(&mut rx, &mut fr, &mut sink);
    writer.join().unwrap();
    assert!(result.is_err());
}

#[test]
fn pump_decode_continues_from_handshake_readers_residual() {
    // Mirrors the agent path: read_one_frame consumes the HANDSHAKE, then the SAME
    // FrameReader is handed to pump_decode — pipelined DATA must not be lost.
    use crate::protocol::{Handshake, read_one_frame};
    let (tx, mut rx) = duplex();
    let writer = thread::spawn(move || {
        let mut tx = tx;
        write_frame(&mut tx, FrameKind::Handshake, &Handshake::pty_default().encode().unwrap())
            .unwrap();
        write_data(&mut tx, Stream::Stdout, b"after-handshake").unwrap();
        write_frame(&mut tx, FrameKind::Exit, &ExitCode(0).encode()).unwrap();
    });
    let mut fr = FrameReader::new();
    let hs = read_one_frame(&mut rx, &mut fr).unwrap();
    assert_eq!(hs.kind, FrameKind::Handshake);
    let mut sink = TestSink::default();
    let outcome = pump_decode(&mut rx, &mut fr, &mut sink).unwrap();
    writer.join().unwrap();
    assert_eq!(outcome, Outcome::Exited(0));
    assert_eq!(sink.stdout, b"after-handshake");
}

#[test]
fn pump_decode_errors_on_empty_data_payload() {
    // A DATA frame with no stream tag at all is malformed.
    let (tx, mut rx) = duplex();
    let writer = thread::spawn(move || {
        let mut tx = tx;
        write_frame(&mut tx, FrameKind::Data, &[]).unwrap();
    });
    let mut fr = FrameReader::new();
    let mut sink = TestSink::default();
    let result = pump_decode(&mut rx, &mut fr, &mut sink);
    writer.join().unwrap();
    assert!(result.is_err());
}

#[test]
fn pump_decode_errors_on_bad_stream_tag() {
    let (tx, mut rx) = duplex();
    let writer = thread::spawn(move || {
        let mut tx = tx;
        write_frame(&mut tx, FrameKind::Data, &[9, b'x']).unwrap(); // tag 9 is invalid
    });
    let mut fr = FrameReader::new();
    let mut sink = TestSink::default();
    let result = pump_decode(&mut rx, &mut fr, &mut sink);
    writer.join().unwrap();
    assert!(result.is_err());
}

#[test]
fn pump_decode_accepts_tag_only_data_as_empty_write() {
    // A DATA frame that is just a stream tag (zero data bytes) is valid and delivers an
    // empty slice — the agent forwards a child's legitimate zero-length writes this way.
    let (tx, mut rx) = duplex();
    let writer = thread::spawn(move || {
        let mut tx = tx;
        write_frame(&mut tx, FrameKind::Data, &[Stream::Stdout as u8]).unwrap();
        write_frame(&mut tx, FrameKind::Exit, &ExitCode(0).encode()).unwrap();
    });
    let mut fr = FrameReader::new();
    let mut sink = TestSink::default();
    let outcome = pump_decode(&mut rx, &mut fr, &mut sink).unwrap();
    writer.join().unwrap();
    assert_eq!(outcome, Outcome::Exited(0));
    assert!(sink.stdout.is_empty());
}

#[test]
fn pump_decode_errors_on_truncated_exit_payload() {
    // EXIT needs a 4-byte code; a short payload must error, not silently misreport.
    let (tx, mut rx) = duplex();
    let writer = thread::spawn(move || {
        let mut tx = tx;
        write_frame(&mut tx, FrameKind::Exit, &[0, 0]).unwrap();
    });
    let mut fr = FrameReader::new();
    let mut sink = TestSink::default();
    let result = pump_decode(&mut rx, &mut fr, &mut sink);
    writer.join().unwrap();
    assert!(result.is_err());
}
