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
        let header = FrameHeader {
            kind: FrameKind::Data,
            len: 10,
        }
        .encode();
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
        write_frame(
            &mut tx,
            FrameKind::Handshake,
            &Handshake::pty_default().encode().unwrap(),
        )
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

/// A sink failure must be reported as a sink failure, not as a lost peer.
///
/// This is the distinction the type exists for. A relayed command that closes its own stdin
/// makes the next write fail while the session carries on normally, so a caller that reads
/// every error as a disconnect would tear down a live session.
#[test]
fn a_failing_sink_is_not_reported_as_the_peer_going_away() {
    struct FailingSink;
    impl FrameSink for FailingSink {
        fn on_data(&mut self, _stream: Stream, _bytes: &[u8]) -> anyhow::Result<()> {
            anyhow::bail!("the child closed its stdin")
        }
    }

    let (mut a, mut b) = duplex();
    // Writer on its own thread: the transport is unbuffered, so writing before the reader
    // runs would deadlock on the same thread.
    let t = thread::spawn(move || {
        let _ = write_data(&mut b, Stream::Stdin, b"hello");
    });

    let mut fr = FrameReader::new();
    let err = pump_decode(&mut a, &mut fr, &mut FailingSink).expect_err("the sink fails");
    let _ = t.join();
    assert!(
        matches!(err, PumpError::Sink(_)),
        "a sink failure must be classified as Sink, got {err:?}"
    );
    assert!(!err.peer_gone(), "a sink failure says nothing about the peer");
}

/// A stream cut mid-frame is the peer going away, not a local problem.
///
/// Reachable rather than theoretical: `write_frame` emits a frame as two separate `write_all`
/// calls, so a peer killed between them leaves exactly this behind.
#[test]
fn a_truncated_frame_is_reported_as_the_peer_going_away() {
    let (mut a, mut b) = duplex();
    // A header promising four payload bytes, then only two of them — the shape a peer killed
    // between `write_frame`'s two `write_all` calls leaves behind. Writer on its own thread,
    // since the transport is unbuffered.
    let t = thread::spawn(move || {
        let header = FrameHeader {
            kind: FrameKind::Data,
            len: 4,
        };
        let _ = b.write_all(&header.encode());
        let _ = b.write_all(b"xx");
    });

    let mut fr = FrameReader::new();
    let err = pump_decode(&mut a, &mut fr, &mut TestSink::default()).expect_err("truncated");
    let _ = t.join();
    assert!(
        matches!(err, PumpError::Protocol(_)),
        "a truncated stream must be classified as Protocol, got {err:?}"
    );
    assert!(err.peer_gone(), "a truncated stream means the peer is gone");
}

/// A clean close with no EXIT frame is still the peer going away — the existing outcome,
/// pinned here alongside its error-shaped siblings so the three stay distinguishable.
#[test]
fn a_clean_close_without_exit_is_peer_closed() {
    let (mut a, b) = duplex();
    drop(b);
    let mut fr = FrameReader::new();
    let outcome = pump_decode(&mut a, &mut fr, &mut TestSink::default()).expect("clean EOF");
    assert_eq!(outcome, Outcome::PeerClosed);
}

/// A reader that yields `Interrupted` once, then behaves normally.
///
/// Models a signal arriving mid-read: the peer is fine and its bytes are already queued.
struct InterruptsOnce {
    interrupted: bool,
    data: std::io::Cursor<Vec<u8>>,
}

impl Read for InterruptsOnce {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if !self.interrupted {
            self.interrupted = true;
            return Err(std::io::Error::from(std::io::ErrorKind::Interrupted));
        }
        self.data.read(buf)
    }
}

/// `Interrupted` is retried, not reported as a lost peer.
///
/// Classifying it as `Transport` would make `peer_gone()` true for a transient signal and
/// discard whatever the peer had already sent — here a complete `EXIT(7)`, which the shim
/// would have turned into 254 instead of 7.
#[test]
fn an_interrupted_read_is_retried_not_treated_as_a_lost_peer() {
    let mut framed = Vec::new();
    write_frame(&mut framed, FrameKind::Exit, &ExitCode(7).encode()).unwrap();
    let mut r = InterruptsOnce {
        interrupted: false,
        data: std::io::Cursor::new(framed),
    };

    let mut fr = FrameReader::new();
    let outcome = pump_decode(&mut r, &mut fr, &mut TestSink::default()).expect("interrupted is retried");
    assert_eq!(
        outcome,
        Outcome::Exited(7),
        "the queued exit code must survive the signal"
    );
}

/// A reader that fails with a genuinely fatal error.
struct AlwaysBroken;

impl Read for AlwaysBroken {
    fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset))
    }
}

/// A transport failure that does not clear by itself is `Transport`, and the peer is gone.
#[test]
fn a_broken_transport_is_reported_as_the_peer_going_away() {
    let mut fr = FrameReader::new();
    let err = pump_decode(&mut AlwaysBroken, &mut fr, &mut TestSink::default()).expect_err("broken");
    assert!(
        matches!(err, PumpError::Transport(_)),
        "a fatal read failure must be classified as Transport, got {err:?}"
    );
    assert!(err.peer_gone(), "a broken transport means the peer is gone");
}

// ── watching a peer you can no longer deliver to ─────────────────────────────────────────

/// A reader that records reaching end-of-stream, so a test can prove a pump read *that far*
/// rather than merely having returned.
struct EofSpy<R> {
    inner: R,
    saw_eof: std::rc::Rc<std::cell::Cell<bool>>,
}

impl<R: std::io::Read> std::io::Read for EofSpy<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n == 0 {
            self.saw_eof.set(true);
        }
        Ok(n)
    }
}

/// A sink failure stops delivery, never watching.
///
/// The regression this pins: teardown was gated on the sink/peer distinction, but the pump
/// still *returned* on a sink failure. That left nobody reading the transport, so the peer's
/// later disconnect was never observed and the agent's waiter blocked forever on a command
/// that never exits on its own — the failure the distinction exists to prevent, reintroduced
/// one layer up.
///
/// The frames are pre-encoded into a buffer rather than sent over the duplex: the duplex is
/// unbuffered, so a regression would block the writer and hang instead of failing. Reading a
/// buffer to `Ok(0)` models the peer's disconnect just as well and reports the defect as a
/// plain assertion.
#[test]
fn pump_until_peer_gone_keeps_watching_after_a_sink_failure() {
    struct FailingSink {
        calls: usize,
    }
    impl FrameSink for FailingSink {
        fn on_data(&mut self, _stream: Stream, _bytes: &[u8]) -> anyhow::Result<()> {
            self.calls += 1;
            anyhow::bail!("the relayed command closed its own stdin")
        }
    }

    let mut framed = Vec::new();
    write_data(&mut framed, Stream::Stdin, b"breaks the sink").unwrap();
    write_data(&mut framed, Stream::Stdin, b"arrives anyway").unwrap();

    let saw_eof = std::rc::Rc::new(std::cell::Cell::new(false));
    let mut spy = EofSpy {
        inner: std::io::Cursor::new(framed),
        saw_eof: std::rc::Rc::clone(&saw_eof),
    };
    let mut sink = FailingSink { calls: 0 };
    pump_until_peer_gone(&mut spy, &mut FrameReader::new(), &mut sink);

    assert!(
        saw_eof.get(),
        "the pump must keep reading to end-of-stream; stopping at the sink failure hides the disconnect"
    );
    assert_eq!(sink.calls, 1, "delivery must stop at the first sink failure");
}

/// The ordinary path is unchanged: a working sink receives every frame, and the pump returns
/// at end-of-stream rather than after the first one.
#[test]
fn pump_until_peer_gone_delivers_every_frame_to_a_working_sink() {
    let mut framed = Vec::new();
    write_data(&mut framed, Stream::Stdout, b"one").unwrap();
    write_data(&mut framed, Stream::Stdout, b"two").unwrap();
    let mut sink = TestSink::default();
    pump_until_peer_gone(&mut std::io::Cursor::new(framed), &mut FrameReader::new(), &mut sink);
    assert_eq!(sink.stdout, b"onetwo");
}

// ── the agent's answer ───────────────────────────────────────────────────────────────────

/// `frames` written in order into one buffer.
fn framed(frames: &[(FrameKind, &[u8])]) -> Vec<u8> {
    let mut wire = Vec::new();
    for (kind, payload) in frames {
        write_frame(&mut wire, *kind, payload).unwrap();
    }
    wire
}

/// A `Serving` first frame calls the sink's `on_serving` once, before anything else, and the pump goes on.
#[test]
fn serving_as_the_first_frame_calls_on_serving_and_the_pump_goes_on() {
    struct Order(Vec<&'static str>);
    impl FrameSink for Order {
        fn on_serving(&mut self) -> anyhow::Result<()> {
            self.0.push("serving");
            Ok(())
        }
        fn on_data(&mut self, _stream: Stream, _bytes: &[u8]) -> anyhow::Result<()> {
            self.0.push("data");
            Ok(())
        }
    }
    let mut wire = Vec::new();
    write_serving(&mut wire).unwrap();
    write_data(&mut wire, Stream::Pty, b"x").unwrap();
    write_frame(&mut wire, FrameKind::Exit, &ExitCode(4).encode()).unwrap();
    let mut order = Order(Vec::new());
    let outcome = pump_decode(&mut wire.as_slice(), &mut FrameReader::new(), &mut order).unwrap();
    assert_eq!(outcome, Outcome::Exited(4));
    assert_eq!(order.0, ["serving", "data"]);
}

/// A `HandBack` first frame ends the pump with the cause, and delivers nothing after it.
#[test]
fn hand_back_as_the_first_frame_ends_the_pump_with_the_cause() {
    let mut wire = Vec::new();
    write_hand_back(&mut wire, "the token cannot be made").unwrap();
    write_data(&mut wire, Stream::Pty, b"never delivered").unwrap();
    let mut sink = TestSink::default();
    let outcome = pump_decode(&mut wire.as_slice(), &mut FrameReader::new(), &mut sink).unwrap();
    assert_eq!(outcome, Outcome::HandedBack("the token cannot be made".to_owned()));
    assert!(sink.stdout.is_empty());
    assert_eq!(sink.served, 0);
}

/// A first frame that is not the answer is still what it was: a refusal's text and exit.
#[test]
fn a_first_frame_that_is_data_is_not_an_answer_and_never_calls_on_serving() {
    let wire = framed(&[
        (FrameKind::Data, &[Stream::Stderr as u8, b'n', b'o']),
        (FrameKind::Exit, &ExitCode(255).encode()),
    ]);
    let mut sink = TestSink::default();
    let outcome = pump_decode(&mut wire.as_slice(), &mut FrameReader::new(), &mut sink).unwrap();
    assert_eq!(outcome, Outcome::Exited(255));
    assert_eq!(sink.served, 0);
}

/// The answer is the first frame or it is a protocol error: after a data frame, `Serving` and `HandBack`
/// both are, and the sink is not told.
#[test]
fn either_answer_after_a_data_frame_is_a_protocol_error() {
    for (name, wire) in [
        (
            "Serving",
            framed(&[(FrameKind::Data, &[Stream::Pty as u8, b'x']), (FrameKind::Serving, &[])]),
        ),
        (
            "HandBack",
            framed(&[
                (FrameKind::Data, &[Stream::Pty as u8, b'x']),
                (FrameKind::HandBack, b"late"),
            ]),
        ),
    ] {
        let mut sink = TestSink::default();
        let err = pump_decode(&mut wire.as_slice(), &mut FrameReader::new(), &mut sink)
            .expect_err("a late answer is a protocol error");
        assert!(matches!(err, PumpError::Protocol(_)), "{name}: {err:?}");
        assert_eq!(sink.served, 0, "{name}");
    }
}

/// A second answer is a protocol error too, and so is a `Serving` after a `Serving`.
#[test]
fn a_second_answer_is_a_protocol_error() {
    let wire = framed(&[(FrameKind::Serving, &[]), (FrameKind::Serving, &[])]);
    let mut sink = TestSink::default();
    let err = pump_decode(&mut wire.as_slice(), &mut FrameReader::new(), &mut sink).expect_err("two answers");
    assert!(matches!(err, PumpError::Protocol(_)), "{err:?}");
    assert_eq!(sink.served, 1);
}

/// "First" is the connection's first frame, not the first of a call: a reader that has yielded a frame
/// already, in an earlier `pump_decode` call, takes an answer as a protocol error.
#[test]
fn an_answer_in_a_later_pump_call_on_the_same_reader_is_a_protocol_error() {
    for (name, answer) in [
        ("Serving", framed(&[(FrameKind::Serving, &[])])),
        ("HandBack", framed(&[(FrameKind::HandBack, b"late")])),
    ] {
        let mut fr = FrameReader::new();
        let mut sink = TestSink::default();
        let first = framed(&[(FrameKind::Data, &[Stream::Pty as u8, b'x'])]);
        let outcome = pump_decode(&mut first.as_slice(), &mut fr, &mut sink).unwrap();
        assert_eq!(outcome, Outcome::PeerClosed);
        let err = pump_decode(&mut answer.as_slice(), &mut fr, &mut sink).expect_err("a late answer");
        assert!(matches!(err, PumpError::Protocol(_)), "{name}: {err:?}");
        assert_eq!(sink.served, 0, "{name}");
    }
}

/// On the agent's side the handshake is frame one, so an answer kind from a client is a protocol error.
#[test]
fn a_client_that_sends_an_answer_after_its_handshake_is_a_protocol_error() {
    use crate::protocol::{Handshake, read_one_frame};
    for (name, answer) in [("Serving", FrameKind::Serving), ("HandBack", FrameKind::HandBack)] {
        let wire = framed(&[
            (FrameKind::Handshake, &Handshake::pty_default().encode().unwrap()),
            (answer, b"not from a client"),
        ]);
        let mut rx = wire.as_slice();
        let mut fr = FrameReader::new();
        assert_eq!(read_one_frame(&mut rx, &mut fr).unwrap().kind, FrameKind::Handshake);
        let mut sink = TestSink::default();
        let err = pump_decode(&mut rx, &mut fr, &mut sink).expect_err("a client has no answer to give");
        assert!(matches!(err, PumpError::Protocol(_)), "{name}: {err:?}");
        assert_eq!(sink.served, 0, "{name}");
    }
}

/// A failing `on_serving` is a sink failure, which says nothing about the peer.
#[test]
fn a_failing_on_serving_is_a_sink_failure() {
    struct Refuses;
    impl FrameSink for Refuses {
        fn on_serving(&mut self) -> anyhow::Result<()> {
            anyhow::bail!("no input worker")
        }
        fn on_data(&mut self, _stream: Stream, _bytes: &[u8]) -> anyhow::Result<()> {
            Ok(())
        }
    }
    let wire = framed(&[(FrameKind::Serving, &[])]);
    let err = pump_decode(&mut wire.as_slice(), &mut FrameReader::new(), &mut Refuses).expect_err("fails");
    assert!(matches!(err, PumpError::Sink(_)), "{err:?}");
    assert!(!err.peer_gone());
}

/// A sink that expects no answer (a logout's reply sink) refuses one: a sink failure, and nothing is delivered.
#[test]
fn a_sink_with_the_default_on_serving_refuses_the_answer() {
    struct Plain(Vec<u8>);
    impl FrameSink for Plain {
        fn on_data(&mut self, _stream: Stream, bytes: &[u8]) -> anyhow::Result<()> {
            self.0.extend_from_slice(bytes);
            Ok(())
        }
    }
    let mut wire = framed(&[(FrameKind::Serving, &[])]);
    write_data(&mut wire, Stream::Stdout, b"after").unwrap();
    let mut plain = Plain(Vec::new());
    let err = pump_decode(&mut wire.as_slice(), &mut FrameReader::new(), &mut plain).expect_err("refused");
    assert!(matches!(err, PumpError::Sink(_)), "{err:?}");
    assert!(plain.0.is_empty());
}

fn a_consent_request() -> crate::protocol::ConsentRequest {
    crate::protocol::ConsentRequest {
        version: crate::protocol::PROTOCOL_VERSION,
        command: "cmd /c whoami".to_owned(),
        cwd: r"C:\Users\me".to_owned(),
    }
}

/// The question and its answer are dispatched to the sink, in order with the data around them.
#[test]
fn pump_decode_dispatches_consent_and_answer_and_a_sink_without_them_errors() {
    use crate::protocol::{ConsentAnswer, ConsentRequest};
    #[derive(Default)]
    struct Asked {
        seen: Vec<String>,
    }
    impl FrameSink for Asked {
        fn on_data(&mut self, _stream: Stream, _bytes: &[u8]) -> anyhow::Result<()> {
            self.seen.push("data".to_owned());
            Ok(())
        }
        fn on_consent(&mut self, request: ConsentRequest) -> anyhow::Result<()> {
            self.seen.push(format!("consent {}", request.command));
            Ok(())
        }
        fn on_consent_answer(&mut self, answer: ConsentAnswer) -> anyhow::Result<()> {
            self.seen.push(format!("answer {answer:?}"));
            Ok(())
        }
    }
    let mut wire = Vec::new();
    write_data(&mut wire, Stream::Pty, b"x").unwrap();
    write_frame(&mut wire, FrameKind::Consent, &a_consent_request().encode().unwrap()).unwrap();
    write_frame(
        &mut wire,
        FrameKind::ConsentAnswer,
        &ConsentAnswer::Refuse.encode().unwrap(),
    )
    .unwrap();
    write_frame(&mut wire, FrameKind::Exit, &ExitCode(0).encode()).unwrap();
    let mut sink = Asked::default();
    let outcome = pump_decode(&mut wire.as_slice(), &mut FrameReader::new(), &mut sink).unwrap();
    assert_eq!(outcome, Outcome::Exited(0));
    assert_eq!(sink.seen, ["data", "consent cmd /c whoami", "answer Refuse"]);

    // A sink that does not take them (an exec session's, the logout reply's) refuses each: a sink failure, which says
    // nothing about the peer.
    for frame in [
        (FrameKind::Consent, a_consent_request().encode().unwrap()),
        (FrameKind::ConsentAnswer, ConsentAnswer::Allow.encode().unwrap()),
    ] {
        let wire = framed(&[(frame.0, &frame.1)]);
        let err = pump_decode(&mut wire.as_slice(), &mut FrameReader::new(), &mut TestSink::default())
            .expect_err("a sink without it refuses");
        assert!(matches!(err, PumpError::Sink(_)), "{:?}: {err:?}", frame.0);
        assert!(!err.peer_gone());
    }
}

/// Payloads that are not what the kind says are the peer's fault, not the sink's.
#[test]
fn a_consent_frame_that_is_not_one_is_a_protocol_error() {
    for (kind, payload) in [
        (FrameKind::Consent, &b"x"[..]),
        (FrameKind::Consent, &[][..]),
        (FrameKind::ConsentAnswer, &[2][..]),
        (FrameKind::ConsentAnswer, &[][..]),
        (FrameKind::ConsentAnswer, &[0, 0][..]),
    ] {
        let wire = framed(&[(kind, payload)]);
        let err =
            pump_decode(&mut wire.as_slice(), &mut FrameReader::new(), &mut TestSink::default()).expect_err("refused");
        assert!(matches!(err, PumpError::Protocol(_)), "{kind:?} {payload:?}: {err:?}");
        assert!(err.peer_gone());
    }
}

/// A request frame is read by whoever takes a connection's first frame, never by the pump: in a stream it is a
/// protocol error, first or not, and nothing is delivered.
#[test]
fn a_request_frame_in_a_stream_is_a_protocol_error() {
    for (name, frames) in [
        ("first", vec![(FrameKind::Request, &b"x"[..])]),
        (
            "after data",
            vec![
                (FrameKind::Data, &[Stream::Pty as u8, b'x'][..]),
                (FrameKind::Request, &b"x"[..]),
            ],
        ),
    ] {
        let wire = framed(&frames);
        let mut sink = TestSink::default();
        let err = pump_decode(&mut wire.as_slice(), &mut FrameReader::new(), &mut sink).expect_err(name);
        assert!(matches!(err, PumpError::Protocol(_)), "{name}: {err:?}");
        assert!(err.peer_gone(), "{name}");
        assert_eq!(sink.served, 0, "{name}");
    }
}
