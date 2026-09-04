//! relay: transport-agnostic frame pumping (encode/decode/dispatch).
//!
//! The pump functions are generic over `Read`/`Write`, so they drive both the real
//! AF_UNIX connection (`afunix::ConnRx`/`ConnTx`) and the in-memory test transport
//! below, with identical logic.

use crate::protocol::{ExitCode, FrameKind, FrameReader, Resize, Stream, write_frame};
use std::io::{Read, Write};

/// Result of a decode pump. `Exited(n)` = a clean `EXIT(n)` frame was received;
/// `PeerClosed` = the stream ended with NO exit frame (a dead or abruptly-closed
/// peer). The shim maps `PeerClosed` to a nonzero failure, never to exit 0, so a dead
/// agent can't masquerade as a successful command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Exited(i32),
    PeerClosed,
}

/// Write a `DATA` frame: `[stream tag: u8][bytes...]`.
pub fn write_data<W: Write>(w: &mut W, stream: Stream, bytes: &[u8]) -> anyhow::Result<()> {
    let mut payload = Vec::with_capacity(1 + bytes.len());
    payload.push(stream as u8);
    payload.extend_from_slice(bytes);
    write_frame(w, FrameKind::Data, &payload)
}

/// Where decoded non-EXIT frames are delivered. Implemented by both the shim and the
/// agent handlers.
pub trait FrameSink {
    fn on_data(&mut self, stream: Stream, bytes: &[u8]) -> anyhow::Result<()>;
    fn on_resize(&mut self, r: Resize) -> anyhow::Result<()> {
        let _ = r;
        Ok(())
    }
}

/// Read frames from `r` until an `EXIT` frame or EOF, dispatching `DATA`/`RESIZE` to
/// `sink`. Reuses `fr`'s residual buffer, so it can continue immediately after a
/// handshake read via `protocol::read_one_frame`. A `HANDSHAKE` frame mid-stream is a
/// protocol violation (error).
pub fn pump_decode<R: Read>(r: &mut R, fr: &mut FrameReader, sink: &mut impl FrameSink) -> anyhow::Result<Outcome> {
    let mut buf = [0u8; 32 * 1024];
    loop {
        while let Some(frame) = fr.next_frame()? {
            match frame.kind {
                FrameKind::Data => {
                    let tag = *frame
                        .payload
                        .first()
                        .ok_or_else(|| anyhow::anyhow!("DATA frame missing stream tag"))?;
                    let stream = Stream::from_u8(tag).ok_or_else(|| anyhow::anyhow!("bad stream tag {tag}"))?;
                    sink.on_data(stream, &frame.payload[1..])?;
                }
                FrameKind::Resize => sink.on_resize(Resize::decode(&frame.payload)?)?,
                FrameKind::Exit => {
                    return Ok(Outcome::Exited(ExitCode::decode(&frame.payload)?.0));
                }
                FrameKind::Handshake => anyhow::bail!("unexpected HANDSHAKE frame mid-stream"),
            }
        }
        let n = r.read(&mut buf)?;
        if n == 0 {
            // A correct peer closes on a frame boundary, so leftover bytes here mean the
            // stream was cut mid-frame — a truncation error, distinct from a clean close.
            anyhow::ensure!(
                fr.buffered_len() == 0,
                "stream truncated: {} buffered byte(s) without a complete frame",
                fr.buffered_len()
            );
            return Ok(Outcome::PeerClosed);
        }
        fr.push(&buf[..n]);
    }
}

// ── Test transport ───────────────────────────────────────────────────────────────

/// In-memory bidirectional byte-stream pair mirroring the production AF_UNIX
/// connection. Each end is `Read + Write`; dropping one end makes the peer's reads hit
/// EOF (`Ok(0)`) — the property `pump_decode`'s `PeerClosed` relies on. Built from two
/// unidirectional `pipe` channels (exactly one writer per direction), so EOF is
/// deterministic when a writer drops. Test-only: the `pipe` dev-dependency is absent
/// from production builds.
#[cfg(test)]
pub struct DuplexEnd {
    reader: pipe::PipeReader,
    writer: pipe::PipeWriter,
}

#[cfg(test)]
impl DuplexEnd {
    /// Split into independent, `Send` read/write halves — mirrors `afunix::split`.
    pub fn split(self) -> (pipe::PipeReader, pipe::PipeWriter) {
        (self.reader, self.writer)
    }
}

#[cfg(test)]
impl Read for DuplexEnd {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.reader.read(buf)
    }
}

#[cfg(test)]
impl Write for DuplexEnd {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.writer.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

/// Create a connected pair of in-memory duplex endpoints. Two unidirectional pipes
/// cross-wire the ends: what end A writes, end B reads, and vice versa.
#[cfg(test)]
pub fn duplex() -> (DuplexEnd, DuplexEnd) {
    let (a_to_b_reader, a_to_b_writer) = pipe::pipe();
    let (b_to_a_reader, b_to_a_writer) = pipe::pipe();
    let a = DuplexEnd {
        reader: b_to_a_reader,
        writer: a_to_b_writer,
    };
    let b = DuplexEnd {
        reader: a_to_b_reader,
        writer: b_to_a_writer,
    };
    (a, b)
}

/// Test `FrameSink` that accumulates decoded streams. `stderr` is kept separate (as SSH
/// preserves it); everything else (PTY/stdout/stdin) collapses into `stdout`.
#[cfg(test)]
#[derive(Default)]
pub struct TestSink {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub resizes: Vec<Resize>,
}

#[cfg(test)]
impl FrameSink for TestSink {
    fn on_data(&mut self, stream: Stream, bytes: &[u8]) -> anyhow::Result<()> {
        match stream {
            Stream::Stderr => self.stderr.extend_from_slice(bytes),
            _ => self.stdout.extend_from_slice(bytes),
        }
        Ok(())
    }
    fn on_resize(&mut self, r: Resize) -> anyhow::Result<()> {
        self.resizes.push(r);
        Ok(())
    }
}

#[cfg(test)]
#[path = "relay_tests.rs"]
mod relay_tests;
