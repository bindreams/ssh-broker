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

/// Why a decode pump stopped without a clean end-of-stream.
///
/// `pump_decode` sits between a transport and a sink, and is the only code that knows which
/// of them failed. Collapsing that into one opaque error would destroy the distinction at the
/// exact layer that owns it, leaving every caller to reconstruct something it cannot see.
///
/// The variants report **what happened**; deciding **what to do** stays with the caller. The
/// distinction that matters to callers is whether the far end is still reachable — see
/// [`PumpError::peer_gone`].
#[derive(Debug, thiserror::Error)]
pub enum PumpError {
    /// Reading the transport failed for a reason that does not clear by itself.
    ///
    /// `ErrorKind::Interrupted` is excluded: it is retried in place, because it signals a
    /// signal arriving mid-read rather than a peer that has gone.
    #[error("transport read failed: {0}")]
    Transport(#[source] std::io::Error),

    /// The bytes did not form valid frames: a peer cut mid-frame, or an encoder is wrong.
    /// Either way the far end can no longer be talked to.
    ///
    /// Reachable rather than theoretical — `write_frame` emits a frame as two separate
    /// `write_all` calls, so a peer killed between them leaves a partial frame behind.
    #[error("protocol error: {0}")]
    Protocol(#[source] anyhow::Error),

    /// Dispatching a decoded frame to the local sink failed. Says nothing about the peer,
    /// which is very often still there — a relayed command closing its own stdin makes the
    /// next write fail while the session continues normally.
    #[error("sink failed: {0}")]
    Sink(#[source] anyhow::Error),
}

impl PumpError {
    /// Whether the far end is unreachable.
    ///
    /// A sink failure is local and must not be read as a disconnect; the other two mean the
    /// peer is gone. Callers tearing a session down should ask this rather than treating
    /// every error alike.
    pub fn peer_gone(&self) -> bool {
        !matches!(self, PumpError::Sink(_))
    }
}

/// A sink that accepts and drops everything, so a pump can keep watching a peer it is no
/// longer able to deliver to.
struct DiscardSink;

impl FrameSink for DiscardSink {
    fn on_data(&mut self, _stream: Stream, _bytes: &[u8]) -> anyhow::Result<()> {
        Ok(())
    }
}

/// Deliver frames from `r` to `sink` until the **peer** is gone, not merely until the sink is.
///
/// [`PumpError::Sink`] is the one ending that must not stop the loop: it is local, and the peer
/// is usually still connected — a relayed command closing its own stdin makes the next write
/// fail mid-session. Delivery stops there, but watching does not; the pump re-enters with the
/// frames discarded.
///
/// Returning early instead would leave nobody reading the transport, so the peer's eventual
/// disconnect is never observed and whoever waits on the child blocks forever on a command that
/// never exits on its own. Separating "cannot deliver" from "nobody is there" is the whole point
/// of [`PumpError`]; this function is where that distinction is spent.
pub fn pump_until_peer_gone<R: Read>(r: &mut R, fr: &mut FrameReader, sink: &mut impl FrameSink) {
    let Err(e) = pump_decode(r, fr, sink) else {
        return; // clean end of stream: the peer is finished
    };
    tracing::debug!("input pump stopped delivering: {e}");
    if e.peer_gone() {
        return;
    }
    if let Err(e) = pump_decode(r, fr, &mut DiscardSink) {
        tracing::debug!("input pump stopped watching: {e}");
    }
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
pub fn pump_decode<R: Read>(r: &mut R, fr: &mut FrameReader, sink: &mut impl FrameSink) -> Result<Outcome, PumpError> {
    let mut buf = [0u8; 32 * 1024];
    loop {
        while let Some(frame) = fr.next_frame().map_err(PumpError::Protocol)? {
            match frame.kind {
                FrameKind::Data => {
                    let tag = *frame
                        .payload
                        .first()
                        .ok_or_else(|| PumpError::Protocol(anyhow::anyhow!("DATA frame missing stream tag")))?;
                    let stream = Stream::from_u8(tag)
                        .ok_or_else(|| PumpError::Protocol(anyhow::anyhow!("bad stream tag {tag}")))?;
                    sink.on_data(stream, &frame.payload[1..]).map_err(PumpError::Sink)?;
                }
                FrameKind::Resize => {
                    let resize = Resize::decode(&frame.payload).map_err(PumpError::Protocol)?;
                    sink.on_resize(resize).map_err(PumpError::Sink)?;
                }
                FrameKind::Exit => {
                    let code = ExitCode::decode(&frame.payload).map_err(PumpError::Protocol)?;
                    return Ok(Outcome::Exited(code.0));
                }
                FrameKind::Handshake => {
                    return Err(PumpError::Protocol(anyhow::anyhow!(
                        "unexpected HANDSHAKE frame mid-stream"
                    )));
                }
            }
        }
        // `Interrupted` is documented as non-fatal and retryable — a signal arriving mid-read,
        // not a lost peer. Reporting it as `Transport` would make `peer_gone()` true while the
        // far end is fine, discarding whatever it had already sent (an `EXIT` frame included).
        // This is a retry on a specific, self-clearing condition, not a bounded retry loop.
        let n = loop {
            match r.read(&mut buf) {
                Ok(n) => break n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(PumpError::Transport(e)),
            }
        };
        if n == 0 {
            // A correct peer closes on a frame boundary, so leftover bytes here mean the
            // stream was cut mid-frame — a truncation error, distinct from a clean close.
            if fr.buffered_len() != 0 {
                return Err(PumpError::Protocol(anyhow::anyhow!(
                    "stream truncated: {} buffered byte(s) without a complete frame",
                    fr.buffered_len()
                )));
            }
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
