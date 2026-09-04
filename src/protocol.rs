//! protocol: length-prefixed typed frames + handshake (pure logic, host-testable).
//!
//! Wire frame: `[kind: u8][len: u32-LE][payload: len bytes]` — a 5-byte header
//! followed by `len` payload bytes. Chosen over a delimiter scheme because the
//! terminal data stream is arbitrary binary that would otherwise need escaping.

use serde::{Deserialize, Serialize};

pub const HEADER_LEN: usize = 5;
/// Guard against absurd allocations from a malformed/hostile length prefix (1 MiB).
pub const MAX_FRAME: u32 = 1 << 20;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    Handshake = 0,
    Data = 1,
    Resize = 2,
    Exit = 3,
}

impl FrameKind {
    fn from_u8(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Handshake),
            1 => Some(Self::Data),
            2 => Some(Self::Resize),
            3 => Some(Self::Exit),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub kind: FrameKind,
    pub len: u32,
}

impl FrameHeader {
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        b[0] = self.kind as u8;
        b[1..5].copy_from_slice(&self.len.to_le_bytes());
        b
    }

    pub fn decode(b: &[u8]) -> anyhow::Result<Self> {
        anyhow::ensure!(b.len() >= HEADER_LEN, "short header: {} < {HEADER_LEN}", b.len());
        let kind = FrameKind::from_u8(b[0]).ok_or_else(|| anyhow::anyhow!("bad frame kind {}", b[0]))?;
        let len = u32::from_le_bytes([b[1], b[2], b[3], b[4]]);
        anyhow::ensure!(len <= MAX_FRAME, "frame too large: {len} > {MAX_FRAME}");
        Ok(Self { kind, len })
    }
}

/// DATA-frame stream tag (the first payload byte). PTY mode uses a single merged
/// terminal stream; EXEC mode keeps stdin/stdout/stderr separate (SSH preserves
/// stderr as a distinct channel).
///
/// EXEC convention: an empty-payload `DATA(Stdin)` frame is the shim's **stdin-EOF
/// marker** — it tells the agent to close the child's stdin (so a reader like `sort`
/// finishes) while keeping the connection open for stdout/stderr/EXIT. A full socket
/// close is the distinct *disconnect* signal (the agent kills the child).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    Pty = 0,
    Stdin = 1,
    Stdout = 2,
    Stderr = 3,
}

impl Stream {
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Pty),
            1 => Some(Self::Stdin),
            2 => Some(Self::Stdout),
            3 => Some(Self::Stderr),
            _ => None,
        }
    }
}

/// RESIZE payload (PTY only): new console size, applied via `ResizePseudoConsole`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resize {
    pub cols: u16,
    pub rows: u16,
}

impl Resize {
    pub fn encode(&self) -> [u8; 4] {
        let mut b = [0u8; 4];
        b[0..2].copy_from_slice(&self.cols.to_le_bytes());
        b[2..4].copy_from_slice(&self.rows.to_le_bytes());
        b
    }
    pub fn decode(b: &[u8]) -> anyhow::Result<Self> {
        anyhow::ensure!(b.len() >= 4, "short resize payload: {}", b.len());
        Ok(Self {
            cols: u16::from_le_bytes([b[0], b[1]]),
            rows: u16::from_le_bytes([b[2], b[3]]),
        })
    }
}

/// EXIT payload: the child's exit code. Carried as `i32` on the wire but the cast
/// from the OS `u32` (`GetExitCodeProcess`) is **bit-preserving**, so high-bit NTSTATUS
/// codes (e.g. `0xC0000142`) survive a round-trip back to `u32` at the shim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitCode(pub i32);

impl ExitCode {
    pub fn encode(&self) -> [u8; 4] {
        self.0.to_le_bytes()
    }
    pub fn decode(b: &[u8]) -> anyhow::Result<Self> {
        anyhow::ensure!(b.len() >= 4, "short exit payload: {}", b.len());
        Ok(Self(i32::from_le_bytes([b[0], b[1], b[2], b[3]])))
    }
}

pub const PROTOCOL_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Mode {
    Pty,
    Exec,
}

/// The first frame on a connection (a HANDSHAKE-kind frame whose payload is this
/// struct, `postcard`-serialized). The shim fills `term`/`cwd` and the allow-listed
/// `env`. The agent currently applies the working directory; `%TERM%`/`env` propagation
/// into the child lands alongside the config-driven shell (Phase 7). Raw DATA frames are
/// NOT routed through serde — only this header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Handshake {
    pub version: u16,
    pub mode: Mode,
    pub cols: u16,
    pub rows: u16,
    pub term: String,
    pub cwd: String,
    pub command: Option<String>,
    pub env: Vec<(String, String)>,
}

impl Handshake {
    pub fn encode(&self) -> anyhow::Result<Vec<u8>> {
        Ok(postcard::to_stdvec(self)?)
    }
    pub fn decode(b: &[u8]) -> anyhow::Result<Self> {
        let h: Handshake = postcard::from_bytes(b)?;
        anyhow::ensure!(
            h.version == PROTOCOL_VERSION,
            "protocol version mismatch: peer {} != ours {PROTOCOL_VERSION}",
            h.version
        );
        Ok(h)
    }

    /// A minimal interactive-PTY handshake, used as a `..Handshake::pty_default()`
    /// base in tests and as the shim's starting point.
    pub fn pty_default() -> Self {
        Self {
            version: PROTOCOL_VERSION,
            mode: Mode::Pty,
            cols: 80,
            rows: 24,
            term: "xterm-256color".into(),
            cwd: String::new(),
            command: None,
            env: Vec::new(),
        }
    }
}

/// A fully-reassembled frame: its kind plus the payload bytes (header stripped).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub kind: FrameKind,
    pub payload: Vec<u8>,
}

/// Write one length-prefixed frame (`[header][payload]`) to `w`.
pub fn write_frame<W: std::io::Write>(w: &mut W, kind: FrameKind, payload: &[u8]) -> anyhow::Result<()> {
    anyhow::ensure!(
        payload.len() as u64 <= MAX_FRAME as u64,
        "payload too large: {} > {MAX_FRAME}",
        payload.len()
    );
    let header = FrameHeader {
        kind,
        len: payload.len() as u32,
    };
    w.write_all(&header.encode())?;
    w.write_all(payload)?;
    Ok(())
}

/// Incremental frame reassembler: feed arbitrary byte chunks via `push`, pull whole
/// frames via `next_frame`. Carries a residual buffer across chunk boundaries so a
/// frame split across reads (or several frames in one read) is handled correctly.
#[derive(Default)]
pub struct FrameReader {
    buf: Vec<u8>,
}

impl FrameReader {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }
    /// Bytes buffered but not yet consumed into a complete frame. After draining all
    /// available frames, a non-zero value at EOF means the stream was cut mid-frame.
    pub fn buffered_len(&self) -> usize {
        self.buf.len()
    }
    /// `Ok(Some(frame))` once a whole frame is buffered; `Ok(None)` if more bytes are
    /// needed; `Err` on a malformed header (bad kind / oversize length).
    pub fn next_frame(&mut self) -> anyhow::Result<Option<Frame>> {
        if self.buf.len() < HEADER_LEN {
            return Ok(None);
        }
        let header = FrameHeader::decode(&self.buf[..HEADER_LEN])?;
        let total = HEADER_LEN + header.len as usize;
        if self.buf.len() < total {
            return Ok(None);
        }
        let payload = self.buf[HEADER_LEN..total].to_vec();
        self.buf.drain(..total);
        Ok(Some(Frame {
            kind: header.kind,
            payload,
        }))
    }
}

/// Read exactly one whole frame from `r`, using `fr`'s residual buffer. Any bytes
/// read past the end of this frame stay in `fr`, so a caller can hand the SAME
/// `FrameReader` to `pump_decode` afterwards without losing pipelined data (e.g. a
/// DATA frame sent in the same write as the HANDSHAKE). Errors on EOF before a
/// complete frame, or on a malformed header.
pub fn read_one_frame(r: &mut impl std::io::Read, fr: &mut FrameReader) -> anyhow::Result<Frame> {
    loop {
        if let Some(frame) = fr.next_frame()? {
            return Ok(frame);
        }
        let mut buf = [0u8; 8192];
        let n = r.read(&mut buf)?;
        anyhow::ensure!(n > 0, "unexpected EOF before a complete frame");
        fr.push(&buf[..n]);
    }
}

#[cfg(test)]
#[path = "protocol_tests.rs"]
mod protocol_tests;
