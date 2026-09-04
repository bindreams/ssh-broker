//! Unit tests for the `protocol` module (sibling-file style per project conventions).
use super::*;

#[test]
fn header_roundtrips() {
    let h = FrameHeader {
        kind: FrameKind::Data,
        len: 5,
    };
    let bytes = h.encode();
    // u8 kind + u32-LE len
    assert_eq!(bytes, [FrameKind::Data as u8, 5, 0, 0, 0]);
    assert_eq!(FrameHeader::decode(&bytes).unwrap(), h);
}

#[test]
fn stream_tag_roundtrips() {
    for s in [Stream::Pty, Stream::Stdin, Stream::Stdout, Stream::Stderr] {
        assert_eq!(Stream::from_u8(s as u8).unwrap(), s);
    }
    assert!(Stream::from_u8(99).is_none());
}

#[test]
fn resize_payload_roundtrips() {
    let r = Resize { cols: 120, rows: 40 };
    assert_eq!(Resize::decode(&r.encode()).unwrap(), r);
}

#[test]
fn resize_decode_rejects_short() {
    assert!(Resize::decode(&[1, 2, 3]).is_err());
}

#[test]
fn exit_payload_roundtrips() {
    assert_eq!(ExitCode::decode(&ExitCode(3).encode()).unwrap(), ExitCode(3));
}

#[test]
fn exit_code_preserves_high_bit() {
    // The agent reads the child's exit code as u32 (GetExitCodeProcess); we carry it
    // as i32 on the wire. The cast must be BIT-PRESERVING, not value-clamping:
    // 0xC0000142 (STATUS_DLL_INIT_FAILED) is a real high-bit code from the spike.
    let raw: u32 = 0xC000_0142;
    let code = ExitCode(raw as i32); // negative as i32
    let decoded = ExitCode::decode(&code.encode()).unwrap();
    assert_eq!(decoded, code);
    // The bits survive the round-trip back to u32 (what the shim ultimately reports).
    assert_eq!(decoded.0 as u32, raw);
}

#[test]
fn exit_code_decode_rejects_short() {
    assert!(ExitCode::decode(&[0, 0, 0]).is_err());
}

#[test]
fn handshake_roundtrips() {
    let h = Handshake {
        version: PROTOCOL_VERSION,
        mode: Mode::Pty,
        cols: 100,
        rows: 30,
        term: "xterm-256color".into(),
        cwd: "C:\\Users\\example".into(),
        command: None,
        env: vec![("LANG".into(), "C".into())],
    };
    let bytes = h.encode().unwrap();
    assert_eq!(Handshake::decode(&bytes).unwrap(), h);
}

#[test]
fn handshake_exec_carries_command() {
    let h = Handshake {
        mode: Mode::Exec,
        command: Some("git status".into()),
        ..Handshake::pty_default()
    };
    assert_eq!(
        Handshake::decode(&h.encode().unwrap()).unwrap().command.as_deref(),
        Some("git status")
    );
}

#[test]
fn handshake_decode_rejects_version_mismatch() {
    let mut h = Handshake::pty_default();
    h.version = PROTOCOL_VERSION + 1;
    let bytes = h.encode().unwrap();
    assert!(
        Handshake::decode(&bytes).is_err(),
        "decode must reject a foreign protocol version"
    );
}

#[test]
fn reader_reassembles_split_frames() {
    let mut wire = Vec::new();
    write_frame(&mut wire, FrameKind::Data, &[Stream::Stdout as u8, b'h', b'i']).unwrap();
    write_frame(&mut wire, FrameKind::Exit, &ExitCode(0).encode()).unwrap();

    let mut reader = FrameReader::new();
    let mut out = Vec::new();
    for byte in wire {
        // one byte at a time = worst-case fragmentation
        reader.push(&[byte]);
        while let Some(frame) = reader.next_frame().unwrap() {
            out.push(frame);
        }
    }
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].kind, FrameKind::Data);
    assert_eq!(out[0].payload, vec![Stream::Stdout as u8, b'h', b'i']);
    assert_eq!(out[1].kind, FrameKind::Exit);
    assert_eq!(out[1].payload, ExitCode(0).encode().to_vec());
}

#[test]
fn reader_handles_multiple_frames_in_one_push() {
    let mut wire = Vec::new();
    write_frame(&mut wire, FrameKind::Data, b"\x02ab").unwrap();
    write_frame(&mut wire, FrameKind::Data, b"\x02cd").unwrap();
    let mut reader = FrameReader::new();
    reader.push(&wire);
    assert_eq!(reader.next_frame().unwrap().unwrap().payload, b"\x02ab");
    assert_eq!(reader.next_frame().unwrap().unwrap().payload, b"\x02cd");
    assert!(reader.next_frame().unwrap().is_none());
}

#[test]
fn reader_returns_none_when_incomplete() {
    let mut reader = FrameReader::new();
    // header claims 3 payload bytes, only 1 supplied
    reader.push(&[FrameKind::Data as u8, 3, 0, 0, 0, b'a']);
    assert!(reader.next_frame().unwrap().is_none());
    reader.push(b"bc");
    assert_eq!(reader.next_frame().unwrap().unwrap().payload, b"abc");
}

#[test]
fn reader_rejects_bad_kind_in_stream() {
    let mut reader = FrameReader::new();
    reader.push(&[9, 0, 0, 0, 0]); // bad kind byte
    assert!(reader.next_frame().is_err());
}

#[test]
fn header_decode_rejects_bad_kind() {
    assert!(FrameHeader::decode(&[9, 0, 0, 0, 0]).is_err());
}

#[test]
fn header_decode_rejects_oversize_len() {
    let len = (MAX_FRAME + 1).to_le_bytes();
    assert!(FrameHeader::decode(&[FrameKind::Data as u8, len[0], len[1], len[2], len[3]]).is_err());
}

#[test]
fn write_frame_rejects_oversize_payload() {
    let big = vec![0u8; (MAX_FRAME as usize) + 1];
    let mut sink = Vec::new();
    assert!(write_frame(&mut sink, FrameKind::Data, &big).is_err());
}

/// A `Read` that hands out at most `chunk` bytes per call, to exercise reassembly
/// across read boundaries (`std::io::Cursor` would return everything at once).
struct ChunkReader {
    data: Vec<u8>,
    pos: usize,
    chunk: usize,
}
impl ChunkReader {
    fn new(data: Vec<u8>, chunk: usize) -> Self {
        Self { data, pos: 0, chunk }
    }
}
impl std::io::Read for ChunkReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let remaining = &self.data[self.pos..];
        if remaining.is_empty() {
            return Ok(0);
        }
        let n = remaining.len().min(self.chunk).min(buf.len());
        buf[..n].copy_from_slice(&remaining[..n]);
        self.pos += n;
        Ok(n)
    }
}

#[test]
fn read_one_frame_leaves_pipelined_bytes_for_reuse() {
    use std::io::Cursor;
    // One write: a HANDSHAKE frame immediately followed by a DATA frame.
    let mut wire = Vec::new();
    let hs = Handshake::pty_default();
    write_frame(&mut wire, FrameKind::Handshake, &hs.encode().unwrap()).unwrap();
    write_frame(&mut wire, FrameKind::Data, &[Stream::Pty as u8, b'x']).unwrap();

    let mut conn = Cursor::new(wire);
    let mut fr = FrameReader::new();

    // Consumes only the handshake...
    let f1 = read_one_frame(&mut conn, &mut fr).unwrap();
    assert_eq!(f1.kind, FrameKind::Handshake);
    assert_eq!(Handshake::decode(&f1.payload).unwrap(), hs);

    // ...and the DATA frame is still available via the SAME FrameReader (its residual
    // buffer must be intact — not lost to an intermediate read buffer).
    let f2 = read_one_frame(&mut conn, &mut fr).unwrap();
    assert_eq!(f2.kind, FrameKind::Data);
    assert_eq!(f2.payload, vec![Stream::Pty as u8, b'x']);
}

#[test]
fn read_one_frame_reassembles_across_reads() {
    let mut wire = Vec::new();
    write_frame(&mut wire, FrameKind::Data, b"\x00hello").unwrap();
    let mut conn = ChunkReader::new(wire, 1); // one byte per read
    let mut fr = FrameReader::new();
    let f = read_one_frame(&mut conn, &mut fr).unwrap();
    assert_eq!(f.payload, b"\x00hello");
}

#[test]
fn read_one_frame_errors_on_eof_before_complete() {
    use std::io::Cursor;
    let mut wire = Vec::new();
    write_frame(&mut wire, FrameKind::Data, b"\x00abc").unwrap();
    wire.truncate(3); // chop mid-frame, then EOF
    let mut conn = Cursor::new(wire);
    let mut fr = FrameReader::new();
    assert!(read_one_frame(&mut conn, &mut fr).is_err());
}
