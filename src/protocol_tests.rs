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

/// The answer's two kinds have the numbers the contract gives them, and a version-5 peer reads them.
#[test]
fn the_answer_kinds_have_their_numbers_and_decode() {
    assert_eq!(FrameKind::Serving as u8, 4);
    assert_eq!(FrameKind::HandBack as u8, 5);
    for kind in [FrameKind::Serving, FrameKind::HandBack] {
        let header = FrameHeader { kind, len: 3 };
        assert_eq!(FrameHeader::decode(&header.encode()).unwrap(), header);
    }
    assert!(
        FrameHeader::decode(&[6, 0, 0, 0, 0]).is_err(),
        "the next number is still unknown"
    );
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
        launch: Launch::Shell,
        elevation: Some(ElevationPolicy::AutoApprove),
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

/// The reader counts the frames it has yielded over the whole connection: a frame still incomplete and a
/// malformed one are not counted.
#[test]
fn the_reader_counts_the_frames_it_has_yielded() {
    let mut reader = FrameReader::new();
    assert_eq!(reader.frames_read(), 0);
    reader.push(&[FrameKind::Data as u8, 3, 0, 0, 0, b'a']);
    assert!(reader.next_frame().unwrap().is_none());
    assert_eq!(reader.frames_read(), 0);
    reader.push(b"bc");
    reader.next_frame().unwrap().unwrap();
    assert_eq!(reader.frames_read(), 1);
    reader.push(&[9, 0, 0, 0, 0]);
    assert!(reader.next_frame().is_err());
    assert_eq!(reader.frames_read(), 1);
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

/// Reordering `Mode` would change the meaning of an installed agent's handshakes: a new variant goes last.
#[test]
fn mode_logout_encodes_after_exec() {
    assert_eq!(postcard::to_stdvec(&Mode::Pty).unwrap(), [0]);
    assert_eq!(postcard::to_stdvec(&Mode::Exec).unwrap(), [1]);
    assert_eq!(postcard::to_stdvec(&Mode::Logout).unwrap(), [2]);
}

#[test]
fn logout_handshake_roundtrips() {
    let h = Handshake {
        mode: Mode::Logout,
        ..Handshake::pty_default()
    };
    assert_eq!(Handshake::decode(&h.encode().unwrap()).unwrap().mode, Mode::Logout);
}

#[test]
fn launch_round_trips() {
    for launch in [Launch::Shell, Launch::Direct] {
        let h = Handshake {
            launch,
            command: Some("x".into()),
            ..Handshake::pty_default()
        };
        assert_eq!(Handshake::decode(&h.encode().unwrap()).unwrap().launch, launch);
    }
    assert_eq!(Handshake::pty_default().launch, Launch::Direct);
}

/// A peer of the other version is refused by name, whichever side is older: the old handshake has
/// no `launch`, and a decoder that read the whole struct first would say "unexpected end of input".
#[test]
fn a_version_1_handshake_is_refused_with_the_version_message() {
    #[derive(serde::Serialize)]
    struct V1 {
        version: u16,
        mode: Mode,
        cols: u16,
        rows: u16,
        term: String,
        cwd: String,
        command: Option<String>,
        env: Vec<(String, String)>,
    }
    let bytes = postcard::to_stdvec(&V1 {
        version: 1,
        mode: Mode::Exec,
        cols: 80,
        rows: 24,
        term: "xterm".into(),
        cwd: String::new(),
        command: Some("whoami".into()),
        env: Vec::new(),
    })
    .unwrap();
    let error = Handshake::decode(&bytes).unwrap_err().to_string();
    assert!(
        error.contains("peer 1") && error.contains(&format!("ours {PROTOCOL_VERSION}")),
        "{error}"
    );
}

/// The version is 5: the first frame of the agent is its answer, which version 4 did not have.
#[test]
fn the_wire_version_is_5() {
    assert_eq!(PROTOCOL_VERSION, 5);
    assert_eq!(Handshake::pty_default().version, 5);
}

#[test]
fn handshake_round_trips_each_policy() {
    for elevation in crate::test_support::asked_policies() {
        let h = Handshake {
            elevation,
            command: Some("x".into()),
            ..Handshake::pty_default()
        };
        assert_eq!(Handshake::decode(&h.encode().unwrap()).unwrap().elevation, elevation);
    }
    assert_eq!(Handshake::pty_default().elevation, Some(ElevationPolicy::DEFAULT));
}

/// The field is the last on the wire: it ends with whether the login asked (`1`) or set nothing (`0`),
/// and the variant index of what it asked.
#[test]
fn the_policy_is_the_last_field() {
    let always = Handshake {
        elevation: Some(ElevationPolicy::Always),
        ..Handshake::pty_default()
    };
    assert_eq!(always.encode().unwrap().last_chunk(), Some(&[1, 3]));
    assert_eq!(
        Handshake::pty_default().encode().unwrap().last_chunk(),
        Some(&[1, ElevationPolicy::DEFAULT as u8])
    );
    let nothing = Handshake {
        elevation: None,
        ..Handshake::pty_default()
    };
    assert_eq!(nothing.encode().unwrap().last(), Some(&0));
}

/// The default is the one level a login that asked for none is given where a level is needed.
#[test]
fn the_default_is_prompt() {
    assert_eq!(ElevationPolicy::DEFAULT, ElevationPolicy::Prompt);
}

#[test]
fn elevation_policy_parses_the_four_words_exactly() {
    for (word, policy) in [
        ("never", ElevationPolicy::Never),
        ("prompt", ElevationPolicy::Prompt),
        ("auto-approve", ElevationPolicy::AutoApprove),
        ("always", ElevationPolicy::Always),
    ] {
        assert_eq!(ElevationPolicy::parse(std::ffi::OsStr::new(word)), Ok(policy), "{word}");
    }
    assert_eq!(ElevationPolicy::VARIABLE, "SSH_BROKER_ELEVATION");
}

#[test]
fn elevation_policy_rejects_other_case_padding_empty_and_unknown_naming_the_value() {
    for value in [
        "Always",
        " always",
        "always ",
        "",
        "sometimes",
        "auto_approve",
        "ALWAYS\n",
    ] {
        let error = ElevationPolicy::parse(std::ffi::OsStr::new(value)).unwrap_err();
        assert_eq!(error.value, value);
        assert!(error.to_string().contains(&format!("{value:?}")), "{error}");
    }
}

/// A value that is not Unicode is refused too, and named by its lossy text.
#[cfg(windows)]
#[test]
fn elevation_policy_rejects_a_value_that_is_not_unicode() {
    use std::os::windows::ffi::OsStringExt;
    let value = std::ffi::OsString::from_wide(&[0x61, 0xd800, 0x62]);
    let error = ElevationPolicy::parse(&value).unwrap_err();
    assert_eq!(error.value, "a\u{fffd}b");
}

#[cfg(unix)]
#[test]
fn elevation_policy_rejects_a_value_that_is_not_unicode() {
    use std::os::unix::ffi::OsStrExt;
    let value = std::ffi::OsStr::from_bytes(&[0x61, 0xff, 0x62]);
    let error = ElevationPolicy::parse(value).unwrap_err();
    assert_eq!(error.value, "a\u{fffd}b");
}

/// The version is read alone, before the policy: a peer of a later version, whose handshake has fields
/// this build does not know, is refused by its version and not by a decoding failure.
#[test]
fn a_peer_of_another_version_is_still_refused_by_name() {
    let mut bytes = Handshake {
        version: PROTOCOL_VERSION + 1,
        ..Handshake::pty_default()
    }
    .encode()
    .unwrap();
    bytes.extend_from_slice(&[9, 9, 9]);
    let error = Handshake::decode(&bytes).unwrap_err().to_string();
    assert!(
        error.contains(&format!("peer {}", PROTOCOL_VERSION + 1))
            && error.contains(&format!("ours {PROTOCOL_VERSION}")),
        "{error}"
    );
}

/// A peer of another version is refused by its number.
#[test]
fn a_version_2_handshake_is_refused_with_the_version_message() {
    #[derive(serde::Serialize)]
    struct V2 {
        version: u16,
        mode: Mode,
        cols: u16,
        rows: u16,
        term: String,
        cwd: String,
        command: Option<String>,
        env: Vec<(String, String)>,
        launch: Launch,
    }
    let bytes = postcard::to_stdvec(&V2 {
        version: 2,
        mode: Mode::Exec,
        cols: 80,
        rows: 24,
        term: "xterm".into(),
        cwd: String::new(),
        command: Some("whoami".into()),
        env: Vec::new(),
        launch: Launch::Shell,
    })
    .unwrap();
    let error = Handshake::decode(&bytes).unwrap_err().to_string();
    assert!(error.contains("peer 2") && error.contains("ours 5"), "{error}");
}

/// A peer of another version is refused by its number.
#[test]
fn a_version_3_handshake_is_refused_with_the_version_message() {
    #[derive(serde::Serialize)]
    struct V3 {
        version: u16,
        mode: Mode,
        cols: u16,
        rows: u16,
        term: String,
        cwd: String,
        command: Option<String>,
        env: Vec<(String, String)>,
        launch: Launch,
        elevation: ElevationPolicy,
    }
    let bytes = postcard::to_stdvec(&V3 {
        version: 3,
        mode: Mode::Exec,
        cols: 80,
        rows: 24,
        term: "xterm".into(),
        cwd: String::new(),
        command: Some("whoami".into()),
        env: Vec::new(),
        launch: Launch::Shell,
        elevation: ElevationPolicy::Never,
    })
    .unwrap();
    let error = Handshake::decode(&bytes).unwrap_err().to_string();
    assert!(error.contains("peer 3") && error.contains("ours 5"), "{error}");
}

/// A peer of version 4 has the layout of this one and not its first frame (an answer, then no input before it):
/// it is refused by its number, not let through to misbehave.
#[test]
fn a_version_4_handshake_is_refused_with_the_version_message() {
    let bytes = Handshake {
        version: 4,
        ..Handshake::pty_default()
    }
    .encode()
    .unwrap();
    let error = Handshake::decode(&bytes).unwrap_err().to_string();
    assert!(error.contains("peer 4") && error.contains("ours 5"), "{error}");
}
