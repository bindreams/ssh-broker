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

/// The EXEC relay must be byte-transparent. This is the premise the whole transfer-classification
/// design rests on, and until now it was only ever asserted in prose: if relaying mangles bytes,
/// a missed classification corrupts an sftp/scp stream and detection is a correctness gate; if it
/// does not, detection is a throughput choice and nothing more.
///
/// The claim entered the tree with `40c30b2`, whose message has no body and which bundled two
/// changes. The only defect actually measured there was sftp *hanging* — `std::io::stdout()` is a
/// `LineWriter`, so newline-less output sat in the buffer — and the fix for that is the per-frame
/// flush, which applies to every relayed command whether or not it is classified as a transfer.
/// Nothing tested byte-transparency itself, so the premise could diverge silently. This is that
/// test.
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

// ── is_transfer_command (route sftp/scp locally, not through the agent) ──────────────

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
    // The shapes below are what an OpenSSH 10.3 client actually sends, measured rather than
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
    // The clusters below come from shipped clients' command templates, except the one marked
    // synthetic. Without them, a rule inspecting only the cluster's last character passes.
    assert!(is_transfer_command("scp -pf /tmp/x"), "libssh2, download");
    assert!(
        is_transfer_command("scp -pt /tmp/x"),
        "libssh2, upload preserving times"
    );
    assert!(
        is_transfer_command("scp -qt /tmp/x"),
        "bramvdbogaerde/go-scp, every upload"
    );
    assert!(is_transfer_command("scp -f /tmp/x"), "the bare fetch direction");
    assert!(
        is_transfer_command("scp -tr /tmp/x"),
        "easyssh-proxy: mode letter not last"
    );
    assert!(
        is_transfer_command("scp -prf /tmp/x"),
        "Renci SSH.NET, recursive download preserving times"
    );
    // An option that consumes the next token cannot itself be the mode flag.
    assert!(
        !is_transfer_command("scp -if /tmp/x"),
        "synthetic: `f` sits behind a value-taking `-i`"
    );
    // A pending consume swallows the NEXT token whatever it looks like: `-o` is `-i`'s value,
    // so it never acts as an option, and the `-t` after it is a genuine flag. Clearing the
    // pending state unconditionally got this backwards.
    assert!(
        is_transfer_command("scp -i -o -t /p"),
        "`-o` was `-i`'s value, so `-t` is a flag"
    );
    // ...including `--`, an argument here rather than an end-of-options marker.
    assert!(is_transfer_command("scp -o -- -t /p"), "`--` was `-o`'s value");
    // Within a cluster, letters are options until one takes a value.
    assert!(
        is_transfer_command("scp -ti /key /p"),
        "`t` precedes the value-taking `i`"
    );
    assert!(
        !is_transfer_command("scp -pi -t file"),
        "the cluster ends in `i`, which takes `-t`"
    );
}

/// `SCP_OPTSTRING` must be scp's optstring verbatim — hardcoded here rather than derived,
/// because a test that reads it cannot notice it shrinking: it just deletes its own coverage.
/// Measured at this commit: with this test absent, six of the eleven value-taking letters
/// (`D F J M S X`) can each be removed with the whole suite still green — precisely the ones no
/// command below exercises. Verified against the shipped `scp` binary, not transcribed from
/// documentation. `M` has no `case` and falls through to usage(), but getopt still consumes its
/// argument, so it keeps its `:`.
#[test]
fn optstring_is_exactly_scps_own() {
    assert_eq!(super::SCP_OPTSTRING, "12346ABCTdfOpqRrstvD:F:J:M:P:S:c:i:l:o:X:");
}

/// A letter scp's own getopt would reject is `BADCH`: scp prints usage and exits, so the command
/// never speaks the rcp protocol at all. Treating an unknown letter as a harmless boolean let a
/// `t` or `f` LATER in the cluster decide the command, routing an ordinary command to the local
/// passthrough — which spawns outside the session's job object and resolves PATH in session 0.
#[test]
fn letters_scp_would_reject_are_not_transfers() {
    // `--force` strips one dash to `-force`; getopt looks up `-`, which is not in the optstring.
    assert!(!is_transfer_command("scp --force a b"), "`-` is BADCH, not a boolean");
    assert!(
        !is_transfer_command("scp --two a b"),
        "`-` is BADCH before `t` is reached"
    );
    assert!(!is_transfer_command("scp -zt /p"), "`z` is not in scp's optstring");
    assert!(!is_transfer_command("scp -Zf /p"), "`Z` is not in scp's optstring");
    // A GNU-cp habit on the remote host, and the shape that made this reachable in practice.
    assert!(
        !is_transfer_command("scp --target-directory=/tmp file host:/x"),
        "the `t` after the BADCH `-` must not decide the command"
    );
}

/// The derivation must itself be right: `value_taking_letters` has to find exactly the
/// `:`-suffixed letters of the optstring. This is the half `optstring_is_exactly_scps_own`
/// cannot see — that test pins the source string, this one pins the parse of it. A bug in
/// either alone silently changes which options consume their argument, and a value-taking
/// letter that stops consuming lets the `-t` after it read as the mode flag.
#[test]
fn value_taking_letters_are_derived_from_the_optstring() {
    let sorted = |mut v: Vec<char>| {
        v.sort_unstable();
        v
    };
    assert_eq!(
        sorted(super::value_taking_letters().collect()),
        sorted("cDFiJlMoPSX".chars().collect())
    );
}

/// Commands where a value-taking option must not swallow the mode flag.
///
/// Only the `-l` pair is client-sourced, and it is the one that bit: jbardin/scp.py appends
/// `-l <n>` whenever a bandwidth limit is set, so dropping `l` makes `1000` read as the first
/// operand and the transfer is missed entirely. The rest are synthetic — scp never forwards
/// `-c`, `-P` or `-i` to the remote command — but they keep those letters from being removed
/// unnoticed.
#[test]
fn value_taking_options_do_not_swallow_the_mode_flag() {
    assert!(
        is_transfer_command("scp -l 1000 -t /path"),
        "scp.py, bandwidth-limited put"
    );
    assert!(
        is_transfer_command("scp -l 1000 -r -p -f /path"),
        "scp.py, the same fetching"
    );
    assert!(is_transfer_command("scp -c aes128-ctr -t /dst"));
    assert!(is_transfer_command("scp -P 2222 -t /dst"));
    assert!(is_transfer_command("scp -i /key/id_ed25519 -t /dst"));
}

/// Guards the CONTENTS of `VALUE_LETTERS`, which the loop below cannot: that loop reads the
/// set, so adding a boolean flag to it silently turns real client commands into missed
/// transfers while the loop stays green. Each assertion names a letter that must stay OUT of
/// the set; the ones marked with a client were captured from that client's source, the rest are
/// synthetic probes chosen because the letter is a plain boolean in scp's optstring.
#[test]
fn real_client_shapes_survive_a_wrong_value_set() {
    // `-d` (target is a directory): OpenSSH sends it for a multi-source or directory upload.
    assert!(is_transfer_command("scp -d -t /dst"), "`-d` must not take a value");
    assert!(is_transfer_command("scp -r -d -t /dst"));
    // `-v`: Terraform's ssh provisioner sends `scp -vt <dir>`; pscp prefixes `-v`.
    assert!(is_transfer_command("scp -vt /dst"), "`-v` must not take a value");
    assert!(is_transfer_command("scp -v -r -p -d -f /src"), "a verbose fetch");
    // Other booleans that appear ahead of the mode letter.
    // Synthetic: `-3`, `-q` and `-B` are booleans in the optstring, but no surveyed client
    // sends them ahead of the mode letter — `-3` and `-B` never reach the remote command at
    // all, and go-scp sends `-q` clustered as `-qt`.
    assert!(is_transfer_command("scp -3 -t /dst"), "`-3` must not take a value");
    assert!(is_transfer_command("scp -q -t /dst"), "`-q` must not take a value");
    assert!(is_transfer_command("scp -B -t /dst"), "`-B` must not take a value");
}

/// An UNQUOTED program path containing spaces is not detected, and that is deliberate.
///
/// `CreateProcessW` with a NULL `lpApplicationName` widens across spaces until a prefix names a
/// real executable, so such a command launches while `CommandLineToArgvW` reads argv[0] as
/// `C:\Program`. Classifying by those same candidates was tried and reverted: it produced worse
/// failures than it fixed. `icacls.exe C:\...\sftp-server.exe /grant Users:R` matched on a later
/// candidate and was routed to the local passthrough — spawned in session 0, outside the
/// session's job object — and no stock install emits the shape it was meant to catch, since
/// Windows OpenSSH's default `Subsystem sftp` line is a bare `sftp-server.exe` with no path.
/// Reaching the miss needs a hand-edited config with an unquoted spaced path; quoting it, which
/// the sshd_config format already expects, avoids it.
#[test]
fn does_not_detect_an_unquoted_program_path_with_spaces() {
    assert!(!is_transfer_command(r"C:\Program Files\OpenSSH\sftp-server.exe"));
    // The quoted form — what a config should use — is detected.
    assert!(is_transfer_command(r#""C:\Program Files\OpenSSH\sftp-server.exe""#));
    assert!(is_transfer_command(
        r#""C:\Program Files\OpenSSH\sftp-server.exe" -l ERROR"#
    ));
    // The failures that reverting avoids: an ordinary command naming the binary as an argument.
    assert!(!is_transfer_command(
        r"C:\Windows\System32\icacls.exe C:\Windows\System32\OpenSSH\sftp-server.exe /grant Users:R"
    ));
    assert!(!is_transfer_command(
        r"C:\Windows\System32\cmd.exe /c del C:\x\sftp-server.exe"
    ));
}

/// The miss above is reachable and corrupts a binary stream, so it must leave a footprint an
/// operator can find. The `split_wide` Err path already logs even though it is unreachable; this
/// case is reachable and logged nothing, so a corrupted transfer gave no signal pointing at the
/// classification layer at all.
///
/// The hint must NOT fire on the commands that reverting the widening protected — that is the
/// whole reason it is a log line and not a routing rule. `icacls.exe` names the binary as an
/// argument but is a real executable in argv[0], so it stays out.
#[test]
fn an_unquoted_spaced_transfer_path_leaves_a_diagnostic() {
    assert!(super::missed_transfer_hint(r"C:\Program Files\OpenSSH\sftp-server.exe"));
    assert!(super::missed_transfer_hint(r"C:\Program Files\OpenSSH\scp.exe -t /dst"));
    // The quoted form is classified correctly, so there is nothing to warn about.
    assert!(!super::missed_transfer_hint(
        r#""C:\Program Files\OpenSSH\sftp-server.exe""#
    ));
    // The false-positive shapes that made widening-based ROUTING untenable.
    assert!(!super::missed_transfer_hint(
        r"C:\Windows\System32\icacls.exe C:\Windows\System32\OpenSSH\sftp-server.exe /grant Users:R"
    ));
    assert!(!super::missed_transfer_hint(
        r"C:\Windows\System32\cmd.exe /c del C:\x\sftp-server.exe"
    ));
    // Ordinary commands, and correctly-classified transfers, stay silent.
    assert!(!super::missed_transfer_hint("scp -t /p"));
    assert!(!super::missed_transfer_hint("sftp-server.exe"));
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

/// Program names are matched case-insensitively, with either separator, and with or without
/// the `.exe` suffix — all shapes a `Subsystem` line or a client may produce.
#[test]
fn program_basename_accepts_every_real_spelling() {
    for cmd in [
        "SFTP-SERVER.EXE",
        r"C:/Windows/System32/OpenSSH/sftp-server.exe",
        r"C:\Windows\System32\OpenSSH\sftp-server",
        "Internal-SFTP",
    ] {
        assert!(is_transfer_command(cmd), "{cmd}");
    }
    assert!(is_transfer_command("SCP.EXE -t /dst"));
}

/// scp does not permute: option parsing stops at the first operand, so a dash-leading token
/// after one is a path. Without this, an ordinary copy with a source operand that merely begins
/// with `-f` was routed to the local passthrough, which spawns outside the session's job object.
#[test]
fn stops_scanning_options_at_the_first_operand() {
    assert!(!is_transfer_command("scp f.txt -f host:/dst"));
    assert!(!is_transfer_command("scp f.txt -t host:/dst"));
    assert!(!is_transfer_command("scp - -t host:/dst"), "a bare `-` is an operand");
}

/// Every value-taking option must consume the token after it, or a path named `-t` reads as
/// the mode flag. Looping the set means a newly added option cannot go untested — but the loop
/// reads the set, so it cannot see the set itself being wrong; that is the test above.
#[test]
fn every_value_taking_option_consumes_its_argument() {
    for letter in super::value_taking_letters() {
        assert!(
            !is_transfer_command(&format!("scp -{letter} -t /p")),
            "-{letter} must consume the `-t` after it"
        );
        assert!(
            is_transfer_command(&format!("scp -{letter}val -t /p")),
            "-{letter}val carries its own value, so `-t` is a flag"
        );
    }
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
