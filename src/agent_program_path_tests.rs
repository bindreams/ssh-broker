//! Windows-only: a program path containing spaces, with arguments after it, must reach the
//! relayed child intact.
//!
//! `pipes::ExecChild::spawn` passes the client's command line to `CreateProcessW(NULL, cmdline)`,
//! which resolves an unquoted `C:\Dir With Spaces\prog.exe /x` by prefix widening. Nothing in the
//! relay may tokenize or re-quote it first. `sshd` takes a `Subsystem sftp <path>` line verbatim,
//! and the path is commonly unquoted.
use crate::afunix::{self, Listener};
use crate::protocol::{FrameKind, FrameReader, Handshake, Mode, Stream, write_frame};
use crate::relay::{Outcome, TestSink, pump_decode, write_data};
use std::path::PathBuf;
use std::thread;

/// A fresh directory holding a hardened socket directory and `Spaced Dir\sftp-server.exe`, a copy
/// of `cmd.exe`, so the test needs no fixture binary.
struct Fixture {
    root: PathBuf,
    sockets: PathBuf,
    program: PathBuf,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!("sb-spaced-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let sockets = root.join("s");
        std::fs::create_dir_all(&sockets).unwrap();
        crate::acl::harden_dir(&sockets, &crate::acl::Sid::current_user().unwrap()).unwrap();

        let program_dir = root.join("Spaced Dir");
        std::fs::create_dir_all(&program_dir).unwrap();
        let program = program_dir.join("sftp-server.exe");
        let system_root = std::env::var_os("SystemRoot").expect("SystemRoot is set on Windows");
        std::fs::copy(PathBuf::from(system_root).join(r"System32\cmd.exe"), &program).unwrap();
        Self { root, sockets, program }
    }

    /// Run `command` through `handle_connection` and return what the client saw.
    fn relay(&self, command: String) -> (Outcome, Vec<u8>) {
        let sock = self.sockets.join("a");
        let listener = Listener::bind(&sock).unwrap();
        let client = thread::spawn(move || {
            let conn = afunix::connect(&sock).unwrap();
            let (mut crx, mut ctx) = afunix::split(conn).unwrap();
            let hs = Handshake {
                mode: Mode::Exec,
                command: Some(command),
                ..Handshake::pty_default()
            };
            write_frame(&mut ctx, FrameKind::Handshake, &hs.encode().unwrap()).unwrap();
            write_data(&mut ctx, Stream::Stdin, b"").unwrap(); // stdin-EOF marker, not a disconnect
            let mut fr = FrameReader::new();
            let mut sink = TestSink::default();
            let outcome = pump_decode(&mut crx, &mut fr, &mut sink).unwrap();
            (outcome, sink.stdout)
        });
        super::handle_connection(listener.accept().unwrap()).unwrap();
        client.join().unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn exec_relay_runs_an_unquoted_program_path_containing_spaces() {
    let fx = Fixture::new("unquoted");
    let (outcome, stdout) = fx.relay(format!("{} /c echo unquoted-ok", fx.program.display()));
    assert_eq!(outcome, Outcome::Exited(0));
    let text = String::from_utf8_lossy(&stdout);
    assert!(text.contains("unquoted-ok"), "relayed output was: {text:?}");
}

#[test]
fn exec_relay_runs_a_quoted_program_path_containing_spaces() {
    let fx = Fixture::new("quoted");
    let (outcome, stdout) = fx.relay(format!("\"{}\" /c echo quoted-ok", fx.program.display()));
    assert_eq!(outcome, Outcome::Exited(0));
    let text = String::from_utf8_lossy(&stdout);
    assert!(text.contains("quoted-ok"), "relayed output was: {text:?}");
}
