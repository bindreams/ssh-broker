//! A background agent started the way the prompt path starts it, and a client that speaks to it as
//! the shim would. **CI only.**
//!
//! The client is the elevated test process: the socket's DACL admits Administrators, so no console and
//! no second logon are needed to hold a PTY or exec session through an account's agent.
//!
//! The including crate declares `account_fixture`, `desktop`, `machine`, `password` and `stand_in`.
#![allow(dead_code)]

use ssh_broker::account::LocalAccount;
use ssh_broker::afunix::{self, ConnRx, ConnTx};
use ssh_broker::logon;
use ssh_broker::protocol::{FrameKind, FrameReader, Handshake, Launch, Mode, Stream, write_frame};
use ssh_broker::relay::{FrameSink, Outcome, PumpError, pump_decode, write_data};
use ssh_broker::socket_loc::{self, SocketLocation};
use ssh_broker::vtinput::{KeyEvent, encode_key_event};
use ssh_broker::winutil::OwnedHandle;
use windows::Win32::System::Threading::TerminateProcess;

use crate::account_fixture::Account;
use crate::stand_in::{Kit, wait_for_serving_marker};

/// How long a session may stay silent while a test reads from it. A read that gets nothing for this
/// long fails with a transport error (`TimedOut`), and the test's message names what it awaited.
const SILENCE_BOUND: std::time::Duration = std::time::Duration::from_secs(240);

/// The product's view of a fixture account.
pub fn local_account(account: &Account) -> LocalAccount {
    LocalAccount {
        name: account.name.clone(),
        sid: account.sid_text.clone(),
        kind: ssh_broker::offer::AccountKind::Local,
    }
}

/// An `ssh-broker agent --background` that `CreateProcessWithLogonW` started for a fixture account,
/// listening. Ended when dropped, so a failing test leaves no agent behind.
pub struct BackgroundAgent {
    pub process: OwnedHandle,
    pub location: SocketLocation,
}

impl BackgroundAgent {
    /// Start it from `kit`'s copy of the real exe and wait until it is listening. Panics with what
    /// the agent left (exit code, `agent.log`) if it ends first.
    pub fn start(kit: &Kit, account: &Account) -> BackgroundAgent {
        let password = crate::password::password(&account.password);
        let started = logon::start_background_agent(&local_account(account), &password, &kit.exe)
            .unwrap_or_else(|e| panic!("the logon for {} failed: {e:?}", account.name));
        let location = socket_loc::for_profile(account.profile()).unwrap();
        let agent = BackgroundAgent {
            process: started.process,
            location,
        };
        wait_for_serving_marker(&agent.location, agent.process.0);
        agent
    }
}

impl Drop for BackgroundAgent {
    fn drop(&mut self) {
        // SAFETY: a valid process handle; ending an agent that already ended is harmless.
        let _ = unsafe { TerminateProcess(self.process.0, 1) };
    }
}

/// A connection to an agent, driven as the shim drives it.
pub struct AgentConn {
    rx: ConnRx,
    tx: ConnTx,
    fr: FrameReader,
    transcript: Transcript,
}

/// Collects the agent's output, and stops the pump once the PTY text contains `until`.
#[derive(Default)]
struct Transcript {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    pty: Vec<u8>,
    until: Option<String>,
}

/// Why a pump stopped early on purpose.
#[derive(Debug)]
struct Found;

impl std::fmt::Display for Found {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the awaited text arrived")
    }
}

impl std::error::Error for Found {}

impl FrameSink for Transcript {
    fn on_data(&mut self, stream: Stream, bytes: &[u8]) -> anyhow::Result<()> {
        match stream {
            Stream::Stderr => self.stderr.extend_from_slice(bytes),
            Stream::Pty => self.pty.extend_from_slice(bytes),
            _ => self.stdout.extend_from_slice(bytes),
        }
        if let Some(needle) = &self.until
            && String::from_utf8_lossy(&self.pty).contains(needle.as_str())
        {
            return Err(Found.into());
        }
        Ok(())
    }
}

/// What a session produced, and how it ended.
pub struct Finished {
    pub stdout: String,
    pub stderr: String,
    pub pty: String,
    /// `None` when the agent closed the connection without an exit code.
    pub exit: Option<i32>,
}

impl AgentConn {
    pub fn connect(location: &SocketLocation) -> AgentConn {
        let conn = afunix::connect(&location.path)
            .unwrap_or_else(|e| panic!("connect to the agent at {}: {e:#}", location.path.display()));
        // A failure bound on the agent's output, an external event that may never come.
        conn.set_read_timeout(Some(SILENCE_BOUND)).unwrap();
        let (rx, tx) = afunix::split(conn).unwrap();
        AgentConn {
            rx,
            tx,
            fr: FrameReader::new(),
            transcript: Transcript::default(),
        }
    }

    fn handshake(&mut self, mode: Mode, command: Option<&str>, launch: Launch) {
        let hs = Handshake {
            mode,
            command: command.map(str::to_string),
            launch,
            ..Handshake::pty_default()
        };
        write_frame(&mut self.tx, FrameKind::Handshake, &hs.encode().unwrap()).unwrap();
    }

    /// Start an interactive session running `command`.
    pub fn start_pty(&mut self, command: &str) {
        self.handshake(Mode::Pty, Some(command), Launch::Direct);
    }

    /// Start a session with a terminal the way the shim asks for one: through the account's configured
    /// shell, running `command` or, with `None`, a login.
    pub fn start_shell_pty(&mut self, command: Option<&str>) {
        self.handshake(Mode::Pty, command, Launch::Shell);
    }

    /// Start a session that runs `command` on redirected pipes.
    pub fn start_exec(&mut self, command: &str) {
        self.handshake(Mode::Exec, Some(command), Launch::Direct);
    }

    /// Type `line` and Enter into a PTY session, as win32-input-mode key events.
    pub fn type_line(&mut self, line: &str) {
        let key = |vk: u16, ch: u16, down: bool| KeyEvent {
            virtual_key_code: vk,
            virtual_scan_code: 0,
            unicode_char: ch,
            key_down: down,
            control_key_state: 0,
            repeat_count: 1,
        };
        let mut bytes = Vec::new();
        for unit in line.encode_utf16() {
            bytes.extend(encode_key_event(&key(0, unit, true)));
            bytes.extend(encode_key_event(&key(0, unit, false)));
        }
        bytes.extend(encode_key_event(&key(0x0D, 0x0D, true)));
        bytes.extend(encode_key_event(&key(0x0D, 0x0D, false)));
        write_data(&mut self.tx, Stream::Pty, &bytes).unwrap();
    }

    /// Mark the end of stdin of an exec session.
    pub fn end_stdin(&mut self) {
        write_data(&mut self.tx, Stream::Stdin, b"").unwrap();
    }

    /// Read until the PTY text contains `needle`; returns the text so far. The wait is on the shell
    /// producing it. A session that ends first is a failure.
    pub fn read_until_pty_shows(&mut self, needle: &str) -> String {
        self.transcript.until = Some(needle.to_string());
        let outcome = pump_decode(&mut self.rx, &mut self.fr, &mut self.transcript);
        self.transcript.until = None;
        let text = String::from_utf8_lossy(&self.transcript.pty).into_owned();
        match outcome {
            Err(PumpError::Sink(e)) if e.is::<Found>() => text,
            other => panic!(
                "the session ended, broke or stayed silent for {SILENCE_BOUND:?} before it showed {needle:?} ({other:?}); it showed:
{text}"
            ),
        }
    }

    /// Read until the session's exit code arrives or the agent closes the connection. This is a wait on
    /// the session itself, which ends when the shell does.
    pub fn read_to_end(&mut self) -> Finished {
        let outcome = pump_decode(&mut self.rx, &mut self.fr, &mut self.transcript);
        let exit = match outcome {
            Ok(Outcome::Exited(code)) => Some(code),
            Ok(Outcome::PeerClosed) => None,
            Err(e) => panic!(
                "the agent's stream broke or stayed silent for {SILENCE_BOUND:?} while the test waited for the session to end: {e:?}
stdout: {:?}
stderr: {:?}
pty: {:?}",
                String::from_utf8_lossy(&self.transcript.stdout),
                String::from_utf8_lossy(&self.transcript.stderr),
                String::from_utf8_lossy(&self.transcript.pty)
            ),
        };
        Finished {
            stdout: String::from_utf8_lossy(&self.transcript.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&self.transcript.stderr).into_owned(),
            pty: String::from_utf8_lossy(&self.transcript.pty).into_owned(),
            exit,
        }
    }
}
