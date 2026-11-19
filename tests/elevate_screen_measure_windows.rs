//! **A throwaway measurement, not a test of the product**: what the person at a terminal sees when `elevate` runs a
//! command in a session with a terminal and the agent only switches the connection from the session to the command
//! and back, with no sequence of its own. It is deleted once the hand-over that the plan's Task 3 builds from it has
//! landed. Windows only; **Elevated (CI only)**: it makes an account and logs it in through the runner's sshd.
//!
//! What it records (the plan's Task 3, first step; the deputy's ruling R5), in the report that its one test panics
//! with, on purpose, so that a run shows it (a passing test shows nothing in nextest):
//!
//! - (a) what the client's terminal shows once the elevated command has ended, with no added sequence: the
//!   client's stream rendered with scrollback, as it is after a marker the session printed, the command, and
//!   a marker after it;
//! - (b) whether `ResizePseudoConsole` of a session's pseudoconsole makes it repaint its whole screen: to the same
//!   size, and one row smaller and back. Measured on a pseudoconsole of the test's own, made as the agent makes
//!   one (`PtySession::spawn`): what conhost does for a resize does not depend on who owns the pseudoconsole;
//! - (c) which scroll reaches the client's scrollback through sshd's own console: line feeds from the bottom row,
//!   or `CSI n S`. Measured with the stock PowerShell as sshd's shell, so that what the program writes goes to
//!   sshd's console as the agent's bytes do (they are written to the shim's stdout, which is that console), and not
//!   through the pseudoconsole a shell of the agent has in between;
//! - the Windows build, and whether `PSEUDOCONSOLE_PASSTHROUGH_MODE` was granted. `create_pty` falls back to the
//!   base flags without a word when it is not; a pseudoconsole made here with the same call gets the answer of
//!   this build, which is the agent's.
#![cfg(windows)]

use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};

use ssh_broker::conpty::{self, PtySession};
use ssh_broker::provision::canonical_exe;
use ssh_broker::provision::registry::{OPENSSH_KEY, set_default_shell_under};

#[path = "common/account.rs"]
mod account_fixture;
#[path = "common/agent_conn.rs"]
mod agent_conn;
#[path = "common/bounded_wait.rs"]
mod bounded_wait;
#[path = "common/child_entry.rs"]
mod child_entry;
#[path = "common/desktop.rs"]
mod desktop;
#[path = "common/drain.rs"]
mod drain;
#[path = "common/hard_errors.rs"]
mod hard_errors;
#[path = "common/logon_session.rs"]
mod logon_session;
#[path = "common/machine.rs"]
mod machine;
#[path = "common/password.rs"]
mod password;
#[path = "common/process_list.rs"]
mod process_list;
#[path = "common/session_end.rs"]
mod session_end;
#[path = "common/sshd_rig.rs"]
mod sshd_rig;
#[path = "common/stand_in.rs"]
mod stand_in;

use account_fixture::{Account, ServiceLogon};
use sshd_rig::{
    Login, SHELL_PROMPT, SILENCE_BOUND, SshSession, no_shell_to_carry, rendered, rendered_at, set_stock_shell,
};
use stand_in::Kit;

/// Rows of history the rendering keeps: more than any run here produces.
const SCROLLBACK: usize = 2000;

// (b): what a resize of a pseudoconsole does =====

/// A shell on a pseudoconsole of this test's own, read as it produces output.
struct Pty {
    session: PtySession,
    chunks: Receiver<Vec<u8>>,
    seen: Vec<u8>,
    reader: Option<std::thread::JoinHandle<()>>,
}

impl Pty {
    fn start(command: &str, cols: u16, rows: u16) -> Pty {
        let session = PtySession::spawn(command, cols, rows, None, None, None, &[]).expect("start the shell");
        let out_read = session.out_read_raw();
        let (sender, chunks) = channel();
        let reader = std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                let n = conpty::read_handle(out_read, &mut buf);
                if n == 0 || sender.send(buf[..n].to_vec()).is_err() {
                    return;
                }
            }
        });
        Pty {
            session,
            chunks,
            seen: Vec::new(),
            reader: Some(reader),
        }
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.seen).into_owned()
    }

    /// Read until the output holds `needle`. The wait is on the shell producing output, bounded by the silence
    /// failure bound: the shell is an external process that may never answer.
    fn read_until(&mut self, needle: &str) {
        while !self.text().contains(needle) {
            let received = self.chunks.recv_timeout(SILENCE_BOUND); // sleep-ok: failure bound on a shell's output, an external event that may never come; expiry fails the test and is not read as state
            match received {
                Ok(chunk) => self.seen.extend_from_slice(&chunk),
                Err(RecvTimeoutError::Disconnected) => {
                    panic!(
                        "the shell ended before it showed {needle:?}; it showed {:?}",
                        self.text()
                    )
                }
                Err(RecvTimeoutError::Timeout) => {
                    panic!("the shell was silent for {SILENCE_BOUND:?} while waiting for {needle:?}")
                }
            }
        }
    }

    fn type_line(&self, line: &str) {
        assert!(
            conpty::write_all_handle(self.session.in_write_raw(), format!("{line}\r").as_bytes()),
            "could not type into the shell"
        );
    }
}

impl Drop for Pty {
    fn drop(&mut self) {
        let _ = self.session.job().kill_tree();
        self.session.close_pty();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

/// Make a pseudoconsole of 80x24 show a marker, apply `resizes` to it, and report what it sent as a result: the bytes
/// the resizes (and a line typed after them, whose output closes the observation) caused, rendered on a terminal of
/// its own, and whether the marker is on it, which is a repaint of the screen.
fn repaint_after(what: &str, resizes: &[(u16, u16)]) -> String {
    let mut pty = Pty::start("cmd.exe /d /k echo SCREEN-MARKER", 80, 24);
    pty.read_until("SCREEN-MARKER");
    let before = pty.seen.len();
    for &(cols, rows) in resizes {
        pty.session.resize(cols, rows).expect("resize the pseudoconsole");
    }
    // The output of this line follows whatever the resizes made conhost send.
    pty.type_line("echo SYNC-%OS%");
    pty.read_until("SYNC-Windows_NT");
    let after = &pty.seen[before..];
    let shown = rendered_at(after, 24, 80, 0);
    let repainted = shown.visible().contains("SCREEN-MARKER");
    let head: String = format!("{:?}", String::from_utf8_lossy(after))
        .chars()
        .take(600)
        .collect();
    format!(
        "  {what}: the screen was repainted: {repainted}\n    the stream after the resize, on a fresh 80x24 terminal:\n{}\n    its first bytes: {head}\n",
        indent(&shown.visible(), "      | ")
    )
}

fn indent(text: &str, by: &str) -> String {
    text.lines()
        .map(|line| format!("{by}{line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

// (c): which scroll reaches the client's scrollback =====

/// Run `lines`, one typed line each, in a session of sshd's stock PowerShell, and render what the client received,
/// with `markers` (the rows the lines print, of which a scroll of a screen's height should leave none visible).
fn scroll_through_sshd(login: &Login<'_>, what: &str, markers: &str, lines: &[&str]) -> String {
    let mut session = SshSession::start(login.command(), login.diagnostics());
    session.read_until(SHELL_PROMPT);
    for line in lines {
        session.type_line(line);
    }
    session.say("SCROLL-DONE");
    let shown = rendered(&session.transcript, SCROLLBACK);
    let visible = shown.visible();
    let history = shown.history();
    let in_history = (1..=10).filter(|n| history.contains(&format!("{markers}{n} "))).count();
    let on_screen = (1..=10).filter(|n| visible.contains(&format!("{markers}{n} "))).count();
    session.leave();
    format!(
        "  {what}: of the 10 marker rows, {in_history} are in the history and {on_screen} are on the visible screen\n    the visible screen:\n{}\n",
        indent(&visible, "      | ")
    )
}

fn powershell() -> std::path::PathBuf {
    let root = std::env::var_os("SystemRoot").expect("SystemRoot is set");
    std::path::PathBuf::from(root).join(r"System32\WindowsPowerShell\v1.0\powershell.exe")
}

// The measurement =====

/// Elevated (CI only). **Fails on purpose**, with everything it recorded in its message: read the run's output.
#[test]
fn measurement_of_the_screen_hand_over_fails_on_purpose_to_show_what_it_recorded() {
    let _machine = machine::exclusive();
    account_fixture::assert_elevated();
    let kit = Kit::broker_with_helper("elms");
    let account = Account::create("elms", true);
    account.make_administrator();
    let _end = session_end::LogOutOnDrop::new(&canonical_exe(), &account, ServiceLogon::Sshd);
    let login = Login::new(&kit, &account);
    let mut report = String::from("MEASUREMENT OF THE SCREEN HAND-OVER (this test fails on purpose)\n\n");

    // The build, and the flags of a pseudoconsole made as the agent makes one.
    let (_, version) = sshd_rig::run("cmd.exe", &["/c", "ver"]);
    let mut probe =
        PtySession::spawn("cmd.exe /d /c exit", 80, 24, None, None, None, &[]).expect("start a probe shell");
    let drained = drain::drain(probe.out_read_raw());
    let passthrough = probe.passthrough();
    let _ = probe.wait();
    probe.close_pty();
    let _ = drained.join();
    report += &format!(
        "The runner: {}\nPSEUDOCONSOLE_PASSTHROUGH_MODE granted: {passthrough}\n\n",
        version.trim()
    );

    // (b)
    report += "(b) Does ResizePseudoConsole make a pseudoconsole repaint its screen?\n";
    report += &repaint_after("to the same size (80x24)", &[(80, 24)]);
    report += &repaint_after("one row smaller and back (80x23, then 80x24)", &[(80, 23), (80, 24)]);
    report += "\n";

    // (c): sshd's own console, with the stock PowerShell in it.
    set_stock_shell(&powershell());
    report += "(c) Which scroll reaches the client's scrollback through sshd's console?\n";
    let rows = "1..10 | ForEach-Object { 'ROW{0} ' -f $_ }";
    let sub = rows.replace("ROW", "SUB");
    let lf = "ROW".to_owned();
    report += &scroll_through_sshd(
        &login,
        "line feeds from the bottom row (CSI 999;1H, then 30 line feeds)",
        &lf,
        &[
            rows,
            "[Console]::Out.Write(\"$([char]27)[999;1H\" + ([string]::new([char]10, 30)))",
        ],
    );
    report += &scroll_through_sshd(
        &login,
        "CSI 30 S (scroll up by 30)",
        "SUB",
        &[&sub, "[Console]::Out.Write(\"$([char]27)[30S\")"],
    );
    report += "\n";

    // (a): the brokered session, with the agent's plain switch.
    set_default_shell_under(OPENSSH_KEY, &kit.exe.to_string_lossy(), &no_shell_to_carry())
        .expect("set the shim as DefaultShell");
    let mut first = login.start();
    first.log_in(&account.password);
    let mut session = SshSession::start(login.command_asking("auto-approve"), login.diagnostics());
    session.read_until(SHELL_PROMPT);
    session.say("BEFORE-THE-SWITCH");
    let mark = session.transcript.len();
    session.type_line(&format!("& '{}' elevate cmd.exe /c whoami /groups", kit.exe.display()));
    session.read_until(r"Mandatory Label\High Mandatory Level");
    session.say("AFTER-THE-SWITCH");
    let shown = rendered(&session.transcript, SCROLLBACK);
    let elevate_part: String = format!("{:?}", String::from_utf8_lossy(&session.transcript[mark..]))
        .chars()
        .take(6000)
        .collect();
    report += "(a) What the terminal shows once the command has ended, with no added sequence:\n";
    report += &format!(
        "  the visible screen:\n{}\n  the screen and its history:\n{}\n  the stream from the line that ran elevate (first 6000 characters, escaped):\n    {elevate_part}\n",
        indent(&shown.visible(), "    | "),
        indent(&shown.history(), "    | ")
    );
    session.leave();
    drop(first);

    // Each of the above is a record, not a verdict: the test fails so that the run's output carries it.
    panic!("{report}");
}
