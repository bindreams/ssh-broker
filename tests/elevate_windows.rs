//! `ssh-broker elevate` through a real sshd. Windows only; **Elevated (CI only)**: each test makes a local account,
//! logs it in through the runner's sshd and starts its agent.
//!
//! An administrator's default session is unelevated, and its agent runs at High. `elevate <command>` typed in it
//! asks that agent, on `request.sock`, to run the command, which the session's login (`SSH_BROKER_ELEVATION`)
//! allows or not:
//!
//! - `never` refuses, and nothing runs;
//! - `auto-approve` runs the command with the agent's own token, elevated. By default, in a session with a terminal
//!   or without, its input is closed and its output is printed by `elevate` in the session, below the typed line, so
//!   it can be piped; with `--terminal` it has a screen of its own, and the session's screen comes back when it ends;
//! - the default (`prompt`) asks the person at the terminal (`tests/consent_windows.rs`); in a session without one it
//!   is refused with a sentence that names the variable;
//! - `always` runs it in place, in a session that is elevated already.
//!
//! What a session with a terminal shows is judged on the client's stream rendered as a terminal would
//! (`sshd_rig::rendered`), with the rows that scrolled off.
#![cfg(windows)]

use ssh_broker::offer::text;
use ssh_broker::provision::canonical_exe;
use ssh_broker::provision::procwait;
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
use ssh_broker::socket_loc::{self, Integrity, SocketLocation};
use sshd_rig::{Login, SHELL_PROMPT, SshSession, no_shell_to_carry, rendered, run_client};
use stand_in::Kit;

/// What `whoami /groups` prints for a process at High, and for one that is not.
const HIGH: &str = r"Mandatory Label\High Mandatory Level";
const MEDIUM: &str = r"Mandatory Label\Medium Mandatory Level";

/// Pieces of what `whoami /groups` prints: no row of a terminal that shows a prompt holds one of these, which is
/// what a command's output garbled into a prompt's row looks like.
const COMMAND_ROWS: [&str; 5] = [
    "Mandatory Label",
    "Group Name",
    r"BUILTIN\",
    "Everyone",
    r"NT AUTHORITY\",
];

/// Rows of history a rendering keeps: more than any run here produces.
const SCROLLBACK: usize = 2000;

/// `elevate` refuses with 126.
const REFUSED: u32 = 126;

/// The exe the agent of a session started at the password prompt runs: the shim starts it from the installed exe,
/// not from its own copy in the kit (`shim_offer::run_offer`), so that is the image to look for.
fn agent_exe() -> std::path::PathBuf {
    canonical_exe()
}

/// An account whose agent a login at the password prompt has started (at High for an administrator), and the kit that
/// holds the shim sshd runs. The first login stays open: it is what keeps the account's session.
struct Started<'a> {
    kit: &'a Kit,
    account: &'a Account,
    login: Login<'a>,
    _first: SshSession,
}

impl<'a> Started<'a> {
    fn start(kit: &'a Kit, account: &'a Account) -> Started<'a> {
        let login = Login::new(kit, account);
        set_default_shell_under(OPENSSH_KEY, &kit.exe.to_string_lossy(), &no_shell_to_carry())
            .expect("set the shim as DefaultShell");
        let mut first = login.start();
        first.log_in(&account.password);
        Started {
            kit,
            account,
            login,
            _first: first,
        }
    }

    /// `ssh -T host -- "& '<exe>' elevate <tail>; exit $LASTEXITCODE"`, a login that asked for `asking` (`None`: it
    /// set nothing): a session without a terminal. The account's shell is PowerShell, which runs a quoted path only
    /// through its call operator; the exit is the elevated command's code, which PowerShell would otherwise make 0
    /// or 1.
    fn elevate_over_ssh(&self, asking: Option<&str>, tail: &str) -> sshd_rig::Outcome {
        self.elevate_over_ssh_after(asking, "", tail)
    }

    /// [`Started::elevate_over_ssh`] after the PowerShell statements `before` (each ending in `;`) have run in the
    /// session.
    fn elevate_over_ssh_after(&self, asking: Option<&str>, before: &str, tail: &str) -> sshd_rig::Outcome {
        let mut ssh = self.login.command_with(asking);
        ssh.arg("-T").arg("--").arg(format!(
            "{before}& '{}' elevate {tail}; exit $LASTEXITCODE",
            self.kit.exe.display()
        ));
        run_client(ssh, false, self.kit.dir())
    }

    /// What explains a failure: what the account's agent and shim logged, in both of its folders, first (the
    /// login's own evidence is long), then the login's.
    fn diagnostics(&self) -> impl Fn() -> String + 'static {
        let logs: Vec<SocketLocation> = [Integrity::High, Integrity::Medium]
            .into_iter()
            .filter_map(|integrity| socket_loc::for_profile(self.account.try_profile()?, integrity).ok())
            .collect();
        let login = self.login.diagnostics();
        move || {
            let mut report = String::new();
            for location in &logs {
                report += &format!(
                    "--- the logs in {} ---\n{}\n",
                    location.logs_dir().display(),
                    stand_in::read_logs(location)
                );
            }
            report + &login()
        }
    }

    /// `outcome`, with its stdout a second time as bytes (a terminal's escape codes do not show otherwise), and
    /// [`Started::diagnostics`].
    fn failure(&self, outcome: &sshd_rig::Outcome) -> String {
        let stdout = String::from_utf8_lossy(&outcome.stdout);
        format!(
            "exit {:?}\nstdout: {stdout}\nstdout, escaped: {stdout:?}\nstderr: {}\n{}",
            outcome.code,
            outcome.stderr,
            (self.diagnostics())()
        )
    }

    /// A session with a terminal whose login asked for `auto-approve`, past its first prompt. `sbk` is an alias of
    /// the broker's exe in it, so that a typed `elevate` line is short enough not to wrap on the screen.
    fn terminal_session(&self) -> SshSession {
        let mut session = SshSession::start(self.login.command_asking("auto-approve"), self.diagnostics());
        session.read_until(SHELL_PROMPT);
        session.type_line(&format!("Set-Alias sbk '{}'", self.kit.exe.display()));
        session.say("ALIAS-IS-SET");
        session
    }
}

/// The index of the first of `rows`, from `from` on, that `wanted` accepts; or a failure that shows all of them.
fn row_from(rows: &[&str], from: usize, what: &str, wanted: impl Fn(&str) -> bool) -> usize {
    rows.iter()
        .enumerate()
        .skip(from)
        .find(|(_, row)| wanted(row))
        .map(|(at, _)| at)
        .unwrap_or_else(|| panic!("no row {what} from row {from} on; the rows were:\n{}", rows.join("\n")))
}

/// A row that shows a prompt and, on the same row, a piece of what `whoami /groups` prints.
fn garbled(row: &str) -> bool {
    row.contains(SHELL_PROMPT) && COMMAND_ROWS.iter().any(|piece| row.contains(piece))
}

fn an_administrator(tag: &str) -> (Kit, Account, session_end::LogOutOnDrop) {
    account_fixture::assert_elevated();
    let kit = Kit::broker_with_helper(tag);
    let account = Account::create(tag, true);
    account.make_administrator();
    let end = session_end::LogOutOnDrop::new(&agent_exe(), &account, ServiceLogon::Sshd);
    (kit, account, end)
}

// What the login allows -----

/// Elevated (CI only). A login that asked for `never` is refused, with the sentence, exit 126, and the command
/// is not run: it would have made a file.
#[test]
fn never_refuses_elevate_and_nothing_runs() {
    let _machine = machine::exclusive();
    let (kit, account, _end) = an_administrator("elnv");
    let admin = Started::start(&kit, &account);

    let marker = kit.path("never-ran");
    let outcome = admin.elevate_over_ssh(Some("never"), &format!("cmd.exe /c copy NUL {}", marker.display()));
    assert_eq!(outcome.code, Some(REFUSED), "{}", admin.failure(&outcome));
    assert!(
        outcome.stderr.contains(text::elevation_never().trim_end()),
        "{}",
        admin.failure(&outcome)
    );
    assert!(!marker.exists(), "the command ran: {}", admin.failure(&outcome));
}

/// Elevated (CI only). `ssh host cmd` with `auto-approve`: the command runs elevated, with the agent's token, its
/// output is `elevate`'s own and so can be piped (only the line the filter keeps comes out), while the session that
/// asked is not elevated.
#[test]
fn a_command_run_without_a_terminal_has_its_output_piped_and_the_session_is_not_elevated() {
    let _machine = machine::exclusive();
    let (kit, account, _end) = an_administrator("elau");
    let admin = Started::start(&kit, &account);

    // The account's shell is PowerShell: its own filter is the pipe's other end.
    let elevated = admin.elevate_over_ssh(
        Some("auto-approve"),
        // Not `Select-String`: PowerShell 7 marks what it matched with escape codes, in the middle of the line.
        "cmd.exe /c whoami /groups | Where-Object { $_ -match 'Mandatory Label' }",
    );
    let shown = String::from_utf8_lossy(&elevated.stdout).into_owned();
    assert!(shown.contains(HIGH), "{}", admin.failure(&elevated));
    assert!(
        !COMMAND_ROWS[1..].iter().any(|piece| shown.contains(piece)),
        "more than the line the filter keeps came through the pipe: {}",
        admin.failure(&elevated)
    );
    assert_eq!(elevated.code, Some(0), "{}", admin.failure(&elevated));

    // The same program in the session itself is the session's: unelevated.
    let mut ssh = admin.login.command_asking("auto-approve");
    ssh.arg("-T").arg("--").arg("whoami /groups");
    let plain = run_client(ssh, false, kit.dir());
    let plain_shown = String::from_utf8_lossy(&plain.stdout).into_owned();
    assert!(
        plain_shown.contains(MEDIUM) && !plain_shown.contains(HIGH),
        "{}",
        admin.failure(&plain)
    );
}

/// Elevated (CI only). In a session with a terminal, without `--terminal`: the command's output is printed in the
/// session below the line that was typed, and the prompt follows it, with the next line and its output after that.
/// Judged on the client's history, in order, and on no row holding a prompt and a row of the command.
#[test]
fn with_a_terminal_the_output_is_below_the_typed_line_and_the_prompt_follows() {
    let _machine = machine::exclusive();
    let (kit, account, _end) = an_administrator("elwt");
    let admin = Started::start(&kit, &account);

    let mut session = admin.terminal_session();
    session.type_line("sbk elevate cmd.exe /c whoami /groups");
    session.read_until(HIGH);
    session.say("NEXT-LINE-OUTPUT");
    let shown = rendered(&session.transcript, SCROLLBACK);
    let history = shown.history();
    let rows: Vec<&str> = history.lines().collect();

    let typed = row_from(&rows, 0, "of the typed line", |row| {
        row.starts_with(SHELL_PROMPT) && row.contains("sbk elevate cmd.exe /c whoami /groups")
    });
    let high = row_from(&rows, typed + 1, "of the High label", |row| row.contains(HIGH));
    // The prompt that follows the output has the next typed line after it.
    let next = row_from(&rows, high + 1, "of a prompt with the next line typed", |row| {
        row.starts_with(SHELL_PROMPT) && row.contains("Write-Output")
    });
    row_from(&rows, next + 1, "of the next line's output", |row| {
        row == "NEXT-LINE-OUTPUT"
    });

    // The history ends with the live screen, so these are the visible rows as well.
    for row in &rows {
        assert!(
            !garbled(row),
            "a row holds a prompt and a row of the command: {row:?}\n{history}\n{}",
            session.text()
        );
    }
    session.leave();
}

/// The elevated `ping` that [`ctrl_c_ends_a_command_run_without_a_terminal_and_the_session_goes_on`] runs, found by
/// its image and by the arguments that test gave it, and held open. This process is elevated, so it can read the
/// command line of an elevated process, which the unelevated session cannot. It looks again until the ping is listed:
/// the command prints its marker just before it starts the ping, so the ping may not be there yet. A process that has
/// exited between the list and the look, or is ending (`procwait::Ending`: a ping an earlier test just ended), is
/// skipped; those are the routine causes of a failure, and any other failure is a panic with its cause.
fn elevated_ping(arguments: &str) -> procwait::Process {
    loop {
        for entry in process_list::snapshot() {
            if !entry.exe.eq_ignore_ascii_case("ping.exe") {
                continue;
            }
            let opened = procwait::Process::open(entry.pid)
                .unwrap_or_else(|e| panic!("could not open the process {} to look at it: {e:#}", entry.pid));
            let Some(process) = opened else {
                continue;
            };
            match procwait::command_line_of(&process) {
                Ok(line) if line.contains(arguments) => return process,
                Ok(_) => {}
                Err(e) if e.chain().any(|cause| cause.is::<procwait::Ending>()) => {}
                Err(_) if process.exit_code().is_ok() => {}
                Err(e) => panic!("could not read the command line of the process {}: {e:#}", entry.pid),
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(50)); // sleep-ok: looks again at whether the ping is listed each time, with no cap
    }
}

/// Elevated (CI only). Ctrl+C at the terminal ends the `elevate` that is running a command without `--terminal`,
/// and the command with it, at once; the session goes on. The command is `ping`, whose arguments are this test's
/// own. This process looks for it, which the unelevated session could not do for an elevated process: it is there
/// while the command runs, and gone (its handle signalled, within the fixtures' bound) after Ctrl+C.
#[test]
fn ctrl_c_ends_a_command_run_without_a_terminal_and_the_session_goes_on() {
    let _machine = machine::exclusive();
    let (kit, account, _end) = an_administrator("elcc");
    let admin = Started::start(&kit, &account);

    let mut session = admin.terminal_session();
    session.type_line("sbk elevate cmd.exe /c \"echo running-%OS%& ping -n 611 127.0.0.1 >nul\"");
    session.read_until("running-Windows_NT");
    let ping = elevated_ping("-n 611");

    // Ctrl+C is the byte the terminal sends for it.
    {
        use std::io::Write as _;
        session
            .stdin
            .write_all(&[0x03])
            .and_then(|()| session.stdin.flush())
            .expect("send Ctrl+C");
    }

    // The command's tree ends with the request: a wait on the process itself, which fails the test after the bound.
    bounded_wait::wait_for_exit(
        ping.handle(),
        ping.pid,
        "the elevated command's ping after Ctrl+C",
        bounded_wait::CHILD_EXIT_BOUND,
        &[],
    );
    // The next line is typed at the shell's next prompt, as a person types it, and not before: PowerShell's own
    // Ctrl+C handler discards the console's pending input once it has stopped the command
    // (`ConsoleHost.HandleBreak` calls `FlushConsoleInputBuffer` on Windows), so a line typed while it is still
    // at that is lost by the shell, whatever carried it there.
    session.read_until_after("running-Windows_NT", SHELL_PROMPT);
    session.say("THE-SESSION-WENT-ON");
    session.leave();
}

/// Elevated (CI only). With `--terminal` the keys typed reach the command straight (it reads a line and exits with a
/// code that says whether it was the line typed), and when it ends the session's screen is back: its marker is on
/// the screen, no row of the command is, and the next line runs.
///
/// What the command read is judged by its exit code, which the session prints afterwards, and not by anything the
/// command prints: its screen is replaced by the session's the moment it ends, so its last words need not reach the
/// client at all.
#[test]
fn with_terminal_keys_reach_the_command_and_the_sessions_screen_comes_back() {
    let _machine = machine::exclusive();
    let (kit, account, _end) = an_administrator("elkt");
    let admin = Started::start(&kit, &account);

    let mut session = admin.terminal_session();
    session.say("SESSION-MARKER");
    session.type_line(
        "sbk elevate --terminal cmd.exe /v:on /c \"set /p x=ELEVATED-%OS%:& if !x!==typed-into-it (exit 42) else \
         (exit 43)\"; Write-Output ('KEYS-' + $LASTEXITCODE)",
    );
    session.read_until("ELEVATED-Windows_NT:");
    session.type_line("typed-into-it");
    session.read_until("KEYS-42");
    session.say("NEXT-LINE-RAN");

    let shown = rendered(&session.transcript, SCROLLBACK);
    let visible = shown.visible();
    assert!(
        visible.contains("SESSION-MARKER"),
        "the session's screen did not come back:\n{visible}"
    );
    assert!(
        !shown.rows().iter().any(|row| row.contains("ELEVATED-Windows_NT:")),
        "a row of the command is left on the screen:\n{visible}"
    );
    session.leave();
}

/// Elevated (CI only). The default login asks the person at the terminal; in a session without one there is nobody
/// to ask, and `elevate` is refused with a sentence that names the variable, and the command does not run. (With a
/// terminal it asks: `tests/consent_windows.rs`.)
#[test]
fn default_policy_without_a_terminal_refuses_naming_the_variable() {
    let _machine = machine::exclusive();
    let (kit, account, _end) = an_administrator("elpr");
    let admin = Started::start(&kit, &account);

    let marker = kit.path("prompt-ran");
    let outcome = admin.elevate_over_ssh(None, &format!("cmd.exe /c copy NUL {}", marker.display()));
    assert_eq!(outcome.code, Some(REFUSED), "{}", admin.failure(&outcome));
    assert!(
        outcome.stderr.contains(text::elevation_no_terminal().trim_end()),
        "{}",
        admin.failure(&outcome)
    );
    assert!(!marker.exists(), "the command ran: {}", admin.failure(&outcome));
}

/// Elevated (CI only). The code `elevate` exits with is the command's.
#[test]
fn the_exit_code_of_the_elevated_command_is_the_codes_of_elevate() {
    let _machine = machine::exclusive();
    let (kit, account, _end) = an_administrator("elex");
    let admin = Started::start(&kit, &account);

    let outcome = admin.elevate_over_ssh(Some("auto-approve"), "cmd.exe /c exit 7");
    assert_eq!(outcome.code, Some(7), "{}", admin.failure(&outcome));

    // A command that did not run exits 126, with a line that says why: a program that is not found is the client's
    // own refusal, and no code of the agent's can be taken for the command's.
    let nowhere = admin.elevate_over_ssh(Some("auto-approve"), "nonesuch-elex");
    assert_eq!(nowhere.code, Some(REFUSED), "{}", admin.failure(&nowhere));
    assert!(
        nowhere
            .stderr
            .contains(text::elevation_cannot_start("nonesuch-elex: not found on PATH").trim_end()),
        "{}",
        admin.failure(&nowhere)
    );
}

/// Elevated (CI only). The line runs as it was typed. In a session whose shell is `cmd.exe`, the quotes round an `&`
/// keep it from being a second command: `elevate cmd /c echo "a&whoami"` prints the text, and `whoami` does not run
/// (argv joined again would have lost the quotes, and `echo a&whoami` runs both).
#[test]
fn the_line_runs_as_typed_from_cmd() {
    let _machine = machine::exclusive();
    let (kit, account, _end) = an_administrator("elcm");
    let admin = Started::start(&kit, &account);
    // Read when the next login starts its session, after the first one has its prompt.
    let system_root = std::env::var("SystemRoot").expect("SystemRoot");
    account.write_user_config(&format!("shell: '{system_root}\\System32\\cmd.exe'\n"));

    let mut ssh = admin.login.command_asking("auto-approve");
    ssh.arg("-T")
        .arg("--")
        .arg(format!("\"{}\" elevate cmd /c echo \"a&whoami\"", kit.exe.display()));
    let outcome = run_client(ssh, false, kit.dir());
    let shown = String::from_utf8_lossy(&outcome.stdout).into_owned();
    assert_eq!(outcome.code, Some(0), "{}", admin.failure(&outcome));
    assert!(shown.contains("\"a&whoami\""), "{}", admin.failure(&outcome));
    assert!(
        !shown.contains(&account.name),
        "whoami ran, and said who it is: {}",
        admin.failure(&outcome)
    );
}

/// Elevated (CI only). A program is found the way the session finds it, not the way the agent would: a relative path
/// is the session's folder's, and a bare name is searched on the session's `PATH`. The program is a copy of `cmd.exe`
/// (which needs no file beside it) under a name of this test's own, in a folder of its own, so nothing the agent could
/// find is that name; the copy runs the real `whoami`, which prints the High label.
#[test]
fn the_program_is_found_where_the_session_finds_it() {
    let _machine = machine::exclusive();
    let (kit, account, _end) = an_administrator("elpg");
    let admin = Started::start(&kit, &account);

    // In the account's own profile: its unelevated session cannot `Set-Location` into the kit, which is under the
    // profile of the account that runs the tests.
    let folder = account.profile().join("probe-folder");
    std::fs::create_dir(&folder).expect("make the folder of the program");
    let system_root = std::env::var("SystemRoot").expect("SystemRoot");
    std::fs::copy(
        std::path::Path::new(&system_root).join(r"System32\cmd.exe"),
        folder.join("probe-elpg.exe"),
    )
    .expect("copy cmd.exe under a name of this test's own");

    // After `cd` into the folder, a relative path names the program.
    let relative = admin.elevate_over_ssh_after(
        Some("auto-approve"),
        &format!("Set-Location '{}'; ", folder.display()),
        r".\probe-elpg.exe /c whoami /groups",
    );
    assert!(
        String::from_utf8_lossy(&relative.stdout).contains(HIGH),
        "{}",
        admin.failure(&relative)
    );
    assert_eq!(relative.code, Some(0), "{}", admin.failure(&relative));

    // With the folder put on the PATH of the session only, from another folder, the bare name finds it.
    let bare = admin.elevate_over_ssh_after(
        Some("auto-approve"),
        &format!("$env:PATH = '{};' + $env:PATH; ", folder.display()),
        "probe-elpg /c whoami /groups",
    );
    assert!(
        String::from_utf8_lossy(&bare.stdout).contains(HIGH),
        "{}",
        admin.failure(&bare)
    );
    assert_eq!(bare.code, Some(0), "{}", admin.failure(&bare));
}

/// Elevated (CI only). A login that asked for `always` is at High already: `elevate` runs the command in place and
/// asks nobody (a request to the agent would be refused: that session is elevated).
#[test]
fn always_runs_elevate_in_place_and_asks_nothing() {
    let _machine = machine::exclusive();
    let (kit, account, _end) = an_administrator("elal");
    let admin = Started::start(&kit, &account);

    let outcome = admin.elevate_over_ssh(Some("always"), "whoami /groups");
    let shown = String::from_utf8_lossy(&outcome.stdout).into_owned();
    assert!(shown.contains(HIGH), "{}", admin.failure(&outcome));
    assert_eq!(outcome.code, Some(0), "{}", admin.failure(&outcome));
    assert!(
        !outcome.stderr.contains(text::elevation_already_elevated().trim_end()),
        "the agent was asked: {}",
        admin.failure(&outcome)
    );
}

/// Elevated (CI only). In place, as a person uses it: the command's exit code is `elevate`'s, `--terminal` changes
/// nothing (no screen is made at High), and a program that is not found is the client's own refusal, 126, with the
/// sentence that names it.
#[test]
fn in_place_elevate_gives_the_commands_code_and_refuses_a_program_it_cannot_find() {
    let _machine = machine::exclusive();
    let (kit, account, _end) = an_administrator("elip");
    let admin = Started::start(&kit, &account);

    let plain = admin.elevate_over_ssh(Some("always"), "cmd.exe /c exit 7");
    assert_eq!(plain.code, Some(7), "{}", admin.failure(&plain));

    let terminal = admin.elevate_over_ssh(Some("always"), "--terminal cmd.exe /c exit 8");
    assert_eq!(terminal.code, Some(8), "{}", admin.failure(&terminal));

    let nowhere = admin.elevate_over_ssh(Some("always"), "nonesuch-elip");
    assert_eq!(nowhere.code, Some(REFUSED), "{}", admin.failure(&nowhere));
    assert!(
        nowhere
            .stderr
            .contains(text::elevation_cannot_start("nonesuch-elip: not found on PATH").trim_end()),
        "{}",
        admin.failure(&nowhere)
    );
}

// Where it is refused -----

/// Elevated (CI only). A shell that is not under ssh-broker (no agent: the shim runs the command itself) has no
/// session id: `elevate` says it is not hosted.
#[test]
fn elevate_in_the_failopen_shell_is_refused_not_hosted() {
    let _machine = machine::exclusive();
    account_fixture::assert_elevated();
    let kit = Kit::broker_with_helper("elfo");
    let account = Account::create("elfo", true);
    let _end = session_end::LogOutOnDrop::new(&agent_exe(), &account, ServiceLogon::Sshd);
    let login = Login::new(&kit, &account);
    set_default_shell_under(OPENSSH_KEY, &kit.exe.to_string_lossy(), &no_shell_to_carry())
        .expect("set the shim as DefaultShell");

    // No login has started this account's agent, and a command is never offered a password prompt.
    let mut ssh = login.command();
    ssh.arg("-T")
        .arg("--")
        .arg(format!("& '{}' elevate whoami; exit $LASTEXITCODE", kit.exe.display()));
    let outcome = run_client(ssh, false, kit.dir());
    assert_eq!(outcome.code, Some(REFUSED), "{:?}\n{}", outcome.code, outcome.stderr);
    assert!(
        outcome.stderr.contains(text::elevation_not_hosted().trim_end()),
        "{}",
        outcome.stderr
    );
}

/// Elevated (CI only). A standard account's agent runs below High and keeps no request socket: `elevate` says
/// that, with exit 126.
#[test]
fn a_standard_accounts_elevate_is_refused_naming_why() {
    let _machine = machine::exclusive();
    account_fixture::assert_elevated();
    let kit = Kit::broker_with_helper("elst");
    let account = Account::create("elst", true);
    let _end = session_end::LogOutOnDrop::new(&agent_exe(), &account, ServiceLogon::Sshd);
    let admin = Started::start(&kit, &account);

    let outcome = admin.elevate_over_ssh(Some("auto-approve"), "whoami");
    assert_eq!(outcome.code, Some(REFUSED), "{}", admin.failure(&outcome));
    assert!(
        outcome.stderr.contains(text::elevation_needs_high_agent().trim_end()),
        "{}",
        admin.failure(&outcome)
    );
}
