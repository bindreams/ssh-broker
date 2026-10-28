//! The prompt path end to end: the shim of an account with no session asks for the Windows password
//! at a real console, the logon starts a background agent, and the login relays into it. Windows only;
//! **Elevated (CI only)**.
//!
//! The shim runs as a throwaway account's network token (what sshd gives it) on a pseudoconsole that a
//! helper hosts (`examples/session_stand_in`, role `pty`); the test types key events into it and reads
//! what it shows. Every test creates accounts and logs them on: run them in CI, never on a workstation.
#![cfg(windows)]

use ssh_broker::socket_loc;
use ssh_broker::userdir;

#[path = "common/account.rs"]
mod account_fixture;
#[path = "common/agent_conn.rs"]
mod agent_conn;
#[path = "common/bounded_wait.rs"]
mod bounded_wait;
#[path = "common/desktop.rs"]
mod desktop;
#[path = "common/hard_errors.rs"]
mod hard_errors;
#[path = "common/machine.rs"]
mod machine;
#[path = "common/password.rs"]
mod password;
#[path = "common/process_list.rs"]
mod process_list;
#[path = "common/pty_client.rs"]
mod pty_client;
#[path = "common/stand_in.rs"]
mod stand_in;

use ssh_broker::winutil::OwnedHandle;
use windows::Win32::System::Threading::{
    GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
};

use account_fixture::Account;
use agent_conn::AgentConn;
use pty_client::PtyRun;
use stand_in::{Kit, RealAgent};

/// What the prompt says first (the owner's sentence).
const PROMPT: &str = "Enter your Windows password to start one.";
/// The second sentence of the prompt.
const WAY_OUT: &str = "Press Ctrl+C for a plain shell.";
/// The start of the line that states the cost of the plain shell.
const COST: &str = "starting a plain shell, without DPAPI";
/// The start of a PowerShell prompt, which both the relayed shell and the plain shell show.
const SHELL_PROMPT: &str = "PS C:\\";

fn kit(tag: &str) -> Kit {
    Kit::broker_with_helper(tag)
}

/// The shim of `account` on a console, with the logs the shim and its agent write printed when a wait
/// for the console fails: they say how far the shim got.
fn start_run(kit: &Kit, account: &Account) -> PtyRun {
    let profile = account.try_profile().map(std::path::Path::to_path_buf);
    PtyRun::start(kit, account, &kit.exe).with_context(move || {
        let logs = profile
            .as_deref()
            .and_then(|profile| socket_loc::for_profile(profile).ok())
            .map(|location| stand_in::read_logs(&location))
            .unwrap_or_default();
        format!("logs of the account (shim.log, agent.log):\n{logs}")
    })
}

/// The folder the agent of `account` logs into, as evidence for a wait that fails.
fn logs_of(account: &Account) -> Vec<std::path::PathBuf> {
    account
        .try_profile()
        .and_then(|profile| socket_loc::for_profile(profile).ok())
        .map(|location| location.logs_dir())
        .into_iter()
        .collect()
}

/// A marker the shell prints but does not echo back as typed: its two halves are joined by the shell.
fn say(run: &mut PtyRun, marker: &str) {
    let (head, tail) = marker.split_at(marker.len() / 2);
    run.type_line(&format!("Write-Output ('{head}' + '{tail}')"));
    run.read_until(marker);
}

/// Type the password at the prompt and wait for a shell. The plain shell the shim falls back to shows
/// the same prompt as the relayed one, so a login that fell back fails here, with the reason the shim
/// gave, and not later in a check that cannot tell the two apart.
fn log_in(run: &mut PtyRun, password: &str) {
    run.read_until(PROMPT);
    run.type_line(password);
    expect_session(run);
}

/// Wait for the shell that follows a submitted password, and fail if the shim fell back to a plain one.
fn expect_session(run: &mut PtyRun) {
    run.read_until(SHELL_PROMPT);
    let shown = run.text();
    assert!(
        !shown.contains(COST),
        "the login fell back to a plain shell instead of starting a session:
{shown}"
    );
    without_psreadline(run);
}

/// Wait for a PowerShell prompt and then take PSReadLine out of that shell: see [`without_psreadline`].
fn shell_up(run: &mut PtyRun) {
    run.read_until(SHELL_PROMPT);
    without_psreadline(run);
}

/// Take PSReadLine out of the shell, so the host's own reader reads the lines typed after this one.
/// Under this harness the shell's PSReadLine cannot make its history mutex (`measure_named_objects`
/// prints the denial; real sshd gives the shell a token that can, which `real_sshd_windows` asserts)
/// and prints a crash report at every prompt. Input typed while a report is printing is no part of
/// what these tests name, and one run lost it (the console went silent after the first character of
/// `exit`).
fn without_psreadline(run: &mut PtyRun) {
    run.type_line("Remove-Module PSReadLine -ErrorAction SilentlyContinue; Write-Output ('psreadline' + '-off')");
    run.read_until("psreadline-off");
}

/// The shell is the session's: the user's DPAPI works in it, which the plain shell of the shim's network
/// token cannot do (the cost line says so). The prompt does not tell the two apart.
fn assert_relayed(run: &mut PtyRun) {
    run.type_line(
        "try { [void][Security.Cryptography.ProtectedData]::Protect([byte[]](1,2,3), $null, 'CurrentUser'); \
         Write-Output ('dpapi' + '-ok') } catch { Write-Output ('dpapi' + '-failed ' + $_) }",
    );
    let found = run.read_until_any(&["dpapi-ok", "dpapi-failed"]);
    assert_eq!(
        found,
        0,
        "the shell is not the session's (DPAPI failed):\n{}",
        run.text()
    );
}

/// Print whether the shell can make a named kernel object: a PowerShell prompt's PSReadLine makes one
/// and crashes without it. A measurement, not a check.
fn measure_named_objects(run: &mut PtyRun, which: &str) {
    run.type_line(
        "try { [void][Threading.Mutex]::new($false, 'sbprobe' + $PID); Write-Output ('mutex' + '-ok') } \
         catch { Write-Output ('mutex' + '-failed ' + $_.Exception.GetType().Name) }",
    );
    let found = run.read_until_any(&["mutex-ok", "mutex-failed"]);
    let crashed = run.text().contains("Oops, something went wrong");
    eprintln!(
        "named objects in {which}: a mutex can{} be made; PSReadLine crashed at its first prompt: {crashed}",
        if found == 0 { "" } else { "not" }
    );
}

fn leave(run: &mut PtyRun) {
    run.type_line("exit");
    run.finish();
}

/// The consoles of these tests run the shim in the job it has under sshd (kill-on-close with breakaway
/// allowed, `LimitFlags` 0x2800 = 10240; measured by `real_sshd_windows`), so that what a console's end
/// does to the agent is what a session's end does under sshd. Read from the shim's own log, so call it
/// once the consoles have left.
fn assert_shim_ran_in_sshds_job(account: &Account) {
    let location = socket_loc::for_profile(account.profile()).unwrap();
    let logs = stand_in::read_logs(&location);
    assert!(
        logs.contains("logon call: caller's job Limits(10240)"),
        "the shim did not run in a job like sshd's (kill-on-close, breakaway allowed); its logs:
{logs}"
    );
}

/// Elevated (CI only).
#[test]
fn prompt_then_password_relays_into_a_background_session() {
    let _machine = machine::shared();
    let kit = kit("pp1");
    let account = Account::create("pp1", true);
    let mut run = start_run(&kit, &account);
    run.read_until(WAY_OUT);
    log_in(&mut run, &account.password);

    // The user's real profile, not the default one a network logon shows.
    run.type_line("Write-Output ('profile=' + $env:USERPROFILE + '.')");
    run.read_until(&format!("profile={}.", account.profile().display()));
    // DPAPI works for the user: a user-scope blob round-trips.
    run.type_line(
        "try { [void][Security.Cryptography.ProtectedData]::Protect([byte[]](1,2,3), $null, 'CurrentUser'); \
         Write-Output ('dpapi' + '-ok') } catch { Write-Output ('dpapi' + '-failed ' + $_) }",
    );
    run.read_until("dpapi-ok");
    measure_named_objects(&mut run, "a single relayed session");
    // Links a non-administrator made resolve (no RedirectionGuard on the shell).
    run.type_line(
        "New-Item -ItemType Junction -Path \"$env:TEMP\\sbjunction\" -Target $env:USERPROFILE | Out-Null; \
         if (Test-Path \"$env:TEMP\\sbjunction\\AppData\") { Write-Output ('link' + '-ok') } else { Write-Output ('link' + '-blocked') }",
    );
    run.read_until("link-ok");
    leave(&mut run);
    assert_shim_ran_in_sshds_job(&account);
}

/// Elevated (CI only). No `ProfileList` entry yet, and the first logon creates one.
#[test]
fn new_account_without_profile_gets_a_profile_and_a_session() {
    let _machine = machine::shared();
    let kit = kit("pp2");
    let account = Account::create("pp2", false);
    let token = account.network_token();
    let before = userdir::profile_dir_of_token(token.0).unwrap_err();
    assert!(before.downcast_ref::<userdir::NoProfile>().is_some(), "{before:#}");

    let mut run = start_run(&kit, &account);
    log_in(&mut run, &account.password);
    say(&mut run, "session-up");
    leave(&mut run);

    let profile = userdir::profile_dir_of_token(account.network_token().0).expect("the logon made the profile");
    assert!(profile.is_dir(), "{}", profile.display());
}

/// Elevated (CI only).
#[test]
fn wrong_password_gives_plain_shell_with_reason_and_no_second_prompt() {
    let _machine = machine::shared();
    let kit = kit("pp3");
    let account = Account::create("pp3", true);
    let mut run = start_run(&kit, &account);
    log_in_expecting_plain(&mut run, "not-the-password");
    run.read_until("Windows did not sign you in:");
    say(&mut run, "plain-shell-works");
    let transcript = run.text();
    assert_eq!(transcript.matches(PROMPT).count(), 1, "no second prompt:\n{transcript}");
    assert!(transcript.contains(COST), "{transcript}");
    leave(&mut run);
}

/// Type `password` at the prompt and wait for the plain shell that follows a failure.
fn log_in_expecting_plain(run: &mut PtyRun, password: &str) {
    run.read_until(PROMPT);
    run.type_line(password);
    run.read_until(COST);
    shell_up(run);
}

/// Elevated (CI only). The sentinel password is typed through the console; nothing the console
/// shows, in any case or as UTF-16, contains it.
#[test]
fn typed_password_is_never_echoed() {
    let _machine = machine::shared();
    let kit = kit("pp4");
    let secret = "Sentinel-7q2x!Aa";
    let account = Account::create_named(&format!("sb ec{:x}", std::process::id()), secret, true);
    let mut run = start_run(&kit, &account);
    log_in(&mut run, secret);
    say(&mut run, "session-up");
    leave(&mut run);

    let shown = run.bytes().to_vec();
    let lower = String::from_utf8_lossy(&shown).to_lowercase();
    assert!(
        !lower.contains(&secret.to_lowercase()),
        "the password was echoed:\n{lower}"
    );
    let utf16: Vec<u8> = secret.encode_utf16().flat_map(u16::to_le_bytes).collect();
    assert!(
        !shown.windows(utf16.len()).any(|w| w == utf16.as_slice()),
        "the password was echoed as UTF-16"
    );
}

/// Elevated (CI only).
#[test]
fn ctrl_c_gives_plain_shell() {
    let _machine = machine::shared();
    let kit = kit("pp5");
    let account = Account::create("pp5", true);
    let mut run = start_run(&kit, &account);
    run.read_until(PROMPT);
    run.ctrl_c();
    run.read_until(COST);
    shell_up(&mut run);
    say(&mut run, "plain-shell-works");
    leave(&mut run);
}

/// Elevated (CI only). Settles which key form a real console under raw input delivers for Ctrl+D:
/// the character 0x04 on the key record, or the virtual key with no character. `PasswordEntry`
/// handles both; this fails if the console delivers a third form.
#[test]
fn ctrl_d_gives_plain_shell() {
    let _machine = machine::shared();
    for (tag, as_character) in [("pp6a", true), ("pp6b", false)] {
        let kit = kit(tag);
        let account = Account::create(tag, true);
        let mut run = start_run(&kit, &account);
        run.read_until(PROMPT);
        if as_character {
            run.ctrl_d_character();
        } else {
            run.ctrl_d_virtual_key();
        }
        run.read_until(COST);
        shell_up(&mut run);
        leave(&mut run);
    }
}

/// Elevated (CI only). Enter on an empty line never means "plain shell".
#[test]
fn empty_enter_reprompts() {
    let _machine = machine::shared();
    let kit = kit("pp7");
    let account = Account::create("pp7", true);
    let mut run = start_run(&kit, &account);
    run.read_until(PROMPT);
    run.press_enter();
    run.read_until_count("empty passwords are not supported yet", 1);
    run.press_enter();
    // The second Enter is answered too: a count of two, since the first answer is still on the screen.
    run.read_until_count("empty passwords are not supported yet", 2);
    // Still asking: a password now signs in, and the shell is the session's, not a plain one that
    // would take the typed password as a command.
    run.type_line(&account.password);
    expect_session(&mut run);
    assert_relayed(&mut run);
    say(&mut run, "session-up");
    leave(&mut run);
}

/// Elevated (CI only). An Enter and then the password, written to the console together (a paste): the
/// Enter is answered as an empty password and the password after it is still read.
#[test]
fn a_password_written_with_an_empty_enter_is_read() {
    let _machine = machine::shared();
    let kit = kit("pp14");
    let account = Account::create("pp14", true);
    let mut run = start_run(&kit, &account);
    run.read_until(PROMPT);
    run.send_raw(&format!("\r{}\r", account.password));
    run.read_until_count("empty passwords are not supported yet", 1);
    expect_session(&mut run);
    assert_relayed(&mut run);
    leave(&mut run);
}

/// Elevated (CI only). A command written to the console in the same piece as the password reaches the
/// session's shell: the prompt does not drop what follows the password's Enter.
#[test]
fn a_command_written_with_the_password_runs_in_the_session() {
    let _machine = machine::shared();
    let kit = kit("pp15");
    let account = Account::create("pp15", true);
    let mut run = start_run(&kit, &account);
    run.read_until(PROMPT);
    run.send_raw(&format!("{}\rWrite-Output ('typed' + 'ahead-ok')\r", account.password));
    run.read_until("typedahead-ok");
    expect_session(&mut run);
    assert_relayed(&mut run);
    leave(&mut run);
}

/// Elevated (CI only). A password with a character outside the BMP, typed as UTF-8
/// the way a terminal sends it, reaches Windows as the exact UTF-16: the login is the session's, not
/// the plain shell that follows a refused password. A console delivers such a character on the Alt
/// key-up record, which the prompt must read.
#[test]
fn password_with_non_bmp_characters_logs_on_through_the_prompt() {
    let _machine = machine::shared();
    let kit = kit("pp8");
    let secret = "Pw-\u{1F600}-Aa1!-x";
    let account = Account::create_named(&format!("sb np{:x}", std::process::id()), secret, true);
    let mut run = start_run(&kit, &account);
    run.read_until(PROMPT);
    run.send_raw(&format!("{secret}\r"));
    expect_session(&mut run);
    assert_relayed(&mut run);
    say(&mut run, "session-up");
    leave(&mut run);
}

/// Elevated (CI only). A space and non-ASCII letters in the account name, through the
/// prompt text, the logon call, `--expect-user` and the socket path.
#[test]
fn account_with_space_and_non_ascii_name_gets_a_session_through_the_prompt() {
    let _machine = machine::shared();
    let kit = kit("pp9");
    let name = format!("sb \u{00e9}z{:x}", std::process::id());
    let account = Account::create_named(&name, "Pw-Sp-Aa1!-9", true);
    let mut run = start_run(&kit, &account);
    run.read_until(&format!("ssh-broker: {name} has no Windows session on this PC."));
    run.type_line(&account.password);
    shell_up(&mut run);
    say(&mut run, "session-up");
    leave(&mut run);
}

/// Elevated (CI only). A local account whose name contains `@`: Windows reads `name@domain` as a UPN,
/// which `CreateProcessWithLogonW` accepts only with no domain, and the logon passes `.` as the domain.
/// The session must start through the prompt all the same, or this test shows the code Windows gave.
#[test]
fn account_with_an_at_sign_in_its_name_gets_a_session_through_the_prompt() {
    let _machine = machine::shared();
    let kit = kit("pp13");
    let name = format!("sb@{:x}", std::process::id());
    let account = Account::create_named(&name, "Pw-At-Aa1!-3", true);
    let mut run = start_run(&kit, &account);
    run.read_until(&format!("ssh-broker: {name} has no Windows session on this PC."));
    run.type_line(&account.password);
    expect_session(&mut run);
    assert_relayed(&mut run);
    say(&mut run, "session-up");
    leave(&mut run);
}

/// Elevated (CI only). The first login starts the session; a later connection finds it and does not
/// ask again.
#[test]
fn second_connection_reuses_the_running_session() {
    let _machine = machine::shared();
    let kit = kit("pp10");
    let account = Account::create("pp10", true);
    let mut first = start_run(&kit, &account);
    log_in(&mut first, &account.password);
    say(&mut first, "first-up");

    let first_parent = parent_pid(&mut first);

    let mut second = start_run(&kit, &account);
    shell_up(&mut second);
    say(&mut second, "second-up");
    assert!(
        !second.text().contains(PROMPT),
        "the running session must be used without a prompt:\n{}",
        second.text()
    );
    // Relayed into the running session: the session's DPAPI works, and the shell is a child of the
    // same agent. A second shim that failed open shows the same prompt and neither of these.
    assert_relayed(&mut second);
    assert_eq!(
        parent_pid(&mut second),
        first_parent,
        "the second connection was not served by the running agent:\n{}",
        second.text()
    );
    leave(&mut second);
    leave(&mut first);
}

/// Elevated (CI only). After `logout` the socket file of the ended agent is still there: the next login
/// finds a stale file, prompts, and logs on again.
#[test]
fn login_after_logout_prompts_again() {
    let _machine = machine::shared();
    let kit = kit("pp11");
    let account = Account::create("pp11", true);
    let mut first = start_run(&kit, &account);
    log_in(&mut first, &account.password);
    let agent = AgentProcess::open(parent_pid(&mut first));
    first.type_line(&format!("& '{}' logout", kit.exe.display()));
    first.read_until("ending your background session.");
    first.finish();
    // The login that follows is the one after the session ended: a login that arrives while the agent
    // is still draining is answered "ending", not prompted (that answer has its own unit test).
    agent.wait_for_exit(&logs_of(&account));

    let mut second = start_run(&kit, &account);
    log_in(&mut second, &account.password);
    say(&mut second, "second-up");
    leave(&mut second);
}

/// Elevated (CI only). Two first connections of one new account at once. Each prompts and
/// logs on, so two agents start; exactly one serves, both consoles end in the session's shell (DPAPI
/// works in it) as children of that one agent, neither hangs, and the agent outlives both consoles.
#[test]
fn two_simultaneous_first_connections_end_with_one_agent_and_no_hang() {
    let _machine = machine::shared();
    let kit = kit("pp12");
    let account = Account::create("pp12", true);
    let mut runs = [start_run(&kit, &account), start_run(&kit, &account)];
    for run in &mut runs {
        run.read_until(PROMPT);
    }
    for run in &mut runs {
        run.type_line(&account.password);
    }
    let mut parents = Vec::new();
    for run in &mut runs {
        expect_session(run);
        assert_relayed(run);
        say(run, "made-it");
        measure_named_objects(run, "one of two simultaneous relayed sessions");
        parents.push(parent_pid(run));
    }
    // One agent served both shells: the parent of each is the same process, and it is an agent of this
    // account. Holding it open from here on lets its exit code be read if it ends.
    assert_eq!(
        parents[0],
        parents[1],
        "{}",
        report("the two shells have different parents.", &runs, &account)
    );
    let agent = AgentProcess::open(parents[0]);
    let line = command_line_of(parents[0]);
    assert!(
        line.contains("agent --background") && line.contains(&account.sid_text),
        "{}",
        report(
            &format!(
                "the parent of the shells (pid {}) is not this account's agent: {line}",
                parents[0]
            ),
            &runs,
            &account
        )
    );
    let agents = agent_count(&account);
    assert_eq!(
        agents,
        1,
        "{}",
        report(
            &format!("{agents} agents of this account run while both shells are connected."),
            &runs,
            &account
        )
    );

    // `leave` returns once the console helper, which holds the job the shim runs in, has exited. Closing
    // that job is what could end the agent, and a process ended by it is not gone the instant its
    // helper is, so the survival is shown by a third login being served, below, and not by a look at
    // the agent's state alone.
    for run in &mut runs {
        leave(run);
    }
    // The agent outlives its connections until logout, restart or upgrade. The shims
    // ran in sshd's job, so the end of a console is the end of an sshd session.
    assert_shim_ran_in_sshds_job(&account);
    if let Some(code) = agent.exit_code() {
        panic!(
            "{}",
            report(
                &format!(
                    "the agent (pid {}) ended after both consoles left, with exit code {code:#x}.",
                    parents[0]
                ),
                &runs,
                &account
            )
        );
    }
    let agents = agent_count(&account);
    assert_eq!(
        agents,
        1,
        "{}",
        report(
            &format!("{agents} agents of this account run after both consoles left."),
            &runs,
            &account
        )
    );
    // Served after every console left: no prompt, the session's DPAPI, and the same agent as the parent.
    let mut third = start_run(&kit, &account);
    shell_up(&mut third);
    assert!(
        !third.text().contains(PROMPT),
        "a login after both consoles left was asked for a password: the agent did not survive:
{}",
        third.text()
    );
    assert_relayed(&mut third);
    assert_eq!(
        parent_pid(&mut third),
        parents[0],
        "{}",
        report(
            "the login after both consoles left was not served by the agent that served them.",
            &runs,
            &account
        )
    );
    leave(&mut third);
}

/// The failure report of the two-consoles test: what happened, and what each console showed.
fn report(why: &str, runs: &[PtyRun; 2], account: &Account) -> String {
    let location = socket_loc::for_profile(account.profile()).unwrap();
    let lines = command_lines();
    let ours: Vec<&str> = lines.lines().filter(|line| line.contains("ssh-broker")).collect();
    format!(
        "{why}
ssh-broker processes:
{}

first console:
{}

second console:
{}

logs:
{}

application crash events:
{}",
        ours.join("\n"),
        runs[0].text(),
        runs[1].text(),
        stand_in::read_logs(&location),
        crash_events()
    )
}

/// The pid of the shell's parent, which is the agent that hosts it.
fn parent_pid(run: &mut PtyRun) -> u32 {
    run.type_line("Write-Output ('parent-' + 'pid=' + (Get-Process -Id $PID).Parent.Id + ';do' + 'ne')");
    run.read_until(";done");
    let text = run.text();
    let after = text.rsplit("parent-pid=").next().unwrap_or_default();
    let digits: String = after.chars().take_while(char::is_ascii_digit).collect();
    digits
        .parse()
        .unwrap_or_else(|_| panic!("the shell did not report its parent:\n{text}"))
}

/// How many background agents of `account` run.
fn agent_count(account: &Account) -> usize {
    command_lines()
        .lines()
        .filter(|line| line.contains("agent --background") && line.contains(&account.sid_text))
        .count()
}

/// The command line of process `pid`.
fn command_line_of(pid: u32) -> String {
    let script = format!("(Get-CimInstance Win32_Process -Filter 'ProcessId={pid}').CommandLine");
    let out = desktop::output(std::process::Command::new("powershell").args([
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        &script,
    ]))
    .unwrap();
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

/// Crash reports of the last while, from the Application log (read only): what a process that vanished
/// without a line in its own log left behind.
fn crash_events() -> String {
    let out = desktop::output(std::process::Command::new("wevtutil").args([
        "qe",
        "Application",
        "/q:*[System[(EventID=1000 or EventID=1001)]]",
        "/c:6",
        "/rd:true",
        "/f:text",
    ]))
    .unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// A handle on a process opened while it runs, so that its exit code can be read after it ends.
struct AgentProcess(OwnedHandle, u32);

impl AgentProcess {
    fn open(pid: u32) -> AgentProcess {
        // SAFETY: a plain open by id; the handle is closed by `OwnedHandle`.
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE, false, pid) }
            .unwrap_or_else(|e| panic!("open the agent (pid {pid}): {e}"));
        AgentProcess(OwnedHandle(handle), pid)
    }

    /// Wait for the process to exit; a process that does not fails the test, naming it and printing
    /// what the agent logged in `logs`.
    fn wait_for_exit(&self, logs: &[std::path::PathBuf]) {
        bounded_wait::wait_for_exit(
            self.0.0,
            self.1,
            "the agent after logout",
            bounded_wait::CHILD_EXIT_BOUND,
            logs,
        );
    }

    /// The exit code, or `None` while the process runs.
    fn exit_code(&self) -> Option<u32> {
        const STILL_ACTIVE: u32 = 259;
        let mut code = 0u32;
        // SAFETY: a live handle and an out-pointer.
        unsafe { GetExitCodeProcess(self.0.0, &mut code) }.expect("read the agent's exit code");
        (code != STILL_ACTIVE).then_some(code)
    }
}

/// The command line of every process on the machine, one per line.
fn command_lines() -> String {
    let out = desktop::output(std::process::Command::new("powershell").args([
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "Get-CimInstance Win32_Process | ForEach-Object { $_.CommandLine }",
    ]))
    .unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Elevated (CI only). A command session never prompts; it prints the notice once, with the installed
/// exe's full path, then the usual fallback line, and runs the command locally.
#[test]
fn exec_session_never_prompts_and_prints_the_notice() {
    let _machine = machine::shared();
    let kit = kit("pp13");
    let account = Account::create("pp13", true);
    let out = kit.path("out.txt");
    let err = kit.path("err.txt");
    // Stdin is NUL so the shim reads the session as one without a PTY (see tests/user_isolation_windows.rs).
    std::fs::write(
        kit.path("run.cmd"),
        format!(
            "@echo off\r\n<nul >\"{out}\" 2>\"{err}\" \"{shim}\" -c \"cmd.exe /c echo shim-ran\"\r\n",
            out = out.display(),
            err = err.display(),
            shim = kit.exe.display(),
        ),
    )
    .unwrap();
    let cmd = std::path::Path::new(&std::env::var_os("SystemRoot").unwrap()).join(r"System32\cmd.exe");
    let command = format!("\"{}\" /c \"{}\"", cmd.display(), kit.path("run.cmd").display());
    let code = account.run_with(
        &cmd,
        &command,
        kit.dir(),
        &[out.clone(), err.clone()],
        windows::Win32::System::Threading::LOGON_WITH_PROFILE,
        None,
    );
    assert_eq!(code, 0, "stderr: {}", std::fs::read_to_string(&err).unwrap_or_default());
    let stderr = std::fs::read_to_string(&err).unwrap();
    assert!(!stderr.contains(PROMPT), "{stderr}");
    assert_eq!(
        stderr.matches("has no Windows session on this PC").count(),
        1,
        "{stderr}"
    );
    assert!(
        stderr.contains(r"C:\ProgramData\ssh-broker\ssh-broker.exe auto-login on"),
        "the notice names the installed exe's full path: {stderr}"
    );
    assert!(std::fs::read_to_string(&out).unwrap().contains("shim-ran"));
}

/// Elevated (CI only). The password has one path: it is in no log and on no command line of any
/// process on the machine.
#[test]
fn password_never_appears_in_logs_or_command_lines() {
    let _machine = machine::shared();
    let kit = kit("pp14");
    let secret = "Sentinel-5k8m!Bb";
    let account = Account::create_named(&format!("sb pw{:x}", std::process::id()), secret, true);
    let mut run = start_run(&kit, &account);
    log_in(&mut run, secret);
    say(&mut run, "session-up");

    let location = socket_loc::for_profile(account.profile()).unwrap();
    let logs = stand_in::read_logs(&location);
    assert!(!logs.contains(secret), "a log holds the password:\n{logs}");
    let lines = command_lines();
    assert!(!lines.contains(secret), "a command line holds the password");
    leave(&mut run);
}

/// Elevated (CI only). Spike M4: a second agent of the same user, started while the background session
/// serves, never binds and leaves, and the session keeps serving.
#[test]
fn second_agent_in_the_same_session_leaves_and_the_session_keeps_serving() {
    let _machine = machine::shared();
    let kit = kit("pp15");
    let account = Account::create("pp15", true);
    let mut run = start_run(&kit, &account);
    log_in(&mut run, &account.password);

    let second = RealAgent::start(&kit, &account);
    second.process.wait();
    let location = socket_loc::for_profile(account.profile()).unwrap();
    let mut conn = AgentConn::connect(&location);
    conn.start_exec("cmd.exe /c echo still-serving");
    conn.end_stdin();
    let done = conn.read_to_end();
    assert!(done.stdout.contains("still-serving"), "stdout: {:?}", done.stdout);
    say(&mut run, "session-up");
    leave(&mut run);
}

/// Elevated (CI only). A socket the user may not connect to (its DACL names others) is not "no agent":
/// the connect is denied, and the shim keeps today's message instead of offering a session.
#[test]
fn absence_of_a_socket_the_user_may_not_connect_to_is_other() {
    use ssh_broker::console_prompt::absence;
    use ssh_broker::offer::Absence;

    let _machine = machine::shared();
    let kit = kit("pp16");
    let account = Account::create("pp16", true);
    // An administrator's private socket: its file grants the account nothing.
    let root = std::env::temp_dir().join(format!("sb-pp16-{}", std::process::id()));
    std::fs::create_dir_all(root.join("AppData").join("Local")).unwrap();
    let location = socket_loc::for_profile(&root).unwrap();
    userdir::ensure_socket_dir(&location, &ssh_broker::acl::Sid::current_user().unwrap()).unwrap();
    let _listener = ssh_broker::afunix::Listener::bind(&location.path).unwrap();

    let result = kit.path("connect.result");
    let command = format!(
        "\"{helper}\" connect \"{socket}\" \"{result}\"",
        helper = kit.helper.display(),
        socket = location.path.display(),
        result = result.display()
    );
    let code = account.run_with(
        &kit.helper,
        &command,
        kit.dir(),
        std::slice::from_ref(&result),
        windows::Win32::System::Threading::CREATE_PROCESS_LOGON_FLAGS(0),
        None,
    );
    assert_eq!(code, 0);
    let outcome = std::fs::read_to_string(&result).unwrap();
    let denied = outcome
        .strip_prefix("os error ")
        .and_then(|code| code.parse::<i32>().ok())
        .unwrap_or_else(|| panic!("the connect as the account did not fail with an OS error: {outcome}"));
    let connect: anyhow::Result<socket2::Socket> = Err(std::io::Error::from_raw_os_error(denied).into());
    assert_eq!(
        absence(&connect, &Ok(location)),
        Absence::Other,
        "a connect refused with OS error {denied}"
    );
    let _ = std::fs::remove_dir_all(&root);
}
