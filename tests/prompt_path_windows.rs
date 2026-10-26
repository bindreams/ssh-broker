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
    run.read_until(SHELL_PROMPT);
    let shown = run.text();
    assert!(
        !shown.contains(COST),
        "the login fell back to a plain shell instead of starting a session:
{shown}"
    );
}

fn leave(run: &mut PtyRun) {
    run.type_line("exit");
    run.finish();
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
    // Links a non-administrator made resolve (no RedirectionGuard on the shell).
    run.type_line(
        "New-Item -ItemType Junction -Path \"$env:TEMP\\sbjunction\" -Target $env:USERPROFILE | Out-Null; \
         if (Test-Path \"$env:TEMP\\sbjunction\\AppData\") { Write-Output ('link' + '-ok') } else { Write-Output ('link' + '-blocked') }",
    );
    run.read_until("link-ok");
    leave(&mut run);
}

/// Elevated (CI only). Review Focus 5: no `ProfileList` entry yet, and the first logon creates one.
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
    run.read_until(SHELL_PROMPT);
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
    run.read_until(SHELL_PROMPT);
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
        run.read_until(SHELL_PROMPT);
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
    run.read_until("empty passwords are not supported yet");
    run.press_enter();
    run.read_until("empty passwords are not supported yet");
    // Still asking: a password now signs in.
    run.type_line(&account.password);
    run.read_until(SHELL_PROMPT);
    say(&mut run, "session-up");
    leave(&mut run);
}

/// Elevated (CI only). Review Focus 3: a password with a character outside the BMP, typed as UTF-8
/// the way a terminal sends it, reaches Windows as the exact UTF-16.
#[test]
fn password_with_non_bmp_characters_logs_on_through_the_prompt() {
    let _machine = machine::shared();
    let kit = kit("pp8");
    let secret = "Pw-\u{1F600}-Aa1!-x";
    let account = Account::create_named(&format!("sb np{:x}", std::process::id()), secret, true);
    let mut run = start_run(&kit, &account);
    run.read_until(PROMPT);
    run.send_raw(&format!("{secret}\r"));
    run.read_until(SHELL_PROMPT);
    say(&mut run, "session-up");
    leave(&mut run);
}

/// Elevated (CI only). Review Focus 4: a space and non-ASCII letters in the account name, through the
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
    run.read_until(SHELL_PROMPT);
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

    let mut second = start_run(&kit, &account);
    second.read_until(SHELL_PROMPT);
    say(&mut second, "second-up");
    assert!(
        !second.text().contains(PROMPT),
        "the running session must be used without a prompt:\n{}",
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
    first.type_line(&format!("& '{}' logout", kit.exe.display()));
    first.read_until("ending your background session.");
    first.finish();

    let mut second = start_run(&kit, &account);
    log_in(&mut second, &account.password);
    say(&mut second, "second-up");
    leave(&mut second);
}

/// Elevated (CI only). Review Focus 2: two first connections of one new account at once. Each may
/// prompt and log on; exactly one agent serves; each ends in a shell, either the session or a plain one
/// with the reason, and neither hangs.
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
    for run in &mut runs {
        run.read_until(SHELL_PROMPT);
        say(run, "made-it");
        let text = run.text();
        let relayed = !text.contains(COST);
        assert!(
            relayed || text.contains("ssh-broker: "),
            "a plain shell must say why:\n{text}"
        );
    }
    for run in &mut runs {
        leave(run);
    }
    // Exactly one agent of this account is left running: the loser of the start race has gone.
    let lines = command_lines();
    let agents = lines
        .lines()
        .filter(|line| line.contains("agent --background") && line.contains(&account.sid_text))
        .count();
    if agents != 1 {
        let location = socket_loc::for_profile(account.profile()).unwrap();
        let ours: Vec<&str> = lines.lines().filter(|line| line.contains("ssh-broker")).collect();
        panic!(
            "one agent must serve; {agents} of {} do.
ssh-broker processes:
{}

first console:
{}

second console:
{}

logs:
{}",
            account.sid_text,
            ours.join(
                "
"
            ),
            runs[0].text(),
            runs[1].text(),
            stand_in::read_logs(&location)
        );
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
