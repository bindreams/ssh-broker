//! What the shell does with a session, through the runner's real `sshd`. Windows only; **Elevated
//! (CI only)**.
//!
//! The probe (a copy of `examples/command_line_probe`) is the shell of a throwaway account's user
//! config, so each test reads back the exact line the shell was started with: through the shim alone
//! (no agent: the fail-open) and through the agent. The same corpus goes through stock sshd with the
//! probe as `DefaultShell`, which says what OpenSSH delivers. The tests change sshd's `DefaultShell`
//! and take the machine alone (`machine::exclusive()`); the runner is discarded after the job.
#![cfg(windows)]

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;

use ssh_broker::cmdline::split_args;
use ssh_broker::provision::registry::{OPENSSH_KEY, set_default_shell_under};
use ssh_broker::shim::spawn_line;
use ssh_broker::socket_loc;

#[path = "common/account.rs"]
mod account_fixture;
#[path = "common/agent_conn.rs"]
mod agent_conn;
#[path = "common/bounded_wait.rs"]
mod bounded_wait;
#[path = "common/command_corpus.rs"]
mod command_corpus;
#[path = "common/command_line_probe.rs"]
mod command_line_probe;
#[path = "common/desktop.rs"]
mod desktop;
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
#[path = "common/sshd_encoder.rs"]
mod sshd_encoder;
#[path = "common/sshd_rig.rs"]
mod sshd_rig;
#[path = "common/stand_in.rs"]
mod stand_in;

use account_fixture::{Account, ServiceLogon};
use sshd_rig::{ConsoleClient, Login, Outcome, SshSession, run_client, set_stock_shell};
use stand_in::Kit;

/// A throwaway account sshd admits, a probe shell it can run, and (on request) its running session.
struct Rig {
    kit: Kit,
    account: Account,
    probe: PathBuf,
    _end: session_end::LogOutOnDrop,
}

impl Rig {
    fn new(tag: &str) -> Rig {
        account_fixture::assert_elevated();
        let kit = Kit::broker_with_helper(tag);
        let account = Account::create(tag, true);
        let end = session_end::LogOutOnDrop::new(&kit.exe, &account, ServiceLogon::Sshd);
        let probe = kit.path("probe.exe");
        std::fs::copy(command_line_probe::path(), &probe).unwrap();
        Rig {
            kit,
            account,
            probe,
            _end: end,
        }
    }

    fn login(&self) -> Login<'_> {
        Login::new(&self.kit, &self.account)
    }

    fn line_file(&self) -> PathBuf {
        let mut file = self.probe.clone().into_os_string();
        file.push(".line");
        PathBuf::from(file)
    }

    /// The line the probe was last started with, if it ran since [`Rig::forget_line`].
    fn probe_line(&self) -> Option<String> {
        std::fs::read_to_string(self.line_file()).ok()
    }

    fn forget_line(&self) {
        let _ = std::fs::remove_file(self.line_file());
    }

    fn use_probe_shell(&self) {
        self.account
            .write_user_config(&format!("shell: '{}'\n", self.probe.display()));
    }

    fn broker_is_default_shell(&self) {
        set_default_shell_under(OPENSSH_KEY, &self.kit.exe.to_string_lossy()).expect("set the shim as DefaultShell");
    }

    /// `ssh host -- command` with (`tty`) or without a terminal.
    fn ssh(&self, login: &Login<'_>, tty: bool, command: &str) -> Outcome {
        let mut ssh = login.command();
        ssh.arg(if tty { "-tt" } else { "-T" }).arg("--").arg(command);
        run_client(ssh, tty, self.kit.dir())
    }

    /// An interactive login that starts the account's background session, left open for the caller to end.
    /// The account's config names pwsh at this point (the fixture default). The shell it shows is the
    /// agent's (DPAPI works), not a plain one the shim fell back to after a logon that failed.
    fn start_session(&self, login: &Login<'_>) -> SshSession {
        let mut session = login.start();
        session.log_in(&self.account.password);
        session.check_relayed_shell();
        session
    }

    /// What the shim and the agent logged for the account, for the message of a failed assertion.
    fn logs(&self) -> String {
        self.account
            .try_profile()
            .and_then(|profile| socket_loc::for_profile(profile).ok())
            .map(|location| stand_in::read_logs(&location))
            .unwrap_or_default()
    }

    /// Fail unless `shown` (what a session wrote) says the agent ran it: the shim says "agent unavailable"
    /// when it ran the session itself.
    fn assert_relayed(&self, what: &str, shown: &str) {
        assert!(
            !shown.contains("agent unavailable"),
            "{what}: the shim ran the session itself, not through the agent\n{shown}\nlogs of the account:\n{}",
            self.logs()
        );
    }

    /// How many sessions the shim has run itself so far: it logs "agent unavailable" for each, whether
    /// or not the session has a terminal (which has no stderr to say it on). Compare two readings around
    /// a session to learn whether the agent served it; the log is flushed when the shim exits.
    fn ran_locally(&self) -> usize {
        self.logs().matches("agent unavailable").count()
    }

    /// Fail unless the agent served every session since `before` ([`Rig::ran_locally`]).
    fn assert_agent_served(&self, what: &str, before: usize) {
        assert_eq!(
            self.ran_locally(),
            before,
            "{what}: the shim ran a session itself, not through the agent\nlogs of the account:\n{}",
            self.logs()
        );
    }

    /// The reverse of [`Rig::assert_relayed`], for a session started with no agent running.
    fn assert_local(&self, what: &str, shown: &str) {
        assert!(
            shown.contains("agent unavailable"),
            "{what}: the shim did not run the session itself\n{shown}\nlogs of the account:\n{}",
            self.logs()
        );
    }
}

fn text(outcome: &Outcome) -> String {
    String::from_utf8_lossy(&outcome.stdout).into_owned()
}

// The command the shell is given =====

/// The corpus through stock sshd with the probe as `DefaultShell`, and through the broker with the probe as
/// the user's shell: through the shim alone, then through the agent. The shell gets the command exactly as
/// the client wrote it (less the edge whitespace and the rewrite sshd does of `scp` and `sftp-server`), as
/// one argument. Stock sshd is checked against the port of its encoder in `tests/common/sshd_encoder.rs`,
/// and the entries where it hands the shell something else are printed: that is the named table of
/// differences, derived from the same port instead of written by hand.
#[test]
fn broker_delivers_every_command_exactly_and_stock_sshd_matches_its_model() {
    corpus_through_stock_and_broker("shd1", false);
}

/// The same corpus with a terminal (`ssh -tt host command`). sshd then builds the line `"shell" -c command` with
/// the command appended raw and conhost splits and rejoins it, so the shell is not given one argument; the
/// broker must give the shell the arguments stock sshd gives it. The stock line is the model: what the broker's
/// probe line splits into is compared with what stock sshd's does, entry by entry.
#[test]
fn broker_gives_a_command_with_a_terminal_the_arguments_stock_sshd_does() {
    corpus_through_stock_and_broker("shd9", true);
}

fn corpus_through_stock_and_broker(tag: &str, tty: bool) {
    let _machine = machine::exclusive();
    let rig = Rig::new(tag);
    let login = rig.login();
    let probe = rig.probe.to_string_lossy().into_owned();
    let commands: Vec<&str> = command_corpus::CORPUS
        .iter()
        .copied()
        .filter(|command| !ssh_broker::shim::is_blank_command(command))
        .collect();
    let mut failures = Vec::new();

    // Stock sshd. `stock` holds the line the probe was started with, per command.
    set_stock_shell(&rig.probe);
    let mut stock = Vec::new();
    for command in &commands {
        rig.forget_line();
        let outcome = rig.ssh(&login, tty, command);
        let Some(line) = rig.probe_line() else {
            failures.push(format!(
                "stock sshd: the probe did not run for {command:?}\n{}",
                outcome.stderr
            ));
            continue;
        };
        // sshd lowercases the whole `DefaultShell` path (`pwd.c`). With a terminal conhost also expands
        // `%VAR%` (modelled in `tests/conhost_windows.rs`), so the stock line itself is the model there.
        if !tty {
            let want = split_args(&sshd_encoder::escaped_line(&probe.to_lowercase(), command));
            if split_args(&line) != want {
                failures.push(format!("stock sshd, {command:?}\n  line: {line:?}\n  model: {want:?}"));
            }
        }
        stock.push((*command, line));
    }

    // The broker, with the probe as the user's shell.
    rig.broker_is_default_shell();
    rig.use_probe_shell();
    let mut check = |path: &str, relayed: bool| {
        for command in &commands {
            rig.forget_line();
            let before = rig.ran_locally();
            let outcome = rig.ssh(&login, tty, command);
            let shown = format!("{}{}", text(&outcome), outcome.stderr);
            // A session with a terminal says "agent unavailable" to the log, not to the terminal.
            if relayed {
                rig.assert_agent_served(&format!("broker ({path}), {command:?}"), before);
            } else {
                assert_eq!(
                    rig.ran_locally(),
                    before + 1,
                    "broker ({path}), {command:?}: the shim did not run the session itself\n{shown}\nlogs of the account:\n{}",
                    rig.logs()
                );
            }
            let Some(line) = rig.probe_line() else {
                failures.push(format!(
                    "broker ({path}): the probe did not run for {command:?}\n{}",
                    outcome.stderr
                ));
                continue;
            };
            let want = if tty {
                // What stock sshd did, with the shell's own spelling of its path.
                let Some((_, stock_line)) = stock.iter().find(|(c, _)| c == command) else {
                    continue; // stock sshd did not run it: said above
                };
                let mut want = split_args(stock_line);
                want[0] = probe.clone();
                want
            } else {
                let delivered = sshd_encoder::build_exec_command(command);
                vec![probe.clone(), "-c".to_owned(), spawn_line(&delivered).to_owned()]
            };
            let mut got = split_args(&line);
            if tty && !got.is_empty() && got[0].eq_ignore_ascii_case(&probe) {
                got[0] = probe.clone();
            }
            if got != want {
                failures.push(format!(
                    "broker ({path}), {command:?}\n  line: {line:?}\n  want: {want:?}"
                ));
            }
        }
    };
    check("shim alone: no agent, fail-open", false);
    // The session starts under the account's pwsh; the probe is the shell again for the commands.
    rig.account.write_user_config("shell: pwsh.exe\n");
    let session = rig.start_session(&login);
    rig.use_probe_shell();
    check("through the agent", true);
    session.leave();

    if !tty {
        for (command, delivered) in &stock {
            let delivered = split_args(delivered).get(2).cloned();
            let exact = delivered.as_deref() == Some(spawn_line(&sshd_encoder::build_exec_command(command)));
            if !exact {
                eprintln!("stock sshd hands the shell {delivered:?} for {command:?}");
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

// scp and sftp =====

/// All 256 byte values, then a deterministic run of pseudo-random bytes.
fn payloads() -> Vec<(&'static str, Vec<u8>)> {
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    let noise = (0..256 * 1024)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect();
    vec![("all256", (0..=255u8).collect()), ("noise", noise)]
}

fn client_options(login: &Login<'_>) -> Vec<OsString> {
    // `Login::command` is `ssh -v -i key -o ... user@localhost`: the same options serve scp and sftp.
    let ssh = login.command();
    let args: Vec<OsString> = ssh.get_args().map(OsString::from).collect();
    // Drop `-v` and the destination, which ssh takes and scp does not in this position.
    args[1..args.len() - 1].to_vec()
}

/// Every byte value both ways through `scp -O`, `scp` (SFTP mode) and `sftp`, with the shell `shell_yaml`
/// names. Stock sshd is byte-exact through both shells (measured), so the broker must be too.
fn byte_clean_through(shell_name: &str, shell_yaml: &str, tag: &str) {
    let _machine = machine::exclusive();
    let rig = Rig::new(tag);
    let login = rig.login();
    rig.broker_is_default_shell();
    let session = rig.start_session(&login);
    rig.account.write_user_config(shell_yaml);
    let profile = rig.account.profile().to_path_buf();
    let target = format!("{}@localhost", rig.account.name);
    let mut failures = Vec::new();

    for (name, bytes) in payloads() {
        let local = rig.kit.path(&format!("src-{name}.bin"));
        std::fs::write(&local, &bytes).unwrap();
        let remote_source = format!("remote-{name}.bin");
        std::fs::write(profile.join(&remote_source), &bytes).unwrap();
        for tool in ["scp-O", "scp", "sftp"] {
            let exe = if tool == "sftp" { "sftp" } else { "scp" };
            let up = format!("up-{shell_name}-{tool}-{name}.bin");
            let down = rig.kit.path(&format!("down-{shell_name}-{tool}-{name}.bin"));
            let mut upload = Command::new(exe);
            let mut download = Command::new(exe);
            for (direction, command, from, to, batch) in [
                (
                    "up",
                    &mut upload,
                    local.to_string_lossy().into_owned(),
                    format!("{target}:{up}"),
                    format!("put {} {up}", local.display()),
                ),
                (
                    "down",
                    &mut download,
                    format!("{target}:{remote_source}"),
                    down.to_string_lossy().into_owned(),
                    format!("get {remote_source} {}", down.display()),
                ),
            ] {
                command.args(client_options(&login));
                match tool {
                    "sftp" => {
                        // One file per direction: both commands are built before either runs.
                        let batch_file = rig.kit.path(&format!("batch-{direction}.txt"));
                        std::fs::write(&batch_file, format!("{batch}\n")).unwrap();
                        command.arg("-v").arg("-b").arg(&batch_file).arg(&target);
                    }
                    "scp-O" => {
                        command.args(["-O", &from, &to]);
                    }
                    _ => {
                        command.args([&from, &to]);
                    }
                }
            }
            let sent = run_client(upload, false, rig.kit.dir());
            if std::fs::read(profile.join(&up)).ok().as_deref() != Some(bytes.as_slice()) {
                failures.push(format!(
                    "{shell_name} {tool} upload of {name}: exit {:?}, remote file {:?} of {} bytes sent\nstdout: {}\n{}",
                    sent.code,
                    std::fs::read(profile.join(&up)).map(|got| got.len()),
                    bytes.len(),
                    String::from_utf8_lossy(&sent.stdout),
                    sent.stderr
                ));
            }
            let got = run_client(download, false, rig.kit.dir());
            if std::fs::read(&down).ok().as_deref() != Some(bytes.as_slice()) {
                failures.push(format!(
                    "{shell_name} {tool} download of {name}: exit {:?}, local file {:?} of {} bytes sent\nstdout: {}\n{}",
                    got.code,
                    std::fs::read(&down).map(|got| got.len()),
                    bytes.len(),
                    String::from_utf8_lossy(&got.stdout),
                    got.stderr
                ));
            }
        }
    }
    session.leave();
    assert!(
        failures.is_empty(),
        "{}\nlogs of the account:\n{}",
        failures.join("\n"),
        rig.logs()
    );
}

#[test]
fn scp_and_sftp_are_byte_clean_through_cmd() {
    let system_root = std::env::var("SystemRoot").expect("SystemRoot");
    byte_clean_through("cmd", &format!("shell: '{system_root}\\System32\\cmd.exe'\n"), "shd2");
}

#[test]
fn scp_and_sftp_are_byte_clean_through_pwsh() {
    byte_clean_through("pwsh", "shell: pwsh.exe\n", "shd3");
}

// A terminal, a broken config, the agent's PATH =====

/// `ssh -t host command` gives the command a terminal (before, it ran on pipes) and ends with the exit code
/// stock sshd gives it; `ssh -T` gives it pipes. The resize has its own test below.
#[test]
fn a_command_with_a_terminal_has_a_terminal() {
    let _machine = machine::exclusive();
    let rig = Rig::new("shd4");
    let login = rig.login();
    // What stock sshd answers for a command with a terminal: the broker answers the same.
    let system_cmd = PathBuf::from(std::env::var("SystemRoot").expect("SystemRoot")).join(r"System32\cmd.exe");
    set_stock_shell(&system_cmd);
    let stock = rig.ssh(&login, true, "exit 7");
    eprintln!("stock sshd: exit {:?} for `exit 7` with a terminal", stock.code);
    rig.broker_is_default_shell();
    let session = rig.start_session(&login);

    let pty = rig.ssh(&login, true, "[Console]::IsOutputRedirected; exit 7");
    rig.assert_relayed("ssh -tt", &format!("{}{}", text(&pty), pty.stderr));
    assert_eq!(
        pty.code,
        stock.code,
        "stock sshd answers {:?} for the same command with a terminal\n{}\n{}",
        stock.code,
        text(&pty),
        pty.stderr
    );
    assert!(
        text(&pty).contains("False"),
        "the command had no terminal: {:?}",
        text(&pty)
    );

    let pipes = rig.ssh(&login, false, "[Console]::IsOutputRedirected; exit 5");
    rig.assert_relayed("ssh -T", &format!("{}{}", text(&pipes), pipes.stderr));
    assert_eq!(pipes.code, Some(5), "{}\n{}", text(&pipes), pipes.stderr);
    assert!(
        text(&pipes).contains("True"),
        "the command had a terminal: {:?}",
        text(&pipes)
    );
    session.leave();
}

/// A resize of the client's console reaches a command that has a terminal: ssh.exe on a pseudoconsole of the
/// test's own tells sshd, which resizes its console, which the shim passes to the agent, which resizes the
/// command's. The command is the stand-in's `console-size`, which reports its console's size at the start and
/// again when the console is resized (it waits for that event, not for time).
#[test]
fn a_resize_reaches_a_command_with_a_terminal() {
    let _machine = machine::exclusive();
    let rig = Rig::new("shd7");
    let login = rig.login();
    rig.broker_is_default_shell();
    let session = rig.start_session(&login);

    let mut ssh = login.command();
    let helper = rig.kit.helper.to_string_lossy().replace('\'', "''");
    ssh.arg("-tt").arg("--").arg(format!("& '{helper}' console-size"));
    let mut client = ConsoleClient::start(&ssh, 80, 25, login.diagnostics());
    client.read_until("size=80x25");
    client.resize(100, 30);
    client.read_until("size=100x30");
    rig.assert_relayed("ssh -tt with a resize", &client.text());
    assert_eq!(client.finish(), 0);
    session.leave();
}

/// A user config that cannot be used is one warning, and `cmd.exe` runs the command, through the agent.
#[test]
fn a_broken_user_config_warns_and_gives_cmd_exe() {
    let _machine = machine::exclusive();
    let rig = Rig::new("shd5");
    let login = rig.login();
    rig.broker_is_default_shell();
    let session = rig.start_session(&login);
    rig.account.write_user_config("shell: {strt: pwsh.exe}\n");

    let out = rig.ssh(&login, false, "echo built-in-ok");
    rig.assert_relayed("a broken config", &format!("{}{}", text(&out), out.stderr));
    assert!(text(&out).contains("built-in-ok"), "{}\n{}", text(&out), out.stderr);
    assert_eq!(
        out.stderr.matches("cannot use the shell from").count(),
        1,
        "{}",
        out.stderr
    );
    assert!(
        out.stderr.contains("config.yaml") && out.stderr.contains("strt"),
        "{}",
        out.stderr
    );
    session.leave();
}

/// `shell: pwsh.exe` is found on the agent's own `PATH`.
#[test]
fn a_path_lookup_finds_pwsh_in_the_agents_path() {
    let _machine = machine::exclusive();
    let rig = Rig::new("shd6");
    let login = rig.login();
    rig.broker_is_default_shell();
    let session = rig.start_session(&login);
    rig.account.write_user_config("shell: pwsh.exe\n");

    let out = rig.ssh(&login, false, "$PSVersionTable.PSVersion.Major");
    rig.assert_relayed("a path lookup", &format!("{}{}", text(&out), out.stderr));
    let shown = text(&out);
    assert!(
        shown.trim().parse::<u32>().is_ok(),
        "pwsh did not answer: {shown:?}\n{}",
        out.stderr
    );
    assert!(!out.stderr.contains("cannot use the shell"), "{}", out.stderr);
    session.leave();
}

/// A shell that exists and cannot be started (a stub that is not a program) is not a lockout: one
/// warning that names the file, the value and the OS error, and `cmd.exe` runs the command. Through the
/// agent, and through the shim alone when there is no agent.
#[test]
fn a_shell_that_exists_and_cannot_start_gives_cmd_exe_with_a_warning() {
    let _machine = machine::exclusive();
    let rig = Rig::new("shd8");
    let login = rig.login();
    rig.broker_is_default_shell();
    let stub = rig.kit.path("unstartable.exe");
    std::fs::write(&stub, b"MZ").unwrap();
    let yaml = format!("shell: '{}'\n", stub.display());

    // No agent: the shim runs it.
    rig.account.write_user_config(&yaml);
    let local = rig.ssh(&login, false, "echo built-in-ok");
    let shown = format!("{}{}", text(&local), local.stderr);
    rig.assert_local("an unstartable shell", &shown);
    assert!(text(&local).contains("built-in-ok"), "{shown}");
    assert_unstartable_warning(&local.stderr, &stub);

    // The agent runs it; its session starts with the fixture's default shell.
    rig.account.write_user_config(
        "shell: pwsh.exe
",
    );
    let session = rig.start_session(&login);
    rig.account.write_user_config(&yaml);
    let relayed = rig.ssh(&login, false, "echo built-in-ok");
    rig.assert_relayed("an unstartable shell", &format!("{}{}", text(&relayed), relayed.stderr));
    assert!(
        text(&relayed).contains("built-in-ok"),
        "{}\n{}",
        text(&relayed),
        relayed.stderr
    );
    assert_unstartable_warning(&relayed.stderr, &stub);
    session.leave();
}

fn assert_unstartable_warning(stderr: &str, stub: &std::path::Path) {
    assert_eq!(stderr.matches("cannot use the shell from").count(), 1, "{stderr}");
    assert!(
        stderr.contains("config.yaml")
            && stderr.contains(&stub.display().to_string())
            && stderr.contains("cannot be started"),
        "{stderr}"
    );
}

/// What a user sees of a session with a terminal when the shell cannot be used: the screen a terminal shows from the
/// bytes ssh delivers, with every clear and cursor move applied.
fn assert_warning_on_screen(what: &str, stream: &[u8], raw: &str) {
    let screen = sshd_rig::screen_text(stream);
    eprintln!("the screen of {what}:\n{screen}\nthe raw stream: {raw:?}");
    assert!(
        screen.contains("built-in-ok"),
        "{what}: the command did not run:\n{screen}\nraw: {raw:?}"
    );
    assert!(
        screen.contains("cannot use the shell from") && screen.contains("config.yaml"),
        "{what}: the warning is not on the screen:\n{screen}\nraw: {raw:?}"
    );
}

/// The warning for a shell that cannot be used is on the screen of a command with a terminal that the shim runs
/// itself (no agent).
#[test]
fn the_warning_survives_on_the_screen_of_a_terminal_session_through_the_shim_alone() {
    let _machine = machine::exclusive();
    let rig = Rig::new("shd10");
    let login = rig.login();
    rig.broker_is_default_shell();
    rig.account.write_user_config("shell: {strt: pwsh.exe}\n");

    let out = rig.ssh(&login, true, "echo built-in-ok");
    assert_warning_on_screen(
        "a command with a terminal, through the shim alone",
        &out.stdout,
        &text(&out),
    );
}

/// The same through the agent, for a command and for a login. ConPTY opens the agent's pseudoconsole with a clear of
/// the screen that reaches the client after anything written ahead of it; the warning has to be on the screen after
/// that clear (measured, ssh-broker#55).
#[test]
fn the_warning_survives_on_the_screen_of_a_terminal_session_through_the_agent() {
    let _machine = machine::exclusive();
    let rig = Rig::new("shd11");
    let login = rig.login();
    rig.broker_is_default_shell();
    let session = rig.start_session(&login);
    rig.account.write_user_config("shell: {strt: pwsh.exe}\n");
    let before = rig.ran_locally();

    let relayed = rig.ssh(&login, true, "echo built-in-ok");
    assert_warning_on_screen(
        "a command with a terminal, through the agent",
        &relayed.stdout,
        &text(&relayed),
    );

    let mut shown = login.start();
    // Both are awaited, in whichever order they arrive.
    shown.read_until("using the built-in cmd.exe");
    shown.read_until("Microsoft Windows");
    let screen = sshd_rig::screen_text(&shown.transcript);
    eprintln!("the screen of a login:\n{screen}\nthe raw stream: {:?}", shown.text());
    assert!(
        screen.contains("cannot use the shell from") && screen.contains("config.yaml"),
        "the warning is not on the screen of a login:\n{screen}\nraw: {:?}",
        shown.text()
    );
    shown.type_line("exit");
    let _ = shown.finish();
    rig.assert_agent_served("the sessions with a broken config", before);
    session.leave();
}

/// The warning is on the screen once. The terminal shows what was written after ConPTY's opening clear, so a
/// warning that went out twice (once ahead of the shell and once from inside the pseudoconsole) would show twice
/// if the second were not cleared, and a verb that prints it twice would show twice always.
#[test]
fn the_warning_is_on_the_screen_once_in_a_terminal_session_through_the_agent() {
    let _machine = machine::exclusive();
    let rig = Rig::new("shd12");
    let login = rig.login();
    rig.broker_is_default_shell();
    let session = rig.start_session(&login);
    rig.account.write_user_config("shell: {strt: pwsh.exe}\n");
    let before = rig.ran_locally();

    let relayed = rig.ssh(&login, true, "echo built-in-ok");
    let screen = sshd_rig::screen_text(&relayed.stdout);
    eprintln!("the screen of a command with a terminal:\n{screen}");
    assert_eq!(
        screen.matches("cannot use the shell from").count(),
        1,
        "a command with a terminal:\n{screen}\nraw: {:?}",
        text(&relayed)
    );

    let mut shown = login.start();
    shown.read_until("using the built-in cmd.exe");
    shown.read_until("Microsoft Windows");
    shown.type_line("echo logged-in-ok");
    shown.read_until("logged-in-ok");
    let screen = sshd_rig::screen_text(&shown.transcript);
    eprintln!("the screen of a login:\n{screen}");
    assert_eq!(
        screen.matches("cannot use the shell from").count(),
        1,
        "a login:\n{screen}\nraw: {:?}",
        shown.text()
    );
    shown.type_line("exit");
    let _ = shown.finish();
    rig.assert_agent_served("the sessions with a broken config", before);
    session.leave();
}

/// The line of the fallback shell near the 32,767 units a command line takes. The verb gets the warning and
/// the line through a pipe, so the warning is printed in the pseudoconsole however long the line is.
#[test]
fn the_warning_is_on_the_screen_when_the_fallback_line_is_near_the_command_line_limit() {
    let _machine = machine::exclusive();
    let rig = Rig::new("shd13");
    let login = rig.login();
    rig.broker_is_default_shell();
    let session = rig.start_session(&login);
    rig.account.write_user_config("shell: {strt: pwsh.exe}\n");
    let location = socket_loc::for_profile(rig.account.profile()).unwrap();

    // `<system directory>\cmd.exe /c ` is under 60 units and the warning and the verb's own name are over 300,
    // so the line fits and the verb's line would not if it carried the line.
    let command = "x".repeat(32_700);
    let mut conn = agent_conn::AgentConn::connect(&location);
    conn.start_shell_pty(Some(&command));
    let finished = conn.read_to_end();
    let screen = sshd_rig::screen_text(finished.pty.as_bytes());
    eprintln!("the screen of the session:\n{screen}");
    assert!(
        screen.contains("cannot use the shell from") && screen.contains("config.yaml"),
        "the warning is not on the screen:\n{screen}\nraw: {:?}",
        finished.pty
    );
    session.leave();
}

/// Ctrl+C in a terminal session whose shell fell back reaches the shell, and the session lives. The fallback
/// shell runs under the hidden verb, which is the console's root process: with the default handler the
/// verb would end on the Ctrl+C that cmd.exe answers, and the session with it (ssh-broker#55). Measured in CI:
/// the agent's pseudoconsole raises the Ctrl+C in every process on it.
#[test]
fn ctrl_c_in_a_terminal_session_whose_shell_fell_back_reaches_the_shell_and_the_session_lives() {
    let _machine = machine::exclusive();
    let rig = Rig::new("shd14");
    let login = rig.login();
    rig.broker_is_default_shell();
    let session = rig.start_session(&login);
    rig.account.write_user_config("shell: {strt: pwsh.exe}\n");
    let location = socket_loc::for_profile(rig.account.profile()).unwrap();

    let mut conn = agent_conn::AgentConn::connect(&location);
    conn.start_shell_pty(None);
    conn.read_until_pty_shows("Microsoft Windows");

    // A program in the shell, interrupted by Ctrl+C: cmd.exe stays and shows the next prompt.
    conn.type_line("ping -n 60 127.0.0.1");
    conn.read_until_pty_shows("Reply from");
    conn.send_pty_bytes(&ctrl_c_keys());
    conn.read_until_pty_shows("Control-C");
    // `^i` is `i` to cmd.exe, so the text appears only as output, not as the echo of what was typed.
    conn.type_line("echo the-sess^ion-lives");
    conn.read_until_pty_shows("the-session-lives");

    conn.type_line("exit");
    let finished = conn.read_to_end();
    assert_eq!(finished.exit, Some(0), "{}", finished.pty);
    session.leave();
}

/// Ctrl+C as the shim sends it for a real keystroke: the Ctrl key, then C with the character 0x03 and the
/// scan codes, then both released.
fn ctrl_c_keys() -> Vec<u8> {
    const LEFT_CTRL: u32 = 0x0008;
    let key = |vk: u16, sc: u16, uc: u16, down: bool, cs: u32| {
        ssh_broker::vtinput::encode_key_event(&ssh_broker::vtinput::KeyEvent {
            virtual_key_code: vk,
            virtual_scan_code: sc,
            unicode_char: uc,
            key_down: down,
            control_key_state: cs,
            repeat_count: 1,
        })
    };
    [
        key(0x11, 0x1D, 0, true, LEFT_CTRL),
        key(0x43, 0x2E, 3, true, LEFT_CTRL),
        key(0x43, 0x2E, 3, false, LEFT_CTRL),
        key(0x11, 0x1D, 0, false, 0),
    ]
    .concat()
}

// MEASUREMENT (ssh-broker#55 round 8, F1): which input interrupts a program through the agent's pseudoconsole.
// Printed always; replaced by the real test.
#[test]
fn measure_ctrl_c_variants() {
    let _machine = machine::exclusive();
    let rig = Rig::new("shd15");
    let login = rig.login();
    rig.broker_is_default_shell();
    let session = rig.start_session(&login);
    let location = socket_loc::for_profile(rig.account.profile()).unwrap();

    let simple: Vec<u8> = {
        let key = |down: bool| {
            ssh_broker::vtinput::encode_key_event(&ssh_broker::vtinput::KeyEvent {
                virtual_key_code: 0x43,
                virtual_scan_code: 0,
                unicode_char: 3,
                key_down: down,
                control_key_state: 0x0008,
                repeat_count: 1,
            })
        };
        [key(true), key(false)].concat()
    };
    let variants: Vec<(&str, Vec<u8>)> = vec![
        ("win32 key C with ctrl, no scan code", simple),
        ("win32 keys: ctrl, C with scan codes, releases", ctrl_c_keys()),
        ("the byte 0x03", vec![3]),
    ];
    for (session_kind, broken_config) in [("direct cmd.exe", false), ("fallback verb", true)] {
        rig.account.write_user_config(if broken_config {
            "shell: {strt: pwsh.exe}\n"
        } else {
            "shell: pwsh.exe\n"
        });
        for (name, bytes) in &variants {
            let mut conn = agent_conn::AgentConn::connect(&location);
            if broken_config {
                conn.start_shell_pty(None);
            } else {
                conn.start_pty("cmd.exe");
            }
            conn.read_until_pty_shows("Microsoft Windows");
            conn.type_line("ping -n 12 127.0.0.1");
            conn.read_until_pty_shows("Reply from");
            conn.send_pty_bytes(bytes);
            // ping answers Ctrl+C itself: it prints "Control-C" and its statistics.
            let shown = conn.read_until_pty_shows("Lost = ");
            let replies = shown.matches("Reply from").count();
            eprintln!(
                "MEASURE ctrl+c, {session_kind}, {name}: Control-C shown = {}, replies = {replies} of 12, ^C shown = {}",
                shown.contains("Control-C"),
                shown.contains("^C")
            );
            conn.type_line("exit");
            let _ = conn.read_to_end();
        }
    }
    session.leave();
}
