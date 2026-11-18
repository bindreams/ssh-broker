//! SPIKE 4: what Windows sshd does with a client's environment variable and with a drop-in config file.
//! Never merged. **CI only** (an elevated runner with the in-box OpenSSH): the tests rewrite `sshd_config`,
//! restart the `sshd` service, replace `DefaultShell` and make accounts.
//!
//! The shell is `examples/command_line_probe`, which records the variables sshd gave it. Every observation is
//! one line that starts with `SPIKE4 Q<n>:`, printed and appended to the file CI prints after the tests
//! (`hive::record`). A test collects its problems (a login that did not run, a config sshd refuses) and asserts
//! at the end, so one wrong step does not hide the answers after it.
#![cfg(windows)]

use std::path::PathBuf;
use std::sync::mpsc::RecvTimeoutError;

#[path = "common/account.rs"]
mod account_fixture;
#[path = "common/bounded_wait.rs"]
mod bounded_wait;
#[path = "common/command_line_probe.rs"]
mod command_line_probe;
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
#[path = "common/sshd_rig.rs"]
mod sshd_rig;
#[path = "common/stand_in.rs"]
mod stand_in;

use account_fixture::{Account, ServiceLogon, hive};
use sshd_rig::{Login, SILENCE_BOUND, SshSession, run, run_client, set_stock_shell};
use stand_in::Kit;

/// The variable the client sends.
const VAR: &str = "SSH_BROKER_ELEVATION";
const DROP_IN: &str = "Include sshd_config.d/*.conf";
const ACCEPT: &str = "AcceptEnv SSH_BROKER_ELEVATION";

/// One observation, as one line of the log.
fn say(question: u8, text: &str) {
    hive::record(&format!(
        "SPIKE4 Q{question}: {}",
        text.trim().replace(['\r', '\n'], " | ")
    ));
}

// The machine's sshd configuration =====

fn ssh_dir() -> PathBuf {
    PathBuf::from(std::env::var("ProgramData").expect("ProgramData is set")).join("ssh")
}

/// `sshd_config`, and the drop-in files the test adds, put back when the test ends.
struct SshdConfig {
    path: PathBuf,
    original: String,
    drop_in_dir: PathBuf,
    /// The drop-in folder did not exist and the test made it.
    made_dir: bool,
    drop_ins: Vec<PathBuf>,
}

impl SshdConfig {
    fn new() -> SshdConfig {
        let path = ssh_dir().join("sshd_config");
        let original = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        SshdConfig {
            path,
            original,
            drop_in_dir: ssh_dir().join("sshd_config.d"),
            made_dir: false,
            drop_ins: Vec::new(),
        }
    }

    fn write(&self, text: &str) {
        std::fs::write(&self.path, text).unwrap_or_else(|e| panic!("write {}: {e}", self.path.display()));
    }

    fn add_drop_in(&mut self, name: &str, text: &str) {
        if !self.drop_in_dir.exists() {
            std::fs::create_dir(&self.drop_in_dir).expect("make sshd_config.d");
            self.made_dir = true;
        }
        let file = self.drop_in_dir.join(name);
        std::fs::write(&file, text).unwrap_or_else(|e| panic!("write {}: {e}", file.display()));
        self.drop_ins.push(file);
    }

    /// The lines of the stock file that decide where an `Include` or a setting lands.
    fn outline(&self) -> String {
        let lines: Vec<String> = self
            .original
            .lines()
            .enumerate()
            .filter(|(_, l)| {
                let l = l.trim_start().to_ascii_lowercase();
                l.starts_with("match")
                    || l.starts_with("include")
                    || l.starts_with("acceptenv")
                    || l.starts_with("setenv")
            })
            .map(|(n, l)| format!("{}:{}", n + 1, l.trim()))
            .collect();
        format!(
            "stock file is {} lines; its Include/Match/AcceptEnv/SetEnv lines: [{}]",
            self.original.lines().count(),
            lines.join(" ; ")
        )
    }

    fn has_administrators_match(&self) -> bool {
        self.original
            .lines()
            .any(|l| l.trim().eq_ignore_ascii_case("match group administrators"))
    }
}

impl Drop for SshdConfig {
    fn drop(&mut self) {
        let _ = std::fs::write(&self.path, &self.original);
        for file in &self.drop_ins {
            let _ = std::fs::remove_file(file);
        }
        if self.made_dir {
            let _ = std::fs::remove_dir(&self.drop_in_dir);
        }
        let _ = restart_sshd();
    }
}

/// The service the rig runs: the runner's in-box `sshd`, as `sshd_rig::admit` starts it.
fn restart_sshd() -> Result<(), String> {
    let _ = run("net", &["stop", "sshd"]);
    let (_, started) = run("net", &["start", "sshd"]);
    let (_, state) = run("sc", &["query", "sshd"]);
    if state.contains("RUNNING") {
        Ok(())
    } else {
        Err(format!("sshd is not running after a restart:\n{started}\n{state}"))
    }
}

/// `acceptenv` and `setenv` lines of `sshd -T`, for no connection, or for `account`'s.
fn effective(account: Option<&Account>) -> String {
    let (ok, text) = match account {
        None => run("sshd", &["-T"]),
        Some(a) => run(
            "sshd",
            &["-T", "-C", &format!("user={},host=localhost,addr=127.0.0.1", a.name)],
        ),
    };
    if !ok {
        return format!("sshd -T failed: {}", text.trim());
    }
    let found: Vec<&str> = text
        .lines()
        .filter(|l| l.starts_with("acceptenv ") || l.starts_with("setenv "))
        .collect();
    if found.is_empty() {
        "(no acceptenv or setenv line)".to_owned()
    } else {
        found.join(" ; ")
    }
}

/// Make `text` the config, check it, restart, and record what `sshd -T` says of it.
fn apply(
    question: u8,
    label: &str,
    config: &SshdConfig,
    text: &str,
    accounts: &[&Account],
    problems: &mut Vec<String>,
) {
    config.write(text);
    let (accepted, said) = run("sshd", &["-t"]);
    if !accepted {
        problems.push(format!("Q{question} [{label}]: sshd -t refuses the config: {said}"));
    }
    let restarted = restart_sshd();
    if let Err(e) = &restarted {
        problems.push(format!("Q{question} [{label}]: {e}"));
    }
    let mut per_account = String::new();
    for account in accounts {
        per_account += &format!(
            "; sshd -T -C user={} ({}): {}",
            account.name,
            if account.is_administrator() {
                "administrator"
            } else {
                "standard"
            },
            effective(Some(account))
        );
    }
    say(
        question,
        &format!(
            "config [{label}] written; sshd -t accepts={accepted} {}; restart={}; sshd -T: {}{per_account}",
            said.trim(),
            if restarted.is_ok() { "ok" } else { "FAILED" },
            effective(None)
        ),
    );
}

// An account and a probe shell =====

struct Rig {
    kit: Kit,
    account: Account,
    probe: PathBuf,
}

impl Rig {
    fn new(tag: &str, administrator: bool) -> Rig {
        account_fixture::assert_elevated();
        let kit = Kit::new(tag);
        let account = Account::create(tag, true);
        if administrator {
            account.make_administrator();
        }
        account.started_by(ServiceLogon::Sshd);
        let probe = kit.path("probe.exe");
        std::fs::copy(command_line_probe::path(), &probe).expect("copy the probe");
        Rig { kit, account, probe }
    }

    fn kind(&self) -> &'static str {
        if self.account.is_administrator() {
            "administrator"
        } else {
            "standard account"
        }
    }

    fn report(&self, extension: &str) -> PathBuf {
        let mut file = self.probe.clone().into_os_string();
        file.push(extension);
        PathBuf::from(file)
    }
}

/// What one login showed.
struct Seen {
    ran: bool,
    /// `absent`, or `present:<value>`.
    var: String,
    ssh_exit: Option<u32>,
    /// The client's `-v` says it sent the variable.
    sent: bool,
}

impl Seen {
    fn text(&self) -> String {
        format!(
            "shell ran={}; {VAR}={}; ssh exit={:?}; ssh -v sent it={}",
            self.ran, self.var, self.ssh_exit, self.sent
        )
    }
}

/// Log in with the probe as the shell, running a remote command, with a terminal or without, the client
/// sending `send` as the variable's value or nothing.
fn connect(rig: &Rig, login: &Login<'_>, tty: bool, send: Option<&str>) -> Seen {
    set_stock_shell(&rig.probe);
    let (line_file, env_file) = (rig.report(".line"), rig.report(".env"));
    let _ = std::fs::remove_file(&line_file);
    let _ = std::fs::remove_file(&env_file);
    let mut ssh = login.command();
    if let Some(value) = send {
        ssh.arg("-o").arg(format!("SetEnv={VAR}={value}"));
    }
    ssh.arg(if tty { "-tt" } else { "-T" }).arg("--").arg("a-command");
    let outcome = run_client(ssh, tty, rig.kit.dir());
    let ran = line_file.is_file();
    let env = std::fs::read_to_string(&env_file).unwrap_or_default();
    let var = env
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{VAR}=")))
        .unwrap_or("(no report)")
        .to_owned();
    Seen {
        ran,
        var,
        ssh_exit: outcome.code,
        sent: outcome.stderr.contains(&format!("Sending env {VAR}")),
    }
}

/// Log in with and without a terminal for each of `sends`, record each, and note a login that did not run.
fn observe(
    question: u8,
    label: &str,
    rig: &Rig,
    login: &Login<'_>,
    sends: &[Option<&str>],
    problems: &mut Vec<String>,
) {
    for send in sends {
        for tty in [false, true] {
            let seen = connect(rig, login, tty, *send);
            say(
                question,
                &format!(
                    "{label}; {}; client sends {}; {}: {}",
                    rig.kind(),
                    send.map_or("nothing".to_owned(), |v| format!("{VAR}={v}")),
                    if tty { "ssh -tt" } else { "ssh -T" },
                    seen.text()
                ),
            );
            if !seen.ran {
                problems.push(format!(
                    "Q{question} [{label}] {}: the probe shell did not run",
                    rig.kind()
                ));
            }
        }
    }
}

fn finish(problems: Vec<String>) {
    assert!(
        problems.is_empty(),
        "problems during the spike:\n{}",
        problems.join("\n")
    );
}

fn with_top(original: &str, lines: &str) -> String {
    format!("{lines}\n{original}")
}

fn with_end(original: &str, lines: &str) -> String {
    format!("{original}\n{lines}\n")
}

// Q1 =====

/// Q1: with `AcceptEnv` the shell sees the variable, with `-T` and with `-tt`; with no `AcceptEnv` it is dropped
/// and the login still succeeds.
#[test]
fn q1_delivery() {
    let _machine = machine::exclusive();
    let rig = Rig::new("sq1", false);
    let login = Login::new(&rig.kit, &rig.account);
    let config = SshdConfig::new();
    let mut problems = Vec::new();
    say(1, &config.outline());
    let original = config.original.clone();

    apply(
        1,
        "AcceptEnv at the top",
        &config,
        &with_top(&original, ACCEPT),
        &[&rig.account],
        &mut problems,
    );
    observe(
        1,
        "AcceptEnv at the top",
        &rig,
        &login,
        &[Some("always"), None],
        &mut problems,
    );

    apply(
        1,
        "no AcceptEnv (the stock file)",
        &config,
        &original,
        &[&rig.account],
        &mut problems,
    );
    observe(1, "no AcceptEnv", &rig, &login, &[Some("always"), None], &mut problems);
    finish(problems);
}

// Q2 =====

/// Q2: the `AcceptEnv` line in `sshd_config.d\10-ssh-broker.conf`, the `Include` above the first `Match`, then the
/// `Include` after the `Match Group administrators` block, for an administrator and for an account that is not one.
#[test]
fn q2_drop_in() {
    let _machine = machine::exclusive();
    let standard = Rig::new("sq2s", false);
    let admin = Rig::new("sq2a", true);
    let standard_login = Login::new(&standard.kit, &standard.account);
    let admin_login = Login::new(&admin.kit, &admin.account);
    let mut config = SshdConfig::new();
    let mut problems = Vec::new();
    say(2, &config.outline());
    config.add_drop_in("10-ssh-broker.conf", &format!("{ACCEPT}\n"));
    let original = config.original.clone();
    let accounts = [&standard.account, &admin.account];

    let label = "Include above the first Match, AcceptEnv in sshd_config.d/10-ssh-broker.conf";
    apply(
        2,
        label,
        &config,
        &with_top(&original, DROP_IN),
        &accounts,
        &mut problems,
    );
    observe(2, label, &standard, &standard_login, &[Some("always")], &mut problems);
    observe(2, label, &admin, &admin_login, &[Some("always")], &mut problems);

    // After the block: the stock file's own `Match Group administrators` is its last one, so the line closes
    // it. A stock file without that block gets one, so that the question is still asked.
    let (label, text) = if config.has_administrators_match() {
        (
            "Include after the stock Match Group administrators block",
            with_end(&original, DROP_IN),
        )
    } else {
        (
            "Include after a Match Group administrators block this test added (the stock file has none)",
            with_end(
                &original,
                &format!("Match Group administrators\n    PermitTTY yes\n{DROP_IN}"),
            ),
        )
    };
    apply(2, label, &config, &text, &accounts, &mut problems);
    observe(2, label, &standard, &standard_login, &[Some("always")], &mut problems);
    observe(2, label, &admin, &admin_login, &[Some("always")], &mut problems);
    finish(problems);
}

// Q3 =====

/// Q3: `SetEnv SSH_BROKER_ELEVATION=never` in the server's config, globally and in a `Match User` block, the
/// client sending `always`, with `AcceptEnv` and without.
#[test]
fn q3_servers_own_setting() {
    let _machine = machine::exclusive();
    let rig = Rig::new("sq3", false);
    let login = Login::new(&rig.kit, &rig.account);
    let config = SshdConfig::new();
    let mut problems = Vec::new();
    say(3, &config.outline());
    let original = config.original.clone();
    let set = format!("SetEnv {VAR}=never");
    let match_block = format!("Match User {}\n    {set}", rig.account.name);

    for accept in [true, false] {
        let with = if accept { "with AcceptEnv" } else { "without AcceptEnv" };
        let top = |extra: &str| {
            if accept {
                with_top(&original, &format!("{ACCEPT}\n{extra}"))
            } else {
                with_top(&original, extra)
            }
        };

        let label = format!("SetEnv never globally at the top, {with}");
        apply(3, &label, &config, &top(&set), &[&rig.account], &mut problems);
        observe(3, &label, &rig, &login, &[Some("always"), None], &mut problems);

        let label = format!("SetEnv never in a Match User block at the end, {with}");
        apply(
            3,
            &label,
            &config,
            &with_end(&top(""), &match_block),
            &[&rig.account],
            &mut problems,
        );
        observe(3, &label, &rig, &login, &[Some("always"), None], &mut problems);
    }
    finish(problems);
}

// Q4 =====

/// Ask an open session to print `answer` (typed with a caret in the middle, so that the echo of the typed line is
/// not the answer) and say what came of it. The wait is on the session's output or its end; the bound is the
/// failure bound of the rig, and its expiry is reported as "no answer", never as proof that the session is gone.
fn ask(session: &mut SshSession, answer: &str) -> String {
    use std::io::Write as _;
    let (head, tail) = answer.split_at(answer.len() / 2);
    let written = session
        .stdin
        .write_all(format!("echo {head}^{tail}\r").as_bytes())
        .and_then(|()| session.stdin.flush());
    if let Err(e) = written {
        return format!(
            "could not write to ssh ({e}); ssh has exited={}",
            session.child.try_wait().is_ok_and(|s| s.is_some())
        );
    }
    loop {
        if session.text().contains(answer) {
            return "the shell answered".to_owned();
        }
        let received = session.output.recv_timeout(SILENCE_BOUND); // sleep-ok: failure bound on the session's output, an external event that may never come; expiry is reported as "no answer" and not read as state
        match received {
            Ok(chunk) => session.transcript.extend_from_slice(&chunk),
            Err(RecvTimeoutError::Disconnected) => {
                let code = session.child.wait().map(|s| s.code());
                return format!("ssh closed its output with no answer; ssh exit={code:?}");
            }
            Err(RecvTimeoutError::Timeout) => {
                return format!("no answer and no end of ssh within {SILENCE_BOUND:?} (a failure bound, not proof)");
            }
        }
    }
}

/// Q4: sshd runs without the `AcceptEnv` line, the line is added to the file: a new connection, then a restart
/// and a new connection; and an interactive session open across the restart.
#[test]
fn q4_picking_up_a_change() {
    let _machine = machine::exclusive();
    let rig = Rig::new("sq4", false);
    let login = Login::new(&rig.kit, &rig.account);
    let config = SshdConfig::new();
    let mut problems = Vec::new();
    say(4, &config.outline());
    say(
        4,
        "the rig runs the runner's in-box sshd as the Windows service `sshd` (net stop / net start), not as a process of its own",
    );
    let original = config.original.clone();

    apply(
        4,
        "no AcceptEnv, sshd restarted so that it runs this file",
        &config,
        &original,
        &[&rig.account],
        &mut problems,
    );

    // An interactive session through cmd.exe, started before the file changes.
    let cmd = PathBuf::from(std::env::var("SystemRoot").expect("SystemRoot is set"))
        .join("System32")
        .join("cmd.exe");
    set_stock_shell(&cmd);
    let mut session = login.start();
    say(
        4,
        &format!(
            "session before the restart (interactive, cmd.exe): {}",
            ask(&mut session, "SB_ALIVE_1")
        ),
    );

    observe(
        4,
        "sshd running with no AcceptEnv (before the edit)",
        &rig,
        &login,
        &[Some("always")],
        &mut problems,
    );

    config.write(&with_top(&original, ACCEPT));
    say(
        4,
        &format!(
            "AcceptEnv added to the file; sshd -T (reads the file, not the running service): {}",
            effective(None)
        ),
    );
    observe(
        4,
        "file edited, sshd NOT restarted",
        &rig,
        &login,
        &[Some("always")],
        &mut problems,
    );

    let restarted = restart_sshd();
    say(
        4,
        &format!(
            "sshd restarted: {}",
            if restarted.is_ok() {
                "ok".to_owned()
            } else {
                format!("{restarted:?}")
            }
        ),
    );
    if let Err(e) = restarted {
        problems.push(format!("Q4: {e}"));
    }
    observe(
        4,
        "file edited, sshd restarted",
        &rig,
        &login,
        &[Some("always")],
        &mut problems,
    );

    say(
        4,
        &format!(
            "session opened before the restart, after it: {}",
            ask(&mut session, "SB_ALIVE_2")
        ),
    );
    finish(problems);
}
