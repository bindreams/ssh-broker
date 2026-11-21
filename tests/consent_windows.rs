//! The consent question of `ssh-broker elevate` through a real sshd. Windows only; **Elevated (CI only)**: each test
//! makes a local administrator, logs it in through the runner's sshd and starts its agent.
//!
//! A login that sets nothing is asked about: in a session with a terminal, `elevate` has the account's shim, which
//! sits under sshd with the account's full token, take the screen and ask the person at the terminal, and runs the
//! command only for `y` or `yes` (any case) and Enter. Everything else refuses and nothing runs: Enter alone, `n`, any
//! other word, Ctrl+C. What a program of the session writes, and what was typed before the question, cannot answer it.
//!
//! The answers are typed as a person types them (`SshSession::type_line` sends the line and Enter). What shows is
//! judged on the client's stream.
#![cfg(windows)]

#[path = "common/account.rs"]
mod account_fixture;
#[path = "common/agent_conn.rs"]
mod agent_conn;
#[path = "common/bounded_wait.rs"]
mod bounded_wait;
#[path = "common/child_entry.rs"]
mod child_entry;
#[path = "common/command_line_probe.rs"]
mod command_line_probe;
#[path = "common/desktop.rs"]
mod desktop;
#[path = "common/drain.rs"]
mod drain;
#[path = "common/elevate_rig.rs"]
mod elevate_rig;
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

use elevate_rig::{Started, an_administrator};
use ssh_broker::provision::procwait;
use ssh_broker::socket_loc::Integrity;
use sshd_rig::{SshSession, run_client};

/// The last line of the question.
const ANSWER_LINE: &str = "[y/N]";

/// A part of what `elevate` says when the person did not allow the command, short enough that no line of the terminal
/// breaks it (`text::elevation_declined`).
fn declined() -> &'static str {
    "was not allowed"
}

/// Send Ctrl+C as the terminal sends it.
fn ctrl_c(session: &mut SshSession) {
    use std::io::Write as _;
    session
        .stdin
        .write_all(&[0x03])
        .and_then(|()| session.stdin.flush())
        .expect("send Ctrl+C");
}

/// Type `line` (a PowerShell line that runs `sbk elevate ...`, for a command that makes `marker`) and read until the
/// question is on the screen. The marker's path is in the question, after which the answer line is.
fn ask(session: &mut SshSession, line: &str, marker: &std::path::Path) {
    session.type_line(line);
    session.read_until_after(&marker.display().to_string(), ANSWER_LINE);
}

// Console attach =====

/// Elevated (CI only). A process of the unelevated session is refused when it asks
/// Windows to attach to the console of the shim, of the console host sshd gave it, or of any other process that
/// shares that console. If Windows allowed it, a program of the session could read the answer as it is typed.
///
/// Over the real sshd with the default policy for an administrator (under `always` the session is at High and no
/// refusal is expected). The processes are found from outside, with the process list: the shim's image is the kit's
/// copy of the broker, and the others are its parent (the console's host) and everything that shares that parent or
/// has the shim as its own.
#[test]
fn an_unelevated_process_is_refused_attachment_to_every_process_of_the_shims_console() {
    let _machine = machine::exclusive();
    let (kit, account, _end) = an_administrator("cnap");
    let admin = Started::start(&kit, &account);

    let probe = kit.path("attach_probe.exe");
    std::fs::copy(command_line_probe::example("console_attach_probe"), &probe).expect("copy the probe into the kit");
    let shim_image = kit.exe.file_name().unwrap().to_string_lossy().into_owned();

    let mut session = admin.terminal_session_asking(None);
    let listed = process_list::snapshot();
    let shims: Vec<&process_list::Entry> = listed
        .iter()
        .filter(|entry| entry.exe.eq_ignore_ascii_case(&shim_image))
        .collect();
    assert!(
        !shims.is_empty(),
        "no process of the image {shim_image} is running: the login has no shim to look for\n{}",
        (admin.diagnostics())()
    );
    let mut ids = std::collections::BTreeSet::new();
    for shim in &shims {
        ids.insert(shim.pid);
        ids.insert(shim.parent);
        for relative in &listed {
            if relative.parent == shim.parent || relative.parent == shim.pid {
                ids.insert(relative.pid);
            }
        }
    }
    ids.remove(&0);
    let ids: Vec<String> = ids.iter().map(u32::to_string).collect();

    let out = kit.path("attach_probe.txt");
    session.type_line(&format!(
        "& '{}' {} | Out-File -Encoding ascii '{}'",
        probe.display(),
        ids.join(" "),
        out.display()
    ));
    session.say("PROBE-IS-DONE");
    let shown = std::fs::read_to_string(&out).expect("the probe's lines");
    for id in &ids {
        let line = shown
            .lines()
            .find(|line| line.starts_with(&format!("pid={id} ")))
            .unwrap_or_else(|| panic!("the probe said nothing of {id}:\n{shown}"));
        assert!(
            !line.ends_with("error=0"),
            "an unelevated process was allowed to attach to the console of {id}: {line}\n{shown}\n{}",
            (admin.diagnostics())()
        );
    }
    // The login's shim (sshd starts it under the console's host; the agent is the same image and has another parent)
    // is alive and holds the console while the session is open, so its refusal is access denied: any other error (a
    // process that is gone, one with no console) would satisfy the check above and show nothing.
    let under_a_console_host = |shim: &&&process_list::Entry| {
        listed
            .iter()
            .any(|entry| entry.pid == shim.parent && entry.exe.eq_ignore_ascii_case("conhost.exe"))
    };
    let of_the_login: Vec<_> = shims.iter().filter(under_a_console_host).collect();
    assert!(
        !of_the_login.is_empty(),
        "no process of the image {shim_image} has a console host for its parent: the login's shim was not found\n{}",
        (admin.diagnostics())()
    );
    for shim in of_the_login {
        let line = shown
            .lines()
            .find(|line| line.starts_with(&format!("pid={} ", shim.pid)))
            .expect("the probe's line of the shim (checked above)");
        assert!(
            line.ends_with("error=5"),
            "attaching to the console of the shim {} was not refused with access denied: {line}\n{shown}\n{}",
            shim.pid,
            (admin.diagnostics())()
        );
    }
    session.leave();
}

// The question =====

/// Elevated (CI only). The question is asked, and `y` and Enter run the command elevated with the keys typed
/// afterwards going to it: it reads a line and exits with a code that says whether it was the line typed, which the
/// session prints.
#[test]
fn elevate_asks_and_y_runs_it_elevated_with_keys_typed_afterwards_going_to_it() {
    let _machine = machine::exclusive();
    let (kit, account, _end) = an_administrator("cnyy");
    let admin = Started::start(&kit, &account);

    let mut session = admin.terminal_session_asking(None);
    session.type_line(
        "sbk elevate --terminal cmd.exe /v:on /c \"set /p x=ELEVATED-%OS%:& if !x!==typed-into-it (exit 42) else \
         (exit 43)\"; Write-Output ('KEYS-' + $LASTEXITCODE)",
    );
    session.read_until(ANSWER_LINE);
    assert!(
        session.text().contains("asks to run as administrator"),
        "{}",
        session.text()
    );
    session.type_line("y");
    session.read_until("ELEVATED-Windows_NT:");
    session.type_line("typed-into-it");
    session.read_until("KEYS-42");
    session.say("THE-SESSION-WENT-ON");
    session.leave();
}

/// Elevated (CI only). `yes`, in any case, allows too; without `--terminal` the command's output is printed in the
/// session as it is when nobody asks.
#[test]
fn yes_in_any_case_allows_and_the_output_is_the_sessions() {
    let _machine = machine::exclusive();
    let (kit, account, _end) = an_administrator("cnyc");
    let admin = Started::start(&kit, &account);

    let mut session = admin.terminal_session_asking(None);
    for (answer, marker) in [("yes", "ALLOWED-LOWER"), ("YeS", "ALLOWED-MIXED")] {
        let made = kit.path(&format!("{marker}.txt"));
        ask(
            &mut session,
            &format!(
                "sbk elevate cmd.exe /c \"echo {marker}-%OS%& copy NUL {}\"",
                made.display()
            ),
            &made,
        );
        session.type_line(answer);
        session.read_until(&format!("{marker}-Windows_NT"));
        session.say(&format!("{marker}-WENT-ON"));
        assert!(made.exists(), "{answer}: the command did not run");
    }
    session.leave();
}

/// Elevated (CI only). Anything but `y` or `yes` refuses, with no second question, and the command does not run: `n`,
/// another word, Enter alone, and Ctrl+C. The session goes on each time.
#[test]
fn n_maybe_enter_alone_and_ctrl_c_refuse_and_nothing_runs() {
    let _machine = machine::exclusive();
    let (kit, account, _end) = an_administrator("cnno");
    let admin = Started::start(&kit, &account);

    let mut session = admin.terminal_session_asking(None);
    for (what, answer) in [
        ("n", Some("n")),
        ("maybe", Some("maybe")),
        ("Enter alone", Some("")),
        ("Ctrl+C", None),
    ] {
        let slug = what.replace([' ', '+'], "-");
        let made = kit.path(&format!("refused-{slug}.txt"));
        ask(
            &mut session,
            &format!("sbk elevate cmd.exe /c copy NUL {}", made.display()),
            &made,
        );
        match answer {
            Some(line) => session.type_line(line),
            None => ctrl_c(&mut session),
        }
        session.read_until_after(&made.display().to_string(), declined());
        session.say(&format!("WENT-ON-AFTER-{}", slug.to_uppercase()));
        assert!(!made.exists(), "{what}: the command ran");
    }
    session.leave();
}

/// Elevated (CI only). What the session's own programs write to the terminal does not answer: a program prints `yes`
/// and Enter and a title and a report request, and then asks. The question is still waiting; `n` refuses, and the
/// command, which would have made a file, did not run.
#[test]
fn a_program_in_the_session_that_writes_yes_to_its_own_output_does_not_answer() {
    let _machine = machine::exclusive();
    let (kit, account, _end) = an_administrator("cnwr");
    let admin = Started::start(&kit, &account);

    let made = kit.path("written-yes.txt");
    let mut session = admin.terminal_session_asking(None);
    ask(
        &mut session,
        &format!(
            "[Console]::Out.Write(\"yes`r\" + [char]27 + ']0;yes' + [char]27 + '\\' + [char]27 + '[21t'); sbk elevate \
             cmd.exe /c copy NUL {}",
            made.display()
        ),
        &made,
    );
    session.type_line("n");
    session.read_until_after(&made.display().to_string(), declined());
    assert!(
        !made.exists(),
        "the command ran: what the session wrote answered the question"
    );
    session.leave();
}

/// Elevated (CI only). `logout` while a question is pending ends the session, the agent has exited, and the command
/// does not run.
#[test]
fn logout_while_a_question_is_pending_ends_the_session_and_runs_nothing() {
    let _machine = machine::exclusive();
    let (kit, account, _end) = an_administrator("cnlo");
    let admin = Started::start(&kit, &account);

    let made = kit.path("logged-out.txt");
    let mut session = admin.terminal_session_asking(None);
    ask(
        &mut session,
        &format!("sbk elevate cmd.exe /c copy NUL {}", made.display()),
        &made,
    );

    let agents = procwait::user_agents(&elevate_rig::agent_exe(), &account.sid, Integrity::High)
        .expect("list the agents of the account");
    assert!(!agents.is_empty(), "the login started no agent at High");
    let mut ssh = admin.login.command_with(None);
    ssh.arg("-T")
        .arg("--")
        .arg(format!("& '{}' logout", admin.kit.exe.display()));
    let outcome = run_client(ssh, false, kit.dir());
    assert!(
        outcome.stderr.contains("ending your background session."),
        "the agent's reply to logout is missing from stderr (exit {:?}):\n{}\n{}",
        outcome.code,
        outcome.stderr,
        (admin.diagnostics())()
    );

    // The session ends with its shell: the wait is for the client to end.
    let _ = session.finish();
    for agent in &agents {
        bounded_wait::wait_for_exit(
            agent.handle(),
            agent.pid,
            "the agent after logout",
            bounded_wait::CHILD_EXIT_BOUND,
            &[],
        );
    }
    assert!(!made.exists(), "the command ran after the session ended");
}
