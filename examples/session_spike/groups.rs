//! The measurement groups M1 to M4, M6 and M7 (M5 and M8 have files of their own).

use std::process::Command;

use windows::Win32::Foundation::LUID;

use crate::account::{Account, Kind};
use crate::harness::{Shared, start_stand_in};
use crate::rec::{Follower, Rec, fact};
use crate::win::{self, Event, event_name};

fn command_lines(program: &str, args: &[&str]) -> Vec<String> {
    match Command::new(program).args(args).output() {
        Ok(out) => String::from_utf8_lossy(&out.stdout)
            .lines()
            .chain(String::from_utf8_lossy(&out.stderr).lines())
            .map(|l| l.trim().to_owned())
            .filter(|l| !l.is_empty())
            .collect(),
        Err(e) => vec![format!("{program} did not run: {e}")],
    }
}

/// `seclogon`'s configuration and state, as `sc` prints them.
pub fn seclogon_state(label: &str, key: &str) {
    for (i, line) in command_lines("sc", &["qc", "seclogon"])
        .into_iter()
        .chain(command_lines("sc", &["query", "seclogon"]))
        .enumerate()
    {
        fact(label, &format!("{key}.{i:02}"), line);
    }
}

// env ----------------------------------------------------------------------------------------

pub fn env(shared: &Shared) {
    let dir = shared.run_dir("env");
    let follower = Follower::start("env", &dir);
    let rec = Rec::create(&dir, "runner");
    for (i, line) in command_lines("cmd", &["/c", "ver"]).into_iter().enumerate() {
        rec.put(&format!("os_version.{i}"), line);
    }
    for var in [
        "ImageOS",
        "ImageVersion",
        "RUNNER_OS",
        "RUNNER_ARCH",
        "USERNAME",
        "COMPUTERNAME",
    ] {
        rec.put(
            &format!("env.{var}"),
            std::env::var(var).unwrap_or_else(|_| "(unset)".into()),
        );
    }
    rec.put("orchestrator_pid", std::process::id());
    rec.put("orchestrator_ts_session", win::session_of(std::process::id()));
    win::own_token_facts(&rec, "orchestrator");
    win::redirection_guard_state(&rec, "orchestrator");
    win::own_job_facts(&rec, "orchestrator");
    seclogon_state("env", "seclogon");
    for (i, line) in command_lines("sc", &["query", "sshd"]).into_iter().enumerate() {
        rec.put(&format!("sshd_service.{i}"), line);
    }
    follower.finish();
}

// M1, M2 -------------------------------------------------------------------------------------

/// The logon of a background agent's stand-in as accounts a (never logged on), b (a profile) and
/// c (an administrator); what each child sees.
pub fn m1(shared: &Shared) {
    seclogon_state("m1", "seclogon_before");
    let a = Account::create("a", false, Kind::Standard);
    let b = Account::create("b", true, Kind::Standard);
    let c = Account::create("c", false, Kind::Administrator);
    for (account, label) in [(&a, "m1-a"), (&b, "m1-b"), (&c, "m1-c")] {
        let before = format!(
            "profile_list_entry={} profile_dir={:?}",
            win::profile_list_entry(&account.sid_text),
            account.profile_dir()
        );
        fact(label, "orchestrator.before_logon", before);
        let redirect = if account.name == b.name {
            vec![("redirect", "1".to_owned())]
        } else {
            vec![]
        };
        let run = start_stand_in(shared, account, label, "m1", &redirect);
        run.wait();
        fact(
            label,
            "orchestrator.after_logon",
            format!(
                "profile_list_entry={} hive_loaded_in_hku={} profile_dir={:?}",
                win::profile_list_entry(&account.sid_text),
                win::hive_loaded(&account.sid_text),
                account.profile_dir().map(|p| (p.exists(), p))
            ),
        );
        run.finish();
    }
    seclogon_state("m1", "seclogon_after");
}

// M3 -----------------------------------------------------------------------------------------

/// Does the logon child outlive the job its starter is in? Without and with `CREATE_BREAKAWAY_FROM_JOB`.
pub fn m3(shared: &Shared) {
    let b = Account::create("b", true, Kind::Standard);
    for (breakaway, label) in [(false, "m3-plain"), (true, "m3-breakaway")] {
        let child_ready = event_name("child-ready");
        let go = event_name("go");
        let ack = event_name("ack");
        let standin_ready = event_name("standin-ready");
        let events: Vec<Event> = [&child_ready, &go, &ack, &standin_ready]
            .iter()
            .map(|n| Event::create(n).expect("create an event"))
            .collect();
        let mut input = vec![
            ("ready", child_ready.clone()),
            ("go", go.clone()),
            ("ack", ack.clone()),
            ("standin_ready", standin_ready.clone()),
        ];
        if breakaway {
            input.push(("breakaway", "1".to_owned()));
        }
        let mut run = start_stand_in(shared, &b, label, "m1", &input);
        if win::wait_any(&[events[3].handle(), run.process.0]) == 1 {
            fact(
                label,
                "orchestrator.result",
                "the stand-in ended before the child was ready",
            );
            run.finish();
            continue;
        }
        let child_pid: u32 = Rec::read_back(&run.dir, "standin", "child_pid")
            .and_then(|v| v.parse().ok())
            .expect("the stand-in recorded the child's pid");
        let child = win::open_for_wait(child_pid).expect("open the child");
        fact(
            label,
            "orchestrator.child_in_job",
            format!("{:?}", run.job_contains(child.0)),
        );
        fact(
            label,
            "orchestrator.job_pids",
            format!("{:?} (stand-in {}, child {child_pid})", run.job_pids(), run.pid),
        );
        fact(label, "orchestrator.child_parent_pid", win::parent_of(child_pid));
        fact(
            label,
            "orchestrator.child_parent_image",
            win::image_of(win::parent_of(child_pid).parse().unwrap_or(0)),
        );

        run.close_job();
        run.wait();
        // The job is closed and the stand-in is gone. A child that is still alive hears this.
        events[1].set();
        let survived = win::wait_any(&[events[2].handle(), child.0]) == 0;
        fact(
            label,
            "orchestrator.child_survived_the_job_close",
            format!("{survived} (true: it answered the go event after its starter's job closed; false: it ended)"),
        );
        run.finish();
    }
}

// M4 -----------------------------------------------------------------------------------------

/// The real agent, started twice for one user. Needs `ssh-broker.exe` built from the spike branch,
/// whose `session_allows_agent` allows session 0.
pub fn m4(shared: &Shared) {
    if shared.broker.is_none() {
        fact(
            "m4",
            "result",
            "ssh-broker.exe was not built beside the example; build it with --bin ssh-broker",
        );
        return;
    }
    let b = Account::create("b", true, Kind::Standard);
    let run = start_stand_in(shared, &b, "m4", "m4", &[]);
    run.wait();
    run.finish();
}

// M6 -----------------------------------------------------------------------------------------

fn parse_luid(text: &str) -> Option<LUID> {
    let (high, low) = text.split_once(':')?;
    let hex = |s: &str| u32::from_str_radix(s.trim_start_matches("0x"), 16).ok();
    Some(LUID {
        LowPart: hex(low)?,
        HighPart: hex(high)? as i32,
    })
}

/// What `logout` ends: kill the logon child and its grandchild, release every handle we hold, and
/// wait with no limit for the logon session to leave `LsaEnumerateLogonSessions`. The last group
/// to run: if the session never goes, this waits for the job's timeout.
pub fn m6(shared: &Shared) {
    let b = Account::create("b", true, Kind::Standard);
    let child_ready = event_name("child-ready");
    let go = event_name("go-never");
    let standin_ready = event_name("standin-ready");
    let closed = event_name("closed");
    let events: Vec<Event> = [&child_ready, &go, &standin_ready, &closed]
        .iter()
        .map(|n| Event::create(n).expect("create an event"))
        .collect();
    let run = start_stand_in(
        shared,
        &b,
        "m6",
        "m1",
        &[
            ("ready", child_ready.clone()),
            ("go", go.clone()),
            ("standin_ready", standin_ready.clone()),
            ("closed", closed.clone()),
            ("grandchild", "1".to_owned()),
        ],
    );
    if win::wait_any(&[events[2].handle(), run.process.0]) == 1 {
        fact(
            "m6",
            "orchestrator.result",
            "the stand-in ended before the children were ready",
        );
        run.finish();
        return;
    }
    let read = |name: &str, key: &str| Rec::read_back(&run.dir, name, key);
    let child_pid: u32 = read("child", "pid").and_then(|v| v.parse().ok()).expect("child pid");
    let grandchild_pid: u32 = read("child", "grandchild_pid")
        .and_then(|v| v.parse().ok())
        .expect("grandchild pid");
    let luid = read("child", "self.logon_luid")
        .and_then(|v| parse_luid(&v))
        .expect("the child's logon session");
    let target = (luid.HighPart, luid.LowPart);
    let listed = |_: ()| win::logon_sessions().iter().any(|l| (l.HighPart, l.LowPart) == target);
    fact("m6", "orchestrator.session_listed_while_children_run", listed(()));

    let child = win::open_for_wait(child_pid).expect("open the child");
    let grandchild = win::open_for_wait(grandchild_pid).expect("open the grandchild");
    win::terminate(grandchild.0);
    win::terminate(child.0);
    win::wait_one(grandchild.0);
    win::wait_one(child.0);
    drop(grandchild);
    drop(child);
    // The stand-in saw the child end, closed its handles and said so.
    win::wait_any(&[events[3].handle(), run.process.0]);
    fact(
        "m6",
        "orchestrator.holders_released",
        "the orchestrator and the stand-in hold no handle to the children",
    );

    let mut last_holders = None;
    while listed(()) {
        let holders: Vec<String> = win::processes()
            .into_iter()
            .filter(|(pid, _, _)| win::process_identity(*pid).is_some_and(|(_, l)| (l.HighPart, l.LowPart) == target))
            .map(|(pid, _, name)| format!("{name}({pid})"))
            .collect();
        if last_holders.as_ref() != Some(&holders) {
            fact(
                "m6",
                "orchestrator.session_still_listed",
                format!("processes of that logon session: {holders:?}"),
            );
            last_holders = Some(holders);
        }
        // A poll of the real condition, with no limit: there is no event for a session's end. The
        // one-second wait on an event nobody sets is the interval between two looks, not a proof.
        win::wait_bounded(events[1].handle(), 1);
    }
    fact(
        "m6",
        "orchestrator.session_gone",
        "true: the logon session left LsaEnumerateLogonSessions after its processes ended",
    );
    run.wait();
    run.finish();
}

// M7 -----------------------------------------------------------------------------------------

/// Windows' reason for each failed logon, and the secondary logon service stopped or disabled.
pub fn m7(shared: &Shared) {
    let a = Account::create("a", false, Kind::Standard);
    let d = Account::create("d", false, Kind::Disabled);
    let e = Account::create("e", false, Kind::MustChangePassword);
    let f = Account::try_create("f", false, Kind::BlankPassword);
    let mut cases = vec![
        ("wrong".to_owned(), a.name.clone(), "Wrong-Pw-0!Aa".to_owned()),
        (
            "empty_for_account_with_password".to_owned(),
            a.name.clone(),
            String::new(),
        ),
        ("disabled_account".to_owned(), d.name.clone(), d.password.clone()),
        ("must_change_password".to_owned(), e.name.clone(), e.password.clone()),
        ("long_300".to_owned(), a.name.clone(), "x".repeat(300)),
        (
            "no_such_user".to_owned(),
            "sb-no-such-user".to_owned(),
            "Whatever-1!".to_owned(),
        ),
    ];
    match &f {
        Ok(f) => cases.push(("blank_account_blank_password".to_owned(), f.name.clone(), String::new())),
        Err(why) => fact("m7", "blank_account", format!("could not be created: {why}")),
    }
    cases.push(("control_correct".to_owned(), a.name.clone(), a.password.clone()));
    let input: Vec<(&str, String)> = cases.iter().map(|(l, u, p)| ("case", format!("{l}|{u}|{p}"))).collect();
    let run = start_stand_in(shared, &a, "m7", "m7", &input);
    run.wait();
    run.finish();

    for (label, disable) in [("stopped", false), ("disabled", true)] {
        let standin_ready = event_name("standin-ready");
        let go = event_name("go");
        let events = [
            Event::create(&standin_ready).expect("create an event"),
            Event::create(&go).expect("create an event"),
        ];
        let run_label = format!("m7-seclogon-{label}");
        let run = start_stand_in(
            shared,
            &a,
            &run_label,
            "m7gated",
            &[("standin_ready", standin_ready), ("go", go)],
        );
        if win::wait_any(&[events[0].handle(), run.process.0]) == 1 {
            fact(&run_label, "orchestrator.result", "the stand-in ended early");
            run.finish();
            continue;
        }
        let guard = SeclogonGuard::stop(&run_label, disable);
        events[1].set();
        run.wait();
        drop(guard);
        run.finish();
    }
}

/// Stops the secondary logon service (and optionally disables it); restores it on drop.
struct SeclogonGuard {
    label: String,
    original_start: String,
}

impl SeclogonGuard {
    fn stop(label: &str, disable: bool) -> SeclogonGuard {
        let qc = command_lines("sc", &["qc", "seclogon"]).join(" ");
        let original_start = if qc.contains("AUTO_START") {
            "auto"
        } else if qc.contains("DISABLED") {
            "disabled"
        } else {
            "demand"
        }
        .to_owned();
        if disable {
            for line in command_lines("sc", &["config", "seclogon", "start=", "disabled"]) {
                fact(label, "orchestrator.sc_config_disabled", line);
            }
        }
        for line in command_lines("net", &["stop", "seclogon"]) {
            fact(label, "orchestrator.net_stop", line);
        }
        seclogon_state(label, "seclogon_when_the_logon_runs");
        SeclogonGuard {
            label: label.to_owned(),
            original_start,
        }
    }
}

impl Drop for SeclogonGuard {
    fn drop(&mut self) {
        for line in command_lines("sc", &["config", "seclogon", "start=", &self.original_start]) {
            fact(&self.label, "orchestrator.sc_config_restore", line);
        }
        for line in command_lines("net", &["start", "seclogon"]) {
            fact(&self.label, "orchestrator.net_start", line);
        }
    }
}
