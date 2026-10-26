//! M5: `auto-login`, a boot task with a stored password.
//!
//! `m5`: (a) who may register, (b) (c) (e) (f) (h). `m5run`, `m5run-batch`: (d) and (g), the task
//! run on demand, without and with the account holding `SeBatchLogonRight`. Each is a workflow
//! step of its own: a task the scheduler never runs holds its step until the step's timeout.

use std::path::Path;

use crate::account::{Account, Kind, LogonKind};
use crate::evlog;
use crate::harness::{Shared, create_events, start_stand_in_with_token};
use crate::rec::{Follower, fact};
use crate::rights;
use crate::tasks::{self, Spec, Trigger};
use crate::win::{self, Event, event_name, wait_bounded};

/// `SCHED_S_TASK_HAS_NOT_RUN`: the task's last result before it has ever run.
const HAS_NOT_RUN: i32 = 0x0004_1303;

fn system32(program: &str) -> std::path::PathBuf {
    Path::new(&std::env::var_os("SystemRoot").expect("SystemRoot"))
        .join("System32")
        .join(program)
}

/// Run the task now and wait for what ends it: the event its action sets, or its instance ending
/// (the scheduler's state, which also covers an action that fails before it can set the event).
/// There is no time limit of our own; the step's timeout bounds a scheduler that never starts it.
/// Whatever the scheduler and the logon audit logged meanwhile is printed. `true`: the event was set.
fn run_and_wait(label: &str, key: &str, task_name: &str, event: &Event) -> bool {
    let scheduler_mark = evlog::mark(&evlog::TASK_SCHEDULER);
    let audit_mark = evlog::mark(&evlog::LOGON_AUDIT);
    let instance = match tasks::run(task_name) {
        Ok(instance) => instance,
        Err(e) => {
            fact(label, key, format!("could not run the task: {}", win::describe(&e)));
            return false;
        }
    };
    let mut last_seen = String::new();
    let reported = loop {
        // One-second wait on the event itself: the interval between two looks at the instance, not a proof.
        if wait_bounded(event.handle(), 1) {
            break true;
        }
        let state = tasks::instance_state(&instance);
        let seen = match &state {
            Ok(s) => format!("instance state {s} (2 Queued, 3 Ready, 4 Running)"),
            Err(e) => format!("instance gone: {}", win::describe(e)),
        };
        if seen != last_seen {
            fact(label, &format!("{key}.observed"), &seen);
            last_seen = seen;
        }
        if !matches!(state, Ok(2 | 4)) {
            // The instance is over. One more look at the event: the action may have set it just before.
            break wait_bounded(event.handle(), 0);
        }
    };
    fact(label, &format!("{key}.child_reported"), reported);
    report_task(label, &format!("{key}.task_after"), task_name);
    evlog::dump_since(label, &evlog::TASK_SCHEDULER, scheduler_mark);
    evlog::dump_since(label, &evlog::LOGON_AUDIT, audit_mark);
    reported
}

fn report_task(label: &str, key: &str, name: &str) {
    match tasks::state_and_result(name) {
        Ok((state, result)) => fact(
            label,
            key,
            format!(
                "state={state} (3 Ready, 4 Running) last_result={result:#010x}{}",
                if result == HAS_NOT_RUN {
                    " (SCHED_S_TASK_HAS_NOT_RUN: the task never ran)"
                } else {
                    ""
                }
            ),
        ),
        Err(e) => fact(label, key, format!("ERROR {}", win::describe(&e))),
    }
}

/// Run `cmdkey /list` as SYSTEM through a one-shot task and print what the vault holds.
fn vault_snapshot(shared: &Shared, tag: &str) {
    let out = shared.root.join(format!("vault-{tag}.txt"));
    let event_text = event_name("vault");
    let event = create_events("m5", &[&event_text], None).remove(0);
    let args = format!(
        "capture \"{}\" \"{event_text}\" \"{}\" /list",
        out.display(),
        system32("cmdkey.exe").display()
    );
    let name = "sbspike-vault";
    if let Err(e) = tasks::register_system_task(name, &shared.exe, &args) {
        fact(
            "m5",
            &format!("vault.{tag}"),
            format!("could not register the SYSTEM task: {}", win::describe(&e)),
        );
        return;
    }
    if run_and_wait("m5", &format!("vault.{tag}"), name, &event) {
        let text = std::fs::read_to_string(&out).unwrap_or_default();
        let mut shown = 0;
        for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
            fact("m5", &format!("vault.{tag}.{shown:02}"), line);
            shown += 1;
        }
        fact("m5", &format!("vault.{tag}.lines"), shown);
        fact(
            "m5",
            &format!("vault.{tag}.task_scheduler_entries"),
            text.lines().filter(|l| l.contains("TaskScheduler")).count(),
        );
    } else {
        fact(
            "m5",
            &format!("vault.{tag}"),
            "the SYSTEM task ended without reporting (see the scheduler records above)",
        );
    }
    let _ = tasks::delete(name);
}

// (a) --------------------------------------------------------------------------------------

/// Is a standard user, in an interactive logon at Medium integrity, refused when it registers a
/// task for itself? One thing changes per run: the logon type of the registering process and
/// whether RedirectionGuard is on in it; the registering process's logon type, integrity and
/// RedirectionGuard state are in its own facts. Two further runs use `CreateProcessWithLogonW`
/// children (the interactive logon the product's agent gets), and an administrator account at
/// its limited Medium token is the control for "standard user". Per run the trigger and the
/// forms of the account name vary inside the registration.
fn selfreg_matrix(shared: &Shared, standard: &Account, administrator: &Account) {
    use LogonKind::{Batch, Interactive, Network};
    let runs: [(&str, &Account, LogonKind, bool, bool); 7] = [
        ("m5-a-std-network-rgon", standard, Network, true, true),
        ("m5-a-std-network-rgoff", standard, Network, false, false),
        ("m5-a-std-interactive-rgon", standard, Interactive, true, false),
        ("m5-a-std-interactive-rgoff", standard, Interactive, false, false),
        ("m5-a-std-batch-rgon", standard, Batch, true, false),
        ("m5-a-std-batch-rgoff", standard, Batch, false, false),
        ("m5-a-admin-network-rgon", administrator, Network, true, true),
    ];
    for (label, account, kind, guard, clw) in runs {
        let token = match account.token(kind) {
            Ok(token) => token,
            Err(e) => {
                fact(
                    label,
                    "orchestrator.token",
                    format!("LogonUserW refused this logon type: {}", win::describe(&e)),
                );
                continue;
            }
        };
        let mut input = vec![("rg", if guard { "on" } else { "off" }.to_owned())];
        if clw {
            input.push(("clw", "1".to_owned()));
        }
        let run = start_stand_in_with_token(shared, account, label, "m5a", &input, token);
        run.wait();
        run.finish();
    }
}

// m5 ---------------------------------------------------------------------------------------

pub fn m5(shared: &Shared) {
    tasks::init_com();
    evlog::enable("m5", &evlog::TASK_SCHEDULER);
    let b = Account::create("b", true, Kind::Standard);
    let c = Account::create("c", true, Kind::Administrator);
    let machine = std::env::var("COMPUTERNAME").unwrap_or_default();
    let qualified = format!("{machine}\\{}", b.name);

    selfreg_matrix(shared, &b, &c);

    vault_snapshot(shared, "before_register");

    // (b), (f), (h): the administrator registers for b, with an explicit SDDL and with the default.
    let explicit_sddl = format!("D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;{})", b.sid_text);
    let register = |name: &str, password: &str, sddl: Option<&str>| {
        tasks::register_password_task(&Spec {
            name,
            qualified_name: &qualified,
            bare_name: &b.name,
            sid: &b.sid_text,
            password,
            exe: &shared.exe,
            args: "child x y",
            sddl,
            trigger: Trigger::Boot,
            sweep_names: false,
        })
    };
    for (name, key, sddl) in [
        (
            "sbspike-explicit",
            "b_by_admin_explicit_sddl",
            Some(explicit_sddl.as_str()),
        ),
        ("sbspike-default", "b_by_admin_default_sddl", None),
    ] {
        match register(name, &b.password, sddl) {
            Ok(combination) => {
                fact("m5", key, format!("ACCEPTED (boot trigger accepted; {combination})"));
                match tasks::sddl(name) {
                    Ok(text) => fact("m5", &format!("{key}.task_dacl"), text),
                    Err(e) => fact(
                        "m5",
                        &format!("{key}.task_dacl"),
                        format!("ERROR {}", win::describe(&e)),
                    ),
                }
            }
            Err(failures) => {
                for (i, (combination, error)) in failures.iter().enumerate() {
                    fact("m5", &format!("{key}.failure{i}"), format!("{combination}: {error}"));
                }
            }
        }
    }
    fact("m5", "explicit_sddl_requested", &explicit_sddl);

    // (c) a wrong password at registration.
    match register("sbspike-wrong", "Wrong-Pw-0!Aa", None) {
        Ok(_) => {
            fact("m5", "wrong_password_at_registration", "ACCEPTED (not refused)");
            let _ = tasks::delete("sbspike-wrong");
        }
        Err(failures) => {
            fact("m5", "wrong_password_at_registration", "REFUSED");
            for (i, (combination, error)) in failures.iter().enumerate() {
                fact(
                    "m5",
                    &format!("wrong_password_at_registration.failure{i}"),
                    format!("{combination}: {error}"),
                );
            }
        }
    }
    vault_snapshot(shared, "after_register");

    // (e) the vault after the tasks are deleted.
    for name in ["sbspike-explicit", "sbspike-default"] {
        match tasks::delete(name) {
            Ok(()) => fact("m5", &format!("delete_task.{name}"), "ok"),
            Err(e) => fact(
                "m5",
                &format!("delete_task.{name}"),
                format!("ERROR {}", win::describe(&e)),
            ),
        }
    }
    vault_snapshot(shared, "after_delete");
    fact("m5", "boot", "not measurable in CI: a real boot");
}

// m5run, m5run-batch -------------------------------------------------------------------------

/// (d) run the password task now, as the user the administrator registered it for; (g) change the
/// user's password and run it again. The child records the user, the session and the profile it
/// sees. With `grant_batch` the account first holds `SeBatchLogonRight`: a password task runs as a
/// batch logon, and a standard user may not hold that right.
pub fn m5run(shared: &Shared, grant_batch: bool) {
    let label = if grant_batch { "m5run-batch" } else { "m5run" };
    tasks::init_com();
    evlog::enable(label, &evlog::TASK_SCHEDULER);
    evlog::enable_logon_audit(label);
    let mut b = Account::create("b", true, Kind::Standard);
    fact(
        label,
        "orchestrator.explicit_rights_before",
        format!("{:?}", rights::explicit_rights(&b.sid_text)),
    );
    if grant_batch {
        match rights::grant(&b.sid_text, "SeBatchLogonRight") {
            Ok(()) => fact(label, "orchestrator.grant_batch_logon_right", "granted"),
            Err(e) => fact(label, "orchestrator.grant_batch_logon_right", format!("ERROR {e}")),
        }
        fact(
            label,
            "orchestrator.explicit_rights_after",
            format!("{:?}", rights::explicit_rights(&b.sid_text)),
        );
    }

    let dir = shared.run_dir(label);
    let follower = Follower::start(label, &dir);
    let ready_text = event_name("m5-ready");
    let ready = create_events(label, &[&ready_text], Some(&b.sid_text)).remove(0);
    let args = format!("child \"{}\" m5d \"ready={ready_text}\"", dir.display());
    let machine = std::env::var("COMPUTERNAME").unwrap_or_default();
    let qualified = format!("{machine}\\{}", b.name);
    let name = "sbspike-run";
    let registered = tasks::register_password_task(&Spec {
        name,
        qualified_name: &qualified,
        bare_name: &b.name,
        sid: &b.sid_text,
        password: &b.password,
        exe: &shared.exe,
        args: &args,
        sddl: None,
        trigger: Trigger::Boot,
        sweep_names: false,
    });
    match registered {
        Ok(combination) => fact(label, "register", format!("ACCEPTED ({combination})")),
        Err(failures) => {
            for (i, (combination, error)) in failures.iter().enumerate() {
                fact(
                    label,
                    &format!("register.failure{i}"),
                    format!("{combination}: {error}"),
                );
            }
            follower.finish();
            return;
        }
    }

    // (d)
    run_and_wait(label, "d_run_now", name, &ready);

    // (g) The stored password is now stale.
    b.set_password("New-Pw-9z!Aa-changed");
    ready.reset();
    fact(
        label,
        "g_stale_password.password_changed",
        "the account's password differs from the one the task stores; its records below are the second run",
    );
    run_and_wait(label, "g_stale_password", name, &ready);

    match tasks::delete(name) {
        Ok(()) => fact(label, "delete_task", "ok"),
        Err(e) => fact(label, "delete_task", format!("ERROR {}", win::describe(&e))),
    }
    follower.finish();
}
