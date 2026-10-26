//! M5: `auto-login`, a boot task with a stored password.

use std::path::Path;

use crate::account::{Account, Kind};
use crate::harness::{Shared, start_stand_in};
use crate::rec::{Follower, fact};
use crate::stand_in::junction_path;
use crate::tasks::{self, Spec};
use crate::win::{self, Event, event_name, wait_bounded};

/// How long to wait for a task the scheduler was asked to run to report. The scheduler is an
/// external service that may never start the task (that is the case (g) looks for), so this is the
/// failure bound surfaced to the reader, not a proof of anything.
const TASK_REPORT_SECONDS: u32 = 120;

fn system32(program: &str) -> std::path::PathBuf {
    Path::new(&std::env::var_os("SystemRoot").expect("SystemRoot"))
        .join("System32")
        .join(program)
}

/// Run `cmdkey /list` as SYSTEM through a one-shot task and print what the vault holds.
fn vault_snapshot(shared: &Shared, tag: &str) {
    let out = shared.root.join(format!("vault-{tag}.txt"));
    let event_text = event_name("vault");
    let event = Event::create(&event_text).expect("create an event");
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
    if let Err(e) = tasks::run(name) {
        fact(
            "m5",
            &format!("vault.{tag}"),
            format!("could not run the SYSTEM task: {}", win::describe(&e)),
        );
    } else if wait_bounded(event.handle(), TASK_REPORT_SECONDS) {
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
            format!("the SYSTEM task did not report within {TASK_REPORT_SECONDS} s"),
        );
    }
    let _ = tasks::delete(name);
}

pub fn m5(shared: &Shared) {
    tasks::init_com();
    let mut b = Account::create("b", true, Kind::Standard);
    let machine = std::env::var("COMPUTERNAME").unwrap_or_default();
    let qualified = format!("{machine}\\{}", b.name);

    // (a) b registers a password boot task for itself from its network-logon token. This run also
    // makes the junction the task's child will try to traverse.
    let prep = start_stand_in(shared, &b, "m5-a", "m5a", &[]);
    prep.wait();
    let junction = junction_path(&prep.dir);
    prep.finish();

    vault_snapshot(shared, "before_register");

    // (b), (f), (h): the administrator registers for b, with an explicit SDDL and with the default.
    let d_dir = shared.run_dir("m5-d");
    let follower = Follower::start("m5-d", &d_dir);
    let ready_text = event_name("m5-ready");
    let ready = Event::create(&ready_text).expect("create an event");
    let args = format!(
        "child \"{}\" m5d \"junction={}\" \"ready={ready_text}\"",
        d_dir.display(),
        junction.display()
    );
    let explicit_sddl = format!("D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;{})", b.sid_text);
    let register = |name: &str, password: &str, sddl: Option<&str>| {
        tasks::register_password_task(&Spec {
            name,
            qualified_name: &qualified,
            bare_name: &b.name,
            sid: &b.sid_text,
            password,
            exe: &shared.exe,
            args: &args,
            sddl,
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
            Ok(variant) => {
                fact(
                    "m5",
                    key,
                    format!(
                        "ACCEPTED (boot trigger accepted; account named in the XML by variant {variant}: 0 SID, 1 qualified name, 2 bare name)"
                    ),
                );
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
                for (i, failure) in failures.iter().enumerate() {
                    fact("m5", &format!("{key}.failure{i}"), failure);
                }
            }
        }
    }
    fact("m5", "explicit_sddl_requested", &explicit_sddl);
    let _ = tasks::delete("sbspike-default");

    // (c) a wrong password at registration.
    match register("sbspike-wrong", "Wrong-Pw-0!Aa", None) {
        Ok(_) => {
            fact("m5", "wrong_password_at_registration", "ACCEPTED (not refused)");
            let _ = tasks::delete("sbspike-wrong");
        }
        Err(failures) => {
            fact("m5", "wrong_password_at_registration", "REFUSED");
            for (i, failure) in failures.iter().enumerate() {
                fact("m5", &format!("wrong_password_at_registration.failure{i}"), failure);
            }
        }
    }
    vault_snapshot(shared, "after_register");

    // (d) run it now.
    match tasks::run("sbspike-explicit") {
        Ok(()) => {
            let reported = wait_bounded(ready.handle(), TASK_REPORT_SECONDS);
            fact("m5", "d_run_now.child_reported", reported);
            if !reported {
                fact(
                    "m5",
                    "d_run_now.note",
                    format!("no report within {TASK_REPORT_SECONDS} s; see the task state below"),
                );
            }
        }
        Err(e) => fact(
            "m5",
            "d_run_now",
            format!("could not run the task: {}", win::describe(&e)),
        ),
    }
    report_task("d_after_first_run");

    // (g) change the password, run again.
    b.set_password("New-Pw-9z!Aa-changed");
    ready.reset();
    match tasks::run("sbspike-explicit") {
        Ok(()) => {
            let reported = wait_bounded(ready.handle(), TASK_REPORT_SECONDS);
            fact("m5", "g_stale_password.child_reported", reported);
        }
        Err(e) => fact(
            "m5",
            "g_stale_password",
            format!("could not run the task: {}", win::describe(&e)),
        ),
    }
    report_task("g_after_stale_password_run");

    // (e) the vault after the task is deleted.
    match tasks::delete("sbspike-explicit") {
        Ok(()) => fact("m5", "delete_task", "ok"),
        Err(e) => fact("m5", "delete_task", format!("ERROR {}", win::describe(&e))),
    }
    vault_snapshot(shared, "after_delete");
    fact("m5", "boot", "not measurable in CI: a real boot");
    follower.finish();
}

fn report_task(key: &str) {
    match tasks::state_and_result("sbspike-explicit") {
        Ok((state, result)) => fact(
            "m5",
            key,
            format!("state={state} (3 Ready, 4 Running) last_result={result:#010x}"),
        ),
        Err(e) => fact("m5", key, format!("ERROR {}", win::describe(&e))),
    }
}
