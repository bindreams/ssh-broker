//! M5(a): a standard user registers a password task for itself. The process that calls this is
//! the variable: the stand-in (a `LogonUserW` token of a chosen logon type, RedirectionGuard on or
//! off) or a `CreateProcessWithLogonW` child (an interactive logon, RedirectionGuard off or on).
//! The caller's facts (logon type, integrity, RedirectionGuard) are recorded by the caller's own
//! startup; this records what the scheduler said to each registration.

use std::collections::BTreeSet;
use std::path::PathBuf;

use crate::rec::{Input, Rec};
use crate::tasks::{self, Spec, Trigger};

/// Try the boot trigger (the product's), a logon trigger and no trigger, each with every way of
/// naming the account, and record per trigger whether it was accepted or why not. `tag` makes the
/// task names unique to the caller.
pub fn attempt(rec: &Rec, tag: &str, input: &Input) {
    tasks::init_com();
    let machine = std::env::var("COMPUTERNAME").unwrap_or_default();
    let user = input.req("user");
    let qualified = format!("{machine}\\{user}");
    let exe = PathBuf::from(input.req("exe"));
    for (trigger_name, trigger) in [
        ("boot", Trigger::Boot),
        ("logon", Trigger::Logon),
        ("none", Trigger::None),
    ] {
        let name = format!("sbspike-selfreg-{tag}-{trigger_name}");
        let key = format!("register_own_task.{trigger_name}");
        let spec = Spec {
            name: &name,
            qualified_name: &qualified,
            bare_name: user,
            sid: input.req("sid"),
            password: input.req("password"),
            exe: &exe,
            args: "child x y",
            sddl: None,
            trigger,
            sweep_names: true,
        };
        match tasks::register_password_task(&spec) {
            Ok(combination) => {
                rec.put(&key, format!("ACCEPTED ({combination})"));
                match tasks::delete(&name) {
                    Ok(()) => rec.put(&format!("{key}.cleanup"), "deleted"),
                    Err(e) => rec.err(&format!("{key}.cleanup"), &e),
                }
            }
            Err(failures) => {
                let distinct: BTreeSet<&str> = failures.iter().map(|(_, error)| error.as_str()).collect();
                if distinct.len() == 1 {
                    rec.put(
                        &key,
                        format!(
                            "REFUSED in all {} namings: {}",
                            failures.len(),
                            distinct.iter().next().unwrap()
                        ),
                    );
                } else {
                    rec.put(&key, format!("REFUSED ({} namings, different errors)", failures.len()));
                    for (i, (combination, error)) in failures.iter().enumerate() {
                        rec.put(&format!("{key}.{i}"), format!("{combination}: {error}"));
                    }
                }
            }
        }
    }
}
