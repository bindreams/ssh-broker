//! Windows event logs through `wevtutil`: the scheduler's, the logon audit and OpenSSH's say why a
//! task or a key authentication did not happen.

use std::os::windows::process::CommandExt;
use std::process::Command;

use crate::rec::fact;

/// A channel and which of its records and lines are worth printing.
pub struct Channel {
    pub name: &'static str,
    /// An XPath condition on `System` (for example `EventID=4624 or EventID=4625`), if any.
    pub system_condition: Option<&'static str>,
    /// Lines of the text rendering that start with one of these are kept; empty keeps all lines
    /// that are not log boilerplate.
    pub keep: &'static [&'static str],
}

pub const TASK_SCHEDULER: Channel = Channel {
    name: "Microsoft-Windows-TaskScheduler/Operational",
    system_condition: None,
    keep: &[],
};

pub const LOGON_AUDIT: Channel = Channel {
    name: "Security",
    system_condition: Some("EventID=4624 or EventID=4625"),
    keep: &[
        "Date:",
        "Event ID:",
        "Logon Type:",
        "Account Name:",
        "Account Domain:",
        "Failure Reason:",
        "Status:",
        "Sub Status:",
        "Process Name:",
        "Logon Process:",
        "Authentication Package:",
        "Source Network Address:",
    ],
};

pub const OPENSSH: Channel = Channel {
    name: "OpenSSH/Operational",
    system_condition: None,
    keep: &[],
};

const BOILERPLATE: &[&str] = &[
    "Log Name:",
    "Source:",
    "Task:",
    "Keyword",
    "Opcode:",
    "Level:",
    "User:",
    "Computer:",
    "Event[",
];

fn wevtutil(args: &[&str]) -> Result<String, String> {
    let out = Command::new("wevtutil")
        .args(args)
        .creation_flags(0x0800_0000)
        .output()
        .map_err(|e| format!("wevtutil did not run: {e}"))?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    if out.status.success() {
        Ok(text)
    } else {
        Err(format!(
            "wevtutil {args:?}: {text} {}",
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}

/// Turn the channel on (the scheduler's operational log is off by default) and say how that went.
pub fn enable(label: &str, channel: &Channel) {
    let outcome = wevtutil(&["sl", channel.name, "/e:true"]);
    fact(
        label,
        &format!("evlog.enable.{}", channel.name),
        outcome.map_or_else(|e| format!("ERROR {e}"), |_| "enabled".into()),
    );
}

/// Audit logons, successes and failures, so the Security log says why one failed.
pub fn enable_logon_audit(label: &str) {
    let outcome = Command::new("auditpol")
        .args(["/set", "/subcategory:Logon", "/success:enable", "/failure:enable"])
        .creation_flags(0x0800_0000)
        .output();
    fact(
        label,
        "evlog.enable.logon_audit",
        match outcome {
            Ok(out) => format!(
                "exit {:?} {}",
                out.status.code(),
                String::from_utf8_lossy(&out.stdout).trim()
            ),
            Err(e) => format!("auditpol did not run: {e}"),
        },
    );
}

/// The highest record id in the channel now (0 if it is empty): records after it are "new".
pub fn mark(channel: &Channel) -> u64 {
    let Ok(text) = wevtutil(&["qe", channel.name, "/c:1", "/rd:true", "/f:xml"]) else {
        return 0;
    };
    text.split("<EventRecordID>")
        .nth(1)
        .and_then(|rest| rest.split("</EventRecordID>").next())
        .and_then(|id| id.trim().parse().ok())
        .unwrap_or(0)
}

/// Print the records added to the channel after `mark`, as facts `evlog.<channel>.<nn>`.
pub fn dump_since(label: &str, channel: &Channel, mark: u64) {
    let condition = match channel.system_condition {
        Some(extra) => format!("*[System[(EventRecordID>{mark}) and ({extra})]]"),
        None => format!("*[System[(EventRecordID>{mark})]]"),
    };
    let query = format!("/q:{condition}");
    let text = match wevtutil(&["qe", channel.name, &query, "/f:text"]) {
        Ok(text) => text,
        Err(e) => {
            fact(label, &format!("evlog.{}", channel.name), format!("ERROR {e}"));
            return;
        }
    };
    let mut shown = 0usize;
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let wanted = if channel.keep.is_empty() {
            !BOILERPLATE.iter().any(|b| line.starts_with(b))
        } else {
            channel.keep.iter().any(|k| line.starts_with(k))
        };
        if wanted {
            fact(label, &format!("evlog.{}.{shown:03}", channel.name), line);
            shown += 1;
        }
    }
    fact(
        label,
        &format!("evlog.{}.lines", channel.name),
        format!("{shown} lines in the records after id {mark}"),
    );
}
