//! provision::report — doctor's human-readable report + exit-code policy (pure).

use std::path::Path;

pub struct Check {
    pub name: &'static str,
    pub pass: bool,
    pub detail: String,
}

impl Check {
    pub fn new(name: &'static str, pass: bool, detail: impl Into<String>) -> Check {
        Check {
            name,
            pass,
            detail: detail.into(),
        }
    }
}

/// The heading of the report: the version and the path of the executable that ran. A path that cannot be read
/// leaves the version alone. It carries no mark: it judges nothing.
fn heading(version: &str, exe: Option<&Path>) -> String {
    match exe {
        Some(exe) => format!("ssh-broker v{version} ({})", exe.display()),
        None => format!("ssh-broker v{version}"),
    }
}

/// The report: the [heading](heading) of this build (`version` and the path of its `exe`, when it can be read),
/// then an aligned PASS/FAIL table.
pub fn format_report(version: &str, exe: Option<&Path>, rows: &[Check]) -> String {
    std::iter::once(heading(version, exe))
        .chain(
            rows.iter()
                .map(|r| format!("[{}] {:<28} {}", if r.pass { "PASS" } else { "FAIL" }, r.name, r.detail)),
        )
        .collect::<Vec<_>>()
        .join("\n")
}

/// 0 iff there is at least one check and every check passed; otherwise 1. Empty is
/// fail-closed (an empty report must never read as success).
pub fn doctor_exit_code(rows: &[Check]) -> i32 {
    if !rows.is_empty() && rows.iter().all(|r| r.pass) {
        0
    } else {
        1
    }
}

#[cfg(test)]
#[path = "report_tests.rs"]
mod report_tests;
