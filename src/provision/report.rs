//! provision::report — verify's human-readable report + exit-code policy (pure).

pub struct Check {
    pub name: &'static str,
    pub pass: bool,
    pub detail: String,
}

impl Check {
    pub fn new(name: &'static str, pass: bool, detail: impl Into<String>) -> Check {
        Check { name, pass, detail: detail.into() }
    }
}

/// Render an aligned PASS/FAIL table.
pub fn format_report(rows: &[Check]) -> String {
    rows.iter()
        .map(|r| {
            format!(
                "[{}] {:<28} {}",
                if r.pass { "PASS" } else { "FAIL" },
                r.name,
                r.detail
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// 0 iff there is at least one check and every check passed; otherwise 1. Empty is
/// fail-closed (an empty report must never read as success).
pub fn verify_exit_code(rows: &[Check]) -> i32 {
    if !rows.is_empty() && rows.iter().all(|r| r.pass) {
        0
    } else {
        1
    }
}

#[cfg(test)]
#[path = "report_tests.rs"]
mod report_tests;
