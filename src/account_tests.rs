//! Unit tests for `account`: the pure parts, and the process's own token (read-only, no machine state).
use super::*;
use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows::core::PCWSTR;

#[test]
fn classify_same_name_is_local() {
    assert_eq!(classify("DESKTOP-1", "DESKTOP-1"), AccountKind::Local);
}

#[test]
fn classify_ignores_case() {
    assert_eq!(classify("desktop-1", "DESKTOP-1"), AccountKind::Local);
    assert_eq!(classify("ÄRZTE-PC", "ärzte-pc"), AccountKind::Local);
}

#[test]
fn classify_another_domain_is_not_local() {
    assert_eq!(classify("CORP", "DESKTOP-1"), AccountKind::NotLocal);
    assert_eq!(classify("NT AUTHORITY", "DESKTOP-1"), AccountKind::NotLocal);
}

#[test]
fn classify_an_empty_domain_is_not_local() {
    assert_eq!(classify("", "DESKTOP-1"), AccountKind::NotLocal);
    assert_eq!(classify("", ""), AccountKind::NotLocal);
}

#[test]
fn an_account_without_the_administrators_group_is_standard_at_every_level() {
    for rid in [INTEGRITY_LOW, INTEGRITY_MEDIUM, INTEGRITY_HIGH] {
        assert_eq!(classify_elevation(AdministratorsSid::Absent, rid), Elevation::Standard);
    }
}

#[test]
fn enabled_administrators_at_high_or_above_is_full() {
    assert_eq!(
        classify_elevation(AdministratorsSid::Enabled, INTEGRITY_HIGH),
        Elevation::Full
    );
    assert_eq!(
        classify_elevation(AdministratorsSid::Enabled, INTEGRITY_SYSTEM),
        Elevation::Full
    );
}

#[test]
fn enabled_administrators_below_high_is_filtered() {
    assert_eq!(
        classify_elevation(AdministratorsSid::Enabled, INTEGRITY_MEDIUM),
        Elevation::Filtered
    );
    assert_eq!(
        classify_elevation(AdministratorsSid::Enabled, INTEGRITY_LOW),
        Elevation::Filtered
    );
}

#[test]
fn deny_only_administrators_is_filtered_at_every_level() {
    for rid in [INTEGRITY_LOW, INTEGRITY_MEDIUM, INTEGRITY_HIGH] {
        assert_eq!(
            classify_elevation(AdministratorsSid::DenyOnly, rid),
            Elevation::Filtered
        );
    }
}

/// The rows of `whoami /groups`, which reads the token through another path and so is an
/// independent source: group name, type, SID and attributes, each a quoted field.
fn whoami_groups() -> Vec<Vec<String>> {
    use std::os::windows::process::CommandExt;
    let out = std::process::Command::new("whoami")
        .args(["/groups", "/fo", "csv", "/nh"])
        .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
        .output()
        .unwrap();
    assert!(out.status.success(), "whoami failed: {out:?}");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            line.trim()
                .strip_prefix('"')
                .and_then(|line| line.strip_suffix('"'))
                .unwrap_or_else(|| panic!("a whoami row that is not quoted: {line}"))
                .split("\",\"")
                .map(str::to_owned)
                .collect()
        })
        .collect()
}

#[test]
fn this_process_reads_as_whoami_reports_it() {
    let rows = whoami_groups();
    let sid_of = |row: &Vec<String>| row.get(2).cloned().unwrap_or_default();
    // The attributes are comma-separated phrases; a localised host spells them differently.
    let attributes_of = |row: &Vec<String>| -> Vec<String> {
        row.get(3)
            .map(|text| text.split(", ").map(str::to_owned).collect())
            .unwrap_or_default()
    };

    let administrators = match rows.iter().find(|row| sid_of(row) == "S-1-5-32-544") {
        None => AdministratorsSid::Absent,
        Some(row) => {
            let attributes = attributes_of(row);
            let has = |phrase: &str| attributes.iter().any(|attribute| attribute == phrase);
            if has("Group used for deny only") {
                AdministratorsSid::DenyOnly
            } else if has("Enabled group") {
                AdministratorsSid::Enabled
            } else {
                panic!(
                    "whoami's attributes of Administrators are neither enabled nor deny-only, or are localised: {row:?}"
                )
            }
        }
    };
    let label = rows
        .iter()
        .find(|row| sid_of(row).starts_with("S-1-16-"))
        .unwrap_or_else(|| panic!("whoami lists no mandatory label: {rows:?}"));
    let integrity: u32 = sid_of(label).rsplit('-').next().unwrap().parse().unwrap();

    let token = own_token().unwrap();
    assert_eq!(administrators_of(token.0).unwrap(), administrators, "whoami: {rows:?}");
    assert_eq!(integrity_of(token.0).unwrap(), integrity, "whoami: {rows:?}");
    let expected = classify_elevation(administrators, integrity);
    assert_eq!(elevation().unwrap(), expected, "whoami: {rows:?}");
    assert_eq!(elevation_of(token.0).unwrap(), expected, "whoami: {rows:?}");
}

#[test]
fn a_process_has_an_integrity_level_of_a_mandatory_label() {
    let rid = integrity_of(own_token().unwrap().0).unwrap();
    assert!((INTEGRITY_LOW..=INTEGRITY_SYSTEM).contains(&rid), "{rid:#x}");
}

/// A SID built from its text, freed when dropped.
struct TextSid(windows::Win32::Security::PSID);

impl TextSid {
    fn new(text: &str) -> TextSid {
        let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
        let mut sid = windows::Win32::Security::PSID::default();
        // SAFETY: `wide` is NUL-terminated and `sid` a valid out-pointer.
        unsafe { ConvertStringSidToSidW(PCWSTR(wide.as_ptr()), &mut sid) }.unwrap();
        TextSid(sid)
    }
}

impl Drop for TextSid {
    fn drop(&mut self) {
        // SAFETY: the SID was allocated by `ConvertStringSidToSidW`.
        let _ = unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
    }
}

#[test]
fn a_label_without_a_sid_is_an_error() {
    let err = rid_of_label(windows::Win32::Security::PSID::default()).unwrap_err();
    assert!(err.to_string().contains("no SID"), "{err:#}");
}

#[test]
fn the_level_of_a_label_is_its_last_sub_authority() {
    let medium = TextSid::new("S-1-16-8192");
    assert_eq!(rid_of_label(medium.0).unwrap(), INTEGRITY_MEDIUM);
}
