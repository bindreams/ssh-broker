//! Unit tests for `account`: the pure parts, and the process's own token (read-only, no machine state).
use super::*;
use windows::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TokenElevation};

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

const LOW: u32 = 0x1000;
const MEDIUM: u32 = 0x2000;
const HIGH: u32 = 0x3000;

#[test]
fn an_account_without_the_administrators_group_is_standard_at_every_level() {
    for rid in [LOW, MEDIUM, HIGH] {
        assert_eq!(classify_elevation(AdministratorsSid::Absent, rid), Elevation::Standard);
    }
}

#[test]
fn enabled_administrators_at_high_or_above_is_full() {
    assert_eq!(classify_elevation(AdministratorsSid::Enabled, HIGH), Elevation::Full);
    assert_eq!(classify_elevation(AdministratorsSid::Enabled, 0x4000), Elevation::Full);
}

#[test]
fn enabled_administrators_below_high_is_filtered() {
    assert_eq!(
        classify_elevation(AdministratorsSid::Enabled, MEDIUM),
        Elevation::Filtered
    );
    assert_eq!(classify_elevation(AdministratorsSid::Enabled, LOW), Elevation::Filtered);
}

#[test]
fn deny_only_administrators_is_filtered_at_every_level() {
    for rid in [LOW, MEDIUM, HIGH] {
        assert_eq!(
            classify_elevation(AdministratorsSid::DenyOnly, rid),
            Elevation::Filtered
        );
    }
}

fn token_is_elevated(token: windows::Win32::Foundation::HANDLE) -> bool {
    let mut info = TOKEN_ELEVATION::default();
    let mut len = 0u32;
    // SAFETY: `info` is a `TOKEN_ELEVATION` and the length passed is its size.
    unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut info as *mut _ as *mut core::ffi::c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
    }
    .unwrap();
    info.TokenIsElevated != 0
}

#[test]
fn elevation_of_this_process_is_what_its_integrity_and_administrators_group_say() {
    let token = own_token().unwrap();
    let integrity = integrity_of(token.0).unwrap();
    let administrators = administrators_of(token.0).unwrap();
    assert_eq!(
        elevation().unwrap(),
        classify_elevation(administrators, integrity),
        "integrity {integrity:#x}, administrators {administrators:?}"
    );
    assert_eq!(elevation_of(token.0).unwrap(), elevation().unwrap());
}

#[test]
fn this_process_is_full_exactly_when_windows_calls_its_token_elevated() {
    let token = own_token().unwrap();
    assert_eq!(elevation().unwrap() == Elevation::Full, token_is_elevated(token.0));
}

#[test]
fn a_process_has_an_integrity_level_of_a_mandatory_label() {
    let rid = integrity_of(own_token().unwrap().0).unwrap();
    assert!((LOW..=0x5000).contains(&rid), "{rid:#x}");
}
