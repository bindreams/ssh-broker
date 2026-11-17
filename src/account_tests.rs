//! Unit tests for `account`: the pure parts, and the process's own token (read-only, no machine state).
use super::*;
use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows::Win32::Security::{
    CREATE_RESTRICTED_TOKEN_FLAGS, CheckTokenMembership, CreateRestrictedToken, SID_AND_ATTRIBUTES,
};
use windows::core::PCWSTR;

use crate::test_support::{own_token_at, own_token_copy};
use crate::winutil::OwnedHandle;

const ADMINISTRATORS: &str = "S-1-5-32-544";

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

/// The rows of `whoami /groups`: group name, type, SID and attributes, each a quoted field. Only the
/// SID column is read: the attribute text is localised.
fn whoami_groups() -> Vec<Vec<String>> {
    crate::test_support::whoami_csv("/groups")
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

/// Whether `CheckTokenMembership` finds `sid` in the calling process's token: true only when it is
/// present and enabled, which whoami's SID column cannot say.
fn is_enabled_member(sid: &TextSid) -> bool {
    let mut member = windows::core::BOOL::default();
    // SAFETY: `sid` is a valid SID and `member` a valid out-pointer.
    unsafe { CheckTokenMembership(None, sid.0, &mut member) }.unwrap();
    member.as_bool()
}

/// Whether a row of `rows` (from [`whoami_groups`]) has `sid` in its SID column.
fn lists(rows: &[Vec<String>], sid: &str) -> bool {
    rows.iter().any(|row| row.get(2).map(String::as_str) == Some(sid))
}

#[test]
fn this_process_reads_as_whoami_reports_it() {
    let rows = whoami_groups();
    let sid_of = |row: &Vec<String>| row.get(2).cloned().unwrap_or_default();

    // Present or not from whoami's SID column; enabled or not from the system's own check.
    let present = lists(&rows, ADMINISTRATORS);
    let administrators = match (present, is_enabled_member(&TextSid::new(ADMINISTRATORS))) {
        (false, _) => AdministratorsSid::Absent,
        (true, true) => AdministratorsSid::Enabled,
        (true, false) => AdministratorsSid::DenyOnly,
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

#[test]
fn this_process_has_the_folder_level_of_its_integrity_label() {
    assert_eq!(
        integrity().unwrap(),
        integrity_class(integrity_of(own_token().unwrap().0).unwrap())
    );
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

/// The elevation of a token that is a copy of this process's with at most its label lowered, from
/// whether this process's token lists `Administrators` at all (whoami's SID column, independent of
/// the library): an account that does not is `Standard`, one that does is cut down to `Filtered`.
fn elevation_of_a_cut_down_copy() -> (AdministratorsSid, Elevation) {
    if lists(&whoami_groups(), ADMINISTRATORS) {
        (AdministratorsSid::DenyOnly, Elevation::Filtered)
    } else {
        (AdministratorsSid::Absent, Elevation::Standard)
    }
}

/// On an elevated host (the CI job) the group goes from enabled to deny-only and the level from
/// `Full` to `Filtered`; on an unelevated administrator's host it was deny-only already and stays;
/// on a standard account's host the group is not there, stays absent, and the level is `Standard`.
#[test]
fn a_copy_with_administrators_disabled_reads_as_deny_only_or_stays_absent() {
    let own = own_token_copy();
    let administrators = TextSid::new(ADMINISTRATORS);
    let disable = [SID_AND_ATTRIBUTES {
        Sid: administrators.0,
        Attributes: 0,
    }];
    let (group, level) = elevation_of_a_cut_down_copy();
    // A group the token lacks cannot be disabled in it.
    let disable = (group == AdministratorsSid::DenyOnly).then_some(&disable[..]);
    let mut copy = HANDLE::default();
    // SAFETY: `own` is a valid token, `disable` and `copy` are valid for the call.
    unsafe { CreateRestrictedToken(own.0, CREATE_RESTRICTED_TOKEN_FLAGS(0), disable, None, None, &mut copy) }.unwrap();
    let copy = OwnedHandle(copy);
    assert_eq!(administrators_of(copy.0).unwrap(), group);
    assert_eq!(elevation_of(copy.0).unwrap(), level);
}

/// A copy of this process's token with its integrity label set to Medium. On an elevated host (the CI
/// job) the group is still enabled and the token reads `Filtered`, which only the label can make it;
/// on an unelevated administrator's host the group is deny-only and it reads `Filtered`; on a
/// standard account's host it reads `Standard`. A process below Medium cannot raise a label, and this
/// fails there.
#[test]
fn a_copy_at_medium_integrity_reads_medium_and_is_never_full() {
    let copy = own_token_at(INTEGRITY_MEDIUM);
    assert_eq!(integrity_of(copy.0).unwrap(), INTEGRITY_MEDIUM);
    let (_, level) = elevation_of_a_cut_down_copy();
    assert_eq!(elevation_of(copy.0).unwrap(), level);
}

#[test]
fn the_level_of_a_label_is_its_last_sub_authority() {
    let medium = TextSid::new("S-1-16-8192");
    // SAFETY: `medium` is a valid SID for the length of the call.
    assert_eq!(unsafe { rid_of_label(medium.0) }.unwrap(), INTEGRITY_MEDIUM);
}

#[test]
fn a_label_with_no_sub_authority_is_an_error() {
    // A revision, a count of zero and a six-byte authority: a whole SID of eight bytes.
    let sid = [1u8, 0, 0, 0, 0, 0, 0, 16];
    // SAFETY: `sid` is a whole SID for the length of the call.
    let err = unsafe { rid_of_label(PSID(sid.as_ptr().cast_mut().cast())) }.unwrap_err();
    assert!(err.to_string().contains("no sub-authority"), "{err:#}");
}

// the folder level of an integrity level -----

#[test]
fn the_folder_level_is_high_from_the_high_integrity_level_up_and_medium_below() {
    use crate::socket_loc::Integrity;
    assert_eq!(integrity_class(INTEGRITY_LOW), Integrity::Medium);
    assert_eq!(integrity_class(INTEGRITY_MEDIUM), Integrity::Medium);
    assert_eq!(
        integrity_class(INTEGRITY_MEDIUM + 0xfff),
        Integrity::Medium,
        "just below High"
    );
    assert_eq!(integrity_class(INTEGRITY_HIGH), Integrity::High);
    assert_eq!(integrity_class(INTEGRITY_SYSTEM), Integrity::High);
}

#[test]
fn the_token_of_a_process_handle_is_that_process_s_token() {
    use windows::Win32::System::Threading::GetCurrentProcess;
    // SAFETY: the pseudo-handle of this process is valid for the call.
    let token = crate::winutil::process_token(unsafe { GetCurrentProcess() }).unwrap();
    assert_eq!(
        integrity_of(token.0).unwrap(),
        integrity_of(crate::winutil::own_token().unwrap().0).unwrap()
    );
}
