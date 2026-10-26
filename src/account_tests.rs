//! Unit tests for `account` (pure parts; runs on the host).
use super::*;

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
