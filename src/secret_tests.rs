//! Unit tests for `secret` (pure; runs on the host). Only live buffers are inspected: reading a freed
//! buffer is undefined behaviour and can pass by accident, so that the drop path wipes is by
//! construction (`Drop` is `wipe`), not by a test.
use super::*;

fn filled(units: &[u16]) -> SecretUnits {
    let mut s = SecretUnits::new();
    for &u in units {
        s.push(u);
    }
    s
}

#[test]
fn wipe_zeroes_the_whole_backing() {
    let mut s = filled(&[1, 2, 3, 4]);
    assert!(s.backing().iter().any(|&u| u != 0));
    s.wipe();
    assert!(s.backing().iter().all(|&u| u == 0));
    assert!(s.as_units().is_empty());
}

#[test]
fn with_nul_appends_exactly_one_nul_and_leaves_the_store_unchanged() {
    let s = filled(&[7, 8, 9]);
    let seen = s.with_nul(|units| units.to_vec());
    assert_eq!(seen, [7, 8, 9, 0]);
    assert_eq!(s.as_units(), [7, 8, 9]);
}

#[test]
fn with_nul_on_an_empty_store_is_one_nul() {
    assert_eq!(SecretUnits::new().with_nul(|units| units.to_vec()), [0]);
}

#[test]
fn growth_keeps_every_unit() {
    let units: Vec<u16> = (1..=1000).collect();
    let s = filled(&units);
    assert_eq!(s.as_units(), units.as_slice());
}

#[test]
fn the_backing_past_the_length_is_zero() {
    let mut s = filled(&[1, 2, 3]);
    s.pop_scalar();
    assert!(s.backing()[s.as_units().len()..].iter().all(|&u| u == 0));
}

#[test]
fn pop_scalar_removes_a_surrogate_pair_as_one_character() {
    let mut s = filled(&[0x61, 0xD83D, 0xDE00]);
    s.pop_scalar();
    assert_eq!(s.as_units(), [0x61]);
}

#[test]
fn pop_scalar_removes_one_unit_otherwise() {
    let mut s = filled(&[0xDE00, 0x61]);
    s.pop_scalar();
    assert_eq!(s.as_units(), [0xDE00]);
    s.pop_scalar();
    assert!(s.as_units().is_empty());
    s.pop_scalar();
    assert!(s.as_units().is_empty());
}

#[test]
fn debug_output_contains_no_password_text() {
    let s = filled(&"hunter2-sentinel".encode_utf16().collect::<Vec<_>>());
    let shown = format!("{s:?}");
    assert!(!shown.contains("hunter2"), "{shown}");
    assert!(!shown.contains("104"), "{shown}"); // the first unit, as a number
}
