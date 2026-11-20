//! Unit tests for `password_entry` (pure; runs on the host).
use super::*;

const VK_RETURN: u16 = 0x0D;
const VK_BACK: u16 = 0x08;
const LEFT_CTRL: u32 = 0x0008;

fn event(vk: u16, ch: u16, down: bool, cks: u32) -> KeyEvent {
    KeyEvent {
        virtual_key_code: vk,
        virtual_scan_code: 0,
        unicode_char: ch,
        key_down: down,
        control_key_state: cks,
        repeat_count: 1,
    }
}

fn typed(ch: u16) -> KeyEvent {
    event(0x41, ch, true, 0)
}

fn type_str(entry: &mut PasswordEntry, text: &str) {
    for unit in text.encode_utf16() {
        assert!(matches!(entry.key(&typed(unit)), Step::Continue));
    }
}

fn enter() -> KeyEvent {
    event(VK_RETURN, 0x0D, true, 0)
}

fn submitted(step: Step) -> Password {
    match step {
        Step::Submit(p) => p,
        _ => panic!("expected Submit"),
    }
}

#[test]
fn enter_submits_what_was_typed() {
    let mut e = PasswordEntry::new();
    type_str(&mut e, "abc");
    assert_eq!(submitted(e.key(&enter())).as_wide(), [0x61, 0x62, 0x63]);
}

#[test]
fn enter_on_nothing_is_empty_and_the_entry_stays_usable() {
    let mut e = PasswordEntry::new();
    assert!(matches!(e.key(&enter()), Step::Empty));
    assert!(matches!(e.key(&enter()), Step::Empty));
    type_str(&mut e, "x");
    assert_eq!(submitted(e.key(&enter())).as_wide(), [0x78]);
}

#[test]
fn backspace_removes_one_scalar_value() {
    let mut e = PasswordEntry::new();
    type_str(&mut e, "ab");
    assert!(matches!(e.key(&event(VK_BACK, 0x08, true, 0)), Step::Continue));
    assert_eq!(submitted(e.key(&enter())).as_wide(), [0x61]);
}

#[test]
fn backspace_over_a_surrogate_pair_removes_both_units() {
    let mut e = PasswordEntry::new();
    type_str(&mut e, "a\u{1F600}");
    e.key(&event(VK_BACK, 0x08, true, 0));
    assert_eq!(submitted(e.key(&enter())).as_wide(), [0x61]);
}

#[test]
fn backspace_on_nothing_does_nothing() {
    let mut e = PasswordEntry::new();
    assert!(matches!(e.key(&event(VK_BACK, 0x08, true, 0)), Step::Continue));
    assert!(matches!(e.key(&enter()), Step::Empty));
}

#[test]
fn a_surrogate_pair_in_separate_records_is_one_character() {
    let mut e = PasswordEntry::new();
    e.key(&typed(0xD83D));
    e.key(&typed(0xDE00));
    e.key(&event(VK_BACK, 0x08, true, 0));
    assert!(matches!(e.key(&enter()), Step::Empty));
}

#[test]
fn repeat_count_repeats_the_character() {
    let mut e = PasswordEntry::new();
    let mut k = typed(0x61);
    k.repeat_count = 3;
    e.key(&k);
    assert_eq!(submitted(e.key(&enter())).as_wide(), [0x61; 3]);
}

/// The console merges a repeated key-down into one record and raises its count: Backspace over `n` of them pops `n`
/// scalar values, as `n` records would.
#[test]
fn backspace_pops_as_many_scalar_values_as_it_repeats() {
    let mut e = PasswordEntry::new();
    type_str(&mut e, "a\u{1F600}\u{1F600}");
    let mut k = event(VK_BACK, 0x08, true, 0);
    k.repeat_count = 2;
    e.key(&k);
    assert_eq!(submitted(e.key(&enter())).as_wide(), [0x61]);
}

/// Ctrl+C on a partly typed password is the cancel step, and the text is wiped.
#[test]
fn cancel_leaves_the_entry_backing_zero() {
    let mut e = PasswordEntry::new();
    type_str(&mut e, "secret");
    assert!(e.backing().iter().any(|&u| u != 0));
    assert!(matches!(e.key(&event(0x43, 0x03, true, LEFT_CTRL)), Step::Cancel));
    assert!(e.backing().iter().all(|&u| u == 0));
}

/// A key that is no text (a key-up, Shift) adds nothing, and the Enter after it submits what was typed before it.
#[test]
fn a_key_that_is_no_text_adds_nothing_to_the_password() {
    let mut e = PasswordEntry::new();
    type_str(&mut e, "ab");
    assert!(
        matches!(e.key(&event(0x41, 0x62, false, 0)), Step::Continue),
        "a key-up"
    );
    assert!(matches!(e.key(&event(0x10, 0, true, 0)), Step::Continue), "Shift");
    assert_eq!(submitted(e.key(&enter())).as_wide(), [0x61, 0x62]);
}

/// A character outside the BMP typed as UTF-8 reaches the console on two key-ups of Alt, one per unit: it is one
/// character of the password, which one Backspace removes whole.
#[test]
fn a_character_outside_the_bmp_on_two_alt_key_ups_is_one_character_of_the_password() {
    const VK_MENU: u16 = 0x12;
    let units: Vec<u16> = "\u{1F600}".encode_utf16().collect();
    assert_eq!(units.len(), 2);
    let mut e = PasswordEntry::new();
    for &unit in &units {
        assert!(matches!(e.key(&event(VK_MENU, unit, false, 0)), Step::Continue));
    }
    let mut erased = PasswordEntry::new();
    for &unit in &units {
        erased.key(&event(VK_MENU, unit, false, 0));
    }
    erased.key(&event(VK_BACK, 0x08, true, 0));
    assert!(
        matches!(erased.key(&enter()), Step::Empty),
        "one Backspace removes both units"
    );
    assert_eq!(submitted(e.key(&enter())).as_wide(), units.as_slice());
}

#[test]
fn submit_moves_the_text_out_and_leaves_the_entry_backing_zero() {
    let mut e = PasswordEntry::new();
    type_str(&mut e, "secret");
    let p = submitted(e.key(&enter()));
    assert_eq!(p.as_wide().len(), 6);
    assert!(e.backing().iter().all(|&u| u == 0));
}

#[test]
fn long_and_non_bmp_password_round_trips_exactly() {
    let text: String = "\u{1F600}".to_string() + &"x".repeat(298);
    let expect: Vec<u16> = text.encode_utf16().collect();
    assert_eq!(expect.len(), 300);
    let mut e = PasswordEntry::new();
    type_str(&mut e, &text);
    assert_eq!(submitted(e.key(&enter())).as_wide(), expect.as_slice());
}

#[test]
fn password_with_nul_appends_one_nul() {
    let mut e = PasswordEntry::new();
    type_str(&mut e, "ab");
    let p = submitted(e.key(&enter()));
    assert_eq!(p.with_nul(|u| u.to_vec()), [0x61, 0x62, 0]);
}

#[test]
fn debug_output_contains_no_password_text() {
    let mut e = PasswordEntry::new();
    type_str(&mut e, "hunter2-sentinel");
    let shown_entry = format!("{e:?}");
    let p = submitted(e.key(&enter()));
    let shown = format!("{p:?} {shown_entry}");
    assert!(!shown.contains("hunter2"), "{shown}");
}
