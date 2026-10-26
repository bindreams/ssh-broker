//! Unit tests for `password_entry` (pure; runs on the host).
use super::*;

const VK_RETURN: u16 = 0x0D;
const VK_BACK: u16 = 0x08;
const LEFT_CTRL: u32 = 0x0008;
const LEFT_ALT: u32 = 0x0002;

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
fn key_up_is_ignored() {
    let mut e = PasswordEntry::new();
    assert!(matches!(e.key(&event(0x41, 0x61, false, 0)), Step::Continue));
    type_str(&mut e, "b");
    let p = submitted(e.key(&enter()));
    assert_eq!(p.as_wide(), [0x62]);
}

/// What a console shows for a character typed as UTF-8 that has no key of its own (measured on a
/// pseudoconsole, build 26100): the unit is on the key-UP record of Alt, as for Alt+numpad entry; the
/// key-down of Alt carries no character.
fn alt_delivery(unit: u16) -> [KeyEvent; 2] {
    const VK_MENU: u16 = 0x12;
    [event(VK_MENU, 0, true, LEFT_ALT), event(VK_MENU, unit, false, 0)]
}

#[test]
fn a_character_delivered_on_the_alt_key_up_is_typed() {
    let mut e = PasswordEntry::new();
    type_str(&mut e, "Pw-");
    for unit in "\u{1F600}".encode_utf16() {
        for k in alt_delivery(unit) {
            assert!(matches!(e.key(&k), Step::Continue));
        }
    }
    type_str(&mut e, "-x");
    let expect: Vec<u16> = "Pw-\u{1F600}-x".encode_utf16().collect();
    assert_eq!(submitted(e.key(&enter())).as_wide(), expect.as_slice());
}

#[test]
fn an_alt_key_up_without_a_character_adds_nothing() {
    let mut e = PasswordEntry::new();
    for k in alt_delivery(0) {
        assert!(matches!(e.key(&k), Step::Continue));
    }
    assert!(matches!(e.key(&enter()), Step::Empty));
}

#[test]
fn the_key_up_of_an_ordinary_key_with_a_character_is_not_typed_twice() {
    let mut e = PasswordEntry::new();
    e.key(&event(0x50, 0x50, true, 0));
    e.key(&event(0x50, 0x50, false, 0));
    assert_eq!(submitted(e.key(&enter())).as_wide(), [0x50]);
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
fn enter_key_up_does_not_submit() {
    let mut e = PasswordEntry::new();
    type_str(&mut e, "x");
    assert!(matches!(e.key(&event(VK_RETURN, 0x0D, false, 0)), Step::Continue));
}

#[test]
fn a_line_feed_record_is_a_control_character_and_ignored() {
    let mut e = PasswordEntry::new();
    type_str(&mut e, "x");
    assert!(matches!(
        e.key(&event(VK_RETURN, 0x0A, true, LEFT_CTRL)),
        Step::Continue
    ));
    assert_eq!(submitted(e.key(&enter())).as_wide(), [0x78]);
}

#[test]
fn ctrl_c_and_ctrl_d_characters_cancel_at_any_point() {
    for ch in [0x03u16, 0x04] {
        let mut e = PasswordEntry::new();
        assert!(matches!(e.key(&event(0x43, ch, true, LEFT_CTRL)), Step::Cancel));
        let mut e = PasswordEntry::new();
        type_str(&mut e, "partial");
        assert!(matches!(e.key(&event(0x43, ch, true, LEFT_CTRL)), Step::Cancel));
    }
}

#[test]
fn ctrl_c_and_ctrl_d_virtual_keys_without_a_character_cancel() {
    for vk in [0x43u16, 0x44] {
        for cks in [LEFT_CTRL, 0x0004] {
            let mut e = PasswordEntry::new();
            type_str(&mut e, "partial");
            assert!(matches!(e.key(&event(vk, 0, true, cks)), Step::Cancel));
        }
    }
}

#[test]
fn a_plain_c_or_d_is_a_character_not_a_cancel() {
    let mut e = PasswordEntry::new();
    assert!(matches!(e.key(&event(0x43, 0x63, true, 0)), Step::Continue));
    assert!(matches!(e.key(&event(0x44, 0x44, true, 0x0010)), Step::Continue));
    assert_eq!(submitted(e.key(&enter())).as_wide(), [0x63, 0x44]);
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
fn other_control_characters_are_ignored() {
    let mut e = PasswordEntry::new();
    for ch in [0x01u16, 0x09, 0x1B, 0x1F] {
        assert!(matches!(e.key(&event(0x20, ch, true, 0)), Step::Continue));
    }
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

#[test]
fn alt_modified_keys_with_no_character_add_nothing() {
    let mut e = PasswordEntry::new();
    assert!(matches!(e.key(&event(0x41, 0, true, LEFT_ALT)), Step::Continue));
    assert!(matches!(e.key(&event(0x70, 0, true, 0)), Step::Continue)); // F1
    assert!(matches!(e.key(&enter()), Step::Empty));
}

#[test]
fn cancel_leaves_the_entry_backing_zero() {
    let mut e = PasswordEntry::new();
    type_str(&mut e, "secret");
    assert!(e.backing().iter().any(|&u| u != 0));
    e.key(&event(0x43, 0x03, true, LEFT_CTRL));
    assert!(e.backing().iter().all(|&u| u == 0));
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
