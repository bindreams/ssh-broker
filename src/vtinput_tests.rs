//! Unit tests for the `vtinput` module (pure; runs on the host).
use super::*;

fn key(vk: u16, sc: u16, uc: u16, down: bool, cks: u32) -> KeyEvent {
    KeyEvent {
        virtual_key_code: vk,
        virtual_scan_code: sc,
        unicode_char: uc,
        key_down: down,
        control_key_state: cks,
        repeat_count: 1,
    }
}

#[test]
fn encodes_a_plain_letter_keydown() {
    // 'a' down: vk=0x41, sc=0x1E, uc=0x61, Kd=1, Cs=0, Rc=1
    let k = key(0x41, 0x1E, 0x61, true, 0);
    assert_eq!(encode_key_event(&k), b"\x1b[65;30;97;1;0;1_");
}

#[test]
fn forwards_key_up_with_kd_zero() {
    // Same key released: Kd field must be 0 (the full edge stream is forwarded).
    let k = key(0x41, 0x1E, 0x61, false, 0);
    assert_eq!(encode_key_event(&k), b"\x1b[65;30;97;0;0;1_");
}

#[test]
fn encodes_ctrl_c() {
    // Ctrl+C arrives as a KEY record: vk=0x43('C'), uc=0x03, Cs=LEFT_CTRL_PRESSED(0x8).
    let k = key(0x43, 0x2E, 0x03, true, 0x0008);
    assert_eq!(encode_key_event(&k), b"\x1b[67;46;3;1;8;1_");
}

#[test]
fn encodes_repeat_count() {
    let mut k = key(0x41, 0x1E, 0x61, true, 0);
    k.repeat_count = 5;
    assert_eq!(encode_key_event(&k), b"\x1b[65;30;97;1;0;5_");
}

#[test]
fn win_size_computes_inclusive_dimensions() {
    assert_eq!(win_size(0, 0, 119, 39), (120, 40));
    assert_eq!(win_size(10, 5, 89, 29), (80, 25));
}

#[test]
fn win_size_clamps_to_at_least_one() {
    assert_eq!(win_size(5, 5, 5, 5), (1, 1)); // single cell
    assert_eq!(win_size(0, 0, -5, -5), (1, 1)); // degenerate/negative
}
