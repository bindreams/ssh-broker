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

// ── mouse → SGR (1006) ─────────────────────────────────────────────────────────────

// Windows MOUSE_EVENT_RECORD constants used by the tests.
const LEFT: u32 = 0x0001; // FROM_LEFT_1ST_BUTTON_PRESSED
const RIGHT: u32 = 0x0002; // RIGHTMOST_BUTTON_PRESSED
const MIDDLE: u32 = 0x0004; // FROM_LEFT_2ND_BUTTON_PRESSED
const MOUSE_MOVED: u32 = 0x0001;
const MOUSE_WHEELED: u32 = 0x0004;

fn mev(x: i16, y: i16, buttons: u32, flags: u32, cks: u32) -> MouseEvent {
    MouseEvent { x, y, button_state: buttons, control_key_state: cks, event_flags: flags }
}

#[test]
fn mouse_left_press_then_release() {
    let mut enc = MouseEncoder::default();
    // Press left at (0,0): SGR button 0, coords 1-based, press = 'M'.
    assert_eq!(enc.encode_sgr(&mev(0, 0, LEFT, 0, 0)), b"\x1b[<0;1;1M");
    // Release (button cleared) at the same cell: same button code, release = 'm'.
    assert_eq!(enc.encode_sgr(&mev(0, 0, 0, 0, 0)), b"\x1b[<0;1;1m");
}

#[test]
fn mouse_right_and_middle_button_codes() {
    let mut enc = MouseEncoder::default();
    assert_eq!(enc.encode_sgr(&mev(9, 4, RIGHT, 0, 0)), b"\x1b[<2;10;5M");
    let mut enc2 = MouseEncoder::default();
    assert_eq!(enc2.encode_sgr(&mev(0, 0, MIDDLE, 0, 0)), b"\x1b[<1;1;1M");
}

#[test]
fn mouse_wheel_up_and_down() {
    let mut enc = MouseEncoder::default();
    // Wheel delta is the signed high word of dwButtonState.
    let up = mev(2, 3, (120u32) << 16, MOUSE_WHEELED, 0);
    assert_eq!(enc.encode_sgr(&up), b"\x1b[<64;3;4M");
    let down = mev(2, 3, ((-120i16) as u16 as u32) << 16, MOUSE_WHEELED, 0);
    assert_eq!(enc.encode_sgr(&down), b"\x1b[<65;3;4M");
}

#[test]
fn mouse_drag_sets_motion_bit() {
    let mut enc = MouseEncoder::default();
    enc.encode_sgr(&mev(0, 0, LEFT, 0, 0)); // press left
    // Move while left held → motion flag (+32) with the held button (left=0) → 32.
    assert_eq!(enc.encode_sgr(&mev(1, 0, LEFT, MOUSE_MOVED, 0)), b"\x1b[<32;2;1M");
}

#[test]
fn mouse_bare_motion_uses_button_3() {
    let mut enc = MouseEncoder::default();
    // Move with no button held → 32 + 3 = 35.
    assert_eq!(enc.encode_sgr(&mev(4, 4, 0, MOUSE_MOVED, 0)), b"\x1b[<35;5;5M");
}

#[test]
fn mouse_reset_drops_held_state() {
    let mut enc = MouseEncoder::default();
    enc.encode_sgr(&mev(0, 0, LEFT, 0, 0)); // press left → prev_buttons records LEFT
    enc.reset(); // gated-off period: forget the held button
    // A release event now diffs against a clean state → no spurious 'm'.
    assert_eq!(enc.encode_sgr(&mev(0, 0, 0, 0, 0)), b"");
    // A fresh press after reset still encodes correctly.
    assert_eq!(enc.encode_sgr(&mev(0, 0, LEFT, 0, 0)), b"\x1b[<0;1;1M");
}

#[test]
fn mouse_modifiers_are_added_to_button_code() {
    const SHIFT_PRESSED: u32 = 0x0010;
    const LEFT_CTRL_PRESSED: u32 = 0x0008;
    let mut enc = MouseEncoder::default();
    // ctrl(+16) + shift(+4) + left(0) = 20.
    let e = mev(0, 0, LEFT, 0, SHIFT_PRESSED | LEFT_CTRL_PRESSED);
    assert_eq!(enc.encode_sgr(&e), b"\x1b[<20;1;1M");
}
