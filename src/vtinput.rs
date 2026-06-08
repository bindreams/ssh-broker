//! vtinput: pure win32-input-mode encoding (host-testable, no Windows types).
//!
//! The shim reads console `INPUT_RECORD`s and forwards keystrokes to the agent, which
//! writes them straight into ConPTY#2 (created with `WIN32_INPUT_MODE`). The wire form
//! is the win32-input-mode CSI sequence `ESC [ Vk ; Sc ; Uc ; Kd ; Cs ; Rc _`
//! (microsoft/terminal doc/specs #4999). Modeled with plain integer fields so the
//! encoder and the window-size math are pure and unit-tested off-Windows BEFORE they
//! become the live input path.

/// A keyboard event, mirroring the fields of a console `KEY_EVENT_RECORD` we care about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyEvent {
    pub virtual_key_code: u16,
    pub virtual_scan_code: u16,
    pub unicode_char: u16,
    pub key_down: bool,
    pub control_key_state: u32,
    pub repeat_count: u16,
}

/// Encode a key event as a win32-input-mode CSI sequence. BOTH key-down and key-up are
/// forwarded (WIN32_INPUT_MODE expects the full edge stream; `Kd` carries 1/0).
pub fn encode_key_event(k: &KeyEvent) -> Vec<u8> {
    format!(
        "\x1b[{};{};{};{};{};{}_",
        k.virtual_key_code,
        k.virtual_scan_code,
        k.unicode_char,
        if k.key_down { 1 } else { 0 },
        k.control_key_state,
        k.repeat_count,
    )
    .into_bytes()
}

/// Window size (cols, rows) from a console window rectangle (`srWindow`: inclusive
/// left/top/right/bottom). Uses the visible window, not the buffer (`dwSize`), and clamps
/// each dimension to at least 1.
pub fn win_size(left: i16, top: i16, right: i16, bottom: i16) -> (u16, u16) {
    let cols = (i32::from(right) - i32::from(left) + 1).max(1) as u16;
    let rows = (i32::from(bottom) - i32::from(top) + 1).max(1) as u16;
    (cols, rows)
}

#[cfg(test)]
#[path = "vtinput_tests.rs"]
mod vtinput_tests;
