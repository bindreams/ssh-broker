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

// ── mouse → SGR (1006) ─────────────────────────────────────────────────────────────

/// A mouse event, mirroring the console `MOUSE_EVENT_RECORD` fields we use. `x`/`y` are
/// 0-based console cells (as Windows reports them); SGR output is 1-based.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MouseEvent {
    pub x: i16,
    pub y: i16,
    /// `dwButtonState`: low word = buttons currently down; high word = wheel delta.
    pub button_state: u32,
    pub control_key_state: u32,
    pub event_flags: u32,
}

// dwEventFlags
const MOUSE_MOVED: u32 = 0x0001;
const MOUSE_WHEELED: u32 = 0x0004;
const MOUSE_HWHEELED: u32 = 0x0008;
// dwButtonState (low word) — Windows orders these left, right, middle, x1, x2.
const BTN_LEFT: u32 = 0x0001;
const BTN_RIGHT: u32 = 0x0002;
const BTN_MIDDLE: u32 = 0x0004;
const BTN_X1: u32 = 0x0008;
const BTN_X2: u32 = 0x0010;
// dwControlKeyState
const SHIFT_PRESSED: u32 = 0x0010;
const ALT_PRESSED: u32 = 0x0001 | 0x0002; // RIGHT_ALT | LEFT_ALT
const CTRL_PRESSED: u32 = 0x0004 | 0x0008; // RIGHT_CTRL | LEFT_CTRL

/// Encodes console mouse events as SGR (1006) mouse reports. Stateful: Windows reports the
/// set of buttons currently held, but SGR needs press/release *transitions*, so the previous
/// button set is tracked to diff against.
#[derive(Default)]
pub struct MouseEncoder {
    prev_buttons: u32,
}

impl MouseEncoder {
    /// Forget the tracked button state. The shim calls this while mouse forwarding is gated
    /// off, so that when the shell re-enables tracking the next event is diffed against a
    /// clean state — no spurious release for a button that was held across the enable
    /// boundary (whose press was never forwarded).
    pub fn reset(&mut self) {
        self.prev_buttons = 0;
    }

    /// Encode one console mouse event as zero or more SGR reports
    /// (`ESC [ < Cb ; Cx ; Cy (M|m)`; `M` = press/motion/wheel, `m` = release). Returns
    /// empty when the event carries no reportable change.
    pub fn encode_sgr(&mut self, e: &MouseEvent) -> Vec<u8> {
        let cx = (i32::from(e.x) + 1).max(1);
        let cy = (i32::from(e.y) + 1).max(1);
        let mods = sgr_modifiers(e.control_key_state);

        if e.event_flags & (MOUSE_WHEELED | MOUSE_HWHEELED) != 0 {
            // Wheel delta is the signed high word; it does not change button state.
            let delta = (e.button_state >> 16) as u16 as i16;
            let base = if e.event_flags & MOUSE_HWHEELED != 0 {
                if delta > 0 { 66 } else { 67 }
            } else if delta > 0 {
                64
            } else {
                65
            };
            return sgr_report(base + mods, cx, cy, true);
        }

        if e.event_flags & MOUSE_MOVED != 0 {
            // Motion: +32, carrying the held button (or 3 when none is held).
            let btn = held_button(e.button_state).unwrap_or(3);
            return sgr_report(btn + 32 + mods, cx, cy, true);
        }

        // Otherwise a button press/release: diff against the previously-held set so each
        // changed button emits its own report (press = 'M', release = 'm').
        let changed = e.button_state ^ self.prev_buttons;
        self.prev_buttons = e.button_state;
        let mut out = Vec::new();
        for (mask, code) in [
            (BTN_LEFT, 0),
            (BTN_MIDDLE, 1),
            (BTN_RIGHT, 2),
            (BTN_X1, 128),
            (BTN_X2, 129),
        ] {
            if changed & mask != 0 {
                let pressed = e.button_state & mask != 0;
                out.extend(sgr_report(code + mods, cx, cy, pressed));
            }
        }
        out
    }
}

/// SGR modifier bits: shift +4, alt(meta) +8, ctrl +16.
fn sgr_modifiers(cks: u32) -> i32 {
    let mut m = 0;
    if cks & SHIFT_PRESSED != 0 {
        m += 4;
    }
    if cks & ALT_PRESSED != 0 {
        m += 8;
    }
    if cks & CTRL_PRESSED != 0 {
        m += 16;
    }
    m
}

/// The SGR button code of the lowest-numbered held button, if any (for drag reports).
fn held_button(buttons: u32) -> Option<i32> {
    if buttons & BTN_LEFT != 0 {
        Some(0)
    } else if buttons & BTN_MIDDLE != 0 {
        Some(1)
    } else if buttons & BTN_RIGHT != 0 {
        Some(2)
    } else {
        None
    }
}

/// Format one SGR report. `press` selects the final byte: `M` (press/motion/wheel) or
/// `m` (release).
fn sgr_report(cb: i32, cx: i32, cy: i32, press: bool) -> Vec<u8> {
    format!("\x1b[<{};{};{}{}", cb, cx, cy, if press { 'M' } else { 'm' }).into_bytes()
}

#[cfg(test)]
#[path = "vtinput_tests.rs"]
mod vtinput_tests;
