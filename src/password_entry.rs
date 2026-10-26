//! The state machine behind the password prompt: console key events in, one finished step out.
//!
//! Pure and host-testable. The console reader (`console_prompt`) feeds it key records; nothing here
//! echoes, logs or formats the text.

use crate::secret::SecretUnits;
use crate::vtinput::KeyEvent;

const VK_BACK: u16 = 0x08;
const VK_RETURN: u16 = 0x0D;
const VK_C: u16 = 0x43;
const VK_D: u16 = 0x44;
const CTRL_PRESSED: u32 = 0x0004 | 0x0008; // RIGHT_CTRL | LEFT_CTRL
const ETX: u16 = 0x03; // Ctrl+C as a character
const EOT: u16 = 0x04; // Ctrl+D as a character
const CR: u16 = 0x0D;

/// A finished password. Holds the text until dropped (which wipes it); no `Clone`, and `Debug`
/// shows no content.
pub struct Password(SecretUnits);

impl Password {
    pub fn as_wide(&self) -> &[u16] {
        self.0.as_units()
    }

    /// Call `f` with a NUL-terminated copy that is wiped before this returns.
    pub fn with_nul<R>(&self, f: impl FnOnce(&[u16]) -> R) -> R {
        self.0.with_nul(f)
    }
}

impl std::fmt::Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Password(..)")
    }
}

/// What one key event did.
#[derive(Debug)]
pub enum Step {
    Continue,
    Submit(Password),
    /// Enter with nothing typed.
    Empty,
    Cancel,
}

#[derive(Debug, Default)]
pub struct PasswordEntry {
    text: SecretUnits,
}

impl PasswordEntry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply one key event. `Submit` moves the text out; `Cancel` wipes it. Either leaves the
    /// entry empty and usable.
    pub fn key(&mut self, k: &KeyEvent) -> Step {
        if !k.key_down {
            return Step::Continue;
        }
        let ctrl = k.control_key_state & CTRL_PRESSED != 0;
        let cancel_key = ctrl && k.unicode_char == 0 && matches!(k.virtual_key_code, VK_C | VK_D);
        if matches!(k.unicode_char, ETX | EOT) || cancel_key {
            self.text.wipe();
            return Step::Cancel;
        }
        if k.virtual_key_code == VK_RETURN && matches!(k.unicode_char, 0 | CR) {
            if self.text.as_units().is_empty() {
                return Step::Empty;
            }
            return Step::Submit(Password(std::mem::take(&mut self.text)));
        }
        if k.virtual_key_code == VK_BACK {
            self.text.pop_scalar();
            return Step::Continue;
        }
        if k.unicode_char >= 0x20 {
            for _ in 0..k.repeat_count.max(1) {
                self.text.push(k.unicode_char);
            }
        }
        Step::Continue
    }

    /// The whole store, for tests.
    #[doc(hidden)]
    pub fn backing(&self) -> &[u16] {
        self.text.backing()
    }
}

#[cfg(test)]
#[path = "password_entry_tests.rs"]
mod password_entry_tests;
