//! The state machine behind the password prompt: console key events in, one finished step out.
//!
//! Pure and host-testable. The console reader (`console_prompt`) feeds it key records; nothing here
//! echoes, logs or formats the text.

use crate::secret::SecretUnits;
use crate::vtinput::{KeyEntry, KeyEvent, LineKey};

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
    /// entry empty and usable. A character or Backspace acts `repeat_count` times (the console
    /// merges a repeated key-down into one record); Enter and Ctrl+C or Ctrl+D act once.
    pub fn key(&mut self, k: &KeyEvent) -> Step {
        match k.line_key() {
            LineKey::Text { unit, count } => {
                for _ in 0..count {
                    self.text.push(unit);
                }
            }
            LineKey::Erase { count } => {
                for _ in 0..count {
                    self.text.pop_scalar();
                }
            }
            LineKey::Enter => {
                if self.text.as_units().is_empty() {
                    return Step::Empty;
                }
                return Step::Submit(Password(std::mem::take(&mut self.text)));
            }
            LineKey::Cancel => {
                self.text.wipe();
                return Step::Cancel;
            }
            LineKey::Other => {}
        }
        Step::Continue
    }

    /// The whole store, for tests.
    #[doc(hidden)]
    pub fn backing(&self) -> &[u16] {
        self.text.backing()
    }
}

impl KeyEntry for PasswordEntry {
    type Step = Step;

    fn key(&mut self, k: &KeyEvent) -> Step {
        PasswordEntry::key(self, k)
    }

    fn finishes_step(step: &Step) -> bool {
        !matches!(step, Step::Continue)
    }

    /// A password read is never stopped from outside (its callers pass a stop that is never true); if it were, it is
    /// a cancel.
    fn stopped() -> Step {
        Step::Cancel
    }
}

#[cfg(test)]
#[path = "password_entry_tests.rs"]
mod password_entry_tests;
