//! The state machine behind the consent question: console key events in, the echo of what is typed and one answer
//! out.
//!
//! Pure and host-testable, like [`crate::password_entry`], which it follows in reading keys. The words that allow
//! are given to [`ConsentEntry::new`]; anything else, Enter alone included, refuses, and there is no second
//! question. What is typed is shown, so that the person sees what they answer, but only as far as an answer can
//! still be right (see [`ConsentEntry::new`]).

use crate::vtinput::{KeyEntry, KeyEvent};

const VK_BACK: u16 = 0x08;
const VK_MENU: u16 = 0x12; // Alt
const VK_RETURN: u16 = 0x0D;
const VK_C: u16 = 0x43;
const VK_D: u16 = 0x44;
const CTRL_PRESSED: u32 = 0x0004 | 0x0008; // RIGHT_CTRL | LEFT_CTRL
const ETX: u16 = 0x03; // Ctrl+C as a character
const EOT: u16 = 0x04; // Ctrl+D as a character
const CR: u16 = 0x0D;

/// What the console shows for a character it cannot be sure takes one cell, and for one that is not text.
const SHOWN_INSTEAD: char = '?';
/// Erases the character before the cursor.
const ERASE: &str = "\x08 \x08";

/// What one key event did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsentStep {
    /// Nothing to show: a key that is no text, or a character past what is echoed.
    Continue,
    /// Write this to the console: the character typed, or the erase of one.
    Echo(String),
    /// Enter, after one of the words that allow.
    Allow,
    /// Enter after anything else, Enter alone, Ctrl+C or Ctrl+D.
    Refuse,
    /// The question was stopped from outside before it was answered.
    Stopped,
}

#[derive(Debug)]
pub struct ConsentEntry {
    /// The answers that allow, in lower case.
    accepted: Vec<String>,
    /// How many characters from the start are echoed.
    echo_limit: usize,
    text: Vec<char>,
    /// The first unit of a pair that the next key completes.
    high_surrogate: Option<u16>,
}

impl ConsentEntry {
    /// An entry in which Enter after any of `accepted`, without regard to case and with nothing around it, allows.
    ///
    /// The first characters, as many as the longest of `accepted` has and one more, are echoed; what is typed after
    /// that is part of the answer and is not shown: an answer that long is wrong whatever it goes on to be, and a
    /// line that wraps cannot be erased in every terminal. A character other than printable ASCII is echoed as `?`,
    /// so that one character is always one cell and the erase of it is exact.
    pub fn new(accepted: &[&str]) -> Self {
        let longest = accepted.iter().map(|word| word.chars().count()).max().unwrap_or(0);
        ConsentEntry {
            accepted: accepted.iter().map(|word| word.to_ascii_lowercase()).collect(),
            echo_limit: longest + 1,
            text: Vec::new(),
            high_surrogate: None,
        }
    }

    /// Apply one key event. A character or Backspace acts `repeat_count` times (the console merges a repeated
    /// key-down into one record); Enter and Ctrl+C or Ctrl+D act once.
    pub fn key(&mut self, k: &KeyEvent) -> ConsentStep {
        if !k.key_down {
            // A console delivers a character that has no key of its own (one outside the BMP, typed as UTF-8) on
            // the key-UP record of Alt. Any other key-up repeats its key-down.
            if k.virtual_key_code == VK_MENU {
                return self.type_char(k);
            }
            return ConsentStep::Continue;
        }
        let ctrl = k.control_key_state & CTRL_PRESSED != 0;
        let cancel_key = ctrl && k.unicode_char == 0 && matches!(k.virtual_key_code, VK_C | VK_D);
        if matches!(k.unicode_char, ETX | EOT) || cancel_key {
            return ConsentStep::Refuse;
        }
        if k.virtual_key_code == VK_RETURN && matches!(k.unicode_char, 0 | CR) {
            return self.answer();
        }
        if k.virtual_key_code == VK_BACK {
            return self.erase(k.repeat_count.max(1));
        }
        self.type_char(k)
    }

    fn answer(&self) -> ConsentStep {
        let typed: String = self.text.iter().collect();
        let allowed =
            self.high_surrogate.is_none() && self.accepted.iter().any(|word| typed.eq_ignore_ascii_case(word));
        if allowed {
            ConsentStep::Allow
        } else {
            ConsentStep::Refuse
        }
    }

    /// Add the event's character, as many times as it repeats, unless it is a control character.
    fn type_char(&mut self, k: &KeyEvent) -> ConsentStep {
        let mut shown = String::new();
        if k.unicode_char >= 0x20 {
            for _ in 0..k.repeat_count.max(1) {
                self.push_unit(k.unicode_char, &mut shown);
            }
        }
        step_of(shown)
    }

    /// Add one UTF-16 unit; a character is complete once its last unit is.
    fn push_unit(&mut self, unit: u16, shown: &mut String) {
        let pending = self.high_surrogate.take();
        match (pending, unit) {
            (Some(high), 0xDC00..=0xDFFF) => {
                let pair = char::decode_utf16([high, unit]).next().and_then(Result::ok);
                self.push_char(pair.unwrap_or(char::REPLACEMENT_CHARACTER), shown);
            }
            (pending, 0xD800..=0xDBFF) => {
                if pending.is_some() {
                    self.push_char(char::REPLACEMENT_CHARACTER, shown);
                }
                self.high_surrogate = Some(unit);
            }
            (pending, unit) => {
                if pending.is_some() {
                    self.push_char(char::REPLACEMENT_CHARACTER, shown);
                }
                self.push_char(
                    char::from_u32(u32::from(unit)).unwrap_or(char::REPLACEMENT_CHARACTER),
                    shown,
                );
            }
        }
    }

    fn push_char(&mut self, c: char, shown: &mut String) {
        if self.text.len() < self.echo_limit {
            shown.push(if c.is_ascii() && !c.is_ascii_control() {
                c
            } else {
                SHOWN_INSTEAD
            });
        }
        self.text.push(c);
    }

    /// Remove `count` characters, and show the erase of those that were shown.
    fn erase(&mut self, count: u16) -> ConsentStep {
        let mut shown = String::new();
        for _ in 0..count {
            // A first unit that waits for its second was not shown, and is the last thing typed.
            if self.high_surrogate.take().is_some() {
                continue;
            }
            if self.text.pop().is_some() && self.text.len() < self.echo_limit {
                shown.push_str(ERASE);
            }
        }
        step_of(shown)
    }
}

fn step_of(shown: String) -> ConsentStep {
    if shown.is_empty() {
        ConsentStep::Continue
    } else {
        ConsentStep::Echo(shown)
    }
}

impl KeyEntry for ConsentEntry {
    type Step = ConsentStep;

    fn key(&mut self, k: &KeyEvent) -> ConsentStep {
        ConsentEntry::key(self, k)
    }

    fn finishes_step(step: &ConsentStep) -> bool {
        !matches!(step, ConsentStep::Continue)
    }

    fn stopped() -> ConsentStep {
        ConsentStep::Stopped
    }
}

#[cfg(test)]
#[path = "consent_entry_tests.rs"]
mod consent_entry_tests;
