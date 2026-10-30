//! A `Password` built from text, for tests and test helpers that have no console to type it into.
#![allow(dead_code)]

use ssh_broker::password_entry::{Password, PasswordEntry, Step};
use ssh_broker::vtinput::KeyEvent;

/// The password `text` as the entry state machine would hand it over after the user typed it and
/// pressed Enter.
pub fn password(text: &str) -> Password {
    let key = |vk: u16, ch: u16| KeyEvent {
        virtual_key_code: vk,
        virtual_scan_code: 0,
        unicode_char: ch,
        key_down: true,
        control_key_state: 0,
        repeat_count: 1,
    };
    let mut entry = PasswordEntry::new();
    for unit in text.encode_utf16() {
        entry.key(&key(0x41, unit));
    }
    match entry.key(&key(0x0D, 0x0D)) {
        Step::Submit(password) => password,
        _ => panic!("the password text is empty"),
    }
}
