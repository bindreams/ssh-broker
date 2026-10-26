//! Host tests for `PasswordVariant`: it holds the password for a COM call and wipes it. Only the live
//! buffer is inspected (reading a freed one is undefined behaviour).
use super::*;
use crate::password_entry::{PasswordEntry, Step};
use crate::vtinput::KeyEvent;

fn password(text: &str) -> Password {
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
        _ => panic!("empty"),
    }
}

#[test]
fn the_variant_holds_the_password_as_a_bstr() {
    let variant = PasswordVariant::new(&password("p\u{1F600}ss"));
    let expect: Vec<u16> = "p\u{1F600}ss".encode_utf16().collect();
    assert_eq!(variant.units(), expect);
    // SAFETY: reading the type tag of a live variant.
    assert_eq!(
        unsafe { variant.variant().Anonymous.Anonymous.vt },
        windows::Win32::System::Variant::VT_BSTR
    );
}

#[test]
fn wipe_zeroes_the_characters_of_the_bstr() {
    let mut variant = PasswordVariant::new(&password("hunter2-sentinel"));
    assert!(variant.units().iter().any(|&u| u != 0));
    variant.wipe();
    let units = variant.units();
    assert_eq!(units.len(), "hunter2-sentinel".len(), "the string keeps its length");
    assert!(units.iter().all(|&u| u == 0), "{units:?}");
}

#[test]
fn debug_output_contains_no_password_text() {
    let variant = PasswordVariant::new(&password("hunter2-sentinel"));
    assert!(!format!("{variant:?}").contains("hunter2"));
}
