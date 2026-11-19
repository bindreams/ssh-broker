//! Unit tests for `consent_entry` (pure; runs on the host).
use super::*;

const VK_RETURN: u16 = 0x0D;
const VK_BACK: u16 = 0x08;
const VK_MENU: u16 = 0x12;
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

fn enter() -> KeyEvent {
    event(VK_RETURN, 0x0D, true, 0)
}

fn backspace() -> KeyEvent {
    event(VK_BACK, 0x08, true, 0)
}

fn apt() -> ConsentEntry {
    ConsentEntry::new(&["y", "yes"])
}

/// Type `text` and press Enter; what Enter did.
fn answer(entry: &mut ConsentEntry, text: &str) -> ConsentStep {
    for unit in text.encode_utf16() {
        entry.key(&typed(unit));
    }
    entry.key(&enter())
}

#[test]
fn y_then_enter_allows() {
    assert_eq!(answer(&mut apt(), "y"), ConsentStep::Allow);
}

#[test]
fn yes_then_enter_allows() {
    assert_eq!(answer(&mut apt(), "yes"), ConsentStep::Allow);
}

#[test]
fn case_is_ignored() {
    for text in ["Y", "YES", "Yes", "yEs"] {
        assert_eq!(answer(&mut apt(), text), ConsentStep::Allow, "{text}");
    }
}

#[test]
fn enter_alone_refuses() {
    assert_eq!(apt().key(&enter()), ConsentStep::Refuse);
}

#[test]
fn no_then_enter_refuses() {
    for text in ["n", "N", "no", "NO"] {
        assert_eq!(answer(&mut apt(), text), ConsentStep::Refuse, "{text}");
    }
}

#[test]
fn anything_else_then_enter_refuses() {
    for text in [
        "ye",
        "yess",
        " y",
        "y ",
        "yes ",
        "yy",
        "yeah",
        "maybe",
        "\u{ff59}",
        "y\u{0301}",
    ] {
        assert_eq!(answer(&mut apt(), text), ConsentStep::Refuse, "{text:?}");
    }
}

#[test]
fn what_is_accepted_is_what_new_was_given() {
    assert_eq!(answer(&mut ConsentEntry::new(&["go"]), "GO"), ConsentStep::Allow);
    assert_eq!(answer(&mut ConsentEntry::new(&["go"]), "y"), ConsentStep::Refuse);
    assert_eq!(answer(&mut ConsentEntry::new(&["go"]), "yes"), ConsentStep::Refuse);
}

#[test]
fn a_typed_character_is_echoed_and_continues_the_entry() {
    let mut e = apt();
    assert_eq!(e.key(&typed('y' as u16)), ConsentStep::Echo("y".into()));
    assert_eq!(e.key(&typed('E' as u16)), ConsentStep::Echo("E".into()));
}

#[test]
fn backspace_edits_and_echoes_the_erase() {
    let mut e = apt();
    e.key(&typed('n' as u16));
    assert_eq!(e.key(&backspace()), ConsentStep::Echo("\x08 \x08".into()));
    assert_eq!(answer(&mut e, "y"), ConsentStep::Allow);
}

#[test]
fn backspace_on_nothing_does_nothing() {
    let mut e = apt();
    assert_eq!(e.key(&backspace()), ConsentStep::Continue);
    assert_eq!(answer(&mut e, "yes"), ConsentStep::Allow);
}

#[test]
fn ctrl_c_and_ctrl_d_refuse_at_any_point() {
    for (vk, ch) in [(0x43, 0x03), (0x44, 0x04)] {
        // As a character, with nothing typed and with the answer typed.
        assert_eq!(apt().key(&event(vk, ch, true, LEFT_CTRL)), ConsentStep::Refuse);
        let mut e = apt();
        e.key(&typed('y' as u16));
        assert_eq!(e.key(&event(vk, ch, true, LEFT_CTRL)), ConsentStep::Refuse);
        // As a virtual key that carries no character.
        let mut e = apt();
        e.key(&typed('y' as u16));
        assert_eq!(e.key(&event(vk, 0, true, LEFT_CTRL)), ConsentStep::Refuse);
    }
}

#[test]
fn a_plain_c_or_d_is_a_character_not_a_refusal() {
    let mut e = apt();
    assert_eq!(e.key(&event(0x43, 'c' as u16, true, 0)), ConsentStep::Echo("c".into()));
    assert_eq!(e.key(&event(0x44, 'd' as u16, true, 0)), ConsentStep::Echo("d".into()));
}

#[test]
fn key_up_records_do_nothing() {
    let mut e = apt();
    assert_eq!(e.key(&event(0x59, 'y' as u16, false, 0)), ConsentStep::Continue);
    // A key-up of Enter does not answer, and the key-up of the character does not type it twice.
    e.key(&typed('y' as u16));
    assert_eq!(e.key(&event(0x59, 'y' as u16, false, 0)), ConsentStep::Continue);
    assert_eq!(e.key(&event(VK_RETURN, 0x0D, false, 0)), ConsentStep::Continue);
    assert_eq!(e.key(&enter()), ConsentStep::Allow);
}

#[test]
fn control_characters_and_escape_sequences_are_not_text() {
    // A line feed record and an Escape are no part of the answer.
    let mut e = apt();
    e.key(&typed('y' as u16));
    assert_eq!(e.key(&event(VK_RETURN, 0x0A, true, LEFT_CTRL)), ConsentStep::Continue);
    assert_eq!(e.key(&event(0x1B, 0x1B, true, 0)), ConsentStep::Continue);
    assert_eq!(
        e.key(&event(0x25, 0, true, 0)),
        ConsentStep::Continue,
        "an arrow has no character"
    );
    assert_eq!(e.key(&enter()), ConsentStep::Allow);
    // What a terminal answers to a cursor-position query, as the console delivers it: its characters are text, so
    // it is not the answer.
    assert_eq!(
        answer(&mut apt(), "\u{1b}[24;80R"),
        ConsentStep::Refuse,
        "a cursor-position report"
    );
}

/// P3: a terminal's answer to an earlier query is read as keys, and the part of it that is text must not make a yes.
#[test]
fn a_title_report_does_not_allow() {
    // ESC ] l y e s CR ESC \: the characters are `]lyes`, and the CR is an Enter.
    assert_eq!(answer(&mut apt(), "\u{1b}]lyes"), ConsentStep::Refuse);
}

/// What a console shows for a character typed as UTF-8 that has no key of its own: its units are on the key-UP
/// records of Alt.
fn alt_delivery(unit: u16) -> [KeyEvent; 2] {
    [event(VK_MENU, 0, true, LEFT_ALT), event(VK_MENU, unit, false, 0)]
}

#[test]
fn the_alt_key_up_character_outside_the_bmp_is_typed() {
    let mut e = apt();
    let mut shown = String::new();
    for unit in "\u{1F600}".encode_utf16() {
        for k in alt_delivery(unit) {
            if let ConsentStep::Echo(text) = e.key(&k) {
                shown.push_str(&text);
            }
        }
    }
    assert_eq!(shown, "?", "one scalar value is one cell of echo, whatever it is");
    // It is text, so it is not yes; and one Backspace removes both of its units.
    assert_eq!(e.key(&enter()), ConsentStep::Refuse);
    let mut e = apt();
    for unit in "\u{1F600}".encode_utf16() {
        for k in alt_delivery(unit) {
            e.key(&k);
        }
    }
    assert_eq!(e.key(&backspace()), ConsentStep::Echo("\x08 \x08".into()));
    assert_eq!(answer(&mut e, "y"), ConsentStep::Allow);
}

#[test]
fn an_alt_key_up_without_a_character_adds_nothing() {
    let mut e = apt();
    for k in alt_delivery(0) {
        assert_eq!(e.key(&k), ConsentStep::Continue);
    }
    assert_eq!(e.key(&enter()), ConsentStep::Refuse);
}

#[test]
fn a_character_that_is_not_printable_ascii_is_echoed_as_one_question_mark() {
    // So that the erase, which is one cell, is exact for a wide character too.
    let mut e = apt();
    assert_eq!(e.key(&typed(0x4E2D)), ConsentStep::Echo("?".into()));
    assert_eq!(e.key(&typed(0x7F)), ConsentStep::Echo("?".into()));
    assert_eq!(e.key(&typed(0x85)), ConsentStep::Echo("?".into()));
    assert_eq!(e.key(&backspace()), ConsentStep::Echo("\x08 \x08".into()));
}

/// An answer longer than the longest accepted one plus one is wrong however it goes on, and a line that wraps cannot
/// be erased by a Backspace in every terminal: past that the typing is taken, and refuses, and is not echoed.
#[test]
fn typing_past_the_longest_accepted_answer_and_one_more_is_not_echoed() {
    let mut e = apt();
    let mut shown = String::new();
    for unit in "yeses and more".encode_utf16() {
        if let ConsentStep::Echo(text) = e.key(&typed(unit)) {
            shown.push_str(&text);
        }
    }
    assert_eq!(shown, "yese", "the three of `yes` and one more");
    assert_eq!(e.key(&enter()), ConsentStep::Refuse);
}

#[test]
fn backspace_erases_only_what_was_echoed() {
    let mut e = apt();
    for unit in "yesxx".encode_utf16() {
        e.key(&typed(unit));
    }
    // `yesx` was echoed; the fifth character was not, so erasing it shows nothing, and the next four do.
    assert_eq!(e.key(&backspace()), ConsentStep::Continue);
    assert_eq!(e.key(&backspace()), ConsentStep::Echo("\x08 \x08".into()));
    assert_eq!(e.key(&backspace()), ConsentStep::Echo("\x08 \x08".into()));
    assert_eq!(e.key(&enter()), ConsentStep::Refuse, "`ye` is left");
    let mut e = apt();
    for unit in "yesxx".encode_utf16() {
        e.key(&typed(unit));
    }
    for _ in 0..2 {
        e.key(&backspace());
    }
    assert_eq!(e.key(&enter()), ConsentStep::Allow, "`yes` is left");
}

#[test]
fn every_key_the_entry_handles_honours_its_repeat_count() {
    // The console merges a repeated key-down into one record.
    let mut e = apt();
    let mut k = typed('y' as u16);
    k.repeat_count = 3;
    assert_eq!(e.key(&k), ConsentStep::Echo("yyy".into()));
    let mut back = backspace();
    back.repeat_count = 2;
    assert_eq!(e.key(&back), ConsentStep::Echo("\x08 \x08\x08 \x08".into()));
    assert_eq!(e.key(&enter()), ConsentStep::Allow, "`y` is left");
}

#[test]
fn a_repeat_of_enter_answers_once() {
    let mut e = apt();
    e.key(&typed('y' as u16));
    let mut k = enter();
    k.repeat_count = 4;
    assert_eq!(e.key(&k), ConsentStep::Allow);
}

#[test]
fn the_trait_finishes_a_step_on_anything_but_continue_and_stopped_is_final() {
    assert!(!ConsentEntry::finishes_step(&ConsentStep::Continue));
    for step in [
        ConsentStep::Echo("y".into()),
        ConsentStep::Allow,
        ConsentStep::Refuse,
        ConsentStep::Stopped,
    ] {
        assert!(ConsentEntry::finishes_step(&step), "{step:?}");
    }
    assert_eq!(ConsentEntry::stopped(), ConsentStep::Stopped);
}
