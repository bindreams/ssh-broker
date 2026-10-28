//! Unit tests for `batch` (pure; no console).
use super::*;
use windows::Win32::System::Console::{FOCUS_EVENT, INPUT_RECORD_0, KEY_EVENT, KEY_EVENT_RECORD, KEY_EVENT_RECORD_0};
use windows::core::BOOL;

fn key(vk: u16, ch: u16) -> INPUT_RECORD {
    INPUT_RECORD {
        EventType: KEY_EVENT as u16,
        Event: INPUT_RECORD_0 {
            KeyEvent: KEY_EVENT_RECORD {
                bKeyDown: BOOL(1),
                wRepeatCount: 1,
                wVirtualKeyCode: vk,
                wVirtualScanCode: 0,
                uChar: KEY_EVENT_RECORD_0 { UnicodeChar: ch },
                dwControlKeyState: 0,
            },
        },
    }
}

/// The records of text pasted into the console: Enter for each `\r`.
fn typed(text: &str) -> Vec<INPUT_RECORD> {
    text.encode_utf16()
        .map(|unit| if unit == 0x0D { key(0x0D, 0x0D) } else { key(0x41, unit) })
        .collect()
}

fn batch_of(records: &[INPUT_RECORD]) -> Batch {
    let mut batch = Batch::new();
    batch
        .fill(|buffer| {
            buffer[..records.len()].copy_from_slice(records);
            Ok(records.len() as u32)
        })
        .unwrap();
    batch
}

fn characters(records: &[INPUT_RECORD]) -> String {
    let units: Vec<u16> = records
        .iter()
        // SAFETY: every record in these tests is a key record.
        .map(|record| unsafe { record.Event.KeyEvent.uChar.UnicodeChar })
        .collect();
    String::from_utf16(&units).unwrap()
}

fn is_zeroed(records: &[INPUT_RECORD]) -> bool {
    // SAFETY: `INPUT_RECORD` is plain data.
    let bytes = unsafe { std::slice::from_raw_parts(records.as_ptr().cast::<u8>(), std::mem::size_of_val(records)) };
    bytes.iter().all(|b| *b == 0)
}

fn submitted(step: Option<Step>) -> Vec<u16> {
    match step {
        Some(Step::Submit(password)) => password.as_wide().to_vec(),
        other => panic!("expected a submitted password, got {other:?}"),
    }
}

/// A paste of an empty Enter and then a password: the Enter finishes a step, and the password and its
/// Enter, in the same batch, are the next step.
#[test]
fn a_password_after_an_empty_enter_in_one_batch_is_not_lost() {
    let mut batch = batch_of(&typed("\rSecret1\r"));
    let mut entry = PasswordEntry::new();
    assert!(matches!(batch.step(&mut entry), Some(Step::Empty)));
    let password = submitted(batch.step(&mut entry));
    assert_eq!(String::from_utf16(&password).unwrap(), "Secret1");
}

/// The first command typed while the session starts arrives in the batch with the password's Enter.
#[test]
fn type_ahead_after_the_password_is_handed_back_in_order() {
    let mut batch = batch_of(&typed("pw\rls\r"));
    let mut entry = PasswordEntry::new();
    assert_eq!(
        submitted(batch.step(&mut entry)),
        "pw".encode_utf16().collect::<Vec<_>>()
    );
    let mut given = None;
    batch.give_back(|records| given = Some(characters(records)));
    assert_eq!(given.as_deref(), Some("ls\r"));
}

/// A cancel leaves what follows it for the shell to read, too.
#[test]
fn type_ahead_after_a_cancel_is_handed_back() {
    let mut records = typed("ab");
    records.insert(1, key(0x43, 0x03));
    let mut batch = batch_of(&records);
    let mut entry = PasswordEntry::new();
    assert!(matches!(batch.step(&mut entry), Some(Step::Cancel)));
    let mut given = None;
    batch.give_back(|records| given = Some(characters(records)));
    assert_eq!(given.as_deref(), Some("b"));
}

/// Records that are not keys (focus, mouse, resize) after the finishing one are handed back as read.
#[test]
fn records_that_are_not_keys_are_handed_back_too() {
    let mut records = typed("pw\r");
    let mut focus = key(0, 0);
    focus.EventType = FOCUS_EVENT as u16;
    records.push(focus);
    let mut batch = batch_of(&records);
    let mut entry = PasswordEntry::new();
    submitted(batch.step(&mut entry));
    let mut given = Vec::new();
    batch.give_back(|records| given = records.iter().map(|r| r.EventType).collect());
    assert_eq!(given, vec![FOCUS_EVENT as u16]);
}

#[test]
fn nothing_is_handed_back_when_the_batch_was_fed_to_its_end() {
    let mut batch = batch_of(&typed("pw\r"));
    let mut entry = PasswordEntry::new();
    submitted(batch.step(&mut entry));
    assert!(batch.step(&mut entry).is_none());
    batch.give_back(|_| panic!("there was nothing left to hand back"));
}

/// Handing the records back more than once does not repeat them.
#[test]
fn records_are_handed_back_once() {
    let mut batch = batch_of(&typed("pw\rls"));
    let mut entry = PasswordEntry::new();
    submitted(batch.step(&mut entry));
    batch.give_back(|records| assert_eq!(records.len(), 2));
    batch.give_back(|_| panic!("handed back twice"));
}

/// A batch with no finishing step is fed whole, and the next batch continues the same entry.
#[test]
fn a_password_split_across_two_reads_is_one_password() {
    let mut entry = PasswordEntry::new();
    let mut batch = batch_of(&typed("Sec"));
    assert!(batch.step(&mut entry).is_none());
    batch
        .fill(|buffer| {
            let rest = typed("ret1\r");
            buffer[..rest.len()].copy_from_slice(&rest);
            Ok(rest.len() as u32)
        })
        .unwrap();
    assert_eq!(
        String::from_utf16(&submitted(batch.step(&mut entry))).unwrap(),
        "Secret1"
    );
}

/// The records hold what was typed: they are overwritten as they are fed, and when handed back.
#[test]
fn fed_records_are_overwritten_and_so_are_the_ones_handed_back() {
    let mut batch = batch_of(&typed("pw\rls\r"));
    let mut entry = PasswordEntry::new();
    submitted(batch.step(&mut entry));
    assert!(is_zeroed(&batch.records[..batch.next]), "a fed record kept its content");
    assert!(
        !is_zeroed(&batch.records[batch.next..batch.len]),
        "the rest is still to be handed back"
    );
    batch.give_back(|_| {});
    assert!(
        is_zeroed(&batch.records),
        "a record kept its content after it was handed back"
    );
}

#[test]
fn a_failed_read_leaves_nothing_behind() {
    let mut batch = batch_of(&typed("pw"));
    let mut entry = PasswordEntry::new();
    assert!(batch.step(&mut entry).is_none());
    let failed = batch.fill(|buffer| {
        buffer[0] = key(0x41, 'x' as u16);
        Err(windows::core::Error::from_hresult(windows::core::HRESULT(-1)))
    });
    assert!(failed.is_err());
    assert!(is_zeroed(&batch.records));
    batch.give_back(|_| panic!("a failed read has nothing to hand back"));
}
