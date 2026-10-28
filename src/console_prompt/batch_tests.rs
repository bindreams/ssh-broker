//! Unit tests for `batch` (pure; the console queue is a fake).
use super::*;
use std::collections::VecDeque;
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

fn characters<'a>(records: impl IntoIterator<Item = &'a INPUT_RECORD>) -> String {
    let units: Vec<u16> = records
        .into_iter()
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

/// A console input queue: `peek` copies from the head, `read` removes from the head. A `read` of an
/// empty queue is the console's blocking wait: the next `arrivals` entry lands in the queue first.
#[derive(Default)]
struct FakeQueue {
    queue: VecDeque<INPUT_RECORD>,
    arrivals: VecDeque<Vec<INPUT_RECORD>>,
    removed: usize,
    fail_peek: bool,
    fail_read: bool,
}

impl FakeQueue {
    fn with(records: Vec<INPUT_RECORD>) -> Self {
        FakeQueue {
            queue: records.into(),
            ..Default::default()
        }
    }

    fn type_more(&mut self, records: Vec<INPUT_RECORD>) {
        self.queue.extend(records);
    }

    fn left(&self) -> String {
        characters(&self.queue)
    }
}

fn failure() -> windows::core::Error {
    windows::core::Error::from_hresult(windows::core::HRESULT(-1))
}

impl InputQueue for FakeQueue {
    fn peek(&mut self, records: &mut [INPUT_RECORD]) -> windows::core::Result<u32> {
        if self.fail_peek {
            records[0] = key(0x41, 'x' as u16);
            return Err(failure());
        }
        let count = records.len().min(self.queue.len());
        for (slot, record) in records.iter_mut().zip(&self.queue) {
            *slot = *record;
        }
        Ok(count as u32)
    }

    fn read(&mut self, records: &mut [INPUT_RECORD]) -> windows::core::Result<u32> {
        if self.fail_read {
            records[0] = key(0x41, 'x' as u16);
            return Err(failure());
        }
        if self.queue.is_empty() {
            let arrived = self
                .arrivals
                .pop_front()
                .expect("a blocking read with nothing to arrive: it would hang");
            self.queue.extend(arrived);
        }
        let count = records.len().min(self.queue.len());
        for slot in records.iter_mut().take(count) {
            *slot = self.queue.pop_front().unwrap();
        }
        self.removed += count;
        Ok(count as u32)
    }
}

fn submitted(step: Step) -> String {
    match step {
        Step::Submit(password) => String::from_utf16(password.as_wide()).unwrap(),
        other => panic!("expected a submitted password, got {other:?}"),
    }
}

/// A paste of an empty Enter and then a password: the Enter finishes a step, and the password and its
/// Enter, still queued, are the next step.
#[test]
fn a_password_after_an_empty_enter_in_one_batch_is_not_lost() {
    let mut queue = FakeQueue::with(typed("\rSecret1\r"));
    let mut batch = Batch::new();
    let mut entry = PasswordEntry::new();
    assert!(matches!(batch.step(&mut queue, &mut entry).unwrap(), Step::Empty));
    assert_eq!(queue.left(), "Secret1\r");
    assert_eq!(submitted(batch.step(&mut queue, &mut entry).unwrap()), "Secret1");
    assert_eq!(queue.left(), "");
}

/// The first command typed while the session starts is queued with the password's Enter.
#[test]
fn type_ahead_after_the_password_stays_queued() {
    let mut queue = FakeQueue::with(typed("pw\rls\r"));
    let mut batch = Batch::new();
    let mut entry = PasswordEntry::new();
    assert_eq!(submitted(batch.step(&mut queue, &mut entry).unwrap()), "pw");
    assert_eq!(queue.left(), "ls\r");
    assert_eq!(queue.removed, 3, "only the records fed to the entry are taken");
}

/// More type-ahead than one batch holds stays in the queue, in order.
#[test]
fn type_ahead_longer_than_a_batch_stays_queued_in_order() {
    let command: String = ('a'..='z').cycle().take(5 * BATCH + 7).collect();
    let mut queue = FakeQueue::with(typed(&format!("pw\r{command}")));
    let mut batch = Batch::new();
    let mut entry = PasswordEntry::new();
    assert_eq!(submitted(batch.step(&mut queue, &mut entry).unwrap()), "pw");
    assert_eq!(queue.left(), command);
}

/// Input typed after the finishing key, while the prompt waits for the agent, is behind the
/// type-ahead that was already queued.
#[test]
fn input_that_arrives_after_the_finishing_key_follows_the_type_ahead() {
    let mut queue = FakeQueue::with(typed("pw\rls\r"));
    let mut batch = Batch::new();
    let mut entry = PasswordEntry::new();
    assert_eq!(submitted(batch.step(&mut queue, &mut entry).unwrap()), "pw");
    queue.type_more(typed("pwd\r"));
    assert_eq!(queue.left(), "ls\rpwd\r");
}

/// A cancel leaves what follows it for the shell to read, too.
#[test]
fn type_ahead_after_a_cancel_stays_queued() {
    let mut records = typed("ab");
    records.insert(1, key(0x43, 0x03));
    let mut queue = FakeQueue::with(records);
    let mut batch = Batch::new();
    let mut entry = PasswordEntry::new();
    assert!(matches!(batch.step(&mut queue, &mut entry).unwrap(), Step::Cancel));
    assert_eq!(queue.left(), "b");
}

/// Records that are not keys (focus, mouse, resize) after the finishing one stay queued as they are.
#[test]
fn records_that_are_not_keys_stay_queued() {
    let mut records = typed("pw\r");
    let mut focus = key(0, 0);
    focus.EventType = FOCUS_EVENT as u16;
    records.push(focus);
    let mut queue = FakeQueue::with(records);
    let mut batch = Batch::new();
    let mut entry = PasswordEntry::new();
    submitted(batch.step(&mut queue, &mut entry).unwrap());
    let types: Vec<u16> = queue.queue.iter().map(|r| r.EventType).collect();
    assert_eq!(types, vec![FOCUS_EVENT as u16]);
}

/// A password longer than one batch is taken batch by batch, and is one password.
#[test]
fn a_password_longer_than_a_batch_is_one_password() {
    let password: String = ('a'..='z').cycle().take(3 * BATCH + 5).collect();
    let mut queue = FakeQueue::with(typed(&format!("{password}\r")));
    let mut batch = Batch::new();
    let mut entry = PasswordEntry::new();
    assert_eq!(submitted(batch.step(&mut queue, &mut entry).unwrap()), password);
    assert_eq!(queue.removed, password.len() + 1);
    assert_eq!(queue.left(), "");
}

/// An empty queue: the step blocks for a record, takes exactly the one it feeds, and the rest of what
/// arrived with it stays queued.
#[test]
fn a_step_that_finds_the_queue_empty_waits_and_takes_only_what_it_feeds() {
    let mut queue = FakeQueue::default();
    queue.arrivals.push_back(typed("pw\rls"));
    let mut batch = Batch::new();
    let mut entry = PasswordEntry::new();
    assert_eq!(submitted(batch.step(&mut queue, &mut entry).unwrap()), "pw");
    assert_eq!(queue.left(), "ls");
}

/// The buffer holds what was typed: it is overwritten before the step returns, the records that
/// stay queued included.
#[test]
fn the_buffer_is_overwritten_when_a_step_returns() {
    let mut queue = FakeQueue::with(typed("pw\rls\r"));
    let mut batch = Batch::new();
    let mut entry = PasswordEntry::new();
    submitted(batch.step(&mut queue, &mut entry).unwrap());
    assert!(is_zeroed(&batch.records), "a record kept its content");
}

#[test]
fn a_failed_peek_leaves_nothing_behind() {
    let mut queue = FakeQueue::with(typed("pw"));
    queue.fail_peek = true;
    let mut batch = Batch::new();
    let mut entry = PasswordEntry::new();
    assert!(batch.step(&mut queue, &mut entry).is_err());
    assert!(is_zeroed(&batch.records));
}

/// The step finishes and its records are fed, but taking them out of the queue fails: the error is
/// the result, and nothing is left in the buffer.
#[test]
fn a_failed_read_leaves_nothing_behind() {
    let mut queue = FakeQueue::with(typed("pw\r"));
    queue.fail_read = true;
    let mut batch = Batch::new();
    let mut entry = PasswordEntry::new();
    assert!(batch.step(&mut queue, &mut entry).is_err());
    assert!(is_zeroed(&batch.records));
}
