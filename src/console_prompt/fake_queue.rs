//! A console's input queue for the tests of `batch` and of the consent question on a console: records that are typed,
//! and the console's blocking wait.
use std::collections::VecDeque;

use windows::Win32::System::Console::{
    FOCUS_EVENT, INPUT_RECORD, INPUT_RECORD_0, KEY_EVENT, KEY_EVENT_RECORD, KEY_EVENT_RECORD_0, MOUSE_EVENT,
    WINDOW_BUFFER_SIZE_EVENT,
};
use windows::core::BOOL;

use super::batch::InputQueue;

pub(super) fn key(vk: u16, ch: u16) -> INPUT_RECORD {
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

/// A record that is not a key: of `event_type`, with nothing in it.
fn other(event_type: u32) -> INPUT_RECORD {
    let mut record = key(0, 0);
    record.EventType = event_type as u16;
    record
}

pub(super) fn focus_record() -> INPUT_RECORD {
    other(FOCUS_EVENT)
}

pub(super) fn mouse_record() -> INPUT_RECORD {
    other(MOUSE_EVENT)
}

pub(super) fn size_record() -> INPUT_RECORD {
    other(WINDOW_BUFFER_SIZE_EVENT)
}

/// The records of text pasted into the console: Enter for each `\r`.
pub(super) fn typed(text: &str) -> Vec<INPUT_RECORD> {
    text.encode_utf16()
        .map(|unit| if unit == 0x0D { key(0x0D, 0x0D) } else { key(0x41, unit) })
        .collect()
}

pub(super) fn characters<'a>(records: impl IntoIterator<Item = &'a INPUT_RECORD>) -> String {
    let units: Vec<u16> = records
        .into_iter()
        // SAFETY: every record in these tests is a key record.
        .map(|record| unsafe { record.Event.KeyEvent.uChar.UnicodeChar })
        .collect();
    String::from_utf16(&units).unwrap()
}

/// A console input queue: `peek` copies from the head, `read` removes from the head. A `read` of an
/// empty queue is the console's blocking wait: the next `arrivals` entry lands in the queue first.
#[derive(Default)]
pub(super) struct FakeQueue {
    pub(super) queue: VecDeque<INPUT_RECORD>,
    pub(super) arrivals: VecDeque<Vec<INPUT_RECORD>>,
    pub(super) removed: usize,
    /// After the next peek that reaches the end of the queue, the console merges a repeat of the last
    /// key-down into that record: its `wRepeatCount` becomes this.
    pub(super) merge_into_tail_after_peek: Option<u16>,
    pub(super) fail_peek: bool,
    pub(super) fail_read: bool,
    pub(super) fail_discard: bool,
}

impl FakeQueue {
    pub(super) fn with(records: Vec<INPUT_RECORD>) -> Self {
        FakeQueue {
            queue: records.into(),
            ..Default::default()
        }
    }

    pub(super) fn type_more(&mut self, records: Vec<INPUT_RECORD>) {
        self.queue.extend(records);
    }

    pub(super) fn left(&self) -> String {
        characters(&self.queue)
    }
}

pub(super) fn failure() -> windows::core::Error {
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
        if count == self.queue.len()
            && let (Some(repeat), Some(tail)) = (self.merge_into_tail_after_peek.take(), self.queue.back_mut())
        {
            tail.Event.KeyEvent.wRepeatCount = repeat;
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

    fn discard(&mut self) -> windows::core::Result<()> {
        if self.fail_discard {
            return Err(failure());
        }
        self.queue.clear();
        Ok(())
    }
}
