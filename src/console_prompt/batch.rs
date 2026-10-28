//! Reading the console's input records into `PasswordEntry`, without taking any it does not feed.
//!
//! A step peeks at the head of the console queue, feeds the records to the entry in turn, and then
//! removes from the queue exactly the records it fed, up to and including the one that finished the
//! step. The rest (a paste's remainder, input typed while the agent starts) keeps its place for the
//! next step and, once the prompt is over, for the relay. Every buffer that held records is
//! overwritten before the step returns.

use windows::Win32::System::Console::INPUT_RECORD;
use zeroize::Zeroize;

use crate::password_entry::{PasswordEntry, Step};
use crate::vtinput::KeyEvent;

/// Records one peek takes.
pub(super) const BATCH: usize = 32;

/// `INPUT_RECORD.EventType` of a key record.
const EVT_KEY: u16 = 0x0001;

/// The console's input queue.
pub(super) trait InputQueue {
    /// Copy up to `records.len()` records from the head of the queue, leaving them there. Returns
    /// how many; 0 if the queue is empty.
    fn peek(&mut self, records: &mut [INPUT_RECORD]) -> windows::core::Result<u32>;

    /// Remove up to `records.len()` records from the head of the queue into `records`, waiting for
    /// at least one. Returns how many.
    fn read(&mut self, records: &mut [INPUT_RECORD]) -> windows::core::Result<u32>;
}

pub(super) struct Batch {
    records: [INPUT_RECORD; BATCH],
}

impl Batch {
    pub fn new() -> Self {
        Batch {
            records: [zeroed_record(); BATCH],
        }
    }

    /// Block until one entry step finishes, and return it. The records after the finishing one are
    /// not taken from the queue. On return, successful or not, the buffer is all zeros.
    pub fn step(&mut self, queue: &mut impl InputQueue, entry: &mut PasswordEntry) -> windows::core::Result<Step> {
        let result = self.step_inner(queue, entry);
        self.wipe();
        result
    }

    fn step_inner(&mut self, queue: &mut impl InputQueue, entry: &mut PasswordEntry) -> windows::core::Result<Step> {
        loop {
            let peeked = (queue.peek(&mut self.records)? as usize).min(BATCH);
            // An empty queue: wait for a record. The one that arrives is fed in any case, so taking it
            // out of the queue is taking exactly what is fed.
            let (len, already_taken) = if peeked == 0 {
                (queue.read(&mut self.records[..1])? as usize, true)
            } else {
                (peeked, false)
            };
            let (fed, step) = self.feed(len, entry);
            self.wipe();
            if !already_taken {
                self.take(queue, fed)?;
            }
            if let Some(step) = step {
                return Ok(step);
            }
        }
    }

    /// Feed the entry the first `len` records in turn until a step finishes. Returns how many were
    /// fed (the finishing one included) and the step. A fed record is overwritten at once.
    fn feed(&mut self, len: usize, entry: &mut PasswordEntry) -> (usize, Option<Step>) {
        for (index, slot) in self.records[..len].iter_mut().enumerate() {
            let mut record = std::mem::replace(slot, zeroed_record());
            if record.EventType != EVT_KEY {
                continue;
            }
            // SAFETY: the event type says this is a key record.
            let key = unsafe { record.Event.KeyEvent };
            let event = KeyEvent {
                virtual_key_code: key.wVirtualKeyCode,
                virtual_scan_code: key.wVirtualScanCode,
                // SAFETY: the character is read as the UTF-16 unit it is.
                unicode_char: unsafe { key.uChar.UnicodeChar },
                key_down: key.bKeyDown.as_bool(),
                control_key_state: key.dwControlKeyState,
                repeat_count: key.wRepeatCount,
            };
            wipe_records(std::slice::from_mut(&mut record));
            match entry.key(&event) {
                Step::Continue => {}
                step => return (index + 1, Some(step)),
            }
        }
        (len, None)
    }

    /// Remove exactly `count` records, the ones fed, from the head of the queue.
    fn take(&mut self, queue: &mut impl InputQueue, count: usize) -> windows::core::Result<()> {
        let mut left = count;
        while left > 0 {
            let taken = (queue.read(&mut self.records[..left])? as usize).min(left);
            self.wipe();
            left -= taken;
        }
        Ok(())
    }

    fn wipe(&mut self) {
        wipe_records(&mut self.records);
    }
}

impl Drop for Batch {
    fn drop(&mut self) {
        self.wipe();
    }
}

fn zeroed_record() -> INPUT_RECORD {
    // SAFETY: `INPUT_RECORD` is plain data; all-zero bytes are a valid value.
    unsafe { std::mem::zeroed() }
}

/// Overwrite console records: they hold the characters just typed.
fn wipe_records(records: &mut [INPUT_RECORD]) {
    // SAFETY: `INPUT_RECORD` is plain data; zeroing its bytes in place is sound.
    let bytes =
        unsafe { std::slice::from_raw_parts_mut(records.as_mut_ptr().cast::<u8>(), std::mem::size_of_val(records)) };
    bytes.zeroize();
}

#[cfg(test)]
#[path = "batch_tests.rs"]
mod batch_tests;
