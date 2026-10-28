//! The console records the prompt has read and not yet fed to `PasswordEntry`.
//!
//! A read returns up to `BATCH` records, and an entry step can finish in the middle of one: a paste
//! of "\rSecret1\r" is an empty Enter, then a password. The records after the finishing one stay here,
//! for the next step or, once the prompt is over, to be put back into the console for whoever reads it
//! next. Every record is overwritten once consumed and when the batch is dropped.

use windows::Win32::System::Console::INPUT_RECORD;
use zeroize::Zeroize;

use crate::password_entry::{PasswordEntry, Step};
use crate::vtinput::KeyEvent;

/// Records one read takes.
const BATCH: usize = 32;

/// `INPUT_RECORD.EventType` of a key record.
const EVT_KEY: u16 = 0x0001;

pub(super) struct Batch {
    records: [INPUT_RECORD; BATCH],
    /// The first record not yet fed; the records before it are zeroed.
    next: usize,
    len: usize,
}

impl Batch {
    pub fn new() -> Self {
        Batch {
            // SAFETY: `INPUT_RECORD` is plain data; all-zero bytes are a valid value.
            records: unsafe { std::mem::zeroed() },
            next: 0,
            len: 0,
        }
    }

    /// Replace the batch, which must be fed to its end, with the records `read` fills in and counts.
    pub fn fill(
        &mut self,
        read: impl FnOnce(&mut [INPUT_RECORD]) -> windows::core::Result<u32>,
    ) -> windows::core::Result<()> {
        debug_assert!(self.next == self.len, "records not yet fed would be lost");
        self.wipe();
        match read(&mut self.records) {
            Ok(count) => {
                debug_assert!(count as usize <= BATCH);
                self.len = (count as usize).min(BATCH);
                Ok(())
            }
            Err(e) => {
                self.wipe();
                Err(e)
            }
        }
    }

    /// Feed the entry the key records in turn until a step finishes, and return it. The rest stay.
    /// `None` when the batch is fed to its end with no step finished: read the next one.
    pub fn step(&mut self, entry: &mut PasswordEntry) -> Option<Step> {
        while self.next < self.len {
            let mut record = std::mem::replace(&mut self.records[self.next], zeroed_record());
            self.next += 1;
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
                step => return Some(step),
            }
        }
        None
    }

    /// Hand the records not yet fed to `put_back` (in the order they were read), then wipe them.
    pub fn give_back(&mut self, put_back: impl FnOnce(&[INPUT_RECORD])) {
        if self.next < self.len {
            put_back(&self.records[self.next..self.len]);
        }
        self.wipe();
    }

    fn wipe(&mut self) {
        wipe_records(&mut self.records);
        self.next = 0;
        self.len = 0;
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
pub(super) fn wipe_records(records: &mut [INPUT_RECORD]) {
    // SAFETY: `INPUT_RECORD` is plain data; zeroing its bytes in place is sound.
    let bytes =
        unsafe { std::slice::from_raw_parts_mut(records.as_mut_ptr().cast::<u8>(), std::mem::size_of_val(records)) };
    bytes.zeroize();
}

#[cfg(test)]
#[path = "batch_tests.rs"]
mod batch_tests;
