//! Reading the console's input records into a [`KeyEntry`] (`PasswordEntry`, `ConsentEntry`), without taking
//! any it does not feed.
//!
//! A step peeks at the head of the console queue, feeds the records to the entry in turn, and removes
//! from the queue exactly the records it fed, up to and including the one that finished the step. The
//! rest (a paste's remainder, input typed while the agent starts) keeps its place for the next step
//! and, once the prompt is over, for the relay.
//!
//! The console merges a key-down that repeats the last queued one into that record (it raises
//! `wRepeatCount`), so the last peeked record may differ from the one the read removes. That record is
//! fed from the read, with the count it has by then: the password is exactly what was typed. If it is
//! the finishing key, its further repeats are the user holding that key: the prompt ends on the first
//! and drops the rest. Every buffer, and every copy of a record, is overwritten before the step
//! returns.
//!
//! A step that has no key to feed waits for one. The caller's `stop` is looked at after every batch that finished no
//! step, so before each wait; a wait is ended from outside by something that makes `stop` true and then puts a record
//! in the queue, which wakes the read.

use windows::Win32::System::Console::INPUT_RECORD;
use zeroize::Zeroize;

use crate::vtinput::{KeyEntry, KeyEvent};

/// Records one peek takes.
pub(super) const BATCH: usize = 32;

/// `INPUT_RECORD.EventType` of a key record.
const EVT_KEY: u16 = 0x0001;

/// The console's input queue.
pub(super) trait InputQueue {
    /// How many records are in the queue now.
    fn queued(&mut self) -> windows::core::Result<u32>;

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

    /// Take the records that are queued now and give them to `relay`, in order, a batch at a time; never wait for one
    /// that is not. One pass: whatever arrives while this runs is left in the queue, so a sustained stream cannot keep
    /// it from ending. `Ok(false)` when `relay` said the records could not be passed on: the rest stays queued. The
    /// buffer is all zeros on return.
    pub fn drain(
        &mut self,
        queue: &mut impl InputQueue,
        relay: &mut dyn FnMut(&[INPUT_RECORD]) -> bool,
    ) -> windows::core::Result<bool> {
        let result = self.drain_inner(queue, relay);
        self.wipe();
        result
    }

    fn drain_inner(
        &mut self,
        queue: &mut impl InputQueue,
        relay: &mut dyn FnMut(&[INPUT_RECORD]) -> bool,
    ) -> windows::core::Result<bool> {
        let mut left = queue.queued()? as usize;
        while left > 0 {
            let batch = left.min(BATCH);
            // At least `batch` records are there, so this does not wait. The console may have merged a repeat into
            // the last, which the read returns as it is by now: a merge adds no record.
            let taken = (queue.read(&mut self.records[..batch])? as usize).min(batch);
            left -= taken;
            if !relay(&self.records[..taken]) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Block until one entry step finishes, and return it, or until `stop` says so while no step is finishing: then
    /// the step is [`KeyEntry::stopped`]. The records after the finishing one are not taken from the queue. On
    /// return, successful or not, the buffer is all zeros.
    pub fn step<E: KeyEntry>(
        &mut self,
        queue: &mut impl InputQueue,
        entry: &mut E,
        stop: &dyn Fn() -> bool,
    ) -> windows::core::Result<E::Step> {
        let result = self.step_inner(queue, entry, stop);
        self.wipe();
        result
    }

    fn step_inner<E: KeyEntry>(
        &mut self,
        queue: &mut impl InputQueue,
        entry: &mut E,
        stop: &dyn Fn() -> bool,
    ) -> windows::core::Result<E::Step> {
        loop {
            let peeked = (queue.peek(&mut self.records)? as usize).min(BATCH);
            // Only the last record of the queue can change after the peek (the console merges a repeated
            // key-down into it), and it is the last peeked one. The records before it are fed from the
            // peek, and the last is fed from the read that removes it.
            let stable = peeked.saturating_sub(1);
            let (fed, step) = self.feed(stable, entry);
            self.wipe();
            if let Some(step) = step {
                self.take(queue, fed)?;
                return Ok(step);
            }
            self.take(queue, stable)?;
            if stop() {
                return Ok(E::stopped());
            }
            // With an empty queue this waits for a record, which is fed in any case.
            let read = (queue.read(&mut self.records[..1])? as usize).min(1);
            let (_, step) = self.feed(read, entry);
            self.wipe();
            if let Some(step) = step {
                return Ok(step);
            }
        }
    }

    /// Feed the entry the first `len` records in turn until a step finishes. Returns how many were
    /// fed (the finishing one included) and the step. A fed record is overwritten at once, and so are
    /// the copies made of it.
    fn feed<E: KeyEntry>(&mut self, len: usize, entry: &mut E) -> (usize, Option<E::Step>) {
        for (index, slot) in self.records[..len].iter_mut().enumerate() {
            let mut record = std::mem::replace(slot, zeroed_record());
            if record.EventType != EVT_KEY {
                continue;
            }
            // SAFETY: the event type says this is a key record.
            let mut key = unsafe { record.Event.KeyEvent };
            let mut event = KeyEvent {
                virtual_key_code: key.wVirtualKeyCode,
                virtual_scan_code: key.wVirtualScanCode,
                // SAFETY: the character is read as the UTF-16 unit it is.
                unicode_char: unsafe { key.uChar.UnicodeChar },
                key_down: key.bKeyDown.as_bool(),
                control_key_state: key.dwControlKeyState,
                repeat_count: key.wRepeatCount,
            };
            wipe_records(std::slice::from_mut(&mut record));
            // SAFETY: `KEY_EVENT_RECORD` is plain data; all-zero bytes are a valid value.
            unsafe { wipe_plain(&mut key) };
            let step = entry.key(&event);
            // SAFETY: `KeyEvent` is integers and a `bool`; all-zero bytes are a valid value.
            unsafe { wipe_plain(&mut event) };
            if E::finishes_step(&step) {
                return (index + 1, Some(step));
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

/// Overwrite a value that holds typed text.
///
/// # Safety
/// All-zero bytes must be a valid `T`.
unsafe fn wipe_plain<T>(value: &mut T) {
    // SAFETY: the bytes of `value` are writable, and the caller says zeros are a valid `T`.
    let bytes =
        unsafe { std::slice::from_raw_parts_mut(std::ptr::from_mut(value).cast::<u8>(), std::mem::size_of::<T>()) };
    bytes.zeroize();
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
