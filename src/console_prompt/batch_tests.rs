//! Unit tests for `batch` (pure; the console queue is a fake).
use super::*;
use crate::console_prompt::fake_queue::{FakeQueue, characters, focus_record, key, typed};
use crate::password_entry::{PasswordEntry, Step};

fn is_zeroed(records: &[INPUT_RECORD]) -> bool {
    // SAFETY: `INPUT_RECORD` is plain data.
    let bytes = unsafe { std::slice::from_raw_parts(records.as_ptr().cast::<u8>(), std::mem::size_of_val(records)) };
    bytes.iter().all(|b| *b == 0)
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
    assert!(matches!(
        batch.step(&mut queue, &mut entry, &|| false).unwrap(),
        Step::Empty
    ));
    assert_eq!(queue.left(), "Secret1\r");
    assert_eq!(
        submitted(batch.step(&mut queue, &mut entry, &|| false).unwrap()),
        "Secret1"
    );
    assert_eq!(queue.left(), "");
}

/// The first command typed while the session starts is queued with the password's Enter.
#[test]
fn type_ahead_after_the_password_stays_queued() {
    let mut queue = FakeQueue::with(typed("pw\rls\r"));
    let mut batch = Batch::new();
    let mut entry = PasswordEntry::new();
    assert_eq!(submitted(batch.step(&mut queue, &mut entry, &|| false).unwrap()), "pw");
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
    assert_eq!(submitted(batch.step(&mut queue, &mut entry, &|| false).unwrap()), "pw");
    assert_eq!(queue.left(), command);
}

/// Input typed after the finishing key, while the prompt waits for the agent, is behind the
/// type-ahead that was already queued.
#[test]
fn input_that_arrives_after_the_finishing_key_follows_the_type_ahead() {
    let mut queue = FakeQueue::with(typed("pw\rls\r"));
    let mut batch = Batch::new();
    let mut entry = PasswordEntry::new();
    assert_eq!(submitted(batch.step(&mut queue, &mut entry, &|| false).unwrap()), "pw");
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
    assert!(matches!(
        batch.step(&mut queue, &mut entry, &|| false).unwrap(),
        Step::Cancel
    ));
    assert_eq!(queue.left(), "b");
}

/// Records that are not keys (focus, mouse, resize) after the finishing one stay queued as they are.
#[test]
fn records_that_are_not_keys_stay_queued() {
    let mut records = typed("pw\r");
    records.push(focus_record());
    let mut queue = FakeQueue::with(records);
    let mut batch = Batch::new();
    let mut entry = PasswordEntry::new();
    submitted(batch.step(&mut queue, &mut entry, &|| false).unwrap());
    let types: Vec<u16> = queue.queue.iter().map(|r| r.EventType).collect();
    assert_eq!(types, vec![focus_record().EventType]);
}

/// A password longer than one batch is taken batch by batch, and is one password.
#[test]
fn a_password_longer_than_a_batch_is_one_password() {
    let password: String = ('a'..='z').cycle().take(3 * BATCH + 5).collect();
    let mut queue = FakeQueue::with(typed(&format!("{password}\r")));
    let mut batch = Batch::new();
    let mut entry = PasswordEntry::new();
    assert_eq!(
        submitted(batch.step(&mut queue, &mut entry, &|| false).unwrap()),
        password
    );
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
    assert_eq!(submitted(batch.step(&mut queue, &mut entry, &|| false).unwrap()), "pw");
    assert_eq!(queue.left(), "ls");
}

/// The buffer holds what was typed: it is overwritten before the step returns, the records that
/// stay queued included.
#[test]
fn the_buffer_is_overwritten_when_a_step_returns() {
    let mut queue = FakeQueue::with(typed("pw\rls\r"));
    let mut batch = Batch::new();
    let mut entry = PasswordEntry::new();
    submitted(batch.step(&mut queue, &mut entry, &|| false).unwrap());
    assert!(is_zeroed(&batch.records), "a record kept its content");
}

#[test]
fn a_failed_peek_leaves_nothing_behind() {
    let mut queue = FakeQueue::with(typed("pw"));
    queue.fail_peek = true;
    let mut batch = Batch::new();
    let mut entry = PasswordEntry::new();
    assert!(batch.step(&mut queue, &mut entry, &|| false).is_err());
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
    assert!(batch.step(&mut queue, &mut entry, &|| false).is_err());
    assert!(is_zeroed(&batch.records));
}

/// The console merges a key-down that repeats the last queued one into that record, between the peek
/// and the read. The character is typed as often as the record the read removed says.
#[test]
fn a_key_the_console_repeats_into_the_last_peeked_record_is_typed_every_time() {
    let mut queue = FakeQueue::with(typed("ab"));
    queue.merge_into_tail_after_peek = Some(3);
    queue.arrivals.push_back(typed("\r"));
    let mut batch = Batch::new();
    let mut entry = PasswordEntry::new();
    assert_eq!(
        submitted(batch.step(&mut queue, &mut entry, &|| false).unwrap()),
        "abbb"
    );
    assert_eq!(queue.left(), "");
}

/// A repeat merged into the finishing Enter is the user holding Enter: one submit, and nothing else
/// is taken or changed. (The feed-from-read path is pinned by the two merged-repeat tests beside it,
/// for a character and for Backspace; this one holds with or without it.)
#[test]
fn a_repeat_merged_into_the_finishing_enter_submits_once() {
    let mut queue = FakeQueue::with(typed("pw\r"));
    queue.merge_into_tail_after_peek = Some(4);
    let mut batch = Batch::new();
    let mut entry = PasswordEntry::new();
    assert_eq!(submitted(batch.step(&mut queue, &mut entry, &|| false).unwrap()), "pw");
    assert_eq!(queue.removed, 3);
    assert_eq!(queue.left(), "");
    assert!(entry.backing().iter().all(|unit| *unit == 0), "the entry kept text");
}

/// The console merges a repeated Backspace into the last queued record too: the entry deletes as many
/// characters as the record the read removed says.
#[test]
fn a_backspace_the_console_repeats_into_the_last_peeked_record_deletes_every_time() {
    let mut records = typed("abcd");
    records.push(key(0x08, 0x08));
    let mut queue = FakeQueue::with(records);
    queue.merge_into_tail_after_peek = Some(3);
    queue.arrivals.push_back(typed("\r"));
    let mut batch = Batch::new();
    let mut entry = PasswordEntry::new();
    assert_eq!(submitted(batch.step(&mut queue, &mut entry, &|| false).unwrap()), "a");
    assert_eq!(queue.left(), "");
}

// A generic entry =====

use crate::consent_entry::{ConsentEntry, ConsentStep};

/// The consent question's wake-up: a record that no entry feeds on arrives while the step waits, and the stop is
/// then true. The step ends as stopped, having taken what it read.
#[test]
fn a_stop_ends_a_step_that_is_waiting_for_a_key() {
    let mut queue = FakeQueue::default();
    queue.arrivals.push_back(vec![focus_record()]);
    let consulted = std::cell::Cell::new(0);
    let stop = || {
        consulted.set(consulted.get() + 1);
        consulted.get() >= 2
    };
    let step = Batch::new()
        .step(&mut queue, &mut ConsentEntry::new(&["yes"]), &stop)
        .unwrap();
    assert_eq!(step, ConsentStep::Stopped);
    assert_eq!(queue.removed, 1, "the wake record was read, and nothing else");
}

/// A stop that was already true before the step began is seen before the step blocks: the fake queue panics on a
/// read that would hang.
#[test]
fn a_stop_that_is_already_true_is_seen_before_the_step_waits() {
    let mut queue = FakeQueue::default();
    let step = Batch::new()
        .step(&mut queue, &mut ConsentEntry::new(&["yes"]), &|| true)
        .unwrap();
    assert_eq!(step, ConsentStep::Stopped);
    assert_eq!(queue.removed, 0);
}

/// The record that woke the read is not the only one queued when the stop is looked at: a key typed right behind it
/// belongs to the session, not to the question that was withdrawn, and stays queued for the relay.
#[test]
fn keys_queued_behind_the_record_that_woke_a_stopped_read_stay_in_the_queue() {
    let mut queue = FakeQueue::with(vec![focus_record()]);
    let mut up = key(0x59, 'y' as u16);
    up.Event.KeyEvent.bKeyDown = windows::core::BOOL(0);
    // The wake record, and the person's `y` right behind it, arrive as the read removes the record that was queued.
    queue.typed_after_read = vec![focus_record(), key(0x59, 'y' as u16), up];
    let consulted = std::cell::Cell::new(0);
    let stop = || {
        consulted.set(consulted.get() + 1);
        consulted.get() >= 2
    };
    let step = Batch::new()
        .step(&mut queue, &mut ConsentEntry::new(&["yes", "y"]), &stop)
        .unwrap();
    assert_eq!(step, ConsentStep::Stopped, "nothing was fed, so nothing was typed");
    assert_eq!(queue.removed, 1, "only the record that woke the read was taken");
    assert_eq!(
        queue.queue.len(),
        3,
        "the wake record and the two `y` records stay queued"
    );
    assert_eq!(
        characters(queue.queue.iter().skip(1)),
        "yy",
        "the person's key stays for the relay"
    );
}

/// The stop is looked at after the queue and before anything of it is fed: a withdrawal whose wake record and a key
/// behind it land just before a pass looks at the queue takes nothing of what that pass sees.
#[test]
fn a_stop_that_turns_true_as_the_queue_is_looked_at_feeds_nothing_of_it() {
    let mut up = key(0x59, 'y' as u16);
    up.Event.KeyEvent.bKeyDown = windows::core::BOOL(0);
    let mut queue = FakeQueue::with(vec![focus_record(), key(0x59, 'y' as u16), up]);
    let peeks = std::rc::Rc::clone(&queue.peeks);
    let step = Batch::new()
        .step(&mut queue, &mut ConsentEntry::new(&["yes", "y"]), &|| peeks.get() > 0)
        .unwrap();
    assert_eq!(step, ConsentStep::Stopped, "nothing was fed, so nothing was typed");
    assert_eq!(queue.removed, 0, "the wake record and the key behind it stay queued");
}

/// An entry whose steps are an echo and an answer: each step takes the records up to the one that finished it, and
/// the rest, typed ahead, stays queued.
#[test]
fn a_generic_entry_leaves_the_records_after_the_finishing_one_in_the_queue() {
    let mut queue = FakeQueue::with(typed("y\rlater"));
    let mut batch = Batch::new();
    let mut entry = ConsentEntry::new(&["yes", "y"]);
    assert_eq!(
        batch.step(&mut queue, &mut entry, &|| false).unwrap(),
        ConsentStep::Echo("y".into())
    );
    assert_eq!(queue.left(), "\rlater");
    assert_eq!(
        batch.step(&mut queue, &mut entry, &|| false).unwrap(),
        ConsentStep::Allow
    );
    assert_eq!(queue.left(), "later");
}
