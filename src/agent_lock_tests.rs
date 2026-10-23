//! Tests for the agent's start-up guards. None needs a second session or elevation.
use super::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Threading::CreateMutexW;
use windows::core::PCWSTR;

fn unique(tag: &str) -> String {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("sb-lock-{tag}-{}-{n}", std::process::id())
}

/// A lock file path in a fresh temp dir, removed on drop.
struct TempLock(PathBuf);

impl TempLock {
    fn new(tag: &str) -> TempLock {
        let dir = std::env::temp_dir().join(unique(tag));
        std::fs::create_dir_all(&dir).unwrap();
        TempLock(dir)
    }
    fn path(&self) -> PathBuf {
        self.0.join("agent.lock")
    }
}

impl Drop for TempLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// session_allows_agent -----------------------------------------------------------------

#[test]
fn session_allows_agent_refuses_session_zero() {
    assert!(!session_allows_agent(0), "session 0 is the services session");
    assert!(session_allows_agent(1));
    assert!(session_allows_agent(2));
    assert!(session_allows_agent(u32::MAX), "any other id is an interactive session");
}

// UserLock -----------------------------------------------------------------------------

#[test]
fn user_lock_try_acquire_reports_a_held_lock_as_none() {
    let dir = TempLock::new("held");
    let held = UserLock::try_acquire(&dir.path()).unwrap();
    assert!(held.is_some(), "an unheld lock is acquired");
    assert!(
        UserLock::try_acquire(&dir.path()).unwrap().is_none(),
        "a held lock is not acquired a second time"
    );
}

#[test]
fn user_lock_is_released_when_dropped() {
    let dir = TempLock::new("drop");
    drop(UserLock::try_acquire(&dir.path()).unwrap().unwrap());
    assert!(UserLock::try_acquire(&dir.path()).unwrap().is_some());
}

#[test]
fn locks_on_different_files_do_not_conflict() {
    let a = TempLock::new("a");
    let b = TempLock::new("b");
    let _first = UserLock::try_acquire(&a.path()).unwrap().unwrap();
    assert!(UserLock::try_acquire(&b.path()).unwrap().is_some());
}

#[test]
fn a_waiting_acquire_takes_over_when_the_holder_drops() {
    let dir = TempLock::new("takeover");
    let holder = UserLock::try_acquire(&dir.path()).unwrap().unwrap();

    let (waiting, saw_it_held) = mpsc::channel();
    let (acquired, wait_done) = mpsc::channel();
    let path = dir.path();
    let waiter = std::thread::spawn(move || {
        let lock = UserLock::acquire(&path, || waiting.send(()).unwrap()).unwrap();
        acquired.send(()).unwrap();
        lock
    });

    // The waiter found the lock held and is about to block on it: only now is the drop a
    // hand-over rather than a lock nobody held. Each wait is on the real condition.
    saw_it_held.recv().expect("acquire never reported that it had to wait");
    drop(holder);
    wait_done.recv().expect("the waiter failed instead of taking over");
    let lock = waiter.join().unwrap();
    assert!(
        UserLock::try_acquire(&dir.path()).unwrap().is_none(),
        "the waiter now holds it"
    );
    drop(lock);
}

#[test]
fn acquire_of_a_free_lock_does_not_report_waiting() {
    let dir = TempLock::new("free");
    let lock = UserLock::acquire(&dir.path(), || panic!("nobody holds the lock")).unwrap();
    assert!(UserLock::try_acquire(&dir.path()).unwrap().is_none());
    drop(lock);
}

#[test]
fn try_acquire_on_a_directory_is_an_error_not_a_held_lock() {
    let dir = TempLock::new("isdir");
    // Only a lock violation means "someone else serves"; anything else must be loud.
    assert!(UserLock::try_acquire(&dir.0).is_err());
}

#[test]
fn a_sharing_violation_on_the_lock_file_is_an_error_not_a_held_lock() {
    use std::os::windows::fs::OpenOptionsExt;
    let dir = TempLock::new("share");
    // What a scanner holding the file looks like: it is open, but it is not the lock.
    let _scanner = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .share_mode(0)
        .open(dir.path())
        .unwrap();
    assert!(UserLock::try_acquire(&dir.path()).is_err());
}

// SessionSlot --------------------------------------------------------------------------

#[test]
fn session_slot_second_try_for_the_same_session_is_none() {
    let dir = TempLock::new("slot");
    let first = SessionSlot::try_acquire(&dir.path()).unwrap();
    assert!(first.is_some());
    assert!(SessionSlot::try_acquire(&dir.path()).unwrap().is_none());
}

#[test]
fn session_slot_is_released_on_drop() {
    let dir = TempLock::new("slot-drop");
    drop(SessionSlot::try_acquire(&dir.path()).unwrap().unwrap());
    assert!(SessionSlot::try_acquire(&dir.path()).unwrap().is_some());
}

#[test]
fn session_slots_of_different_sessions_do_not_conflict() {
    let dir = TempLock::new("slot-x");
    let _a = SessionSlot::try_acquire(&dir.0.join("session-1.lock"))
        .unwrap()
        .unwrap();
    assert!(
        SessionSlot::try_acquire(&dir.0.join("session-2.lock"))
            .unwrap()
            .is_some()
    );
}

#[test]
fn a_foreign_object_in_the_session_namespace_cannot_take_the_slot() {
    // The slot used to be the named mutex `Local\ssh-broker-agent`, which any process in the
    // session can create first, whatever account it runs as. It is now a lock on a file in the
    // user's verified folder, so a mutex of that old name means nothing to it.
    let wide: Vec<u16> = r"Local\ssh-broker-agent"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: `wide` is NUL-terminated and outlives the call; the handle is closed below.
    let squatter = unsafe { CreateMutexW(None, true, PCWSTR(wide.as_ptr())) }.unwrap();

    let dir = TempLock::new("slot-squat");
    let slot = SessionSlot::try_acquire(&dir.path()).unwrap();

    // SAFETY: the handle was just created and is closed once.
    let _ = unsafe { CloseHandle(squatter) };
    assert!(slot.is_some(), "the squatter's object did not stop the slot");
}
