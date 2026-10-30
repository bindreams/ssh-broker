//! Tests for `starting_agent` on real lock files in a temp folder. No account, no machine state.
use super::*;
use crate::agent_lock::UserLock;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use windows::Win32::Foundation::WAIT_OBJECT_0;
use windows::Win32::System::Threading::{INFINITE, WaitForSingleObject};

/// A folder for a lock file, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> TempDir {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("sb-starting-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }

    fn lock(&self) -> PathBuf {
        self.0.join("agent.lock")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn is_signaled(watch: &HolderWatch, wait: u32) -> bool {
    // SAFETY: a valid event handle owned by `watch`.
    let woke = unsafe { WaitForSingleObject(watch.handle(), wait) }; // sleep-ok: wait 0 is a look, and INFINITE is a wait on the real condition
    woke == WAIT_OBJECT_0
}

#[test]
fn a_lock_an_agent_holds_is_a_starting_agent() {
    let dir = TempDir::new("held");
    let _agent = UserLock::try_acquire(&dir.lock()).unwrap().unwrap();
    assert!(is_held(&dir.lock()).unwrap());
}

#[test]
fn a_leftover_lock_file_is_no_agent() {
    let dir = TempDir::new("left");
    drop(UserLock::try_acquire(&dir.lock()).unwrap().unwrap());
    assert!(dir.lock().is_file(), "the file stays after the agent");
    assert!(!is_held(&dir.lock()).unwrap());
}

#[test]
fn a_user_who_never_had_an_agent_has_no_lock_and_nothing_is_created() {
    let dir = TempDir::new("never");
    assert!(!is_held(&dir.lock()).unwrap());
    assert!(
        !dir.lock().exists(),
        "looking must not create the file an agent will lock"
    );
}

#[test]
fn checking_does_not_keep_an_agent_waiting_for_the_lock() {
    let dir = TempDir::new("brief");
    assert!(!is_held(&dir.lock()).unwrap());
    assert!(
        UserLock::try_acquire(&dir.lock()).unwrap().is_some(),
        "the check must have released the lock"
    );
}

#[test]
fn the_holder_watch_signals_when_the_holder_ends_and_not_before() {
    let dir = TempDir::new("watch");
    let agent = UserLock::try_acquire(&dir.lock()).unwrap().unwrap();
    let watch = HolderWatch::start(&dir.lock()).unwrap();
    assert!(!is_signaled(&watch, 0), "the holder is still there");
    drop(agent);
    assert!(is_signaled(&watch, INFINITE), "the holder ended");
}

#[test]
fn the_holder_watch_does_not_keep_the_lock_after_it_signals() {
    let dir = TempDir::new("release");
    let agent = UserLock::try_acquire(&dir.lock()).unwrap().unwrap();
    let watch = HolderWatch::start(&dir.lock()).unwrap();
    drop(agent);
    assert!(is_signaled(&watch, INFINITE));
    assert!(
        UserLock::try_acquire(&dir.lock()).unwrap().is_some(),
        "an agent that takes over must find the lock free"
    );
}
