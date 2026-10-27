use super::*;
use crate::test_support::TempProfile;
use std::sync::mpsc;

/// Stands in for making the file private, which needs an elevated administrator.
fn not_private(_: &Path) -> anyhow::Result<()> {
    Ok(())
}

fn session(sid: &str) -> String {
    format!("{}{sid}", super::super::session_task::TASK_PREFIX)
}

#[test]
fn a_free_lock_is_taken_without_waiting_and_loads_the_record() {
    let dir = TempProfile::new("apply-lock-free");
    let (lock, owed) = acquire_and_load_with(
        not_private,
        &dir.0.join("apply.lock"),
        &dir.0.join("pending.txt"),
        || panic!("nobody holds the lock"),
    )
    .unwrap();
    assert!(owed.is_empty());
    drop(lock);
}

#[test]
fn a_second_apply_waits_for_the_first_and_reads_the_record_the_first_left() {
    let dir = TempProfile::new("apply-lock-contend");
    let (lock_path, pending) = (dir.0.join("apply.lock"), dir.0.join("pending.txt"));
    let (first, owed) =
        acquire_and_load_with(not_private, &lock_path, &pending, || panic!("nobody holds the lock")).unwrap();
    assert!(owed.is_empty());

    let (waiting, saw_it_held) = mpsc::channel();
    let second = std::thread::spawn({
        let (lock_path, pending) = (lock_path.clone(), pending.clone());
        move || {
            let (lock, owed) =
                acquire_and_load_with(not_private, &lock_path, &pending, || waiting.send(()).unwrap()).unwrap();
            drop(lock);
            owed
        }
    });
    // The second is about to block on the lock. The first, still holding it, records what it
    // disabled: a second that read the record before the lock would miss this.
    saw_it_held
        .recv()
        .expect("the second apply did not report that it had to wait");
    pending_sessions::store(&pending, &[session("a")]).unwrap();
    drop(first);
    assert_eq!(second.join().unwrap(), [session("a")]);
}

#[test]
fn the_lock_is_released_when_the_holder_drops() {
    let dir = TempProfile::new("apply-lock-drop");
    let (lock_path, pending) = (dir.0.join("apply.lock"), dir.0.join("pending.txt"));
    drop(acquire_and_load_with(not_private, &lock_path, &pending, || {}).unwrap());
    drop(
        acquire_and_load_with(not_private, &lock_path, &pending, || {
            panic!("the first apply let go of it")
        })
        .unwrap(),
    );
}

#[test]
fn the_lock_file_is_made_private_before_the_lock_is_asked_for() {
    let dir = TempProfile::new("apply-lock-private");
    let (lock_path, pending) = (dir.0.join("apply.lock"), dir.0.join("pending.txt"));
    let made = std::cell::RefCell::new(Vec::new());
    let (lock, _) = acquire_and_load_with(
        |path| {
            made.borrow_mut().push(path.to_path_buf());
            assert!(!path.exists(), "the file is made by the private step, not by the lock");
            Ok(())
        },
        &lock_path,
        &pending,
        || panic!("nobody holds the lock"),
    )
    .unwrap();
    drop(lock);
    assert_eq!(made.into_inner(), [lock_path]);
}

#[test]
fn a_lock_file_that_cannot_be_made_private_is_not_locked_and_not_created() {
    let dir = TempProfile::new("apply-lock-refused");
    let (lock_path, pending) = (dir.0.join("apply.lock"), dir.0.join("pending.txt"));
    let err = acquire_and_load_with(
        |_| anyhow::bail!("open to Users"),
        &lock_path,
        &pending,
        || panic!("no wait on a refused file"),
    )
    .unwrap_err();
    assert!(format!("{err:#}").contains("open to Users"), "{err:#}");
    assert!(!lock_path.exists(), "the lock must not create the file itself");
}
