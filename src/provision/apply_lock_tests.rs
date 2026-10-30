use super::*;
use crate::test_support::TempProfile;
use std::sync::mpsc;

/// Stands in for making the file private, which needs an elevated administrator.
fn not_private(_: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[test]
fn a_free_lock_is_taken_without_waiting() {
    let dir = TempProfile::new("apply-lock-free");
    let lock = acquire_with(not_private, &dir.0.join("apply.lock"), || {
        panic!("nobody holds the lock")
    })
    .unwrap();
    drop(lock);
}

#[test]
fn a_second_holder_waits_for_the_first() {
    let dir = TempProfile::new("apply-lock-contend");
    let lock_path = dir.0.join("apply.lock");
    let first = acquire_with(not_private, &lock_path, || panic!("nobody holds the lock")).unwrap();

    let (waiting, saw_it_held) = mpsc::channel();
    let (taken, second_took_it) = mpsc::channel();
    let second = std::thread::spawn({
        let lock_path = lock_path.clone();
        move || {
            let lock = acquire_with(not_private, &lock_path, || waiting.send(()).unwrap()).unwrap();
            taken.send(()).unwrap();
            drop(lock);
        }
    });
    saw_it_held
        .recv()
        .expect("the second holder did not report that it had to wait");
    drop(first);
    second_took_it.recv().expect("the second holder never got the lock");
    second.join().unwrap();
}

#[test]
fn the_lock_is_released_when_the_holder_drops() {
    let dir = TempProfile::new("apply-lock-drop");
    let lock_path = dir.0.join("apply.lock");
    drop(acquire_with(not_private, &lock_path, || {}).unwrap());
    drop(acquire_with(not_private, &lock_path, || panic!("the first holder let go of it")).unwrap());
}

#[test]
fn the_lock_file_is_made_private_before_the_lock_is_asked_for() {
    let dir = TempProfile::new("apply-lock-private");
    let lock_path = dir.0.join("apply.lock");
    let made = std::cell::RefCell::new(Vec::new());
    let lock = acquire_with(
        |path| {
            made.borrow_mut().push(path.to_path_buf());
            assert!(!path.exists(), "the file is made by the private step, not by the lock");
            Ok(())
        },
        &lock_path,
        || panic!("nobody holds the lock"),
    )
    .unwrap();
    drop(lock);
    assert_eq!(made.into_inner(), [lock_path]);
}

#[test]
fn a_lock_file_that_cannot_be_made_private_is_not_locked_and_not_created() {
    let dir = TempProfile::new("apply-lock-refused");
    let lock_path = dir.0.join("apply.lock");
    let err = acquire_with(
        |_| anyhow::bail!("open to Users"),
        &lock_path,
        || panic!("no wait on a refused file"),
    )
    .unwrap_err();
    assert!(format!("{err:#}").contains("open to Users"), "{err:#}");
    assert!(!lock_path.exists(), "the lock must not create the file itself");
}
