//! Tests for the log that opens each day's file under a folder's handle.
use super::*;
use crate::acl;
use crate::test_support::TempProfile;
use std::io::Write;
use std::sync::{Arc, Mutex};
use time::{Date, Month};

fn date(year: i32, month: Month, day: u8) -> Date {
    Date::from_calendar_date(year, month, day).unwrap()
}

/// A folder to log into, and a clock the test moves.
fn folder_and_clock(tag: &str, start: Date) -> (TempProfile, acl::DirHandle, Arc<Mutex<Date>>) {
    let profile = TempProfile::new(tag);
    let dir = acl::open_root(&profile.0).unwrap();
    (profile, dir, Arc::new(Mutex::new(start)))
}

fn clock_of(now: &Arc<Mutex<Date>>) -> impl Fn() -> Date + Send + 'static + use<> {
    let now = Arc::clone(now);
    move || *now.lock().unwrap()
}

#[test]
fn a_new_utc_date_opens_a_new_file_under_the_same_handle() {
    let (profile, dir, now) = folder_and_clock("day", date(2026, Month::January, 1));
    let mut log = DailyLog::new(dir, "shim.log", clock_of(&now)).unwrap();

    log.write_all(b"first\n").unwrap();
    *now.lock().unwrap() = date(2026, Month::January, 2);
    log.write_all(b"second\n").unwrap();
    log.write_all(b"third\n").unwrap();

    let read = |name: &str| std::fs::read_to_string(profile.0.join(name)).unwrap();
    assert_eq!(read("shim.log.2026-01-01"), "first\n");
    assert_eq!(read("shim.log.2026-01-02"), "second\nthird\n");
}

#[test]
fn the_first_file_is_opened_when_the_log_is_made() {
    let (profile, dir, now) = folder_and_clock("first", date(2026, Month::March, 9));
    let _log = DailyLog::new(dir, "agent.log", clock_of(&now)).unwrap();
    assert!(profile.0.join("agent.log.2026-03-09").is_file());
}

#[test]
fn the_file_name_is_what_tracing_appender_would_have_used() {
    let (profile, dir, now) = folder_and_clock("name", date(2026, Month::January, 1));
    // The appender names the file by the UTC date at its creation; a day change between the two
    // reads is allowed for, not a failure.
    let before = time::OffsetDateTime::now_utc().date();
    let _appender = tracing_appender::rolling::RollingFileAppender::builder()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix("shim.log")
        .build(&profile.0)
        .unwrap();
    let after = time::OffsetDateTime::now_utc().date();
    let made: Vec<String> = std::fs::read_dir(&profile.0)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("shim.log"))
        .collect();
    assert_eq!(made.len(), 1, "{made:?}");
    assert!(
        made[0] == file_name("shim.log", before) || made[0] == file_name("shim.log", after),
        "{} is neither {} nor {}",
        made[0],
        file_name("shim.log", before),
        file_name("shim.log", after)
    );
    drop((dir, now));
}

#[test]
fn a_link_named_like_the_first_file_is_refused_when_the_log_is_made() {
    let (profile, dir, now) = folder_and_clock("link", date(2026, Month::January, 1));
    let victim = profile.0.join("victim.txt");
    std::fs::write(&victim, "keep").unwrap();
    std::os::windows::fs::symlink_file(&victim, profile.0.join("shim.log.2026-01-01"))
        .unwrap_or_else(|e| panic!("file symlink: {e} (needs Developer Mode or the symlink privilege)"));

    let err = DailyLog::new(dir, "shim.log", clock_of(&now)).err().expect("refused");

    assert!(format!("{err:#}").contains("shim.log.2026-01-01"), "{err:#}");
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
}

#[test]
fn a_file_that_cannot_be_opened_at_the_date_change_fails_that_write_and_the_next_write_tries_again() {
    let (profile, dir, now) = folder_and_clock("fail", date(2026, Month::January, 1));
    let mut log = DailyLog::new(dir, "shim.log", clock_of(&now)).unwrap();
    let blocker = profile.0.join("shim.log.2026-01-02");
    std::fs::create_dir(&blocker).unwrap();
    *now.lock().unwrap() = date(2026, Month::January, 2);

    assert!(log.write_all(b"lost\n").is_err());
    std::fs::remove_dir(&blocker).unwrap();
    log.write_all(b"kept\n").unwrap();

    assert_eq!(
        std::fs::read_to_string(profile.0.join("shim.log.2026-01-02")).unwrap(),
        "kept\n"
    );
    assert_eq!(
        std::fs::read_to_string(profile.0.join("shim.log.2026-01-01")).unwrap(),
        "",
        "the failed line went nowhere"
    );
}
