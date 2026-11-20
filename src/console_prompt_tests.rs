//! Unit tests for `console_prompt`: why the shim has no agent (no account, no console).
use super::*;
use crate::socket_loc::SocketLocationError;
use crate::test_support::TempProfile;
use crate::userdir::NoProfile;

fn some_location() -> anyhow::Result<SocketLocation> {
    Ok(crate::test_support::location_in(std::path::Path::new(r"C:\nowhere")))
}

fn refused() -> anyhow::Result<socket2::Socket> {
    Err(anyhow::anyhow!("a connect that failed for no OS reason"))
}

// absence: the shapes that are not OS codes -----

#[test]
fn absence_of_a_location_without_a_profile_is_no_profile_yet() {
    assert_eq!(absence(&refused(), &Err(NoProfile.into())), Absence::NoProfileYet);
}

#[test]
fn absence_of_a_too_long_path_is_other() {
    let too_long: anyhow::Error = SocketLocationError::TooLong {
        path: std::path::PathBuf::from(r"C:\very\long\agent.sock"),
        bytes: 120,
        max: 107,
    }
    .into();
    assert_eq!(absence(&refused(), &Err(too_long)), Absence::Other);
}

#[test]
fn absence_of_any_other_location_error_is_other() {
    assert_eq!(
        absence(&refused(), &Err(anyhow::anyhow!("the token could not be read"))),
        Absence::Other
    );
}

#[test]
fn absence_of_a_protocol_error_is_other() {
    assert_eq!(absence(&refused(), &some_location()), Absence::Other);
}

#[test]
fn absence_of_an_unobserved_os_code_is_other() {
    for code in [5, 10013, 10061 + 1000] {
        let denied: anyhow::Result<socket2::Socket> = Err(std::io::Error::from_raw_os_error(code).into());
        assert_eq!(absence(&denied, &some_location()), Absence::Other, "code {code}");
    }
}

// absence: the codes Windows returns, observed with real connects -----

/// The raw OS error a real `connect` to `path` fails with.
fn real_connect(path: &std::path::Path) -> anyhow::Result<socket2::Socket> {
    crate::afunix::connect(path)
}

fn code_of(result: &anyhow::Result<socket2::Socket>) -> String {
    match result {
        Ok(_) => "connected".to_string(),
        Err(e) => match e
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::raw_os_error)
        {
            Some(code) => format!("os error {code}"),
            None => format!("no OS code: {e:#}"),
        },
    }
}

#[test]
fn absence_of_a_connect_to_a_missing_folder_is_no_agent() {
    // The profile exists and its `AppData\Local` too, but no agent has made `ssh-broker` yet.
    let profile = TempProfile::new("ab-dir");
    let location = profile.location();
    assert!(!location.dir().exists());
    let connect = real_connect(location.path());
    assert_eq!(
        absence(&connect, &Ok(location)),
        Absence::NoAgent,
        "a connect to a missing folder failed with {}",
        code_of(&connect)
    );
}

#[test]
fn absence_of_a_connect_to_a_missing_file_in_an_existing_folder_is_no_agent() {
    let profile = TempProfile::new("ab-file");
    let location = profile.location();
    std::fs::create_dir_all(location.dir()).unwrap();
    let connect = real_connect(location.path());
    assert_eq!(
        absence(&connect, &Ok(location)),
        Absence::NoAgent,
        "a connect to a missing socket file failed with {}",
        code_of(&connect)
    );
}

/// What `logout` leaves behind: a socket file nobody listens on any more.
#[test]
fn absence_of_a_connect_to_a_stale_socket_file_is_no_agent() {
    let profile = TempProfile::new("ab-stale");
    let location = profile.location();
    crate::userdir::ensure_socket_dir(&location, &crate::acl::Sid::current_user().unwrap()).unwrap();
    drop(crate::afunix::Listener::bind(location.path(), crate::socket_loc::Integrity::Medium).unwrap());
    assert!(
        location.path().exists(),
        "the stale socket file is what is being tested"
    );
    let connect = real_connect(location.path());
    assert_eq!(
        absence(&connect, &Ok(location)),
        Absence::NoAgent,
        "a connect to a stale socket file failed with {}",
        code_of(&connect)
    );
}

// is_no_agent: the same codes, for a caller that has only the connect error -----

#[test]
fn only_the_observed_codes_for_nothing_listening_are_no_agent() {
    for code in [10050, 10061] {
        let error: anyhow::Error = std::io::Error::from_raw_os_error(code).into();
        assert!(is_no_agent(&error), "code {code}");
    }
    for code in [5, 10013, 10048] {
        let error: anyhow::Error = std::io::Error::from_raw_os_error(code).into();
        assert!(!is_no_agent(&error), "code {code}");
    }
    assert!(!is_no_agent(&anyhow::anyhow!("not an OS error")));
}

/// A walk that finds a folder of the way to the socket missing has found no agent, as a connect to a
/// path in a missing folder did.
#[test]
fn a_folder_of_the_walk_that_is_not_there_is_no_agent() {
    let profile = TempProfile::new("no-folder");
    std::fs::remove_dir_all(profile.0.join("AppData")).unwrap();
    let missing = crate::userdir::inspect_socket_dir(&profile.location(), &crate::acl::Sid::current_user().unwrap())
        .err()
        .expect("AppData is not there");

    assert!(is_no_agent(&missing), "{missing:#}");
}

// The consent question on a console -----

use crate::console_prompt::fake_queue::{FakeQueue, focus_record, key, mouse_record, size_record, typed};
use crate::offer::text::{CONSENT_ALLOWING_ANSWERS, CONSENT_SCREEN_ENTER};
use crate::protocol::ConsentAnswer;
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use windows::Win32::System::Console::{FOCUS_EVENT, KEY_EVENT, MOUSE_EVENT, WINDOW_BUFFER_SIZE_EVENT};

/// What the question did to the console and the relay, in order: each `relay` of records and each `write`.
type Log = Rc<RefCell<Vec<String>>>;

const QUESTION: &str = "ssh-broker: a question\r\nRun it as administrator? [y/N] ";

/// The records as text: a key is its character, any other record its kind.
fn described(records: &[INPUT_RECORD]) -> String {
    records
        .iter()
        .map(|record| match u32::from(record.EventType) {
            KEY_EVENT => {
                // SAFETY: the event type says this is a key record.
                let unit = unsafe { record.Event.KeyEvent.uChar.UnicodeChar };
                String::from_utf16(&[unit]).unwrap()
            }
            MOUSE_EVENT => "<mouse>".to_owned(),
            FOCUS_EVENT => "<focus>".to_owned(),
            WINDOW_BUFFER_SIZE_EVENT => "<size>".to_owned(),
            other => format!("<{other}>"),
        })
        .collect()
}

/// Ask on `queue`, logging to `log` what is written and what is relayed.
fn ask(queue: &mut FakeQueue, log: &Log, stop: &dyn Fn() -> bool) -> windows::core::Result<ConsentAnswer> {
    ask_relaying(queue, log, &mut |_| true, stop)
}

/// [`ask`] with `relay_ok` answering whether the relayed records could be sent.
fn ask_relaying(
    queue: &mut FakeQueue,
    log: &Log,
    relay_ok: &mut dyn FnMut(&[INPUT_RECORD]) -> bool,
    stop: &dyn Fn() -> bool,
) -> windows::core::Result<ConsentAnswer> {
    let (writes, relays) = (Rc::clone(log), Rc::clone(log));
    ask_on(
        queue,
        &mut |text: &str| {
            writes.borrow_mut().push(format!("write {text}"));
            Ok(())
        },
        &mut |records: &[INPUT_RECORD]| {
            relays.borrow_mut().push(format!("relay {}", described(records)));
            relay_ok(records)
        },
        QUESTION,
        &CONSENT_ALLOWING_ANSWERS,
        stop,
    )
}

/// What was typed or pasted before the question is the session's: it is relayed, in order and whole, before the question
/// is written, and cannot answer it. Mouse, focus and size records that come during the question are no answer
/// either. The answer is the first allowing word and Enter after the question.
#[test]
fn records_queued_before_the_question_are_relayed_in_order_before_it_and_mouse_focus_and_resize_records_during_it_do_not_answer()
 {
    // Typed ahead: a yes, which must not be the answer.
    let mut ahead = typed("ye");
    ahead.push(mouse_record());
    ahead.extend(typed("s\r"));
    let mut queue = FakeQueue::with(ahead);
    queue
        .arrivals
        .push_back(vec![mouse_record(), focus_record(), size_record()]);
    queue.arrivals.push_back(typed("n\r"));
    let log = Log::default();
    assert_eq!(ask(&mut queue, &log, &|| false).unwrap(), ConsentAnswer::Refuse);
    assert_eq!(
        *log.borrow(),
        [
            "relay ye<mouse>s\r".to_owned(),
            format!("write {CONSENT_SCREEN_ENTER}{QUESTION}"),
            "write n".to_owned()
        ],
        "the typed-ahead records, the screen and the question, and the echo"
    );

    // The same with the person's yes after the question.
    let mut queue = FakeQueue::with(typed("no\r"));
    queue
        .arrivals
        .push_back(vec![mouse_record(), focus_record(), size_record()]);
    queue.arrivals.push_back(typed("Y"));
    queue.arrivals.push_back(typed("\r"));
    let log = Log::default();
    assert_eq!(ask(&mut queue, &log, &|| false).unwrap(), ConsentAnswer::Allow);
    assert_eq!(log.borrow().first().map(String::as_str), Some("relay no\r"));
    assert_eq!(log.borrow().last().map(String::as_str), Some("write Y"));
}

/// A paste longer than one batch is relayed whole, in order.
#[test]
fn a_paste_longer_than_one_batch_is_relayed_whole() {
    let paste: String = ('a'..='z').cycle().take(3 * batch::BATCH + 5).collect();
    let mut queue = FakeQueue::with(typed(&paste));
    queue.arrivals.push_back(typed("n\r"));
    let log = Log::default();
    assert_eq!(ask(&mut queue, &log, &|| false).unwrap(), ConsentAnswer::Refuse);
    let relayed: String = log
        .borrow()
        .iter()
        .filter_map(|entry| entry.strip_prefix("relay "))
        .collect();
    assert_eq!(relayed, paste);
}

/// With nothing queued nothing is relayed, and the question does not wait for anything before it is written.
#[test]
fn a_console_with_nothing_queued_relays_nothing_and_does_not_wait() {
    let mut queue = FakeQueue::default();
    queue.arrivals.push_back(typed("n\r"));
    let log = Log::default();
    assert_eq!(ask(&mut queue, &log, &|| false).unwrap(), ConsentAnswer::Refuse);
    assert_eq!(
        *log.borrow(),
        [format!("write {CONSENT_SCREEN_ENTER}{QUESTION}"), "write n".to_owned()]
    );
}

/// The drain is one pass over what is queued when the question is taken: what arrives while it runs arrived after the
/// question was asked, so it is the person's answer and not the session's, and a stream that does not stop cannot keep
/// the question from appearing.
#[test]
fn what_arrives_during_the_drain_is_not_drained() {
    let paste: String = ('a'..='z').cycle().take(2 * batch::BATCH + 5).collect();
    let mut queue = FakeQueue::with(typed(&paste));
    queue.typed_after_read = typed("late");
    queue.arrivals.push_back(typed("\r"));
    let log = Log::default();
    assert_eq!(ask(&mut queue, &log, &|| false).unwrap(), ConsentAnswer::Refuse);
    let relayed: String = log
        .borrow()
        .iter()
        .filter_map(|entry| entry.strip_prefix("relay "))
        .collect();
    assert_eq!(relayed, paste, "only what was queued when the question was taken");
    assert_eq!(
        log.borrow().iter().filter(|entry| entry.starts_with("write ")).count(),
        // The question, then the echo of each of the four late characters.
        1 + 4,
        "the late records came after the question and were read as its answer: {:?}",
        log.borrow()
    );
}

/// A question withdrawn, or a shim stopped, while the drain ran paints nothing: the screen is not cleared for a
/// question that is already over.
#[test]
fn a_stop_that_is_true_after_the_drain_paints_nothing() {
    let mut queue = FakeQueue::with(typed("ls\r"));
    let log = Log::default();
    assert_eq!(ask(&mut queue, &log, &|| true).unwrap(), ConsentAnswer::Refuse);
    assert_eq!(*log.borrow(), ["relay ls\r".to_owned()], "relayed, and nothing written");
}

/// Records that cannot be relayed mean the connection is gone: the question is not written.
#[test]
fn a_relay_that_fails_refuses_and_writes_nothing() {
    let mut queue = FakeQueue::with(typed("ls\r"));
    let log = Log::default();
    assert_eq!(
        ask_relaying(&mut queue, &log, &mut |_| false, &|| false).unwrap(),
        ConsentAnswer::Refuse
    );
    assert_eq!(*log.borrow(), ["relay ls\r".to_owned()]);
}

#[test]
fn y_yes_and_any_case_allow_and_anything_else_refuses() {
    for (typed_text, expected) in [
        ("y\r", ConsentAnswer::Allow),
        ("yes\r", ConsentAnswer::Allow),
        ("YES\r", ConsentAnswer::Allow),
        ("\r", ConsentAnswer::Refuse),
        ("n\r", ConsentAnswer::Refuse),
        ("no\r", ConsentAnswer::Refuse),
        ("ye\r", ConsentAnswer::Refuse),
        (" y\r", ConsentAnswer::Refuse),
        ("yess\r", ConsentAnswer::Refuse),
    ] {
        let mut queue = FakeQueue::default();
        queue.arrivals.push_back(typed(typed_text));
        assert_eq!(
            ask(&mut queue, &Log::default(), &|| false).unwrap(),
            expected,
            "{typed_text:?}"
        );
    }
    // Ctrl+C is a refusal, with the answer typed and without.
    for typed_text in ["", "y"] {
        let mut records = typed(typed_text);
        records.push(key(0x43, 0x03));
        let mut queue = FakeQueue::default();
        queue.arrivals.push_back(records);
        assert_eq!(
            ask(&mut queue, &Log::default(), &|| false).unwrap(),
            ConsentAnswer::Refuse
        );
    }
}

/// The rest of what was typed after the answer stays in the console's queue, for the session.
#[test]
fn what_follows_the_answer_stays_queued() {
    let mut queue = FakeQueue::default();
    queue.arrivals.push_back(typed("y\rls\r"));
    assert_eq!(
        ask(&mut queue, &Log::default(), &|| false).unwrap(),
        ConsentAnswer::Allow
    );
    assert_eq!(queue.left(), "ls\r");
}

/// The session ended (or the shim is ending) while the question waits: that is a refusal, and nothing more is written.
#[test]
fn a_stop_refuses_and_writes_nothing_more() {
    let mut queue = FakeQueue::default();
    queue.arrivals.push_back(vec![focus_record()]);
    let log = Log::default();
    let consulted = Cell::new(0);
    let stop = || {
        consulted.set(consulted.get() + 1);
        consulted.get() >= 2
    };
    assert_eq!(ask(&mut queue, &log, &stop).unwrap(), ConsentAnswer::Refuse);
    assert_eq!(*log.borrow(), [format!("write {CONSENT_SCREEN_ENTER}{QUESTION}")]);
}

#[test]
fn a_failed_read_of_the_answer_is_a_refusal() {
    let mut queue = FakeQueue {
        fail_read: true,
        ..FakeQueue::default()
    };
    assert_eq!(
        ask(&mut queue, &Log::default(), &|| false).unwrap(),
        ConsentAnswer::Refuse
    );
}

/// A console whose queue cannot be read, so that what is typed ahead cannot be relayed, or that cannot be written
/// to, shows no question: it is not asked, and reads no key.
#[test]
fn a_console_that_cannot_be_read_or_written_is_not_asked() {
    let mut queue = FakeQueue {
        fail_peek: true,
        ..FakeQueue::default()
    };
    let log = Log::default();
    assert!(ask(&mut queue, &log, &|| false).is_err());
    assert!(log.borrow().is_empty(), "nothing was written");

    // Nothing arrives, so a read for the answer would panic: the question was not asked.
    let mut queue = FakeQueue::with(typed("y\r"));
    let outcome = ask_on(
        &mut queue,
        &mut |_: &str| Err(crate::console_prompt::fake_queue::failure()),
        &mut |_: &[INPUT_RECORD]| true,
        QUESTION,
        &CONSENT_ALLOWING_ANSWERS,
        &|| false,
    );
    assert!(outcome.is_err());
}
