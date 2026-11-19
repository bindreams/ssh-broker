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

/// What the question did to the console, in order: `discard`, and each `write`.
type Log = Rc<RefCell<Vec<String>>>;

/// A [`FakeQueue`] that says when it is discarded.
struct Logged {
    queue: FakeQueue,
    log: Log,
}

impl InputQueue for Logged {
    fn peek(&mut self, records: &mut [INPUT_RECORD]) -> windows::core::Result<u32> {
        self.queue.peek(records)
    }
    fn read(&mut self, records: &mut [INPUT_RECORD]) -> windows::core::Result<u32> {
        self.queue.read(records)
    }
    fn discard(&mut self) -> windows::core::Result<()> {
        self.log.borrow_mut().push("discard".to_owned());
        self.queue.discard()
    }
}

fn logged(queue: FakeQueue) -> (Logged, Log) {
    let log: Log = Rc::default();
    (
        Logged {
            queue,
            log: Rc::clone(&log),
        },
        log,
    )
}

const QUESTION: &str = "ssh-broker: a question\r\nRun it as administrator? [y/N] ";

/// Ask on `console`, writing to `log`.
fn ask(console: &mut Logged, log: &Log, stop: &dyn Fn() -> bool) -> windows::core::Result<ConsentAnswer> {
    let log = Rc::clone(log);
    ask_on(
        console,
        &mut |text: &str| {
            log.borrow_mut().push(format!("write {text}"));
            Ok(())
        },
        QUESTION,
        &CONSENT_ALLOWING_ANSWERS,
        stop,
    )
}

/// P3 and Review Focus 3: what was typed ahead, and what the terminal answered to earlier queries, is thrown away
/// before the question is written and so cannot answer it; mouse, focus and size records that come during it are no
/// answer either. The answer is the first allowing word and Enter after the question.
#[test]
fn typed_ahead_records_are_flushed_before_the_question_and_mouse_focus_and_resize_records_during_it_do_not_answer() {
    // Typed ahead: a yes, which must not be the answer.
    let mut queue = FakeQueue::with(typed("yes\r"));
    queue
        .arrivals
        .push_back(vec![mouse_record(), focus_record(), size_record()]);
    queue.arrivals.push_back(typed("n\r"));
    let (mut console, log) = logged(queue);
    assert_eq!(ask(&mut console, &log, &|| false).unwrap(), ConsentAnswer::Refuse);
    assert_eq!(
        *log.borrow(),
        [
            "discard".to_owned(),
            format!("write {CONSENT_SCREEN_ENTER}{QUESTION}"),
            "write n".to_owned()
        ],
        "the flush, the screen and the question, and the echo"
    );

    // The same with the person's yes after the question.
    let mut queue = FakeQueue::with(typed("no\r"));
    queue
        .arrivals
        .push_back(vec![mouse_record(), focus_record(), size_record()]);
    queue.arrivals.push_back(typed("Y"));
    queue.arrivals.push_back(typed("\r"));
    let (mut console, log) = logged(queue);
    assert_eq!(ask(&mut console, &log, &|| false).unwrap(), ConsentAnswer::Allow);
    assert_eq!(log.borrow().last().map(String::as_str), Some("write Y"));
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
        let (mut console, log) = logged(queue);
        assert_eq!(ask(&mut console, &log, &|| false).unwrap(), expected, "{typed_text:?}");
    }
    // Ctrl+C is a refusal, with the answer typed and without.
    for typed_text in ["", "y"] {
        let mut records = typed(typed_text);
        records.push(key(0x43, 0x03));
        let mut queue = FakeQueue::default();
        queue.arrivals.push_back(records);
        let (mut console, log) = logged(queue);
        assert_eq!(ask(&mut console, &log, &|| false).unwrap(), ConsentAnswer::Refuse);
    }
}

/// The rest of what was typed after the answer stays in the console's queue, for the session.
#[test]
fn what_follows_the_answer_stays_queued() {
    let mut queue = FakeQueue::default();
    queue.arrivals.push_back(typed("y\rls\r"));
    let (mut console, log) = logged(queue);
    assert_eq!(ask(&mut console, &log, &|| false).unwrap(), ConsentAnswer::Allow);
    assert_eq!(console.queue.left(), "ls\r");
}

/// The session ended (or the shim is ending) while the question waits: that is a refusal, and nothing more is written.
#[test]
fn a_stop_refuses_and_writes_nothing_more() {
    let mut queue = FakeQueue::default();
    queue.arrivals.push_back(vec![focus_record()]);
    let (mut console, log) = logged(queue);
    let consulted = Cell::new(0);
    let stop = || {
        consulted.set(consulted.get() + 1);
        consulted.get() >= 2
    };
    assert_eq!(ask(&mut console, &log, &stop).unwrap(), ConsentAnswer::Refuse);
    assert_eq!(
        *log.borrow(),
        ["discard".to_owned(), format!("write {CONSENT_SCREEN_ENTER}{QUESTION}")]
    );
}

#[test]
fn a_failed_read_is_a_refusal() {
    let queue = FakeQueue {
        fail_peek: true,
        ..FakeQueue::default()
    };
    let (mut console, log) = logged(queue);
    assert_eq!(ask(&mut console, &log, &|| false).unwrap(), ConsentAnswer::Refuse);
}

/// A console that cannot be flushed may hold an answer typed ahead, and one that cannot be written to shows no
/// question: neither is asked, and neither reads a key.
#[test]
fn a_console_that_cannot_be_flushed_or_written_is_not_asked() {
    let queue = FakeQueue {
        fail_discard: true,
        ..FakeQueue::default()
    };
    let (mut console, log) = logged(queue);
    assert!(ask(&mut console, &log, &|| false).is_err());
    assert_eq!(*log.borrow(), ["discard".to_owned()], "nothing was written");

    // Nothing arrives, so a read would panic: the question was not asked.
    let (mut console, _log) = logged(FakeQueue::with(typed("y\r")));
    let outcome = ask_on(
        &mut console,
        &mut |_: &str| Err(crate::console_prompt::fake_queue::failure()),
        QUESTION,
        &CONSENT_ALLOWING_ANSWERS,
        &|| false,
    );
    assert!(outcome.is_err());
}
