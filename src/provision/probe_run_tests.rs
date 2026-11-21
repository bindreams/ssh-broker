//! Tests for which probes `doctor` runs, how it asks each, what it makes of the answers and what it cleans
//! up after them, with the probes driven by a stand-in that answers as a probe would and makes the
//! directory a make-probe makes, with the product's own maker, and a junction in it that leads outside.
use std::cell::RefCell;
use std::ffi::OsString;
use std::fs::File;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use super::*;
use crate::account::{INTEGRITY_HIGH, INTEGRITY_MEDIUM};
use crate::protocol::ElevationPolicy;
use crate::provision::probe::{ProbeResult, SymlinkState, UpstreamState};
use crate::provision::session_rows::parity_rows;
use crate::socket_loc::{Elevation, StepDown};
use crate::test_support::Scratch;

fn answer(elevation: Elevation, integrity: u32, symlink: Option<SymlinkState>, said: &str) -> ProbeOutcome {
    ProbeOutcome::Answered(Answer {
        result: ProbeResult {
            session_id: 1,
            dpapi_ok: true,
            symlink,
            upstream: UpstreamState::Ok,
            logon_type: Some(2),
            elevation: Some(elevation),
            integrity: Some(integrity),
        },
        binary_ok: true,
        junction_said: said.to_string(),
        token_said: String::new(),
    })
}

/// What each probe of a run is asked, in order, and how the stand-in answers each: a probe that is told to
/// make a directory makes it (as the real one does, with a junction in it that leads to a folder outside
/// it); the answer is `made` for a probe that `account::step_down` gives a token and `followed` for one that
/// it gives the agent's own.
struct Probing {
    made: fn() -> ProbeOutcome,
    followed: fn() -> ProbeOutcome,
    asked: RefCell<Vec<(ElevationPolicy, ProbeLink)>>,
    /// The folder the junctions lead to, with a file in it that nothing may touch.
    outside: Scratch,
    /// Whether the maker keeps a file of what it made open, which stops the directory from being removed.
    hold: bool,
    held: RefCell<Vec<File>>,
}

impl Probing {
    fn new(made: fn() -> ProbeOutcome, followed: fn() -> ProbeOutcome) -> Probing {
        let outside = Scratch::new();
        std::fs::write(outside.0.join("keep.txt"), b"keep").unwrap();
        Probing {
            made,
            followed,
            asked: RefCell::default(),
            outside,
            hold: false,
            held: RefCell::default(),
        }
    }

    fn holding(mut self) -> Probing {
        self.hold = true;
        self
    }

    fn run(&self, integrity: Integrity, temp: &Path) -> Probes {
        run_at(integrity, temp, &|elevation, link| {
            self.asked.borrow_mut().push((elevation, link.clone()));
            if let ProbeLink::Make(dir) = &link {
                self.make(Path::new(dir));
            }
            match crate::account::step_down(Some(elevation), || Ok(integrity), || Ok(())) {
                Ok(StepDown::Token(())) => (self.made)(),
                Ok(StepDown::Own) => (self.followed)(),
                other => panic!("a probe asking for {elevation:?} at {integrity:?} gets {other:?}"),
            }
        })
    }

    /// Make the directory as a probe does, and point its junction at the folder outside.
    fn make(&self, dir: &Path) {
        probe::link::make(dir).unwrap();
        let link = dir.join("link");
        std::fs::remove_dir(&link).unwrap();
        crate::test_support::junction(&link, &self.outside.0);
        if self.hold {
            // No sharing at all: the file cannot be deleted while it is open.
            let file = std::fs::OpenOptions::new()
                .read(true)
                .share_mode(0)
                .open(dir.join("target").join("parity.txt"))
                .unwrap();
            self.held.borrow_mut().push(file);
        }
    }

    fn links(&self) -> Vec<ProbeLink> {
        self.asked.borrow().iter().map(|(_, link)| link.clone()).collect()
    }

    /// What was behind the junction is still there, whole.
    fn assert_outside_intact(&self) {
        assert_eq!(std::fs::read(self.outside.0.join("keep.txt")).unwrap(), b"keep");
    }
}

/// A probe whose relay broke before its child's exit: whether the child still runs is not known.
fn broke(cause: &str) -> ProbeOutcome {
    ProbeOutcome::Failed {
        cause: cause.into(),
        may_still_run: true,
    }
}

/// A probe whose relay ended with its child's exit, with no PROBE line to read.
fn exited(cause: &str) -> ProbeOutcome {
    ProbeOutcome::Failed {
        cause: cause.into(),
        may_still_run: false,
    }
}

fn unelevated_ok() -> ProbeOutcome {
    answer(Elevation::Filtered, INTEGRITY_MEDIUM, Some(SymlinkState::Ok), "")
}

fn elevated_ok() -> ProbeOutcome {
    answer(Elevation::Full, INTEGRITY_HIGH, Some(SymlinkState::Ok), "")
}

/// The junction the run found, as its state and note, or `None` for no junction from below High.
fn read(probes: &Probes) -> Option<(Option<SymlinkState>, &str)> {
    match &probes.junction {
        Junction::Read { state, note } => Some((*state, note)),
        Junction::Unavailable { .. } | Junction::Unread { .. } => None,
    }
}

/// Why no junction from below High could be tested, and what the probes said.
fn unavailable(probes: &Probes) -> (&str, &str) {
    match &probes.junction {
        Junction::Unavailable { cause, note } => (cause, note),
        other => panic!("expected no junction from below High, got {other:?}"),
    }
}

fn row_names(rows: &[crate::provision::report::Check]) -> Vec<&str> {
    rows.iter().map(|row| row.name).collect()
}

fn is_answered(outcome: &ProbeOutcome) -> bool {
    matches!(outcome, ProbeOutcome::Answered(_))
}

// the agent is at High ---------------------------------------------------------------------

/// One directory goes to both probes, and `doctor` removes it without following the junction in it.
#[test]
fn an_agent_at_high_gets_two_probes_with_one_directory_which_is_removed() {
    let scratch = Scratch::new();
    let probing = Probing::new(
        || answer(Elevation::Filtered, INTEGRITY_MEDIUM, Some(SymlinkState::Ok), "made it"),
        || answer(Elevation::Full, INTEGRITY_HIGH, Some(SymlinkState::Blocked), "refused"),
    );

    let probes = probing.run(Integrity::High, &scratch.0);

    let links = probing.links();
    let [ProbeLink::Make(made), ProbeLink::Follow(followed)] = links.as_slice() else {
        panic!("expected a make and a follow, got {links:?}");
    };
    assert_eq!(made, followed);
    assert_eq!(Path::new(made).parent(), Some(scratch.0.as_path()));
    assert!(scratch.is_empty(), "the directory and what is in it are removed");
    probing.assert_outside_intact();
    assert_eq!(probes.leftover, None);
    assert!(is_answered(&probes.session));
    let (state, note) = read(&probes).expect("a junction from below High was read");
    assert_eq!(state, Some(SymlinkState::Blocked));
    assert!(note.contains("made it") && note.contains("refused"), "{note}");
}

/// The junction is made by the session probe (the default level) and followed by the `always` probe, in that order.
#[test]
fn an_agent_at_high_is_probed_with_prompt_then_always() {
    let scratch = Scratch::new();
    let probing = Probing::new(unelevated_ok, elevated_ok);

    probing.run(Integrity::High, &scratch.0);

    assert_eq!(
        probing.asked.borrow().iter().map(|(p, _)| *p).collect::<Vec<_>>(),
        [ElevationPolicy::Prompt, ElevationPolicy::Always]
    );
}

/// An agent below High gives its own token to every policy but refuses `always`: it is asked the default.
#[test]
fn an_agent_below_high_is_probed_once_with_prompt() {
    let scratch = Scratch::new();
    let probing = Probing::new(unelevated_ok, elevated_ok);

    probing.run(Integrity::Medium, &scratch.0);

    assert_eq!(
        probing.asked.borrow().iter().map(|(p, _)| *p).collect::<Vec<_>>(),
        [ElevationPolicy::Prompt]
    );
}

/// A probe that failed may still create the directory, so `doctor` says so; the `always` probe runs on.
#[test]
fn a_failed_session_probe_gives_the_may_still_create_note_and_the_always_probe_runs_without_a_junction() {
    let scratch = Scratch::new();
    let probing = Probing::new(
        || broke("probe relay failed (code 254)"),
        || answer(Elevation::Full, INTEGRITY_HIGH, None, "the probe was given no junction"),
    );

    let probes = probing.run(Integrity::High, &scratch.0);

    assert!(scratch.is_empty(), "the directory the first probe made is removed");
    probing.assert_outside_intact();
    let links = probing.links();
    let [ProbeLink::Make(dir), ProbeLink::NoJunction] = links.as_slice() else {
        panic!("expected a make and a probe with no junction, got {links:?}");
    };
    let leftover = probes.leftover.as_deref().expect("a note that the directory may come");
    assert!(leftover.contains(dir.as_str()), "{leftover}");
    assert!(leftover.contains("may still create"), "{leftover}");
    assert!(matches!(&probes.session, ProbeOutcome::Failed { cause, .. } if cause.contains("code 254")));
    assert!(matches!(&probes.elevated, Some(ProbeOutcome::Answered(_))));
    let (cause, note) = unavailable(&probes);
    assert!(cause.contains("code 254"), "{cause}");
    assert!(
        note.contains("no junction"),
        "the always probe's words are kept: {note}"
    );
}

/// An agent that is not answering is not waited on a second time.
#[test]
fn a_timed_out_first_probe_starts_no_second_probe_and_leaves_a_warning() {
    let scratch = Scratch::new();
    let probing = Probing::new(
        || ProbeOutcome::TimedOut("no output within 30s".into()),
        || panic!("no second probe may be started"),
    );

    let probes = probing.run(Integrity::High, &scratch.0);

    assert_eq!(probing.asked.borrow().len(), 1);
    assert!(matches!(&probes.session, ProbeOutcome::TimedOut(_)));
    assert!(
        matches!(&probes.elevated, Some(ProbeOutcome::NotRun(why)) if why.contains("did not answer the first probe")),
        "{:?}",
        probes.elevated
    );
    assert!(scratch.is_empty());
    let leftover = probes
        .leftover
        .as_deref()
        .expect("a warning that the directory may come");
    let links = probing.links();
    let [ProbeLink::Make(dir)] = links.as_slice() else {
        panic!("expected a make, got {links:?}");
    };
    assert!(leftover.contains(dir.as_str()), "{leftover}");
    assert!(leftover.contains("may still create"), "{leftover}");
    assert!(leftover.contains("delete"), "{leftover}");
    assert!(unavailable(&probes).0.contains("no output within 30s"));
}

/// A junction made as an elevated process proves nothing about RedirectionGuard.
#[test]
fn a_maker_at_high_gets_no_follower_and_a_failing_junction() {
    let scratch = Scratch::new();
    let probing = Probing::new(
        || {
            answer(
                Elevation::Full,
                INTEGRITY_HIGH,
                Some(SymlinkState::Ok),
                "made by the elevated one",
            )
        },
        elevated_ok,
    );

    let probes = probing.run(Integrity::High, &scratch.0);

    assert!(matches!(
        probing.links().as_slice(),
        [ProbeLink::Make(_), ProbeLink::NoJunction]
    ));
    let (cause, note) = unavailable(&probes);
    assert!(cause.contains("below High"), "{cause}");
    assert!(note.contains("made by the elevated one"), "{note}");
    assert!(scratch.is_empty());
    assert_eq!(probes.leftover, None, "the maker answered");
}

/// A maker that did not report its level is not known to be below High.
#[test]
fn a_maker_that_did_not_report_its_level_gets_no_follower() {
    let scratch = Scratch::new();
    let probing = Probing::new(
        || {
            let ProbeOutcome::Answered(mut made) = unelevated_ok() else {
                unreachable!("unelevated_ok answers")
            };
            made.result.integrity = None;
            ProbeOutcome::Answered(made)
        },
        elevated_ok,
    );

    let probes = probing.run(Integrity::High, &scratch.0);

    assert!(matches!(
        probing.links().as_slice(),
        [ProbeLink::Make(_), ProbeLink::NoJunction]
    ));
    assert!(unavailable(&probes).0.contains("did not report"));
}

/// A maker that reported no link outcome did not make a junction: it is not taken for one that was made.
#[test]
fn a_maker_that_reported_no_junction_outcome_gets_no_follower() {
    let scratch = Scratch::new();
    let probing = Probing::new(|| answer(Elevation::Filtered, INTEGRITY_MEDIUM, None, ""), elevated_ok);

    let probes = probing.run(Integrity::High, &scratch.0);

    assert!(matches!(
        probing.links().as_slice(),
        [ProbeLink::Make(_), ProbeLink::NoJunction]
    ));
    assert!(unavailable(&probes).0.contains("did not report its junction"));
}

/// A maker that could not make the junction gives none to follow.
#[test]
fn a_directory_that_could_not_be_made_gives_no_junction_from_below_high() {
    let scratch = Scratch::new();
    let probing = Probing::new(
        || {
            answer(
                Elevation::Filtered,
                INTEGRITY_MEDIUM,
                Some(SymlinkState::NotMade),
                "making a junction failed: access denied",
            )
        },
        elevated_ok,
    );

    let probes = probing.run(Integrity::High, &scratch.0);

    assert!(matches!(
        probing.links().as_slice(),
        [ProbeLink::Make(_), ProbeLink::NoJunction]
    ));
    let (_, note) = unavailable(&probes);
    assert!(note.contains("access denied"), "{note}");
}

/// A volume that holds no junctions was not tested, which fails nothing.
#[test]
fn a_volume_without_junctions_is_not_tested() {
    let scratch = Scratch::new();
    let probing = Probing::new(
        || {
            answer(
                Elevation::Filtered,
                INTEGRITY_MEDIUM,
                Some(SymlinkState::Skipped),
                "the volume holds no junctions",
            )
        },
        elevated_ok,
    );

    let probes = probing.run(Integrity::High, &scratch.0);

    assert!(matches!(
        probing.links().as_slice(),
        [ProbeLink::Make(_), ProbeLink::NoJunction]
    ));
    let (state, note) = read(&probes).expect("the junction is judged");
    assert_eq!(state, Some(SymlinkState::Skipped));
    assert!(note.contains("holds no junctions"), "{note}");
    assert!(scratch.is_empty());
}

/// A failed session probe takes its own rows with it and no others.
#[test]
fn a_failed_session_probe_keeps_the_elevated_row_and_the_leftover() {
    let scratch = Scratch::new();
    let probing = Probing::new(
        || ProbeOutcome::TimedOut("no output within 30s".into()),
        || broke("relay: refused"),
    );
    let probes = probing.run(Integrity::High, &scratch.0);
    // A timed-out first probe starts no second one, so the probe of `always` here is the one that did not run.
    assert!(matches!(&probes.elevated, Some(ProbeOutcome::NotRun(_))));

    let rows = parity_rows(&probes, 1);

    let names: Vec<&str> = rows.iter().map(|row| row.name).collect();
    assert_eq!(
        names,
        [
            "parity probe (via agent)",
            "elevated session on request",
            "junction directory"
        ]
    );

    // The session probe is the one that did not answer, whichever way it did not.
    let failing = Probing::new(|| exited("no PROBE line in probe output: refused"), elevated_ok);
    let probes = failing.run(Integrity::High, &scratch.0);
    assert!(matches!(&probes.session, ProbeOutcome::Failed { .. }));
    let rows = parity_rows(&probes, 1);
    let names: Vec<&str> = rows.iter().map(|row| row.name).collect();
    assert_eq!(names, ["parity probe (via agent)", "elevated session on request"]);
    assert!(rows[0].detail.contains("refused"), "{}", rows[0].detail);
    assert!(rows[1].pass, "{}", rows[1].detail);
}

/// A failed `always` probe takes its own row and the junction it reads with it, and no other: the session rows
/// are the session probe's, which answered.
#[test]
fn a_failed_always_probe_keeps_the_session_rows() {
    let scratch = Scratch::new();
    let probing = Probing::new(unelevated_ok, || exited("no PROBE line in probe output: refused"));

    let probes = probing.run(Integrity::High, &scratch.0);

    assert!(is_answered(&probes.session));
    assert!(matches!(&probes.elevated, Some(ProbeOutcome::Failed { .. })));
    let rows = parity_rows(&probes, 1);
    let failing: Vec<&str> = rows.iter().filter(|row| !row.pass).map(|row| row.name).collect();
    assert_eq!(failing, ["elevated session on request", "junction (via agent)"]);
    let session = rows.iter().find(|row| row.name == "session").expect("a session row");
    assert!(session.pass, "{}", session.detail);
}

/// A directory that cannot be told to a probe as text is not given to one.
#[test]
fn a_temp_directory_that_is_not_text_gives_no_junction_and_runs_the_probes() {
    let not_text = PathBuf::from(OsString::from_wide(&[u16::from(b'C'), u16::from(b':'), 0xD800]));
    assert!(not_text.to_str().is_none(), "control: not Unicode text");
    let probing = Probing::new(unelevated_ok, elevated_ok);

    let probes = probing.run(Integrity::High, &not_text);

    assert_eq!(probing.links(), [ProbeLink::NoJunction, ProbeLink::NoJunction]);
    assert!(unavailable(&probes).0.contains("text"));
    assert!(is_answered(&probes.session));
    assert_eq!(probes.leftover, None, "no probe was told the directory");

    let probing = Probing::new(unelevated_ok, elevated_ok);
    let probes = probing.run(Integrity::Medium, &not_text);

    assert_eq!(probing.links(), [ProbeLink::NoJunction]);
    assert!(unavailable(&probes).0.contains("text"));
}

// the agent is below High ------------------------------------------------------------------

/// The one probe below High makes and follows a junction in the directory `doctor` named, and `doctor` removes it.
#[test]
fn an_agent_below_high_has_one_probe_with_a_directory_that_doctor_removes() {
    let scratch = Scratch::new();
    let probing = Probing::new(unelevated_ok, || {
        answer(
            Elevation::Standard,
            INTEGRITY_MEDIUM,
            Some(SymlinkState::Ok),
            "reading through the junction was slow",
        )
    });

    let probes = probing.run(Integrity::Medium, &scratch.0);

    let links = probing.links();
    let [ProbeLink::Make(dir)] = links.as_slice() else {
        panic!("expected one make, got {links:?}");
    };
    assert_eq!(Path::new(dir).parent(), Some(scratch.0.as_path()));
    assert!(probes.elevated.is_none());
    let (state, note) = read(&probes).expect("its own junction");
    assert_eq!(state, Some(SymlinkState::Ok));
    assert!(note.contains("slow"), "{note}");
    assert!(scratch.is_empty(), "the directory and what is in it are removed");
    probing.assert_outside_intact();
    assert_eq!(probes.leftover, None);
}

/// A probe below High that did not answer may still create the directory it was told.
#[test]
fn an_agent_below_high_that_does_not_answer_has_its_outcome_as_the_session_and_a_note() {
    for unanswered in [
        (|| ProbeOutcome::TimedOut("no output".into())) as fn() -> ProbeOutcome,
        || broke("relay failed"),
    ] {
        let scratch = Scratch::new();
        let probing = Probing::new(unelevated_ok, unanswered);

        let probes = probing.run(Integrity::Medium, &scratch.0);

        assert!(matches!(
            &probes.session,
            ProbeOutcome::TimedOut(_) | ProbeOutcome::Failed { .. }
        ));
        assert!(
            matches!(&probes.junction, Junction::Unread { note } if note.is_empty()),
            "{:?}",
            probes.junction
        );
        assert!(probes.elevated.is_none());
        assert!(scratch.is_empty());
        probing.assert_outside_intact();
        let links = probing.links();
        let [ProbeLink::Make(dir)] = links.as_slice() else {
            panic!("expected one make, got {links:?}");
        };
        let leftover = probes.leftover.as_deref().expect("a note that the directory may come");
        assert!(leftover.contains(dir.as_str()), "{leftover}");
        assert!(leftover.contains("may still create"), "{leftover}");
    }
}

// a probe that cannot create the directory -------------------------------------------------

/// A probe whose child is gone, or was never started, cannot create the directory: no note says it may.
#[test]
fn a_probe_that_ended_or_never_started_gives_no_may_still_create_note() {
    #[allow(clippy::type_complexity)]
    let ended: [(&str, fn() -> ProbeOutcome); 2] = [
        ("exited", || exited("no PROBE line in probe output")),
        ("not started", || {
            ProbeOutcome::NotRun("connect to agent: no agent".into())
        }),
    ];
    for (name, outcome) in ended {
        for integrity in [Integrity::High, Integrity::Medium] {
            let scratch = Scratch::new();
            let probing = Probing::new(outcome, outcome);

            let probes = probing.run(integrity, &scratch.0);

            assert_eq!(probes.leftover, None, "{name} at {integrity:?}");
            assert!(scratch.is_empty(), "{name} at {integrity:?}");
            let rows = parity_rows(&probes, 1);
            assert!(
                !row_names(&rows).contains(&"junction directory"),
                "{name} at {integrity:?}: {:?}",
                row_names(&rows)
            );
        }
    }
}

/// With no agent running, `doctor` has no probe and no junction directory to name; the one row is the
/// probe's, with the cause.
#[test]
fn with_no_agent_running_there_is_no_junction_directory_row() {
    let scratch = Scratch::new();
    let probing = Probing::new(
        || ProbeOutcome::NotRun("connect to agent: no agent is running".into()),
        || ProbeOutcome::NotRun("connect to agent: no agent is running".into()),
    );

    let probes = probing.run(Integrity::Medium, &scratch.0);

    let rows = parity_rows(&probes, 1);
    assert_eq!(row_names(&rows), ["parity probe (via agent)"]);
    assert!(rows[0].detail.contains("no agent is running"), "{}", rows[0].detail);
}

// the directory cannot be removed -----------------------------------------------------------

/// A removal that fails is said with the directory and the error, at either level.
#[test]
fn a_directory_that_cannot_be_removed_is_named_with_the_error() {
    for integrity in [Integrity::High, Integrity::Medium] {
        let scratch = Scratch::new();
        let probing = Probing::new(unelevated_ok, elevated_ok).holding();

        let probes = probing.run(integrity, &scratch.0);

        let links = probing.links();
        let Some(ProbeLink::Make(dir)) = links.first() else {
            panic!("expected a make first, got {links:?}");
        };
        let leftover = probes.leftover.as_deref().expect("the directory is left behind");
        assert!(leftover.contains(dir.as_str()), "{integrity:?}: {leftover}");
        assert!(leftover.contains("could not be removed"), "{integrity:?}: {leftover}");
        assert!(
            leftover.contains("(os error"),
            "the error is named: {integrity:?}: {leftover}"
        );
        assert!(!leftover.contains("may still create"), "{integrity:?}: {leftover}");
        probing.assert_outside_intact();
    }
}

// the rows -----------------------------------------------------------------------------------

/// Each maker and follower pair, through `run_at` and `parity_rows`, has the junction row it should.
#[test]
fn each_pair_of_maker_and_follower_has_the_expected_junction_row() {
    fn maker(symlink: Option<SymlinkState>) -> ProbeOutcome {
        answer(Elevation::Filtered, INTEGRITY_MEDIUM, symlink, "")
    }
    fn follower(symlink: Option<SymlinkState>) -> ProbeOutcome {
        answer(Elevation::Full, INTEGRITY_HIGH, symlink, "")
    }
    #[allow(clippy::type_complexity)]
    let table: [(&str, fn() -> ProbeOutcome, fn() -> ProbeOutcome, bool, &str); 7] = [
        (
            "followed",
            || maker(Some(SymlinkState::Ok)),
            || follower(Some(SymlinkState::Ok)),
            true,
            "followed",
        ),
        (
            "refused",
            || maker(Some(SymlinkState::Ok)),
            || follower(Some(SymlinkState::Blocked)),
            false,
            "RedirectionGuard",
        ),
        (
            "made and not read",
            || maker(Some(SymlinkState::Ok)),
            || follower(Some(SymlinkState::Failed)),
            false,
            "not followed",
        ),
        (
            "follower reports none",
            || maker(Some(SymlinkState::Ok)),
            || follower(None),
            false,
            "did not report its junction",
        ),
        (
            "no junctions on the volume",
            || maker(Some(SymlinkState::Skipped)),
            || follower(None),
            true,
            "NOT tested",
        ),
        (
            "not made",
            || maker(Some(SymlinkState::NotMade)),
            || follower(Some(SymlinkState::Ok)),
            false,
            "no junction from below High could be tested",
        ),
        (
            "maker reports none",
            || maker(None),
            || follower(Some(SymlinkState::Ok)),
            false,
            "did not report its junction",
        ),
    ];
    // The session probe is the one that gives the rows, and its failure is the one `parity probe (via agent)` row,
    // which names the junction's cause.
    for (name, made, followed, passes, says) in table {
        let scratch = Scratch::new();
        let probing = Probing::new(made, followed);

        let probes = probing.run(Integrity::High, &scratch.0);

        let rows = parity_rows(&probes, 1);
        let row = rows
            .iter()
            .find(|row| row.name == "junction (via agent)")
            .unwrap_or_else(|| panic!("{name}: no junction row in {:?}", row_names(&rows)));
        assert_eq!(row.pass, passes, "{name}: {}", row.detail);
        assert!(row.detail.contains(says), "{name}: {}", row.detail);
    }

    fn sole(symlink: Option<SymlinkState>) -> ProbeOutcome {
        answer(Elevation::Standard, INTEGRITY_MEDIUM, symlink, "")
    }
    #[allow(clippy::type_complexity)]
    let below: [(&str, fn() -> ProbeOutcome, bool, &str); 4] = [
        ("followed", || sole(Some(SymlinkState::Ok)), true, "followed"),
        (
            "no junctions on the volume",
            || sole(Some(SymlinkState::Skipped)),
            true,
            "NOT tested",
        ),
        (
            "not made",
            || sole(Some(SymlinkState::NotMade)),
            false,
            "no junction could be made",
        ),
        ("reports none", || sole(None), false, "did not report its junction"),
    ];
    for (name, only, passes, says) in below {
        let scratch = Scratch::new();
        let probing = Probing::new(unelevated_ok, only);

        let probes = probing.run(Integrity::Medium, &scratch.0);

        let rows = parity_rows(&probes, 1);
        let row = rows
            .iter()
            .find(|row| row.name == "junction (via agent)")
            .unwrap_or_else(|| panic!("below High, {name}: no junction row in {:?}", row_names(&rows)));
        assert_eq!(row.pass, passes, "below High, {name}: {}", row.detail);
        assert!(row.detail.contains(says), "below High, {name}: {}", row.detail);
    }
}

// what a bounded probe came to --------------------------------------------------------------

/// What became of the worker decides the outcome, and with it whether the probe's child may still run: a
/// probe that never started has none, a timeout and a relay that broke before the child's exit may have
/// one, and a relay that ended with the child's exit has none.
#[test]
fn what_became_of_the_worker_decides_the_outcome() {
    let ProbeOutcome::Answered(done) = unelevated_ok() else {
        unreachable!("unelevated_ok answers")
    };

    let answered = outcome_of(Ok(Ok(done)));
    assert!(matches!(answered, ProbeOutcome::Answered(_)));
    assert!(!answered.may_still_run());

    let not_started = outcome_of(Ok(Err(Stop::NotStarted(anyhow::anyhow!("connect to agent: refused")))));
    assert!(
        matches!(&not_started, ProbeOutcome::NotRun(cause) if cause.contains("refused")),
        "{not_started:?}"
    );
    assert!(!not_started.may_still_run());

    let broke = outcome_of(Ok(Err(Stop::RelayBroke(anyhow::anyhow!(
        "probe relay failed (code 254)"
    )))));
    assert!(
        matches!(&broke, ProbeOutcome::Failed { cause, may_still_run: true } if cause.contains("code 254")),
        "{broke:?}"
    );
    assert!(broke.may_still_run());

    let exited = outcome_of(Ok(Err(Stop::Exited(anyhow::anyhow!("no PROBE line in probe output")))));
    assert!(
        matches!(&exited, ProbeOutcome::Failed { cause, may_still_run: false } if cause.contains("no PROBE line")),
        "{exited:?}"
    );
    assert!(!exited.may_still_run());

    let timed_out = outcome_of(Err(WaitError::TimedOut { secs: 30 }));
    assert!(
        matches!(&timed_out, ProbeOutcome::TimedOut(cause) if cause.contains("30s")),
        "{timed_out:?}"
    );
    assert!(timed_out.may_still_run());

    let stopped = outcome_of(Err(WaitError::WorkerStopped));
    assert!(
        matches!(&stopped, ProbeOutcome::Failed { cause, may_still_run: true } if cause.contains("worker stopped")),
        "{stopped:?}"
    );
}
