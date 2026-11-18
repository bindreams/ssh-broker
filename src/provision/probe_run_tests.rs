//! Tests for which probes `verify` runs, how it asks each, what it makes of the answers and what it cleans
//! up after them, with the probes driven by a stand-in that answers as a probe would and makes the
//! directory a make-probe makes.
use std::cell::RefCell;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};

use super::*;
use crate::account::{INTEGRITY_HIGH, INTEGRITY_MEDIUM};
use crate::provision::probe::{ProbeResult, SymlinkState, UpstreamState};
use crate::provision::session_rows::parity_rows;
use crate::socket_loc::Elevation;
use crate::test_support::Scratch;

fn answer(elevation: Elevation, integrity: u32, symlink: SymlinkState, said: &str) -> ProbeOutcome {
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
        said: said.to_string(),
    })
}

/// What each probe of a run is asked, in order, and how the stand-in answers each: the one that asks for
/// an unelevated session makes the directory it is given (as the real one does) and then answers with
/// `made`; the other answers with `followed`.
struct Probing {
    made: fn() -> ProbeOutcome,
    followed: fn() -> ProbeOutcome,
    asked: RefCell<Vec<(Privilege, ProbeLink)>>,
}

impl Probing {
    fn new(made: fn() -> ProbeOutcome, followed: fn() -> ProbeOutcome) -> Probing {
        Probing {
            made,
            followed,
            asked: RefCell::default(),
        }
    }

    fn run(&self, integrity: Integrity, temp: &Path) -> Probes {
        run_at(integrity, temp, &|privilege, link| {
            self.asked.borrow_mut().push((privilege, link.clone()));
            match (privilege, &link) {
                (Privilege::Unelevated, ProbeLink::Make(dir)) => {
                    std::fs::create_dir(dir).unwrap();
                    std::fs::write(Path::new(dir).join("left.txt"), b"x").unwrap();
                    (self.made)()
                }
                (Privilege::Unelevated, _) => (self.made)(),
                _ => (self.followed)(),
            }
        })
    }

    fn links(&self) -> Vec<ProbeLink> {
        self.asked.borrow().iter().map(|(_, link)| link.clone()).collect()
    }
}

fn unelevated_ok() -> ProbeOutcome {
    answer(Elevation::Filtered, INTEGRITY_MEDIUM, SymlinkState::Ok, "")
}

fn elevated_ok() -> ProbeOutcome {
    answer(Elevation::Full, INTEGRITY_HIGH, SymlinkState::Ok, "")
}

/// The junction the run found, as its state and note, or `None` for no junction from below High.
fn read(probes: &Probes) -> Option<(SymlinkState, &str)> {
    match &probes.junction {
        Junction::Read { state, note } => Some((*state, note)),
        Junction::Unavailable { .. } => None,
    }
}

/// Why no junction from below High could be tested, and what the probes said.
fn unavailable(probes: &Probes) -> (&str, &str) {
    match &probes.junction {
        Junction::Unavailable { cause, note } => (cause, note),
        other => panic!("expected no junction from below High, got {other:?}"),
    }
}

fn is_answered(outcome: &Option<ProbeOutcome>) -> bool {
    matches!(outcome, Some(ProbeOutcome::Answered(_)))
}

// the agent is at High ---------------------------------------------------------------------

/// The directory `verify` names is under its own temp directory and goes to both probes, the one that
/// makes the junction and the one that follows it; the junction row is the follower's, with what both
/// said; and the directory is gone afterwards.
#[test]
fn an_agent_at_high_gets_two_probes_with_one_directory_which_is_removed() {
    let scratch = Scratch::new();
    let probing = Probing::new(
        || answer(Elevation::Filtered, INTEGRITY_MEDIUM, SymlinkState::Ok, "made it"),
        || answer(Elevation::Full, INTEGRITY_HIGH, SymlinkState::Blocked, "refused"),
    );

    let probes = probing.run(Integrity::High, &scratch.0);

    let links = probing.links();
    let [ProbeLink::Make(made), ProbeLink::Follow(followed)] = links.as_slice() else {
        panic!("expected a make and a follow, got {links:?}");
    };
    assert_eq!(made, followed);
    assert_eq!(Path::new(made).parent(), Some(scratch.0.as_path()));
    assert_eq!(
        probing.asked.borrow().iter().map(|(p, _)| *p).collect::<Vec<_>>(),
        [Privilege::Unelevated, Privilege::Account]
    );
    assert!(
        scratch.is_empty(),
        "the directory and what the probe left in it are removed"
    );
    assert_eq!(probes.leftover, None);
    assert!(is_answered(&probes.unelevated));
    let (state, note) = read(&probes).expect("a junction from below High was read");
    assert_eq!(state, SymlinkState::Blocked);
    assert!(note.contains("made it") && note.contains("refused"), "{note}");
}

/// A probe that fails leaves nothing behind: `verify` removes the directory it named whatever became of the
/// probes. The default probe still runs, as itself and with a junction of its own, since there is none
/// from below High to follow, and the junction cannot be tested.
#[test]
fn a_failed_unelevated_probe_removes_the_directory_and_the_default_probe_runs_on_its_own() {
    let scratch = Scratch::new();
    let probing = Probing::new(
        || ProbeOutcome::Failed("probe relay failed (code 254)".into()),
        || answer(Elevation::Full, INTEGRITY_HIGH, SymlinkState::Ok, "own junction"),
    );

    let probes = probing.run(Integrity::High, &scratch.0);

    assert!(scratch.is_empty(), "the directory the first probe made is removed");
    assert_eq!(probes.leftover, None);
    assert!(matches!(
        probing.links().as_slice(),
        [ProbeLink::Make(_), ProbeLink::Own]
    ));
    assert!(matches!(&probes.unelevated, Some(ProbeOutcome::Failed(cause)) if cause.contains("code 254")));
    assert!(matches!(&probes.default, ProbeOutcome::Answered(_)));
    let (cause, note) = unavailable(&probes);
    assert!(cause.contains("code 254"), "{cause}");
    assert!(
        note.contains("own junction"),
        "the fallback probe's words are kept: {note}"
    );
}

/// A first probe that did not answer in time is not followed by a second: an agent that is not answering
/// is not waited on again. `verify` still removes the directory, and says that the probe may yet create it.
#[test]
fn a_timed_out_first_probe_starts_no_second_probe_and_leaves_a_warning() {
    let scratch = Scratch::new();
    let probing = Probing::new(
        || ProbeOutcome::TimedOut("no output within 30s".into()),
        || panic!("no second probe may be started"),
    );

    let probes = probing.run(Integrity::High, &scratch.0);

    assert_eq!(probing.asked.borrow().len(), 1);
    assert!(matches!(&probes.unelevated, Some(ProbeOutcome::TimedOut(_))));
    assert!(
        matches!(&probes.default, ProbeOutcome::NotRun(why) if why.contains("did not answer the first probe")),
        "{:?}",
        probes.default
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

/// A maker that reports High made its junction as an elevated process, which proves nothing: the default
/// probe gets a junction of its own, and the junction row fails, saying so.
#[test]
fn a_maker_at_high_gets_no_follower_and_a_failing_junction() {
    let scratch = Scratch::new();
    let probing = Probing::new(
        || {
            answer(
                Elevation::Full,
                INTEGRITY_HIGH,
                SymlinkState::Ok,
                "made by the elevated one",
            )
        },
        elevated_ok,
    );

    let probes = probing.run(Integrity::High, &scratch.0);

    assert!(matches!(
        probing.links().as_slice(),
        [ProbeLink::Make(_), ProbeLink::Own]
    ));
    let (cause, note) = unavailable(&probes);
    assert!(cause.contains("below High"), "{cause}");
    assert!(note.contains("made by the elevated one"), "{note}");
    assert!(scratch.is_empty());
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
        [ProbeLink::Make(_), ProbeLink::Own]
    ));
    assert!(unavailable(&probes).0.contains("did not report"));
}

/// A maker that could not make the directory made no junction: the junction row fails with what the
/// probe said, and the default probe has a junction of its own.
#[test]
fn a_directory_that_could_not_be_made_gives_no_junction_from_below_high() {
    let scratch = Scratch::new();
    let probing = Probing::new(
        || {
            answer(
                Elevation::Filtered,
                INTEGRITY_MEDIUM,
                SymlinkState::NotMade,
                "making the directory failed: access denied",
            )
        },
        elevated_ok,
    );

    let probes = probing.run(Integrity::High, &scratch.0);

    assert!(matches!(
        probing.links().as_slice(),
        [ProbeLink::Make(_), ProbeLink::Own]
    ));
    let (_, note) = unavailable(&probes);
    assert!(note.contains("access denied"), "{note}");
}

/// A volume that refused the junction was not tested, which fails nothing: the follower is not asked to
/// follow what is not there, and what the probes said is the note.
#[test]
fn a_junction_the_volume_refused_is_not_tested() {
    let scratch = Scratch::new();
    let probing = Probing::new(
        || {
            answer(
                Elevation::Filtered,
                INTEGRITY_MEDIUM,
                SymlinkState::Skipped,
                "the volume does not hold a junction",
            )
        },
        elevated_ok,
    );

    let probes = probing.run(Integrity::High, &scratch.0);

    assert!(matches!(
        probing.links().as_slice(),
        [ProbeLink::Make(_), ProbeLink::Own]
    ));
    let (state, note) = read(&probes).expect("the junction is judged");
    assert_eq!(state, SymlinkState::Skipped);
    assert!(note.contains("does not hold a junction"), "{note}");
    assert!(scratch.is_empty());
}

/// A failed default probe takes its own rows with it and no others: the unelevated probe's row and the
/// directory that is left are still shown.
#[test]
fn a_failed_default_probe_keeps_the_unelevated_row_and_the_leftover() {
    let scratch = Scratch::new();
    let probing = Probing::new(
        || ProbeOutcome::TimedOut("no output within 30s".into()),
        || ProbeOutcome::Failed("connect to agent: refused".into()),
    );
    let probes = probing.run(Integrity::High, &scratch.0);
    // A timed-out first probe starts no second one, so the default probe here is the one that did not run.
    assert!(matches!(&probes.default, ProbeOutcome::NotRun(_)));

    let rows = parity_rows(&probes, 1);

    let names: Vec<&str> = rows.iter().map(|row| row.name).collect();
    assert_eq!(
        names,
        [
            "parity probe (via agent)",
            "unelevated session on request",
            "junction directory"
        ]
    );

    let failing = Probing::new(unelevated_ok, || {
        ProbeOutcome::Failed("connect to agent: refused".into())
    });
    let probes = failing.run(Integrity::High, &scratch.0);
    assert!(matches!(&probes.default, ProbeOutcome::Failed(_)));
    let rows = parity_rows(&probes, 1);
    let names: Vec<&str> = rows.iter().map(|row| row.name).collect();
    assert_eq!(names, ["parity probe (via agent)", "unelevated session on request"]);
    assert!(rows[0].detail.contains("refused"), "{}", rows[0].detail);
    assert!(rows[1].pass, "{}", rows[1].detail);
}

/// A temp directory that cannot be written as text cannot be given to a probe: `verify` says so on the
/// junction row, which fails, and runs both probes with no directory to name.
#[test]
fn a_temp_directory_that_is_not_text_gives_no_junction_and_runs_the_probes() {
    let not_text = PathBuf::from(OsString::from_wide(&[u16::from(b'C'), u16::from(b':'), 0xD800]));
    assert!(not_text.to_str().is_none(), "control: not Unicode text");
    let probing = Probing::new(unelevated_ok, elevated_ok);

    let probes = probing.run(Integrity::High, &not_text);

    assert_eq!(probing.links(), [ProbeLink::Own, ProbeLink::Own]);
    assert!(unavailable(&probes).0.contains("text"));
    assert!(is_answered(&probes.unelevated));
}

// the agent is below High ------------------------------------------------------------------

/// An agent below High has one probe, which makes and follows a junction of its own; the junction row is
/// its result and what it said.
#[test]
fn an_agent_below_high_has_one_probe_with_a_junction_of_its_own() {
    let scratch = Scratch::new();
    let probing = Probing::new(unelevated_ok, || {
        answer(
            Elevation::Standard,
            INTEGRITY_MEDIUM,
            SymlinkState::Ok,
            "removing the directory failed: in use",
        )
    });

    let probes = probing.run(Integrity::Medium, &scratch.0);

    assert_eq!(probing.links(), [ProbeLink::Own]);
    assert!(probes.unelevated.is_none());
    let (state, note) = read(&probes).expect("its own junction");
    assert_eq!(state, SymlinkState::Ok);
    assert!(note.contains("in use"), "{note}");
}

/// A probe below High that did not answer is the default probe's outcome, whichever way it did not.
#[test]
fn an_agent_below_high_that_does_not_answer_has_its_outcome_as_the_default() {
    let scratch = Scratch::new();
    let probing = Probing::new(unelevated_ok, || ProbeOutcome::TimedOut("no output".into()));

    let probes = probing.run(Integrity::Medium, &scratch.0);

    assert!(matches!(&probes.default, ProbeOutcome::TimedOut(_)));
    assert!(probes.unelevated.is_none());
    assert_eq!(probes.leftover, None);
}
