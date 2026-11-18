//! Tests for which probes `verify` runs and what it cleans up after them, with the probes driven by a
//! stand-in that answers as a probe would and makes the directory a make-probe makes.
use std::cell::RefCell;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};

use super::*;
use crate::account::{INTEGRITY_HIGH, INTEGRITY_MEDIUM};
use crate::provision::probe::{SymlinkState, UpstreamState};
use crate::socket_loc::Elevation;

/// A directory of this test's own, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let path = std::env::temp_dir().join(format!("sb-run-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Scratch(path)
    }

    fn is_empty(&self) -> bool {
        std::fs::read_dir(&self.0).unwrap().next().is_none()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn answer(elevation: Elevation, integrity: u32, symlink: SymlinkState, said: &str) -> Answer {
    Answer {
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
    }
}

/// What each probe of a run is asked, in order, and how the stand-in answers each: the one that asks for
/// an unelevated session makes the directory it is given (as the real one does) and then answers with
/// `made`; the other answers with `followed`.
struct Probing {
    made: fn() -> anyhow::Result<Answer>,
    followed: fn() -> anyhow::Result<Answer>,
    asked: RefCell<Vec<(Privilege, ProbeLink)>>,
}

impl Probing {
    fn new(made: fn() -> anyhow::Result<Answer>, followed: fn() -> anyhow::Result<Answer>) -> Probing {
        Probing {
            made,
            followed,
            asked: RefCell::default(),
        }
    }

    fn run(&self, integrity: Integrity, temp: &Path) -> anyhow::Result<Probes> {
        run_at(integrity, temp, &|privilege, link| {
            self.asked.borrow_mut().push((privilege, link.clone()));
            match (privilege, &link) {
                (Privilege::Unelevated, ProbeLink::Make(dir)) => {
                    std::fs::create_dir(dir).unwrap();
                    std::fs::write(Path::new(dir).join("left.txt"), b"x").unwrap();
                    (self.made)()
                }
                _ => (self.followed)(),
            }
        })
    }

    fn links(&self) -> Vec<ProbeLink> {
        self.asked.borrow().iter().map(|(_, link)| link.clone()).collect()
    }
}

fn unelevated_ok() -> anyhow::Result<Answer> {
    Ok(answer(Elevation::Filtered, INTEGRITY_MEDIUM, SymlinkState::Ok, ""))
}

fn elevated_ok() -> anyhow::Result<Answer> {
    Ok(answer(Elevation::Full, INTEGRITY_HIGH, SymlinkState::Ok, ""))
}

/// The directory `verify` names is under its own temp directory and goes to both probes, the one that
/// makes the junction and the one that follows it; the junction row is the follower's; and the directory is
/// gone afterwards.
#[test]
fn an_agent_at_high_gets_two_probes_with_one_directory_which_is_removed() {
    let scratch = Scratch::new("two");
    let probing = Probing::new(unelevated_ok, || {
        Ok(answer(
            Elevation::Full,
            INTEGRITY_HIGH,
            SymlinkState::Blocked,
            "refused",
        ))
    });

    let probes = probing.run(Integrity::High, &scratch.0).unwrap();

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
    assert!(matches!(probes.unelevated, Some(Ok(_))));
    assert_eq!(probes.junction.state, SymlinkState::Blocked);
    assert_eq!(probes.junction.note, "refused");
}

/// A probe that fails, times out or answers nothing leaves nothing behind: `verify` removes the directory
/// it named whatever became of the probes.
#[test]
fn the_directory_is_removed_when_the_first_probe_fails() {
    let scratch = Scratch::new("first");
    let probing = Probing::new(|| Err(anyhow::anyhow!("probe did not answer within 30s")), elevated_ok);

    let probes = probing.run(Integrity::High, &scratch.0).unwrap();

    assert!(scratch.is_empty(), "the directory the first probe made is removed");
    assert_eq!(probes.leftover, None);
    assert!(
        matches!(&probes.unelevated, Some(Err(cause)) if cause.contains("did not answer")),
        "{:?}",
        probes.unelevated
    );
}

#[test]
fn the_directory_is_removed_when_the_second_probe_fails() {
    let scratch = Scratch::new("second");
    let probing = Probing::new(unelevated_ok, || Err(anyhow::anyhow!("connect to agent: refused")));

    let err = probing.run(Integrity::High, &scratch.0).unwrap_err();

    assert!(format!("{err:#}").contains("refused"), "{err:#}");
    assert!(scratch.is_empty());
}

/// The first probe's failure is data: the default probe still runs, as itself and with a junction of its
/// own, since there is none from below High to follow, so every row but the two about the unelevated
/// session still has its facts. The junction check says it could not be run, and does not pass.
#[test]
fn a_failed_unelevated_probe_does_not_stop_the_default_probe() {
    let scratch = Scratch::new("data");
    let probing = Probing::new(|| Err(anyhow::anyhow!("probe relay failed (code 254)")), elevated_ok);

    let probes = probing.run(Integrity::High, &scratch.0).unwrap();

    assert!(matches!(
        probing.links().as_slice(),
        [ProbeLink::Make(_), ProbeLink::Own]
    ));
    assert_eq!(probes.default.integrity, Some(INTEGRITY_HIGH));
    assert!(probes.binary_ok);
    assert!(probes.junction.state.is_failure(), "{:?}", probes.junction.state);
    assert!(
        probes.junction.note.contains("could be tested") && probes.junction.note.contains("code 254"),
        "{}",
        probes.junction.note
    );
}

/// A junction that could not be made (a volume with no reparse points) was not tested, which fails
/// nothing: the follower is not asked to follow what is not there, and the probe's reason is the note.
#[test]
fn a_junction_that_could_not_be_made_is_not_tested() {
    let scratch = Scratch::new("skip");
    let probing = Probing::new(
        || {
            Ok(answer(
                Elevation::Filtered,
                INTEGRITY_MEDIUM,
                SymlinkState::Skipped,
                "making a junction failed: the volume does not support reparse points",
            ))
        },
        elevated_ok,
    );

    let probes = probing.run(Integrity::High, &scratch.0).unwrap();

    assert!(matches!(
        probing.links().as_slice(),
        [ProbeLink::Make(_), ProbeLink::Own]
    ));
    assert_eq!(probes.junction.state, SymlinkState::Skipped);
    assert!(
        probes.junction.note.contains("reparse points"),
        "{}",
        probes.junction.note
    );
    assert!(scratch.is_empty());
}

/// A temp directory that cannot be written as text cannot be given to a probe: `verify` says so on the
/// junction row and runs both probes with no directory to name.
#[test]
fn a_temp_directory_that_is_not_text_is_said_and_runs_the_probes_without_a_junction() {
    let not_text = PathBuf::from(OsString::from_wide(&[u16::from(b'C'), u16::from(b':'), 0xD800]));
    assert!(not_text.to_str().is_none(), "control: not Unicode text");
    let probing = Probing::new(unelevated_ok, elevated_ok);

    let probes = probing.run(Integrity::High, &not_text).unwrap();

    assert_eq!(probing.links(), [ProbeLink::Own, ProbeLink::Own]);
    assert_eq!(probes.junction.state, SymlinkState::Skipped);
    assert!(probes.junction.note.contains("text"), "{}", probes.junction.note);
    assert!(matches!(probes.unelevated, Some(Ok(_))));
}

/// An agent below High has one probe, which makes and follows a junction of its own; the junction row is
/// its result and what it said.
#[test]
fn an_agent_below_high_has_one_probe_with_a_junction_of_its_own() {
    let scratch = Scratch::new("medium");
    let probing = Probing::new(unelevated_ok, || {
        Ok(answer(
            Elevation::Standard,
            INTEGRITY_MEDIUM,
            SymlinkState::Ok,
            "removing the directory failed: in use",
        ))
    });

    let probes = probing.run(Integrity::Medium, &scratch.0).unwrap();

    assert_eq!(probing.links(), [ProbeLink::Own]);
    assert!(probes.unelevated.is_none());
    assert_eq!(probes.junction.state, SymlinkState::Ok);
    assert!(probes.junction.note.contains("in use"), "{}", probes.junction.note);
}
