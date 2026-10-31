//! Host tests for the file that hands a fallback shell's notice and line to `console-fallback`
//! (pure; runs on any platform).

use std::path::{Path, PathBuf};

use super::{stage, sweep, take};

/// A fresh folder standing in for the user's private one; removed when dropped.
pub(crate) struct Folder(pub(crate) PathBuf);

impl Folder {
    pub(crate) fn new(tag: &str) -> Folder {
        let dir = std::env::temp_dir().join(format!("ssh-broker-fallback-file-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Folder(dir)
    }

    pub(crate) fn entries(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&self.0)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }
}

impl Drop for Folder {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn trusted(_: &Path) -> anyhow::Result<bool> {
    Ok(true)
}

/// Whatever the notice and the line hold, `take` returns exactly them.
#[test]
fn a_staged_file_gives_back_the_notice_and_the_line_exactly() {
    let folder = Folder::new("exact");
    for (notice, line) in [
        (
            "ssh-broker: cannot use the shell from C:\\a b\\config.yaml",
            "cmd.exe /c echo hi",
        ),
        ("two\r\nlines", r#"echo "a  b" \"#),
        ("héllo ✓", "echo \ttab\0nul"),
        ("", ""),
    ] {
        let staged = stage(&folder.0, notice, line).unwrap();
        let file = staged.path().to_owned();
        staged.hand_over();
        let got = take(&file, &folder.0, trusted).unwrap();
        assert_eq!(got, (notice.to_owned(), line.to_owned()));
    }
}

/// A line of the longest size `CreateProcessW` takes goes through a file as it is: the file is how
/// the verb gets a line that would not fit beside the verb's own name on a command line.
#[test]
fn a_line_at_the_command_line_limit_goes_through_the_file() {
    let folder = Folder::new("long");
    let line = "x".repeat(crate::shell::pack::MAX_LINE_UNITS - 1);
    let staged = stage(&folder.0, "notice", &line).unwrap();
    let file = staged.path().to_owned();
    staged.hand_over();
    assert_eq!(take(&file, &folder.0, trusted).unwrap().1, line);
}

#[test]
fn the_file_is_made_in_the_folder_and_nothing_else_is_left_there() {
    let folder = Folder::new("place");
    let staged = stage(&folder.0, "n", "l").unwrap();
    assert_eq!(staged.path().parent(), Some(folder.0.as_path()));
    assert_eq!(folder.entries().len(), 1, "{:?}", folder.entries());
    assert!(!folder.entries()[0].ends_with(".tmp"), "{:?}", folder.entries());
    staged.hand_over();
}

#[test]
fn two_staged_files_are_two_files() {
    let folder = Folder::new("two");
    let (a, b) = (stage(&folder.0, "a", "a").unwrap(), stage(&folder.0, "b", "b").unwrap());
    assert_ne!(a.path(), b.path());
    assert_eq!(folder.entries().len(), 2);
    a.hand_over();
    b.hand_over();
}

/// A staged file that is never handed over (the spawn failed) is removed.
#[test]
fn a_file_not_handed_over_is_removed_when_dropped() {
    let folder = Folder::new("drop");
    drop(stage(&folder.0, "n", "l").unwrap());
    assert_eq!(folder.entries(), Vec::<String>::new());
}

#[test]
fn a_handed_over_file_is_left_for_the_verb() {
    let folder = Folder::new("kept");
    stage(&folder.0, "n", "l").unwrap().hand_over();
    assert_eq!(folder.entries().len(), 1);
}

/// The verb removes the file once it has read it, so the line is not left lying in the folder.
#[test]
fn take_removes_the_file() {
    let folder = Folder::new("take");
    let staged = stage(&folder.0, "n", "l").unwrap();
    let file = staged.path().to_owned();
    staged.hand_over();
    take(&file, &folder.0, trusted).unwrap();
    assert_eq!(folder.entries(), Vec::<String>::new());
}

/// The verb starts the line the file holds, so it reads only a file in the private folder.
#[test]
fn take_refuses_a_file_outside_the_folder() {
    let folder = Folder::new("inside");
    let other = Folder::new("outside");
    let staged = stage(&other.0, "n", "l").unwrap();
    let file = staged.path().to_owned();
    staged.hand_over();
    let error = take(&file, &folder.0, trusted).unwrap_err();
    assert!(format!("{error:#}").contains("private folder"), "{error:#}");
    assert_eq!(other.entries().len(), 1, "a file that is not ours is left alone");
}

#[test]
fn take_refuses_a_path_that_climbs_out_of_the_folder() {
    let folder = Folder::new("climb");
    let other = Folder::new("climbed");
    let staged = stage(&other.0, "n", "l").unwrap();
    let file = staged.path().to_owned();
    staged.hand_over();
    let name = file.file_name().unwrap();
    let sneaky = folder.0.join("..").join(other.0.file_name().unwrap()).join(name);
    assert!(take(&sneaky, &folder.0, trusted).is_err());
    assert_eq!(other.entries().len(), 1);
}

/// A file the account's ACL check refuses is not run, and not kept either.
#[test]
fn take_refuses_a_file_that_is_not_private_and_removes_it() {
    let folder = Folder::new("untrusted");
    let staged = stage(&folder.0, "n", "l").unwrap();
    let file = staged.path().to_owned();
    staged.hand_over();
    let error = take(&file, &folder.0, |_| Ok(false)).unwrap_err();
    assert!(format!("{error:#}").contains("not private"), "{error:#}");
    assert_eq!(folder.entries(), Vec::<String>::new());
}

#[test]
fn take_reports_a_check_that_could_not_be_made() {
    let folder = Folder::new("unchecked");
    let staged = stage(&folder.0, "n", "l").unwrap();
    let file = staged.path().to_owned();
    staged.hand_over();
    let error = take(&file, &folder.0, |_| anyhow::bail!("access denied")).unwrap_err();
    assert!(format!("{error:#}").contains("access denied"), "{error:#}");
}

#[test]
fn take_of_a_missing_or_garbled_file_is_an_error() {
    let folder = Folder::new("garbled");
    assert!(take(&folder.0.join("nope"), &folder.0, trusted).is_err());
    let file = folder.0.join("garbled");
    std::fs::write(&file, [0xff, 0xff, 0xff]).unwrap();
    assert!(take(&file, &folder.0, trusted).is_err());
}

#[test]
fn staging_in_a_missing_folder_is_an_error() {
    let folder = Folder::new("missing");
    assert!(stage(&folder.0.join("no-such-folder"), "n", "l").is_err());
}

// sweep -----

/// A file named as `stage` names the files of the process `pid`, written without `stage`.
fn file_of(folder: &Folder, pid: u32, n: u32, suffix: &str) -> String {
    let name = format!("console-fallback-{pid}-{n}{suffix}");
    std::fs::write(folder.0.join(&name), b"x").unwrap();
    name
}

/// The files of a writer that is gone are removed; the files of one that is running stay. Both the
/// finished file and the one a crash left half-made (`.tmp`) are the writer's.
#[test]
fn sweep_removes_the_files_of_a_dead_writer_and_keeps_those_of_a_live_one() {
    let folder = Folder::new("sweep-pids");
    let (dead, live) = (4_000_000_001, 4_000_000_002);
    file_of(&folder, dead, 0, "");
    file_of(&folder, dead, 1, ".tmp");
    let kept = [file_of(&folder, live, 0, ""), file_of(&folder, live, 1, ".tmp")];

    sweep(&folder.0, |pid| Ok(pid == live)).unwrap();

    let mut want = kept.to_vec();
    want.sort();
    assert_eq!(folder.entries(), want);
}

/// A name that is not exactly `console-fallback-<pid>-<n>` or that plus `.tmp` is not ours to remove,
/// and the writer is not even asked about it.
#[test]
fn sweep_leaves_alone_what_it_did_not_name() {
    let folder = Folder::new("sweep-others");
    let others = [
        "agent.log",
        "console-fallback-",
        "console-fallback-12",
        "console-fallback-x-1",
        "console-fallback-12-x",
        "console-fallback-12-1.bak",
        "console-fallback-12-1.tmp.tmp",
        "console-fallback--1-2",
        "console-fallback-+12-1",
        "console-fallback-12-1-3",
        "xconsole-fallback-12-1",
        "console-fallback-99999999999-1",
    ];
    for name in others {
        std::fs::write(folder.0.join(name), b"x").unwrap();
    }
    std::fs::create_dir(folder.0.join("console-fallback-7-7")).unwrap();

    sweep(&folder.0, |pid| {
        panic!("asked about the writer {pid} of a file that is not ours")
    })
    .unwrap();

    let mut want: Vec<String> = others.iter().map(|name| name.to_string()).collect();
    want.push("console-fallback-7-7".into());
    want.sort();
    assert_eq!(folder.entries(), want);
}

/// When the writer cannot be told apart from a running one, its file stays (nothing proves it is an
/// orphan) and the files of the others are still swept.
#[test]
fn sweep_keeps_a_file_whose_writer_it_could_not_check_and_goes_on() {
    let folder = Folder::new("sweep-unsure");
    let (unsure, dead) = (4_000_000_003, 4_000_000_004);
    let kept = file_of(&folder, unsure, 0, "");
    file_of(&folder, dead, 0, "");

    sweep(&folder.0, |pid| {
        if pid == unsure {
            anyhow::bail!("cannot read the image of process {pid}")
        }
        Ok(false)
    })
    .unwrap();

    assert_eq!(folder.entries(), [kept]);
}

/// A file that `stage` made is found by the sweep: the two agree on the name.
#[test]
fn sweep_removes_a_file_staged_by_a_writer_that_is_gone() {
    let folder = Folder::new("sweep-staged");
    stage(&folder.0, "n", "l").unwrap().hand_over();
    let mine = std::process::id();

    sweep(&folder.0, |pid| Ok(pid == mine)).unwrap();
    assert_eq!(folder.entries().len(), 1, "the writer is running: the file stays");

    sweep(&folder.0, |_| Ok(false)).unwrap();
    assert_eq!(folder.entries(), Vec::<String>::new());
}

#[test]
fn sweep_of_a_folder_that_is_not_there_is_an_error() {
    let folder = Folder::new("sweep-missing");
    assert!(sweep(&folder.0.join("nope"), |_| Ok(false)).is_err());
}
