//! Tests for waiting on processes by handle. The children are console-less (`CREATE_NO_WINDOW`)
//! and live until the test closes their stdin.
use super::*;
use std::os::windows::process::CommandExt;
use std::process::{Child, Command, Stdio};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

fn cmd_exe() -> PathBuf {
    PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot is set")).join(r"System32\cmd.exe")
}

/// A `cmd.exe` that exits when its stdin closes, and not before.
fn child_until_stdin_closes() -> Child {
    Command::new(cmd_exe())
        .args(["/d", "/c", "set /p unused="])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .unwrap()
}

#[test]
fn a_running_process_of_the_expected_image_is_opened() {
    let mut child = child_until_stdin_closes();
    let found = open_if_image(child.id(), &cmd_exe()).unwrap();
    assert_eq!(found.map(|p| p.pid), Some(child.id()));
    drop(child.stdin.take());
    child.wait().unwrap();
}

#[test]
fn a_process_of_another_image_is_not_taken_for_the_agent() {
    // A reused PID names some other program; waiting on it would wait on the wrong thing.
    let mut child = child_until_stdin_closes();
    let other = PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot is set")).join(r"System32\find.exe");
    assert!(open_if_image(child.id(), &other).unwrap().is_none());
    drop(child.stdin.take());
    child.wait().unwrap();
}

#[test]
fn a_pid_that_names_no_process_is_an_exited_one() {
    assert!(open_if_image(u32::MAX - 1, &cmd_exe()).unwrap().is_none());
}

#[test]
fn the_wait_ends_when_the_process_exits_and_fails_at_the_bound_while_it_runs() {
    let mut child = child_until_stdin_closes();
    let process = open_if_image(child.id(), &cmd_exe()).unwrap().unwrap();

    // The child cannot exit until its stdin closes, so this expiry is the bound being reported,
    // not a race.
    let err = wait_all_exited(std::slice::from_ref(&process), Duration::from_millis(50)).unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains(&child.id().to_string()), "names the process: {text}");
    assert!(text.contains("did not exit"), "{text}");

    drop(child.stdin.take());
    wait_all_exited(std::slice::from_ref(&process), Duration::from_secs(60)).unwrap();
    assert!(
        child.try_wait().unwrap().is_some(),
        "the process had exited when the wait returned"
    );
}

#[test]
fn waiting_for_no_processes_returns_at_once() {
    wait_all_exited(&[], Duration::from_millis(1)).unwrap();
}

/// A temp directory holding a copy of `cmd.exe`, so that a process can run from a path of its own.
struct CmdCopy {
    dir: PathBuf,
}

impl CmdCopy {
    fn new(tag: &str) -> CmdCopy {
        let dir = std::env::temp_dir().join(format!("sb-procwait-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::copy(cmd_exe(), dir.join("cmd.exe")).unwrap();
        CmdCopy { dir }
    }

    fn exe(&self) -> PathBuf {
        self.dir.join("cmd.exe")
    }

    /// The copy, running until its stdin closes.
    fn spawn_until_stdin_closes(&self) -> Child {
        Command::new(self.exe())
            .args(["/d", "/c", "set /p unused="])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .unwrap()
    }
}

impl Drop for CmdCopy {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn a_process_is_found_by_the_file_it_runs_not_by_the_spelling_of_its_path() {
    // A junction on the install path names the same file by another path. Comparing path text
    // would call the process a stranger and the wait would silently do nothing.
    let copy = CmdCopy::new("junction");
    let link = copy.dir.with_extension("link");
    let _ = std::fs::remove_dir(&link);
    let made = Command::new(cmd_exe())
        .args(["/d", "/c", "mklink", "/J"])
        .arg(&link)
        .arg(&copy.dir)
        .stdout(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .status()
        .unwrap();
    assert!(made.success(), "control: the junction was made");

    let mut child = copy.spawn_until_stdin_closes();
    let through_the_link = link.join("cmd.exe");
    assert_ne!(through_the_link, copy.exe(), "control: another spelling");
    let found = open_if_image(child.id(), &through_the_link);

    drop(child.stdin.take());
    child.wait().unwrap();
    std::fs::remove_dir(&link).unwrap();
    assert_eq!(found.unwrap().map(|p| p.pid), Some(child.id()));
}

#[test]
fn another_case_of_the_same_path_is_the_same_file() {
    let copy = CmdCopy::new("case");
    let mut child = copy.spawn_until_stdin_closes();
    let upper = PathBuf::from(copy.exe().to_string_lossy().to_uppercase());
    let found = open_if_image(child.id(), &upper);
    drop(child.stdin.take());
    child.wait().unwrap();
    assert_eq!(found.unwrap().map(|p| p.pid), Some(child.id()));
}

#[test]
fn a_process_that_cannot_be_identified_is_an_error_never_nothing_to_wait_for() {
    let mut child = child_until_stdin_closes();
    let outcome = open_if_image_by(child.id(), &cmd_exe(), &|path| {
        if path == cmd_exe() {
            Ok(FileId::default())
        } else {
            Err(std::io::Error::from_raw_os_error(5))
        }
    });
    drop(child.stdin.take());
    child.wait().unwrap();
    let text = format!("{:#}", outcome.err().expect("could not tell"));
    assert!(text.contains(&child.id().to_string()), "names the process: {text}");
}

#[test]
fn an_exe_that_does_not_exist_is_held_by_no_process() {
    // Nothing can be running a file that is not there (the first `apply` of an install).
    let mut child = child_until_stdin_closes();
    let absent = std::env::temp_dir().join(format!("sb-procwait-absent-{}.exe", std::process::id()));
    let found = open_if_image(child.id(), &absent);
    drop(child.stdin.take());
    child.wait().unwrap();
    assert!(found.unwrap().is_none());
}

#[test]
fn a_wait_that_fails_leaves_the_process_a_survivor_with_the_error_and_the_rest_are_still_waited_for() {
    // If the exit cannot be confirmed the process may still be dying, holding its session's slot:
    // agents must not be started in that session, which is what a survivor is for.
    let mut fails = child_until_stdin_closes();
    let mut exits = child_until_stdin_closes();
    let processes: Vec<_> = [&fails, &exits]
        .iter()
        .map(|c| open_if_image(c.id(), &cmd_exe()).unwrap().unwrap())
        .collect();
    drop(exits.stdin.take());
    exits.wait().unwrap();
    let failing_pid = fails.id();

    let err = wait_all_exited_by(&processes, Duration::from_secs(60), &|process, _millis| {
        if process.pid == failing_pid {
            Err(std::io::Error::from_raw_os_error(6))
        } else {
            wait_on(process, 0)
        }
    })
    .unwrap_err();

    let still = err.downcast_ref::<StillRunning>().expect("a typed error");
    assert_eq!(still.survivors.len(), 1, "{still}");
    let survivor = &still.survivors[0];
    assert_eq!(survivor.pid, failing_pid);
    assert!(
        survivor.unconfirmed.as_deref().is_some_and(|e| e.contains("handle")),
        "{survivor:?}"
    );
    let text = format!("{err:#}");
    assert!(text.contains(&failing_pid.to_string()), "{text}");
    assert!(text.contains("could not confirm"), "{text}");
    assert!(text.contains("run apply again"), "{text}");

    drop(fails.stdin.take());
    fails.wait().unwrap();
}

#[test]
fn processes_that_outlive_the_bound_are_all_named_with_their_sessions() {
    let mut exits = child_until_stdin_closes();
    let mut stays_a = child_until_stdin_closes();
    let mut stays_b = child_until_stdin_closes();
    let processes: Vec<_> = [&exits, &stays_a, &stays_b]
        .iter()
        .map(|c| open_if_image(c.id(), &cmd_exe()).unwrap().unwrap())
        .collect();
    drop(exits.stdin.take());
    exits.wait().unwrap();

    let err = wait_all_exited(&processes, Duration::from_millis(50)).unwrap_err();
    let still = err.downcast_ref::<StillRunning>().expect("a typed error");
    let mut pids: Vec<u32> = still.survivors.iter().map(|s| s.pid).collect();
    pids.sort();
    let mut expected = vec![stays_a.id(), stays_b.id()];
    expected.sort();
    assert_eq!(pids, expected, "the one that exited is not named");
    let session = crate::provision::probe::current_session_id();
    assert!(still.survivors.iter().all(|s| s.session == Some(session)));
    let text = format!("{err:#}");
    assert!(text.contains(&stays_a.id().to_string()), "{text}");
    assert!(text.contains("run apply again"), "{text}");

    drop(stays_a.stdin.take());
    drop(stays_b.stdin.take());
    stays_a.wait().unwrap();
    stays_b.wait().unwrap();
}
