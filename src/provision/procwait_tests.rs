//! Tests for waiting on processes by handle. The children are console-less (`CREATE_NO_WINDOW`)
//! and live until the test closes their stdin.
use super::*;
use std::os::windows::process::CommandExt;
use std::process::{Child, Command, Stdio};

use windows::Win32::Foundation::{STATUS_ACCESS_DENIED, STATUS_INFO_LENGTH_MISMATCH, STILL_ACTIVE};

use crate::acl::Sid;

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
    // The first identification is of the exe looked for; the second, of the image the process
    // runs, fails. By order, not by path: the two paths may be spelled alike.
    let calls = std::cell::Cell::new(0u32);
    let outcome = open_if_image_by(
        child.id(),
        &cmd_exe(),
        &|_| {
            calls.set(calls.get() + 1);
            if calls.get() == 1 {
                Ok(FileId::default())
            } else {
                Err(std::io::Error::from_raw_os_error(5))
            }
        },
        &image_of,
        IfEnding::TakeForRunning,
    );
    drop(child.stdin.take());
    child.wait().unwrap();
    // Reaching the second identification proves the process was opened and its image read; an
    // earlier failure there also names the pid, so the pid alone would not.
    assert_eq!(calls.get(), 2, "the process's image was identified");
    let text = format!("{:#}", outcome.err().expect("could not tell"));
    assert!(
        text.contains(&format!("which process {} runs", child.id())),
        "names the process whose image could not be identified: {text}"
    );
}

#[test]
fn a_process_whose_image_cannot_be_read_because_it_is_ending_is_taken_only_when_the_caller_says_so() {
    // This test's own process stands for the one that ends: it is running, and the image read is
    // made to say it is ending, which is what the kernel answers a process in its exit that has
    // let go of its image. The real kernel answers in no way a test can make on demand.
    let pid = std::process::id();
    let ending = |_: &OwnedHandle| Err(Ending { pid }.into());
    let open = |if_ending| open_if_image_by(pid, &cmd_exe(), &|_| Ok(FileId::default()), &ending, if_ending);

    assert_eq!(
        open(IfEnding::TakeForRunning).unwrap().map(|p| p.pid),
        Some(pid),
        "an ending process that may run the image is waited for"
    );
    assert!(
        open(IfEnding::Skip).unwrap().is_none(),
        "an ending process nothing says runs the image is none to wait for"
    );
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
        survivor
            .unconfirmed
            .as_deref()
            .is_some_and(|e| e.contains("os error 6")),
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

// the agents of one user -----

/// A copy of `cmd.exe` named like the installed exe, so that the process snapshot lists it as an
/// ssh-broker process.
struct NamedCopy(CmdCopy);

impl NamedCopy {
    fn new(tag: &str) -> NamedCopy {
        let copy = CmdCopy::new(tag);
        std::fs::rename(copy.exe(), copy.dir.join(crate::provision::EXE_NAME)).unwrap();
        NamedCopy(copy)
    }

    fn exe(&self) -> PathBuf {
        self.0.dir.join(crate::provision::EXE_NAME)
    }

    /// The copy with `args` after the program (cmd ignores them and reads its stdin), until its
    /// stdin closes.
    fn spawn(&self, args: &[&str]) -> Child {
        Command::new(self.exe())
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .unwrap()
    }
}

fn end(mut child: Child) {
    drop(child.stdin.take());
    child.wait().unwrap();
}

fn pids(agents: &[Process]) -> Vec<u32> {
    let mut pids: Vec<u32> = agents.iter().map(|p| p.pid).collect();
    pids.sort();
    pids
}

#[test]
fn a_running_agent_of_the_user_is_found_before_it_has_taken_any_lock() {
    let copy = NamedCopy::new("mine");
    let background = copy.spawn(&["agent", "--background"]);
    let desktop = copy.spawn(&["agent"]);
    let shim = copy.spawn(&["-c", "agent --background"]);
    let me = Sid::current_user().unwrap();

    let found = user_agents(&copy.exe(), &me).unwrap();
    let mut expected = vec![background.id(), desktop.id()];
    expected.sort();
    assert_eq!(pids(&found), expected, "both agents, and not the shim");

    drop(found);
    end(background);
    end(desktop);
    end(shim);
}

#[test]
fn another_users_agent_is_none_of_this_users() {
    let copy = NamedCopy::new("other");
    let agent = copy.spawn(&["agent", "--background"]);
    let someone_else = Sid::well_known(crate::acl::WellKnown::System).unwrap();
    assert!(user_agents(&copy.exe(), &someone_else).unwrap().is_empty());
    end(agent);
}

#[test]
fn an_agent_of_another_image_is_not_taken_for_this_one() {
    let copy = NamedCopy::new("image");
    let agent = copy.spawn(&["agent", "--background"]);
    let elsewhere = NamedCopy::new("elsewhere");
    let me = Sid::current_user().unwrap();
    assert!(user_agents(&elsewhere.exe(), &me).unwrap().is_empty());
    end(agent);
}

#[test]
fn an_image_that_does_not_exist_has_no_agents() {
    let absent = std::env::temp_dir().join(format!("sb-procwait-absent-{}.exe", std::process::id()));
    assert!(user_agents(&absent, &Sid::current_user().unwrap()).unwrap().is_empty());
}

#[test]
fn an_agent_that_has_ended_is_not_found_while_a_handle_keeps_it_listed() {
    let copy = NamedCopy::new("ended");
    let mut agent = copy.spawn(&["agent", "--background"]);
    let me = Sid::current_user().unwrap();
    let held = user_agents(&copy.exe(), &me).unwrap();
    assert_eq!(pids(&held), vec![agent.id()], "control: it is found while it runs");

    drop(agent.stdin.take());
    wait_all_exited(&held, Duration::from_secs(60)).unwrap();
    // `held` and `agent` keep the ended process in the system's list; waiting on it would return at once.
    assert!(user_agents(&copy.exe(), &me).unwrap().is_empty());
    agent.wait().unwrap();
}

#[test]
fn a_process_that_has_ended_but_is_still_held_is_nothing_to_wait_for_not_an_error() {
    // The snapshot can name a process that ends before it is opened: its image can no longer be
    // read, and `background_agents` would fail the whole `apply` on it.
    let copy = NamedCopy::new("held-ended");
    let mut agent = copy.spawn(&["agent", "--background"]);
    let held = user_agents(&copy.exe(), &Sid::current_user().unwrap()).unwrap();
    drop(agent.stdin.take());
    wait_all_exited(&held, Duration::from_secs(60)).unwrap();
    assert!(open_if_image(agent.id(), &copy.exe()).unwrap().is_none());
    agent.wait().unwrap();
}

#[test]
fn ending_a_process_that_has_already_ended_is_success() {
    let mut child = child_until_stdin_closes();
    let process = open_if_image(child.id(), &cmd_exe()).unwrap().unwrap();
    drop(child.stdin.take());
    wait_all_exited(std::slice::from_ref(&process), Duration::from_secs(60)).unwrap();
    // The handles on it keep it listed; ending it is the goal state already.
    process.terminate().unwrap();
    child.wait().unwrap();
}

#[test]
fn ending_a_running_process_ends_it() {
    let mut child = child_until_stdin_closes();
    let process = open_if_image(child.id(), &cmd_exe()).unwrap().unwrap();
    process.terminate().unwrap();
    wait_all_exited(std::slice::from_ref(&process), Duration::from_secs(60)).unwrap();
    assert_eq!(child.wait().unwrap().code(), Some(1));
    drop(child.stdin.take());
}

// the role of an ssh-broker process, from its command line -----

#[test]
fn agent_alone_is_a_desktop_agent() {
    assert_eq!(
        role_of(r"C:\ProgramData\ssh-broker\ssh-broker.exe agent"),
        Role::DesktopAgent
    );
}

#[test]
fn agent_background_with_flags_is_a_background_agent() {
    let line = r"C:\ProgramData\ssh-broker\ssh-broker.exe agent --background --expect-user S-1-5-21-1";
    assert_eq!(role_of(line), Role::BackgroundAgent);
    assert_eq!(
        role_of(r"C:\ProgramData\ssh-broker\ssh-broker.exe agent --background"),
        Role::BackgroundAgent
    );
}

#[test]
fn a_shim_whose_command_text_mentions_agent_is_a_shim() {
    assert_eq!(
        role_of(r#"C:\ProgramData\ssh-broker\ssh-broker.exe -c "agent --background""#),
        Role::Shim
    );
    assert_eq!(
        role_of(r"C:\ProgramData\ssh-broker\ssh-broker.exe -c agent --background"),
        Role::Shim
    );
}

#[test]
fn no_arguments_is_a_shim() {
    assert_eq!(role_of(r"C:\ProgramData\ssh-broker\ssh-broker.exe"), Role::Shim);
    assert_eq!(role_of(""), Role::Shim);
}

#[test]
fn a_spaced_exe_path_is_parsed() {
    assert_eq!(
        role_of(r#""C:\Program Files\ssh-broker\ssh-broker.exe" agent --background"#),
        Role::BackgroundAgent
    );
    assert_eq!(
        role_of(r#""C:\Program Files\ssh-broker\ssh-broker.exe" agent"#),
        Role::DesktopAgent
    );
}

#[test]
fn other_verbs_are_not_agents() {
    for verb in ["verify", "apply", "logout", "auto-login on"] {
        assert_eq!(role_of(&format!(r"C:\x\ssh-broker.exe {verb}")), Role::Shim, "{verb}");
    }
}

#[test]
fn only_a_background_agent_is_selected_to_end() {
    let lines = [
        (1u32, r"C:\x\ssh-broker.exe"),
        (2, r"C:\x\ssh-broker.exe agent"),
        (3, r"C:\x\ssh-broker.exe agent --background --expect-user S-1"),
        (4, r#"C:\x\ssh-broker.exe -c "agent --background""#),
    ];
    let selected: Vec<u32> = select_background_agents(lines.iter().map(|(pid, line)| (*pid, role_of(line)))).collect();
    assert_eq!(selected, [3]);
}

#[test]
fn the_command_line_of_a_running_process_is_readable() {
    let mut child = child_until_stdin_closes();
    let process = open_if_image(child.id(), &cmd_exe())
        .unwrap()
        .expect("the child runs cmd.exe");
    let line = command_line_of(&process).unwrap();
    assert!(line.contains("set /p unused="), "{line}");
    drop(child.stdin.take());
    child.wait().unwrap();
}

// the scan for a user's agents, over processes the test makes up -----

/// How reading something about a made-up process fails.
#[derive(Clone, Copy)]
enum Fail {
    /// The kernel answers `STATUS_PROCESS_IS_TERMINATING` (which Win32 callers see as access denied).
    Ending,
    /// Access denied with nothing to say the process is going away.
    Denied,
}

impl Fail {
    fn error(self, pid: u32) -> anyhow::Error {
        match self {
            Fail::Ending => anyhow::Error::new(Ending { pid }).context(format!("read something of process {pid}")),
            Fail::Denied => {
                let denied = windows::core::Error::from(HRESULT::from_win32(ERROR_ACCESS_DENIED.0));
                anyhow::Error::new(denied).context(format!("read something of process {pid}"))
            }
        }
    }
}

/// A process the scan is told about. Every question has the answer of a process that is an agent of
/// the user unless the test changes it.
#[derive(Clone)]
struct Made {
    pid: u32,
    owner: Result<&'static str, Fail>,
    image: Result<bool, Fail>,
    exited: bool,
    /// The kernel says it is ending while every read of it still succeeds (a process held in its exit).
    ending: bool,
    command_line: Result<&'static str, Fail>,
}

const ME: &str = "S-1-5-21-1-2-3-1001";

fn made(pid: u32) -> Made {
    Made {
        pid,
        owner: Ok(ME),
        image: Ok(true),
        exited: false,
        ending: false,
        command_line: Ok(r"C:\x\ssh-broker.exe agent --background"),
    }
}

impl Inspect for Made {
    fn owner(&self) -> anyhow::Result<String> {
        self.owner.map(str::to_owned).map_err(|f| f.error(self.pid))
    }
    fn runs_image(&self, _wanted: &FileId) -> anyhow::Result<bool> {
        self.image.map_err(|f| f.error(self.pid))
    }
    fn has_exited(&self) -> bool {
        self.exited
    }
    fn is_ending(&self) -> bool {
        self.ending
    }
    fn command_line(&self) -> anyhow::Result<String> {
        self.command_line.map(str::to_owned).map_err(|f| f.error(self.pid))
    }
}

/// The pids the scan returns for `processes`, which all carry the installed exe's name.
fn scanned(processes: &[Made]) -> anyhow::Result<Vec<u32>> {
    let names: Vec<(u32, String)> = processes
        .iter()
        .map(|p| (p.pid, crate::provision::EXE_NAME.to_owned()))
        .collect();
    let found = scan_user_agents(&names, 1, crate::provision::EXE_NAME, ME, &FileId::default(), &|pid| {
        Ok(processes.iter().find(|p| p.pid == pid).cloned())
    })?;
    Ok(found.iter().map(|p| p.pid).collect())
}

#[test]
fn the_scan_finds_the_agents_of_the_user_and_not_a_shim() {
    let shim = Made {
        command_line: Ok(r"C:\x\ssh-broker.exe"),
        ..made(30)
    };
    assert_eq!(scanned(&[made(10), made(20), shim]).unwrap(), [10, 20]);
}

#[test]
fn a_process_of_another_user_or_another_image_is_none_of_the_users() {
    let other_user = Made {
        owner: Ok("S-1-5-18"),
        ..made(10)
    };
    let other_image = Made {
        image: Ok(false),
        ..made(20)
    };
    assert_eq!(scanned(&[other_user, other_image, made(30)]).unwrap(), [30]);
}

#[test]
fn a_process_whose_token_is_refused_is_none_of_the_users() {
    let refused = Made {
        owner: Err(Fail::Denied),
        ..made(10)
    };
    assert_eq!(scanned(&[refused, made(20)]).unwrap(), [20]);
}

#[test]
fn a_process_whose_image_is_refused_because_it_is_ending_is_skipped_not_fatal() {
    // The image read of a process that is being ended fails; that must not fail the whole scan.
    let ending = Made {
        image: Err(Fail::Ending),
        ..made(10)
    };
    assert_eq!(scanned(&[ending, made(20)]).unwrap(), [20]);
}

#[test]
fn a_process_the_kernel_says_is_ending_is_none_of_the_users_though_every_read_of_it_succeeds() {
    // A process held in its exit is readable, not signalled, and refuses TerminateProcess.
    let held = Made {
        ending: true,
        ..made(10)
    };
    assert_eq!(scanned(&[held, made(20)]).unwrap(), [20]);
}

#[test]
fn a_process_that_ends_between_the_image_and_the_command_line_is_skipped() {
    let ending = Made {
        command_line: Err(Fail::Ending),
        ..made(10)
    };
    assert_eq!(scanned(&[ending, made(20)]).unwrap(), [20]);
}

#[test]
fn a_process_that_has_exited_is_skipped_whatever_it_refuses() {
    let gone = Made {
        exited: true,
        image: Err(Fail::Denied),
        ..made(10)
    };
    assert_eq!(scanned(&[gone, made(30)]).unwrap(), [30]);
}

/// A process that is alive at the first look and has exited by the time a read of it has failed.
struct ExitsWhenAsked {
    made: Made,
    asked: std::cell::Cell<bool>,
}

impl Inspect for ExitsWhenAsked {
    fn owner(&self) -> anyhow::Result<String> {
        self.made.owner()
    }
    fn runs_image(&self, wanted: &FileId) -> anyhow::Result<bool> {
        self.made.runs_image(wanted)
    }
    fn has_exited(&self) -> bool {
        self.asked.get()
    }
    fn is_ending(&self) -> bool {
        false
    }
    fn command_line(&self) -> anyhow::Result<String> {
        self.asked.set(true);
        self.made.command_line()
    }
}

#[test]
fn a_process_that_exits_while_its_command_line_is_read_is_skipped() {
    let names = vec![(20, crate::provision::EXE_NAME.to_owned())];
    let found = scan_user_agents(&names, 1, crate::provision::EXE_NAME, ME, &FileId::default(), &|pid| {
        Ok(Some(ExitsWhenAsked {
            made: Made {
                command_line: Err(Fail::Denied),
                ..made(pid)
            },
            asked: std::cell::Cell::new(false),
        }))
    })
    .unwrap();
    assert!(found.is_empty());
}

#[test]
fn a_process_of_the_user_whose_image_is_refused_for_no_known_reason_fails_the_scan_naming_it() {
    let unreadable = Made {
        image: Err(Fail::Denied),
        ..made(4242)
    };
    let err = scanned(&[made(10), unreadable]).unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("4242"), "names the process: {text}");
    assert!(text.contains("Access is denied"), "names the cause: {text}");
}

#[test]
fn a_process_of_the_user_whose_command_line_is_refused_for_no_known_reason_fails_the_scan_naming_it() {
    let unreadable = Made {
        command_line: Err(Fail::Denied),
        ..made(4243)
    };
    let err = scanned(&[unreadable]).unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("4243"), "names the process: {text}");
    assert!(text.contains("Access is denied"), "names the cause: {text}");
}

#[test]
fn this_process_and_processes_of_other_names_are_not_looked_at() {
    let names = vec![(1, crate::provision::EXE_NAME.to_owned()), (2, "other.exe".to_owned())];
    let found = scan_user_agents::<Made>(&names, 1, crate::provision::EXE_NAME, ME, &FileId::default(), &|pid| {
        panic!("process {pid} was opened")
    })
    .unwrap();
    assert!(found.is_empty());
}

#[test]
fn the_scan_looks_for_the_file_name_of_the_image_it_is_given_not_for_the_installed_name() {
    // The tests run a copy of the exe under another name; a scan for `ssh-broker.exe` only would find
    // none of its agents.
    let names = vec![
        (10, "stand_in.exe".to_owned()),
        (20, crate::provision::EXE_NAME.to_owned()),
    ];
    let opened = std::cell::RefCell::new(Vec::new());
    let found = scan_user_agents(&names, 1, "stand_in.exe", ME, &FileId::default(), &|pid| {
        opened.borrow_mut().push(pid);
        Ok(Some(made(pid)))
    })
    .unwrap();
    assert_eq!(found.iter().map(|p| p.pid).collect::<Vec<_>>(), [10]);
    assert_eq!(*opened.borrow(), [10], "a process of another name is not opened");
}

#[test]
fn the_scan_compares_file_names_without_regard_to_case() {
    let names = vec![(10, "Stand_In.EXE".to_owned())];
    let found = scan_user_agents(&names, 1, "stand_in.exe", ME, &FileId::default(), &|pid| {
        Ok(Some(made(pid)))
    })
    .unwrap();
    assert_eq!(found.len(), 1);
}

#[test]
fn a_process_that_cannot_be_opened_is_none_of_the_users() {
    let names = vec![(5, crate::provision::EXE_NAME.to_owned())];
    let found = scan_user_agents::<Made>(&names, 1, crate::provision::EXE_NAME, ME, &FileId::default(), &|_| {
        Ok(None)
    })
    .unwrap();
    assert!(found.is_empty());
}

// the scan for background agents, over processes the test makes up -----

const OURS: &str = crate::provision::EXE_NAME;

/// A made-up process whose image cannot be read because it is ending: `open` takes it for running
/// the image only if it is told to, as the real one does.
fn ending_image(pid: u32) -> Made {
    Made {
        command_line: Err(Fail::Ending),
        ..made(pid)
    }
}

/// The pids a scan returned, and for each pid asked about whether an ending one was to be taken.
type Scanned = (Vec<u32>, Vec<(u32, bool)>);

/// The pids the scan for background agents returns, and what it was told to do with an ending process
/// when it opened each one. `ending` holds the pids whose image is unreadable because they are ending.
fn background_scanned(names: &[(u32, &str)], processes: &[Made], ending: &[u32]) -> anyhow::Result<Scanned> {
    let names: Vec<(u32, String)> = names.iter().map(|(pid, name)| (*pid, (*name).to_owned())).collect();
    let asked = std::cell::RefCell::new(Vec::new());
    let found = scan_background_agents(&names, 1, OURS, &|pid, if_ending| {
        asked.borrow_mut().push((pid, if_ending == IfEnding::TakeForRunning));
        if ending.contains(&pid) && if_ending == IfEnding::Skip {
            return Ok(None);
        }
        Ok(processes.iter().find(|p| p.pid == pid).cloned())
    })?;
    Ok((found.iter().map(|p| p.pid).collect(), asked.into_inner()))
}

#[test]
fn the_scan_for_background_agents_finds_background_agents_and_not_other_roles() {
    let desktop = Made {
        command_line: Ok(r"C:\x\ssh-broker.exe agent"),
        ..made(20)
    };
    let (found, _) = background_scanned(&[(10, OURS), (20, OURS)], &[made(10), desktop], &[]).unwrap();
    assert_eq!(found, [10]);
}

#[test]
fn an_ending_process_of_another_name_is_not_a_background_agent() {
    // A process mid-exit (a browser's child, a build tool) has an unreadable image; it must not be
    // classed an agent that `apply` then waits for.
    let (found, asked) =
        background_scanned(&[(10, "chrome.exe"), (20, OURS)], &[ending_image(10), made(20)], &[10]).unwrap();
    assert_eq!(found, [20]);
    assert!(
        asked.contains(&(10, false)),
        "an ending process of another name must be opened to be skipped: {asked:?}"
    );
}

#[test]
fn an_ending_process_with_our_name_is_a_background_agent_to_wait_for() {
    // It holds the exe until it is gone, and nothing says it is not the agent.
    let (found, asked) = background_scanned(&[(10, OURS), (20, OURS)], &[ending_image(10), made(20)], &[10]).unwrap();
    assert_eq!(found, [10, 20]);
    assert!(asked.contains(&(10, true)), "{asked:?}");
}

#[test]
fn the_name_of_an_ending_process_is_compared_without_regard_to_case() {
    let (found, _) = background_scanned(&[(10, "SSH-Broker.EXE")], &[ending_image(10)], &[10]).unwrap();
    assert_eq!(found, [10]);
}

#[test]
fn a_process_of_another_name_that_runs_the_image_and_ends_while_read_is_skipped() {
    // It was opened as running the image, then its command line was refused because it is ending.
    let (found, _) = background_scanned(&[(10, "copy.exe"), (20, OURS)], &[ending_image(10), made(20)], &[]).unwrap();
    assert_eq!(found, [20]);
}

#[test]
fn a_process_with_our_name_that_cannot_be_read_for_no_known_reason_fails_the_scan() {
    let refused = Made {
        command_line: Err(Fail::Denied),
        ..made(10)
    };
    let err = background_scanned(&[(10, OURS)], &[refused], &[]).unwrap_err();
    assert!(format!("{err:#}").contains("10"), "{err:#}");
}

// what to make of a process that cannot be read -----

#[test]
fn an_unreadable_process_is_told_apart_as_exited_ending_or_failed() {
    let ending = Fail::Ending.error(1);
    let denied = Fail::Denied.error(1);
    assert_eq!(unreadable(&ending, true), Unreadable::Exited);
    assert_eq!(unreadable(&denied, true), Unreadable::Exited);
    assert_eq!(unreadable(&ending, false), Unreadable::Ending);
    assert_eq!(unreadable(&denied, false), Unreadable::Failed);
}

// what tells a process is ending -----

/// What the kernel answers about a running process.
fn running_signs() -> EndingSigns {
    EndingSigns {
        probe: STATUS_INFO_LENGTH_MISMATCH.0,
        basic: 0,
        exit_status: STILL_ACTIVE.0,
        deleting: false,
    }
}

#[test]
fn a_running_process_shows_no_sign_of_ending() {
    assert!(!running_signs().ending());
}

#[test]
fn each_sign_alone_says_the_process_is_ending() {
    let probe = EndingSigns {
        probe: STATUS_PROCESS_IS_TERMINATING.0,
        ..running_signs()
    };
    let basic = EndingSigns {
        basic: STATUS_PROCESS_IS_TERMINATING.0,
        ..running_signs()
    };
    let deleting = EndingSigns {
        deleting: true,
        ..running_signs()
    };
    let exit_status = EndingSigns {
        exit_status: 1,
        ..running_signs()
    };
    for (what, signs) in [
        ("probe", probe),
        ("query", basic),
        ("deleting flag", deleting),
        ("exit status", exit_status),
    ] {
        assert!(signs.ending(), "{what}: {signs}");
    }
}

#[test]
fn a_refused_query_is_no_sign_of_ending_whatever_it_left_in_its_fields() {
    // A real access denial on a running process stays an error: the fields of a query that failed
    // are not an answer.
    let refused = EndingSigns {
        basic: STATUS_ACCESS_DENIED.0,
        exit_status: 1,
        deleting: true,
        ..running_signs()
    };
    assert!(!refused.ending(), "{refused}");
}

#[test]
fn the_signs_print_every_answer_for_a_test_that_measures_them() {
    let text = running_signs().to_string();
    assert!(text.contains("0xc0000004"), "{text}");
    assert!(text.contains("exit status 0x00000103"), "{text}");
    assert!(text.contains("deleting false"), "{text}");
}
