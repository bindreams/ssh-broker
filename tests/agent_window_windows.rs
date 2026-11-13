//! The agent shows no window on the desktop of the session that starts it. Windows only;
//! **Elevated (CI only)**.
//!
//! The logon task starts `ssh-broker agent` from a process with no console, so the system gives
//! the agent a console with a window. The test starts the real agent the same way, with a console
//! of its own (`CREATE_NEW_CONSOLE`), on a desktop of its own, and looks at that desktop from
//! outside: any window on it is a failure, before the agent serves a session and while it serves a
//! terminal session and a command on pipes, which start children of their own from an agent that has
//! no console.
//!
//! A look that finds nothing proves nothing if the window can never appear there, so a control
//! comes first: a plain console program started the same way must show a window on the same kind of
//! desktop. Without that, the test fails.
#![cfg(windows)]

use std::fs::OpenOptions;
use std::os::windows::io::AsRawHandle as _;
use std::path::Path;

use ssh_broker::agent_background::Refusal;
use ssh_broker::socket_loc::{self, SocketLocation};
use windows::Win32::Foundation::{HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation, WAIT_OBJECT_0};
use windows::Win32::System::Threading::{INFINITE, TerminateProcess, WaitForSingleObject};

#[path = "common/account.rs"]
mod account_fixture;
#[path = "common/agent_conn.rs"]
mod agent_conn;
#[path = "common/bounded_wait.rs"]
mod bounded_wait;
#[path = "common/desktop.rs"]
mod desktop;
#[path = "common/hard_errors.rs"]
mod hard_errors;
#[path = "common/machine.rs"]
mod machine;
#[path = "common/password.rs"]
mod password;
#[path = "common/process_list.rs"]
mod process_list;
#[path = "common/stand_in.rs"]
mod stand_in;

use account_fixture::{Account, SharedDir, Spawned};
use agent_conn::AgentConn;
use process_list::Descendants;
use stand_in::file_signal::{FileWaited, wait_for_file};
use stand_in::{Kit, RealAgent};

/// The class of the window a console of its own has. A pseudoconsole's host makes no window of this class.
const CONSOLE_WINDOW: &str = "ConsoleWindowClass";

/// The control: a console program started with a console of its own shows a window
/// on its desktop, which is what the looks below depend on.
///
/// The program writes a file once it runs, and the window is looked at after that. The window is the console
/// host's, made when it hands the console to its first client, so a client that has run has one; a desktop
/// that does not show it by then fails the control, naming what it does show. The console host has no handle
/// or event for "my window exists" to wait on from outside.
#[test]
fn a_console_program_with_its_own_console_shows_a_window_to_the_look() {
    let _machine = machine::shared();
    let account = Account::create("winctl", true);
    let shared = SharedDir::new("winctl");
    let marker = shared.0.join("ran.txt");
    let cmd = Path::new(r"C:\Windows\System32\cmd.exe");
    // `/k` keeps it running, waiting for input on its console.
    let line = format!(r#""{}" /k echo ran>"{}""#, cmd.display(), marker.display());
    let child = account.spawn_in_new_console(cmd, &line, cmd.parent().unwrap(), &[], None);
    child.resume();
    match wait_for_file(&marker, Some(child.process.0), None, "the control console program") {
        FileWaited::Appeared => {}
        FileWaited::ProcessEnded(code) => panic!("the control console program ended with {code:#x} before it ran"),
    }
    let classes = child.window_classes();
    // SAFETY: a valid process handle; ending a process that already ended is harmless.
    let _ = unsafe { TerminateProcess(child.process.0, 1) };
    assert!(
        classes.iter().any(|class| class == CONSOLE_WINDOW),
        "a console program with a console of its own shows no window to the look; the windows on its desktop are {classes:?}"
    );
}

/// The agent, started as the logon task starts it (a console of its own), frees
/// the console once it runs and no window is left on the desktop; a terminal session and a command on
/// pipes then run with none either, and the agent still runs. It is the `--background` form because a CI
/// runner's session is 0, where a desktop agent refuses to start; the console is freed before the two
/// forms differ.
#[test]
fn the_agent_leaves_no_window_on_the_desktop() {
    let _machine = machine::shared();
    let kit = Kit::copy_of_broker("nowin");
    let account = Account::create("nowin", true);
    let agent = RealAgent::start_in_new_console(&kit, &account);

    // Serving begins after the console is freed.
    let location = socket_loc::for_profile(account.profile()).unwrap();
    stand_in::wait_for_serving_marker(&location, agent.process.process.0);
    wait_until_the_console_is_gone(&agent.process);
    assert_serving(&agent, &location, "it freed its console");

    // A terminal session: the shell runs in a pseudoconsole.
    let mut terminal = AgentConn::connect(&location);
    terminal.start_pty("cmd.exe");
    terminal.type_line("echo pty-%OS%");
    terminal.read_until_pty_shows("pty-Windows_NT");
    assert_no_console_window(&agent.process, "a terminal session runs");
    let terminal_hosts = live_console_hosts(&agent.process, "a terminal session runs");
    terminal.type_line("exit");
    terminal.read_to_end();
    wait_until_the_hosts_are_gone(&terminal_hosts);
    assert_no_console_window(&agent.process, "a terminal session ended");
    assert_serving(&agent, &location, "a terminal session ended");

    // A command on pipes.
    let mut command = AgentConn::connect(&location);
    command.start_exec("cmd.exe /c echo exec-ready & more");
    command.read_until_stdout_shows("exec-ready");
    assert_no_console_window(&agent.process, "a command on pipes runs");
    let command_hosts = live_console_hosts(&agent.process, "a command on pipes runs");
    command.end_stdin();
    let finished = command.read_to_end();
    assert_eq!(finished.exit, Some(0), "the command ended with {:?}", finished.exit);
    wait_until_the_hosts_are_gone(&command_hosts);
    assert_no_console_window(&agent.process, "a command on pipes ended");
    assert_serving(&agent, &location, "a command on pipes ended");
}

/// An agent that freed its console and then refuses to start still exits with its refusal code, which the
/// shim reads as the reason: writing the refusal to the now-null handles must not change it. No window is
/// left once it has ended.
///
/// The refusal comes before the agent's log opens, and the agent's exit ends its console whether or not it
/// freed it first, so this does not show that the free ran; it pins the exit code and the desktop.
#[test]
fn an_agent_that_freed_its_console_and_then_refuses_exits_with_its_refusal_code() {
    let _machine = machine::shared();
    let kit = Kit::copy_of_broker("nowinref");
    let account = Account::create("nowinref", true);
    // Not this account's SID, so the agent refuses once the console is freed.
    let agent = RealAgent::start_in_new_console_expecting(&kit, &account, "S-1-5-32-544", None);
    let code = agent.process.wait();
    assert_eq!(
        code,
        Refusal::WrongUser.code() as u32,
        "the agent that refused ended with {code:#x}"
    );
    wait_until_the_console_is_gone(&agent.process);
}

/// An agent that freed its console keeps a standard error an operator redirected to a file, and the
/// refusal text reaches it. That only the handles that referred to the console are nulled is checked on real
/// handles by `agent::console::console_tests`: a start here cannot give a child a console handle for one
/// standard stream and a file for another.
#[test]
fn an_agent_that_freed_its_console_keeps_a_redirected_standard_error() {
    let _machine = machine::shared();
    let kit = Kit::copy_of_broker("nowinredir");
    let account = Account::create("nowinredir", true);
    let shared = SharedDir::new("nowinredir");
    let written = shared.0.join("agent-stderr.txt");
    let output = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&written)
        .expect("create the file for the agent's output");
    let input = OpenOptions::new()
        .read(true)
        .write(true)
        .open("NUL")
        .expect("open NUL for the agent's input");
    let [input, output] = [&input, &output].map(|file| {
        let handle = HANDLE(file.as_raw_handle());
        // SAFETY: a valid handle; the secondary logon service copies inheritable handles into the child.
        unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT) }
            .expect("make a standard handle of the agent inheritable");
        handle
    });
    // Not this account's SID, so the agent refuses once the console is freed. It is alone on its console, so
    // it frees it.
    let agent =
        RealAgent::start_in_new_console_expecting(&kit, &account, "S-1-5-32-544", Some([input, output, output]));
    let code = agent.process.wait();
    assert_eq!(
        code,
        Refusal::WrongUser.code() as u32,
        "the agent that refused ended with {code:#x}"
    );
    wait_until_the_console_is_gone(&agent.process);
    let text = std::fs::read_to_string(&written).expect("read what the agent wrote");
    assert!(
        text.contains(&Refusal::WrongUser.to_string()),
        "the refusal did not reach the redirected standard error: {text:?}"
    );
}

/// The console hosts under the agent now, held open. The host of a console ends when its last client leaves,
/// and its window goes with it. A process that could not be opened may be a host, so it fails the test
/// instead of going unwaited.
fn console_hosts(agent: &Spawned) -> Descendants {
    let mut tree = process_list::descendants(agent.process.0, agent.pid);
    assert!(
        tree.unopened.is_empty(),
        "processes under the agent could not be opened to tell whether they are console hosts: {:?}",
        tree.unopened
    );
    tree.members
        .retain(|member| member.exe.eq_ignore_ascii_case("conhost.exe"));
    tree
}

/// [`console_hosts`] while `what` keeps a console alive, so that at least one host must be there. None found
/// means the host is not a descendant of the agent as the wait assumes (unmeasured), and fails the test
/// instead of letting the wait pass with nothing to wait for.
fn live_console_hosts(agent: &Spawned, what: &str) -> Descendants {
    let hosts = console_hosts(agent);
    assert!(
        !hosts.members.is_empty(),
        "no console host is under the agent while {what}; the processes under it are {:?}",
        process_list::descendants(agent.process.0, agent.pid)
            .members
            .iter()
            .map(|member| (member.pid, member.exe.clone()))
            .collect::<Vec<_>>()
    );
    hosts
}

/// Wait until every console host in `hosts` has ended. A host already gone has taken its window with it.
///
/// The wait has no bound: the host's exit is the real condition, and a host that never ends is a hang that
/// the runner's time limit for this binary ends and reports.
fn wait_until_the_hosts_are_gone(hosts: &Descendants) {
    for host in &hosts.members {
        // SAFETY: a valid process handle, held open by the member.
        let woke = unsafe { WaitForSingleObject(host.handle(), INFINITE) }; // sleep-ok: an unbounded wait on the real condition, the console host's exit
        assert_eq!(
            woke, WAIT_OBJECT_0,
            "waiting for the console host (pid {}) failed",
            host.pid
        );
    }
}

/// Wait until the console host of the agent's own console, if it is still there, has ended, and fail if a
/// window is then left. The host ends when the agent, its last client, frees the console or ends. The agent
/// frees it as its first act, so by the time of this look the host has usually ended already and taken its
/// window with it: none found is the normal case here, unlike for a session's console.
fn wait_until_the_console_is_gone(agent: &Spawned) {
    let hosts = console_hosts(agent);
    let found: Vec<_> = hosts.members.iter().map(|m| (m.pid, m.exe.clone())).collect();
    wait_until_the_hosts_are_gone(&hosts);
    let classes = agent.window_classes();
    assert!(
        classes.is_empty(),
        "a window is left on the agent's desktop after its console host ended: {classes:?}; the console hosts          found were {found:?}"
    );
}

/// No window of a console of its own is on the agent's desktop while `what`. A pseudoconsole host keeps
/// helper windows of its own there, so this names the class a console of its own makes (see
/// [`CONSOLE_WINDOW`]) and the control shows the look finds it.
///
/// A look while a session runs assumes the console host has made its window before the session's first
/// client runs, which is not measured. The look after the session and its host have ended still sees a window
/// that came late and stayed.
fn assert_no_console_window(agent: &Spawned, what: &str) {
    let classes = agent.window_classes();
    assert!(
        !classes.iter().any(|class| class == CONSOLE_WINDOW),
        "a console window is on the agent's desktop while {what}: {classes:?}"
    );
}

/// The agent runs, after `after`: a state check, not a wait.
fn assert_serving(agent: &RealAgent, location: &SocketLocation, after: &str) {
    assert!(
        agent.is_running(),
        "the agent ended after {after}; its log is in {}",
        location.logs_dir().display()
    );
}
