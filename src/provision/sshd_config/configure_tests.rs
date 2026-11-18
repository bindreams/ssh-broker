//! Host tests for the flow of `apply`'s sshd step, over a stand-in for the machine: files in memory, the
//! answers of `sshd` scripted, a service whose state follows a script of what `net` says and does, and a clock
//! that ticks at every write and every start. The real files, the real `sshd` and the service are measured by
//! `tests/sshd_config_windows.rs`, which CI runs.
use super::super::{ACCEPT_LINE, DROP_IN_NAME, INCLUDE_LINE, drop_in_text, with_line};
use super::*;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::time::{Duration, UNIX_EPOCH};

const STOCK: &str = "#Port 22\r\n#AcceptEnv LANG LC_*\r\nSubsystem sftp sftp-server.exe\r\n\r\nMatch Group administrators\r\n       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys\r\n";

/// What one `net` command says, and the state the service manager shows after it.
struct NetStep {
    said: Result<(), String>,
    state: ServiceState,
}

fn step(said: Result<(), &str>, state: ServiceState) -> NetStep {
    NetStep {
        said: said.map_err(str::to_owned),
        state,
    }
}

fn changing(name: &str) -> ServiceState {
    ServiceState::Changing(name.to_owned())
}

/// The machine: what the host's methods read and write, what was done in which order, and what goes wrong.
#[derive(Default)]
struct Fake {
    config: Vec<u8>,
    drop_in: Option<Vec<u8>>,
    candidate: Option<Vec<u8>>,
    /// Every call that changes or runs something, in order.
    events: Vec<String>,
    /// Every call of any method, in order.
    calls: RefCell<Vec<&'static str>>,
    /// The original, as it was when `sshd -t` looked at the candidate.
    config_at_check: Option<Vec<u8>>,
    /// What `sshd -t` says of the candidate when it rejects it.
    check_error: Option<String>,
    /// `sshd -T -f <candidate>` does not show the variable.
    candidate_hides_variable: bool,
    /// What the service manager says; `Fake::with_config` makes it `Running`.
    state: Option<ServiceState>,
    /// What each `net stop` and `net start` says and leaves the service in, in order; when it runs out, success
    /// and stopped, or success and running.
    net_script: VecDeque<NetStep>,
    /// What each wait for the service's process leaves the service in; stopped when it runs out.
    wait_script: VecDeque<ServiceState>,
    /// The wait's failure bound expires, with this cause.
    wait_error: Option<String>,
    waits: usize,
    /// How many times the state was read, and which of those reads (counted from 0) fail.
    state_reads: usize,
    unreadable_reads: Vec<usize>,
    /// The method that fails.
    fail: Option<&'static str>,
    /// The call of `sshd -T` (counted from 0, candidate or not) from which it fails.
    sshd_t_fails_from: Option<usize>,
    sshd_t_calls: usize,
    /// Why the drop-in folder is refused: it is there and cannot be used.
    folder_problem: Option<String>,
    /// Why the drop-in folder cannot be made.
    folder_not_made: Option<String>,
    /// The arguments the service's command line has.
    arguments: Option<String>,
    /// The server sets the variable itself, whatever the file says.
    pins_the_variable: bool,
    drop_in_writes: usize,
    config_replacements: usize,
    /// The clock, which ticks at every write and every start of the service.
    clock: u64,
    /// When the running service started; `None` when it is not running.
    service_started_at: Option<u64>,
    config_time: u64,
    drop_in_time: Option<u64>,
}

impl Fake {
    /// A machine whose sshd started after both files were written: it has read them.
    fn with_config(config: &str) -> Fake {
        Fake {
            config: config.as_bytes().to_vec(),
            clock: 100,
            service_started_at: Some(2),
            state: Some(ServiceState::Running),
            config_time: 1,
            ..Fake::default()
        }
    }

    /// The service is not running.
    fn stopped(mut self) -> Fake {
        self.state = Some(ServiceState::Stopped);
        self.service_started_at = None;
        self
    }

    /// `with_config` with the drop-in that `apply` writes, and an `Include` that reads it.
    fn configured() -> Fake {
        let mut host = Fake::with_config(&format!("Port 22\r\n{INCLUDE_LINE}\r\nMatch All\r\n"));
        host.drop_in = Some(drop_in_text().into_bytes());
        host.drop_in_time = Some(1);
        host
    }

    fn event(&mut self, name: &str) {
        self.events.push(name.to_owned());
    }

    fn call(&self, name: &'static str) {
        self.calls.borrow_mut().push(name);
    }

    fn tick(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }

    fn fails(&self, method: &str) -> anyhow::Result<()> {
        anyhow::ensure!(self.fail != Some(method), "{method} failed");
        Ok(())
    }

    /// What `sshd -T` prints for `config` with the drop-in as it is: the variable is accepted when an `AcceptEnv`
    /// for it, or an `Include` of the drop-ins that finds the drop-in, comes before the first `Match`.
    fn listing(&self, config: &[u8]) -> String {
        let mut accepted = false;
        for line in String::from_utf8_lossy(config).lines() {
            let line = line.trim();
            if line.to_ascii_lowercase().starts_with("match ") {
                break;
            }
            accepted |= line == ACCEPT_LINE
                || (line == INCLUDE_LINE && self.drop_in.as_deref() == Some(drop_in_text().as_bytes()));
        }
        let mut out = "port 22\r\n".to_owned();
        if accepted {
            out += "acceptenv SSH_BROKER_ELEVATION\r\n";
        }
        if self.pins_the_variable {
            out += "setenv SSH_BROKER_ELEVATION=never\r\n";
        }
        out
    }

    fn stops(&self) -> usize {
        self.events.iter().filter(|e| *e == "stop").count()
    }

    fn starts(&self) -> usize {
        self.events.iter().filter(|e| *e == "start").count()
    }

    fn folder() -> PathBuf {
        PathBuf::from("sshd_config.d")
    }
}

fn at(tick: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(tick)
}

impl SshdHost for Fake {
    fn config_path(&self) -> PathBuf {
        self.call("config_path");
        PathBuf::from("sshd_config")
    }

    fn service_arguments(&self) -> Option<String> {
        self.call("service_arguments");
        self.arguments.clone()
    }

    fn sshd_t(&mut self, config: Option<&Path>) -> anyhow::Result<String> {
        self.call("sshd_t");
        self.fails("sshd_t")?;
        let call = self.sshd_t_calls;
        self.sshd_t_calls += 1;
        anyhow::ensure!(self.sshd_t_fails_from.is_none_or(|from| call < from), "sshd_t failed");
        Ok(match config {
            None => self.listing(&self.config),
            Some(_) if self.candidate_hides_variable => "port 22\r\n".into(),
            Some(_) => self.listing(self.candidate.as_deref().expect("the candidate was written")),
        })
    }

    fn sshd_check(&mut self, _config: &Path) -> Result<(), String> {
        self.call("sshd_check");
        self.events.push("sshd -t".into());
        self.config_at_check = Some(self.config.clone());
        self.check_error.clone().map_or(Ok(()), Err)
    }

    fn service_state(&mut self) -> anyhow::Result<ServiceState> {
        self.call("service_state");
        let read = self.state_reads;
        self.state_reads += 1;
        anyhow::ensure!(!self.unreadable_reads.contains(&read), "state read {read} failed");
        Ok(self.state.clone().expect("the stand-in has a state"))
    }

    fn net(&mut self, verb: Service) -> Result<(), String> {
        self.call("net");
        self.event(match verb {
            Service::Stop => "stop",
            Service::Start => "start",
        });
        let step = self.net_script.pop_front().unwrap_or(NetStep {
            said: Ok(()),
            state: match verb {
                Service::Stop => ServiceState::Stopped,
                Service::Start => ServiceState::Running,
            },
        });
        match (verb, &step.state) {
            (_, ServiceState::Stopped) => self.service_started_at = None,
            (Service::Start, ServiceState::Running) => self.service_started_at = Some(self.tick()),
            _ => {}
        }
        self.state = Some(step.state);
        step.said
    }

    fn wait_while_stopping(&mut self) -> anyhow::Result<()> {
        self.call("wait_while_stopping");
        self.event("wait");
        self.waits += 1;
        if let Some(cause) = &self.wait_error {
            anyhow::bail!("{cause}");
        }
        let state = self.wait_script.pop_front().unwrap_or(ServiceState::Stopped);
        if state == ServiceState::Stopped {
            self.service_started_at = None;
        }
        self.state = Some(state);
        Ok(())
    }

    fn service_started(&mut self) -> anyhow::Result<Option<SystemTime>> {
        self.call("service_started");
        self.fails("service_started")?;
        Ok(self.service_started_at.map(at))
    }

    fn now(&self) -> SystemTime {
        self.call("now");
        at(self.clock)
    }

    fn config_written(&mut self) -> anyhow::Result<(PathBuf, SystemTime)> {
        self.call("config_written");
        self.fails("config_written")?;
        Ok(match self.drop_in_time {
            Some(drop_in) if drop_in > self.config_time => (Fake::folder().join(DROP_IN_NAME), at(drop_in)),
            _ => (PathBuf::from("sshd_config"), at(self.config_time)),
        })
    }

    fn ensure_drop_in_dir(&mut self) -> Result<(), DropInProblem> {
        self.call("ensure_drop_in_dir");
        self.fails("ensure_drop_in_dir")
            .map_err(|e| DropInProblem::Refused(format!("{e:#}")))?;
        if let Some(cause) = &self.folder_not_made {
            return Err(DropInProblem::NotMade(cause.clone()));
        }
        match &self.folder_problem {
            Some(problem) => Err(DropInProblem::Refused(problem.clone())),
            None => Ok(()),
        }
    }

    fn read_drop_in(&mut self) -> anyhow::Result<Option<Vec<u8>>> {
        self.call("read_drop_in");
        self.fails("read_drop_in")?;
        Ok(self.drop_in.clone())
    }

    fn write_drop_in(&mut self, text: &[u8]) -> anyhow::Result<()> {
        self.call("write_drop_in");
        self.fails("write_drop_in")?;
        self.event("write drop-in");
        self.drop_in_writes += 1;
        self.drop_in = Some(text.to_vec());
        self.drop_in_time = Some(self.tick());
        Ok(())
    }

    fn remove_drop_in(&mut self) -> anyhow::Result<()> {
        self.call("remove_drop_in");
        self.fails("remove_drop_in")?;
        self.event("remove drop-in");
        self.drop_in = None;
        self.drop_in_time = None;
        Ok(())
    }

    fn read_config(&mut self) -> anyhow::Result<Vec<u8>> {
        self.call("read_config");
        self.fails("read_config")?;
        Ok(self.config.clone())
    }

    fn write_candidate(&mut self, text: &[u8]) -> anyhow::Result<PathBuf> {
        self.call("write_candidate");
        self.fails("write_candidate")?;
        self.event("write candidate");
        self.candidate = Some(text.to_vec());
        Ok(PathBuf::from("sshd_config.candidate"))
    }

    fn copy_security(&mut self, _candidate: &Path) -> anyhow::Result<()> {
        self.call("copy_security");
        self.fails("copy_security")?;
        self.event("copy security");
        Ok(())
    }

    fn replace_config(&mut self, _candidate: &Path) -> anyhow::Result<()> {
        self.call("replace_config");
        self.fails("replace_config")?;
        self.event("replace config");
        self.config_replacements += 1;
        self.config = self.candidate.take().expect("the candidate was written");
        self.config_time = self.tick();
        Ok(())
    }

    fn discard_candidate(&mut self, _candidate: &Path) {
        self.call("discard_candidate");
        self.event("discard candidate");
        self.candidate = None;
    }
}

/// Run the flow and return what it said with its result.
fn run(host: &mut Fake) -> (bool, Vec<String>) {
    let mut said = Vec::new();
    let accepted = configure(host, &mut |line| said.push(line.to_owned()));
    (accepted, said)
}

fn position(events: &[String], name: &str) -> usize {
    events
        .iter()
        .position(|e| e == name)
        .unwrap_or_else(|| panic!("no {name:?} in {events:?}"))
}

/// What `apply` says to do by hand.
fn advice() -> String {
    format!(
        "apply: add `{ACCEPT_LINE}` above the first `Match` in sshd_config, then run `ssh-broker apply` again, \
         which restarts sshd; `ssh-broker elevate` works without it"
    )
}

fn said_advice(said: &[String]) -> bool {
    said.contains(&advice())
}

/// What `apply` says when it cannot ask sshd for its configuration: the next `apply` stops at the same place,
/// so the advice is to add the line by hand.
fn ask_failed(cause: &str, left: &str) -> String {
    format!(
        "apply: could not ask sshd for its configuration ({cause}), so {left}. To have sshd accept \
         SSH_BROKER_ELEVATION, add `{ACCEPT_LINE}` above the first `Match` in sshd_config and restart sshd; \
         `ssh-broker elevate` works without it."
    )
}

/// No sentence of the step tells anyone to remove a file or a folder.
fn assert_nothing_to_remove(said: &[String]) {
    for line in said {
        assert!(
            !line.to_ascii_lowercase().contains("remove") && !line.contains("Inspect it"),
            "{line}"
        );
    }
}

// the question to sshd =====

#[test]
fn sshd_is_asked_before_anything_is_written_and_a_failure_writes_nothing() {
    let mut host = Fake::with_config(STOCK);
    host.fail = Some("sshd_t");
    let (accepted, said) = run(&mut host);
    assert!(!accepted);
    assert!(host.events.is_empty(), "{:?}", host.events);
    assert_eq!(host.drop_in, None);
    assert_eq!(host.config, STOCK.as_bytes());
    assert_eq!(said, [ask_failed("sshd_t failed", "nothing of sshd's was changed")]);
    assert_eq!(*host.calls.borrow(), ["service_arguments", "sshd_t", "config_path"]);
}

#[test]
fn a_service_with_arguments_changes_nothing_and_says_where_to_add_the_line() {
    let mut host = Fake::with_config(STOCK);
    host.arguments = Some(r"-f D:\conf\sshd_config".into());
    let (accepted, said) = run(&mut host);
    assert!(!accepted);
    assert_eq!(
        said,
        [format!(
            "apply: the sshd service runs with arguments (`-f D:\\conf\\sshd_config`), which can name another \
             configuration file, so nothing of sshd's was changed. To have sshd accept SSH_BROKER_ELEVATION, add \
             `{ACCEPT_LINE}` above the first `Match` in the file it reads and restart sshd; `ssh-broker elevate` \
             works without it."
        )]
    );
    // Nothing of sshd's was read or changed: the check is the only call.
    assert_eq!(*host.calls.borrow(), ["service_arguments"]);
}

// a variable that is in force =====

#[test]
fn a_config_that_already_accepts_the_variable_is_left_alone_and_nothing_is_restarted() {
    // Through the drop-in and its `Include`.
    let mut host = Fake::configured();
    let (accepted, said) = run(&mut host);
    assert!(accepted, "{said:?}");
    assert!(host.events.is_empty(), "{:?}", host.events);
    assert!(said.is_empty(), "{said:?}");

    // Through a line of its own: no drop-in is written for it.
    let mut host = Fake::with_config(&format!("Port 22\r\n{ACCEPT_LINE}\r\nMatch All\r\n"));
    let (accepted, said) = run(&mut host);
    assert!(accepted, "{said:?}");
    assert!(host.events.is_empty(), "{:?}", host.events);
    assert_eq!(host.drop_in, None);
    assert!(said.is_empty(), "{said:?}");
}

#[test]
fn a_server_that_sets_the_variable_itself_is_left_alone() {
    let mut host = Fake::with_config(STOCK);
    host.pins_the_variable = true;
    let (accepted, said) = run(&mut host);
    assert!(accepted, "{said:?}");
    assert!(host.events.is_empty(), "{:?}", host.events);
    assert_eq!(host.config, STOCK.as_bytes());
    assert_eq!(host.drop_in, None);
}

// a change sshd has not read =====

#[test]
fn a_change_sshd_has_not_read_gets_a_restart_and_nothing_written() {
    // The configuration was written after sshd started.
    let mut host = Fake::configured();
    host.config_time = 20;
    let (accepted, said) = run(&mut host);
    assert!(accepted, "{said:?}");
    assert_eq!(host.events, ["stop", "start"]);
    assert_eq!(
        said[0],
        "apply: sshd was started before sshd_config was last written, so it may not have read it; restarting sshd"
    );

    // The drop-in is the later file: it is the one named.
    let mut host = Fake::configured();
    host.drop_in_time = Some(20);
    let (accepted, said) = run(&mut host);
    assert!(accepted, "{said:?}");
    assert_eq!(host.events, ["stop", "start"]);
    assert_eq!(
        said[0],
        format!(
            "apply: sshd was started before {} was last written, so it may not have read it; restarting sshd",
            Fake::folder().join(DROP_IN_NAME).display()
        )
    );

    // Written after it started, so nothing is restarted. A service that is not running reads what is there when
    // it starts.
    let mut host = Fake::configured();
    host.service_started_at = Some(5);
    assert!(run(&mut host).0 && host.events.is_empty());
    let mut host = Fake::configured();
    host.config_time = 20;
    host.service_started_at = None;
    let (accepted, said) = run(&mut host);
    assert!(accepted && host.events.is_empty() && said.is_empty(), "{said:?}");
}

#[test]
fn a_file_written_in_the_tick_sshd_started_in_is_judged_unread() {
    let mut host = Fake::configured();
    host.service_started_at = Some(5);
    host.config_time = 5;
    let (accepted, said) = run(&mut host);
    assert!(accepted, "{said:?}");
    assert_eq!(host.events, ["stop", "start"]);
    assert_eq!(
        said[0],
        "apply: sshd was started before sshd_config was last written, so it may not have read it; restarting sshd"
    );
}

#[test]
fn a_file_whose_time_is_ahead_of_the_clock_cannot_be_judged_and_sshd_is_restarted_each_time() {
    let mut host = Fake::configured();
    host.config_time = host.clock + 1000;
    let (accepted, said) = run(&mut host);
    assert!(accepted, "{said:?}");
    assert_eq!(host.events, ["stop", "start"]);
    assert_eq!(
        said[0],
        "apply: sshd_config's last-write time is ahead of this machine's clock, so it cannot be told whether sshd \
         has read it; restarting sshd"
    );
    assert_eq!(
        said.last().unwrap(),
        "apply: sshd restarted; it accepts SSH_BROKER_ELEVATION"
    );

    // The restart did not settle it: the next run restarts sshd again.
    let (accepted, said) = run(&mut host);
    assert!(accepted, "{said:?}");
    assert_eq!(host.events, ["stop", "start", "stop", "start"]);

    // A service that is not running reads what is there when it starts, whatever the time.
    let mut host = Fake::configured().stopped();
    host.config_time = host.clock + 1000;
    let (accepted, said) = run(&mut host);
    assert!(accepted && host.events.is_empty() && said.is_empty(), "{said:?}");
}

#[test]
fn a_time_that_cannot_be_read_says_so_and_restarts_nothing() {
    for method in ["service_started", "config_written"] {
        let mut host = Fake::configured();
        host.config_time = 20;
        host.fail = Some(method);
        let (accepted, said) = run(&mut host);
        assert!(!accepted, "{method}");
        assert!(host.events.is_empty(), "{method}: {:?}", host.events);
        let line = said.last().unwrap();
        assert!(
            line.starts_with("apply: cannot tell whether sshd has read its configuration (")
                && line.contains(&format!("{method} failed"))
                && line.ends_with("); it was not restarted"),
            "{method}: {said:?}"
        );
    }
}

#[test]
fn a_restart_of_an_unread_configuration_whose_first_start_fails_has_nothing_to_put_back_and_the_second_start_runs() {
    let mut host = Fake::configured();
    host.config_time = 20;
    host.net_script = VecDeque::from([
        step(Ok(()), ServiceState::Stopped),
        step(Err("The service did not respond"), ServiceState::Stopped),
        step(Ok(()), ServiceState::Running),
    ]);
    let (accepted, said) = run(&mut host);
    assert!(accepted, "sshd runs and has read the files: {said:?}");
    assert_eq!(host.starts(), 2);
    assert_eq!(host.config_replacements + host.drop_in_writes, 0, "no file was touched");
    assert_eq!(
        said.last().unwrap(),
        "apply: sshd failed to start once (The service did not respond); a second start worked and sshd is \
         running. It accepts SSH_BROKER_ELEVATION."
    );
}

// the include =====

#[test]
fn a_config_that_has_the_include_but_no_drop_in_gets_the_drop_in_and_no_second_include() {
    let config = format!("Port 22\r\n{INCLUDE_LINE}\r\nMatch All\r\n");
    let mut host = Fake::with_config(&config);
    let (accepted, said) = run(&mut host);
    assert!(accepted, "{said:?}");
    assert_eq!(host.config, config.as_bytes(), "the main file is left alone");
    assert_eq!(host.drop_in.as_deref(), Some(drop_in_text().as_bytes()));
    assert!(
        !host.events.iter().any(|e| e == "sshd -t"),
        "no candidate was made: {:?}",
        host.events
    );
    // The drop-in is a change: sshd reads it at its next start.
    assert_eq!(host.events, ["write drop-in", "stop", "start"]);
}

#[test]
fn a_config_that_does_not_gets_the_drop_in_and_the_include_and_the_original_is_replaced_only_after_sshd_t_passes() {
    let mut host = Fake::with_config(STOCK);
    let (accepted, said) = run(&mut host);
    assert!(accepted, "{said:?}");
    assert_eq!(host.config, with_line(STOCK.as_bytes(), INCLUDE_LINE).unwrap());
    assert_eq!(host.drop_in.as_deref(), Some(drop_in_text().as_bytes()));
    assert_eq!(
        host.config_at_check.as_deref(),
        Some(STOCK.as_bytes()),
        "the original, when sshd -t ran"
    );
    let order = |name: &str| position(&host.events, name);
    assert!(order("write drop-in") < order("write candidate"));
    assert!(order("write candidate") < order("sshd -t") && order("sshd -t") < order("replace config"));
    assert!(order("replace config") < order("stop") && order("stop") < order("start"));
    assert_eq!(host.config_replacements, 1);
    assert!(
        host.candidate.is_none(),
        "the candidate is gone: it was renamed over the original"
    );
}

#[test]
fn a_candidate_sshd_rejects_leaves_the_original_byte_for_byte_and_says_which_line_to_add() {
    let mut host = Fake::with_config(STOCK);
    host.check_error = Some("line 5: Bad configuration option".into());
    let (accepted, said) = run(&mut host);
    assert!(!accepted);
    assert_eq!(host.config, STOCK.as_bytes());
    assert_eq!(host.config_replacements, 0);
    assert!(host.candidate.is_none(), "the candidate is removed: {:?}", host.events);
    assert!(said_advice(&said), "{said:?}");
    assert!(
        said.iter().any(|line| line.contains("Bad configuration option")),
        "{said:?}"
    );
    assert_nothing_to_remove(&said);
    // Nothing is in effect that was not, so there is nothing to restart for.
    assert_eq!(host.stops(), 0, "{:?}", host.events);
}

#[test]
fn a_candidate_that_does_not_show_the_variable_leaves_the_original() {
    let mut host = Fake::with_config(STOCK);
    host.candidate_hides_variable = true;
    let (accepted, said) = run(&mut host);
    assert!(!accepted);
    assert_eq!(host.config, STOCK.as_bytes());
    assert_eq!(host.config_replacements, 0);
    assert!(host.candidate.is_none());
    assert!(said_advice(&said), "{said:?}");
}

#[test]
fn a_config_that_cannot_be_edited_safely_is_left_and_says_which_line_to_add() {
    let mut host = Fake::with_config(STOCK);
    host.config = [&[0xFF, 0xFE][..], &[b'P', 0, b'o', 0]].concat();
    let before = host.config.clone();
    let (accepted, said) = run(&mut host);
    assert!(!accepted);
    assert_eq!(host.config, before);
    assert!(said_advice(&said), "{said:?}");
    assert!(said.iter().any(|line| line.contains("UTF-16")), "{said:?}");
    assert!(!host.events.iter().any(|e| e == "write candidate"));
}

#[test]
fn the_originals_acl_is_on_the_replacement() {
    let mut host = Fake::with_config(STOCK);
    run(&mut host);
    let order = |name: &str| position(&host.events, name);
    assert!(
        order("write candidate") < order("copy security") && order("copy security") < order("replace config"),
        "{:?}",
        host.events
    );
}

#[test]
fn a_question_to_sshd_that_fails_after_the_drop_in_was_written_changes_nothing_more() {
    let mut host = Fake::with_config(STOCK);
    host.sshd_t_fails_from = Some(1);
    let (accepted, said) = run(&mut host);
    assert!(!accepted);
    assert_eq!(host.events, ["write drop-in"]);
    assert_eq!(host.config, STOCK.as_bytes());
    assert_eq!(said, [ask_failed("sshd_t failed", "sshd_config was left as it is")]);
}

// a folder that cannot be used =====

#[test]
fn a_drop_in_folder_that_is_not_administrator_only_gets_the_acceptenv_line_in_sshd_config() {
    let mut host = Fake::with_config(STOCK);
    host.folder_problem = Some("its ACL is not the hardened one".into());
    let (accepted, said) = run(&mut host);
    assert!(accepted, "{said:?}");
    assert_eq!(host.config, with_line(STOCK.as_bytes(), ACCEPT_LINE).unwrap());
    assert_eq!(host.drop_in, None);
    assert_eq!(host.drop_in_writes, 0);
    assert!(
        !host.calls.borrow().contains(&"write_drop_in") && !host.calls.borrow().contains(&"read_drop_in"),
        "{:?}",
        host.calls
    );
    assert!(
        said.contains(&format!(
            "apply: {} is left as it is (its ACL is not the hardened one); SSH_BROKER_ELEVATION is accepted by a \
             line in sshd_config instead",
            Fake::folder().display()
        )),
        "{said:?}"
    );
    // Through the same candidate, checks and rename, and then a restart.
    let order = |name: &str| position(&host.events, name);
    assert!(order("write candidate") < order("sshd -t") && order("sshd -t") < order("replace config"));
    assert!(order("replace config") < order("stop") && order("stop") < order("start"));
    assert_nothing_to_remove(&said);
}

#[test]
fn a_drop_in_folder_that_cannot_be_made_is_said_not_to_be_made_and_the_line_goes_into_sshd_config() {
    let mut host = Fake::with_config(STOCK);
    host.folder_not_made = Some("Access is denied".into());
    let (accepted, said) = run(&mut host);
    assert!(accepted, "{said:?}");
    assert_eq!(host.config, with_line(STOCK.as_bytes(), ACCEPT_LINE).unwrap());
    assert_eq!(host.drop_in, None);
    assert!(
        said.contains(&format!(
            "apply: {} could not be made (Access is denied); SSH_BROKER_ELEVATION is accepted by a line in \
             sshd_config instead",
            Fake::folder().display()
        )),
        "{said:?}"
    );
    assert!(
        said.iter().all(|line| !line.contains("is left as it is")),
        "a folder that is not there is not left as it is: {said:?}"
    );
}

#[test]
fn a_drop_in_that_cannot_be_read_or_written_is_left_and_the_line_goes_into_sshd_config() {
    for method in ["read_drop_in", "write_drop_in"] {
        let mut host = Fake::with_config(STOCK);
        host.fail = Some(method);
        let (accepted, said) = run(&mut host);
        assert!(accepted, "{method}: {said:?}");
        assert_eq!(
            host.config,
            with_line(STOCK.as_bytes(), ACCEPT_LINE).unwrap(),
            "{method}"
        );
        assert_eq!(host.drop_in, None, "{method}");
        assert!(
            said.iter()
                .any(|line| line.contains("is left as it is") && line.contains(&format!("{method} failed"))),
            "{method}: {said:?}"
        );
        assert_nothing_to_remove(&said);
    }
}

#[test]
fn when_the_acceptenv_line_cannot_go_into_sshd_config_either_the_advice_is_to_add_it() {
    let mut host = Fake::with_config(STOCK);
    host.folder_problem = Some("its ACL is not the hardened one".into());
    host.check_error = Some("line 5: Bad configuration option".into());
    let (accepted, said) = run(&mut host);
    assert!(!accepted);
    assert_eq!(host.config, STOCK.as_bytes());
    assert!(said_advice(&said), "{said:?}");
    assert!(!said.iter().any(|line| line.contains("accepted by a line")), "{said:?}");
    assert_nothing_to_remove(&said);
}

// the restart =====

#[test]
fn sshd_is_restarted_only_after_a_change_and_not_when_it_is_stopped() {
    // A change restarts it, and the restart is the last thing done.
    let mut host = Fake::with_config(STOCK);
    let (accepted, _) = run(&mut host);
    assert!(accepted);
    assert_eq!(&host.events[host.events.len() - 2..], ["stop", "start"]);

    // A service that is not running stays stopped: it reads the change when it is started.
    let mut host = Fake::with_config(STOCK).stopped();
    let (accepted, said) = run(&mut host);
    assert!(accepted, "{said:?}");
    assert_eq!((host.stops(), host.starts()), (0, 0), "{:?}", host.events);
    assert_eq!(
        host.config,
        with_line(STOCK.as_bytes(), INCLUDE_LINE).unwrap(),
        "the change stays"
    );
    assert_eq!(
        said.last().unwrap(),
        "apply: sshd is not running, so it was not started; it reads the change when it is"
    );
}

const COULD_NOT_STOP_TAIL: &str = "and is running with its earlier configuration, so it does not accept \
     SSH_BROKER_ELEVATION yet; run `ssh-broker apply` again to restart it";

#[test]
fn a_stop_that_fails_while_sshd_still_runs_issues_no_start() {
    let mut host = Fake::with_config(STOCK);
    host.net_script = VecDeque::from([step(Err("Access is denied"), ServiceState::Running)]);
    let (accepted, said) = run(&mut host);
    assert!(!accepted, "{said:?}");
    assert_eq!(
        host.starts(),
        0,
        "it runs by the service manager's own word: {:?}",
        host.events
    );
    assert_eq!(host.waits, 0);
    assert_eq!(host.config, with_line(STOCK.as_bytes(), INCLUDE_LINE).unwrap());
    assert_eq!(
        said.last().unwrap(),
        &format!("apply: sshd could not be stopped (Access is denied) {COULD_NOT_STOP_TAIL}")
    );

    // And the next apply does restart it: sshd started before the files were written.
    host.net_script.clear();
    let before = host.events.len();
    let (accepted, said) = run(&mut host);
    assert!(accepted, "{said:?}");
    assert_eq!(host.events[before..], ["stop", "start"]);
}

#[test]
fn a_stop_that_reports_success_while_the_state_stays_running_is_a_stop_that_could_not_be_done() {
    let mut host = Fake::with_config(STOCK);
    host.net_script = VecDeque::from([step(Ok(()), ServiceState::Running)]);
    let (accepted, said) = run(&mut host);
    assert!(!accepted, "{said:?}");
    assert_eq!(host.starts(), 0, "{:?}", host.events);
    assert_eq!(
        said.last().unwrap(),
        &format!("apply: sshd could not be stopped (net reported success) {COULD_NOT_STOP_TAIL}")
    );
}

#[test]
fn a_stop_that_fails_while_sshd_is_stopping_waits_for_it_and_then_starts_it() {
    let mut host = Fake::with_config(STOCK);
    host.net_script = VecDeque::from([step(Err("The sshd service could not be stopped"), changing("stopping"))]);
    let (accepted, said) = run(&mut host);
    assert!(accepted, "{said:?}");
    assert_eq!(host.waits, 1);
    assert_eq!(host.events[host.events.len() - 3..], ["stop", "wait", "start"]);
    assert_eq!(host.config, with_line(STOCK.as_bytes(), INCLUDE_LINE).unwrap());
    assert_eq!(
        said.last().unwrap(),
        "apply: sshd restarted (net stop had said: The sshd service could not be stopped); it accepts \
         SSH_BROKER_ELEVATION"
    );
    assert!(
        host.service_started_at
            .is_some_and(|started| started > host.config_time)
    );
}

#[test]
fn a_service_that_is_running_again_after_the_wait_is_a_stop_that_could_not_be_done() {
    let mut host = Fake::with_config(STOCK);
    host.net_script = VecDeque::from([step(Err("Access is denied"), changing("stopping"))]);
    host.wait_script = VecDeque::from([ServiceState::Running]);
    let (accepted, said) = run(&mut host);
    assert!(!accepted, "{said:?}");
    assert_eq!((host.waits, host.starts()), (1, 0), "{:?}", host.events);
    assert_eq!(
        said.last().unwrap(),
        &format!("apply: sshd could not be stopped (Access is denied) {COULD_NOT_STOP_TAIL}")
    );
}

#[test]
fn a_wait_whose_bound_expires_is_said_and_the_start_is_issued_anyway() {
    let mut host = Fake::with_config(STOCK);
    host.net_script = VecDeque::from([step(Err("x"), changing("stopping"))]);
    host.wait_error = Some("the sshd service is still stopping".into());
    let (accepted, said) = run(&mut host);
    assert!(accepted, "{said:?}");
    assert_eq!(host.events[host.events.len() - 3..], ["stop", "wait", "start"]);
    assert!(
        said.contains(&"apply: the sshd service is still stopping; starting sshd anyway".to_owned()),
        "{said:?}"
    );
    assert_eq!(
        said.last().unwrap(),
        "apply: sshd restarted (net stop had said: x); it accepts SSH_BROKER_ELEVATION"
    );
}

#[test]
fn a_start_that_net_calls_a_failure_and_the_service_manager_calls_running_is_a_restart() {
    let mut host = Fake::with_config(STOCK);
    host.net_script = VecDeque::from([
        step(Ok(()), ServiceState::Stopped),
        step(
            Err("The requested service has already been started"),
            ServiceState::Running,
        ),
    ]);
    let (accepted, said) = run(&mut host);
    assert!(accepted, "{said:?}");
    assert_eq!(host.config, with_line(STOCK.as_bytes(), INCLUDE_LINE).unwrap());
    assert_eq!(
        said.last().unwrap(),
        "apply: sshd restarted; it accepts SSH_BROKER_ELEVATION"
    );
}

#[test]
fn a_state_that_cannot_be_read_is_never_a_sentence_that_says_sshd_runs_or_does_not() {
    let as_fact = |said: &[String]| {
        said.iter()
            .any(|line| line.contains("is running") || line.contains("NOT running") || line.contains("running again"))
    };

    // The first read (before the stop): not known to be stopped, so the stop is issued.
    let mut host = Fake::with_config(STOCK);
    host.unreadable_reads = vec![0];
    let (accepted, said) = run(&mut host);
    assert!(accepted, "{said:?}");
    assert_eq!(host.events[host.events.len() - 2..], ["stop", "start"]);
    assert_eq!(
        said.last().unwrap(),
        "apply: sshd restarted; it accepts SSH_BROKER_ELEVATION"
    );

    // The reads after the stop and after the wait: not known to be running or stopped, so the start is issued.
    let mut host = Fake::with_config(STOCK);
    host.net_script = VecDeque::from([step(Err("Access is denied"), ServiceState::Running)]);
    host.unreadable_reads = vec![1, 2];
    let (accepted, said) = run(&mut host);
    assert!(accepted, "{said:?}");
    assert_eq!((host.waits, host.starts()), (1, 1), "{:?}", host.events);
    assert!(!as_fact(&said), "{said:?}");
    assert_eq!(
        said.last().unwrap(),
        "apply: sshd restarted (net stop had said: Access is denied); it accepts SSH_BROKER_ELEVATION"
    );

    // The reads after both starts: the files are put back, and what is said is that it is not known.
    let mut host = Fake::with_config(STOCK);
    host.unreadable_reads = vec![2, 3];
    let (accepted, said) = run(&mut host);
    assert!(!accepted, "{said:?}");
    assert_eq!(host.starts(), 2);
    assert_eq!(host.config, STOCK.as_bytes());
    assert!(!as_fact(&said), "{said:?}");
    assert_eq!(
        said.last().unwrap(),
        "apply: sshd may not be running (its state could not be read: state read 3 failed): it failed to start \
         with SSH_BROKER_ELEVATION accepted (net start sshd reported success, and its state could not be read: \
         state read 2 failed), and again with the original configuration put back (net start sshd reported \
         success, and its state could not be read: state read 3 failed). Start it at this PC: `net start sshd`."
    );
}

#[test]
fn a_start_that_fails_after_the_stop_puts_the_original_config_and_drop_in_back_and_starts_again_and_says_so() {
    // The drop-in did not exist before: it is removed.
    let mut host = Fake::with_config(STOCK);
    host.net_script = VecDeque::from([
        step(Ok(()), ServiceState::Stopped),
        step(Err("The service did not respond"), ServiceState::Stopped),
        step(Ok(()), ServiceState::Running),
    ]);
    let (accepted, said) = run(&mut host);
    assert!(!accepted);
    assert_eq!(host.config, STOCK.as_bytes(), "the original, byte for byte");
    assert_eq!(host.drop_in, None);
    assert_eq!(host.starts(), 2);
    assert_eq!(
        said.last().unwrap(),
        "apply: sshd failed to start with SSH_BROKER_ELEVATION accepted (The service did not respond); the \
         original configuration was put back and sshd is running again. It does not accept SSH_BROKER_ELEVATION."
    );

    // A drop-in that was there with other text comes back as it was.
    let mut host = Fake::with_config(STOCK);
    host.drop_in = Some(b"AcceptEnv OTHER\r\n".to_vec());
    host.drop_in_time = Some(1);
    host.net_script = VecDeque::from([
        step(Ok(()), ServiceState::Stopped),
        step(Err("no"), ServiceState::Stopped),
        step(Ok(()), ServiceState::Running),
    ]);
    run(&mut host);
    assert_eq!(host.config, STOCK.as_bytes());
    assert_eq!(host.drop_in.as_deref(), Some(&b"AcceptEnv OTHER\r\n"[..]));
}

#[test]
fn two_failed_starts_say_sshd_is_not_running_with_the_state_and_how_to_start_it() {
    let mut host = Fake::with_config(STOCK);
    host.net_script = VecDeque::from([
        step(Ok(()), ServiceState::Stopped),
        step(Err("first"), ServiceState::Stopped),
        step(Err("second"), ServiceState::Stopped),
    ]);
    let (accepted, said) = run(&mut host);
    assert!(!accepted);
    assert_eq!(host.config, STOCK.as_bytes(), "the original is back even so");
    assert_eq!(
        said.last().unwrap(),
        "apply: sshd is NOT running (the service manager says: stopped): it failed to start with \
         SSH_BROKER_ELEVATION accepted (first), and again with the original configuration put back (second). \
         Start it at this PC: `net start sshd`."
    );

    // A start that net calls a success and the service manager does not show running is quoted as that.
    let mut host = Fake::with_config(STOCK);
    host.net_script = VecDeque::from([
        step(Ok(()), ServiceState::Stopped),
        step(Ok(()), changing("starting")),
        step(Ok(()), changing("starting")),
    ]);
    let (accepted, said) = run(&mut host);
    assert!(!accepted);
    let seen = "net start sshd reported success, and the service manager says: starting";
    assert_eq!(
        said.last().unwrap(),
        &format!(
            "apply: sshd is NOT running (the service manager says: starting): it failed to start with \
             SSH_BROKER_ELEVATION accepted ({seen}), and again with the original configuration put back ({seen}). \
             Start it at this PC: `net start sshd`."
        )
    );
}

// a second run and failures =====

#[test]
fn apply_twice_changes_nothing_and_restarts_nothing() {
    let mut host = Fake::with_config(STOCK);
    let (first, _) = run(&mut host);
    assert!(first);
    let (config, drop_in) = (host.config.clone(), host.drop_in.clone());
    // Every write was before the last start: sshd has read them.
    assert!(host.service_started_at.unwrap() > host.config_time);
    assert!(host.service_started_at.unwrap() > host.drop_in_time.unwrap());
    let events = host.events.len();

    let (second, said) = run(&mut host);
    assert!(second, "{said:?}");
    assert!(said.is_empty(), "{said:?}");
    assert_eq!((&host.config, &host.drop_in), (&config, &drop_in));
    assert_eq!(
        host.events.len(),
        events,
        "nothing was done at all: {:?}",
        &host.events[events..]
    );
}

#[test]
fn a_failure_of_any_step_does_not_fail_apply() {
    // These leave sshd's files as they were, say so, and report that the variable is not accepted.
    for method in [
        "sshd_t",
        "read_config",
        "write_candidate",
        "copy_security",
        "replace_config",
    ] {
        let mut host = Fake::with_config(STOCK);
        host.fail = Some(method);
        let (accepted, said) = run(&mut host);
        assert!(!said.is_empty(), "{method}: it said nothing");
        assert!(!accepted, "{method}");
        assert_eq!(host.config, STOCK.as_bytes(), "{method}");
        assert!(host.candidate.is_none(), "{method}: the candidate is not left behind");
        assert_eq!(host.stops(), 0, "{method}");
        assert_nothing_to_remove(&said);
    }
    // These make the folder unusable: the line goes into sshd_config instead.
    for method in ["ensure_drop_in_dir", "read_drop_in", "write_drop_in"] {
        let mut host = Fake::with_config(STOCK);
        host.fail = Some(method);
        let (accepted, said) = run(&mut host);
        assert!(accepted, "{method}: {said:?}");
        assert!(!said.is_empty(), "{method}: it said nothing");
    }
    // `remove_drop_in` is reached only by a rollback.
    let mut host = Fake::with_config(STOCK);
    host.fail = Some("remove_drop_in");
    host.net_script = VecDeque::from([
        step(Ok(()), ServiceState::Stopped),
        step(Err("x"), ServiceState::Stopped),
    ]);
    let (accepted, said) = run(&mut host);
    assert!(!accepted && !said.is_empty());
}
