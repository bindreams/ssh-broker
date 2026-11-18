//! Host tests for the flow of `apply`'s sshd step, over a stand-in for the machine: files in memory, the
//! answers of `sshd` and `net` scripted, and a clock that ticks at every write and every start. The real
//! files, the real `sshd` and the service are measured by `tests/sshd_config_windows.rs`, which CI runs.
use super::super::{ACCEPT_LINE, DROP_IN_NAME, INCLUDE_LINE, drop_in_text, with_line};
use super::*;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::time::{Duration, UNIX_EPOCH};

const STOCK: &str = "#Port 22\r\n#AcceptEnv LANG LC_*\r\nSubsystem sftp sftp-server.exe\r\n\r\nMatch Group administrators\r\n       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys\r\n";

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
    /// What the service answers to each stop and start, in order; `Done` when it runs out.
    answers: VecDeque<ServiceOutcome>,
    /// The method that fails.
    fail: Option<&'static str>,
    /// The call of `sshd -T` (counted from 0, candidate or not) from which it fails.
    sshd_t_fails_from: Option<usize>,
    sshd_t_calls: usize,
    /// Why the drop-in folder is refused.
    folder_problem: Option<String>,
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
            clock: 10,
            service_started_at: Some(2),
            config_time: 1,
            ..Fake::default()
        }
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

    fn service(&mut self, verb: Service) -> ServiceOutcome {
        self.call("service");
        self.event(match verb {
            Service::Stop => "stop",
            Service::Start => "start",
        });
        let answer = self.answers.pop_front().unwrap_or(ServiceOutcome::Done);
        match (verb, &answer) {
            (Service::Stop, ServiceOutcome::Done | ServiceOutcome::Unchanged) => self.service_started_at = None,
            (Service::Start, ServiceOutcome::Done) => self.service_started_at = Some(self.tick()),
            _ => {}
        }
        answer
    }

    fn service_started(&mut self) -> anyhow::Result<Option<SystemTime>> {
        self.call("service_started");
        self.fails("service_started")?;
        Ok(self.service_started_at.map(at))
    }

    fn config_written(&mut self) -> anyhow::Result<(PathBuf, SystemTime)> {
        self.call("config_written");
        self.fails("config_written")?;
        Ok(match self.drop_in_time {
            Some(drop_in) if drop_in > self.config_time => (Fake::folder().join(DROP_IN_NAME), at(drop_in)),
            _ => (PathBuf::from("sshd_config"), at(self.config_time)),
        })
    }

    fn ensure_drop_in_dir(&mut self) -> anyhow::Result<()> {
        self.call("ensure_drop_in_dir");
        self.fails("ensure_drop_in_dir")?;
        match &self.folder_problem {
            Some(problem) => anyhow::bail!("{problem}"),
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
    assert!(said_advice(&said), "{said:?}");
    assert!(said.iter().any(|line| line.contains("could not ask sshd")), "{said:?}");
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
fn a_restart_of_an_unread_configuration_that_fails_to_start_says_nothing_was_put_back() {
    let mut host = Fake::configured();
    host.config_time = 20;
    host.answers = VecDeque::from([
        ServiceOutcome::Done,
        ServiceOutcome::Failed("The service did not respond".into()),
        ServiceOutcome::Done,
    ]);
    let (accepted, said) = run(&mut host);
    assert!(!accepted);
    assert_eq!(host.starts(), 2);
    assert_eq!(host.config_replacements + host.drop_in_writes, 0, "no file was touched");
    let last = said.last().unwrap();
    assert!(
        last.contains("The service did not respond") && last.contains("running again"),
        "{said:?}"
    );
    assert!(!last.contains("put back"), "{last}");
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
    assert!(said_advice(&said), "{said:?}");
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
    let mut host = Fake::with_config(STOCK);
    host.answers = VecDeque::from([ServiceOutcome::Unchanged]);
    let (accepted, said) = run(&mut host);
    assert!(accepted, "{said:?}");
    assert_eq!(host.starts(), 0, "{:?}", host.events);
    assert_eq!(
        host.config,
        with_line(STOCK.as_bytes(), INCLUDE_LINE).unwrap(),
        "the change stays"
    );
    assert!(said.last().unwrap().contains("not running"), "{said:?}");
}

#[test]
fn a_stop_that_fails_is_followed_by_a_start_and_what_that_says_decides() {
    let stop_failed = || ServiceOutcome::Failed("Access is denied".into());

    // It still runs: not restarted, and the next apply will.
    let mut host = Fake::with_config(STOCK);
    host.answers = VecDeque::from([stop_failed(), ServiceOutcome::Unchanged]);
    let (accepted, said) = run(&mut host);
    assert!(!accepted, "{said:?}");
    assert_eq!(host.starts(), 1, "a start is issued after a stop that failed");
    assert_eq!(host.config, with_line(STOCK.as_bytes(), INCLUDE_LINE).unwrap());
    assert_eq!(
        said.last().unwrap(),
        "apply: sshd could not be stopped (Access is denied) and is running with its earlier configuration, so it \
         does not accept SSH_BROKER_ELEVATION yet; run `ssh-broker apply` again to restart it"
    );

    // And the next apply does restart it: sshd started before the files were written.
    host.answers.clear();
    let before = host.events.len();
    let (accepted, said) = run(&mut host);
    assert!(accepted, "{said:?}");
    assert_eq!(host.events[before..], ["stop", "start"]);

    // It had stopped after all: the start brought it up with the change.
    let mut host = Fake::with_config(STOCK);
    host.answers = VecDeque::from([stop_failed(), ServiceOutcome::Done]);
    let (accepted, said) = run(&mut host);
    assert!(accepted, "{said:?}");
    assert_eq!(host.starts(), 1);
    assert_eq!(host.config, with_line(STOCK.as_bytes(), INCLUDE_LINE).unwrap());
    let last = said.last().unwrap();
    assert!(
        last.contains("Access is denied") && last.contains("restarted"),
        "{said:?}"
    );
    assert!(
        host.service_started_at
            .is_some_and(|started| started > host.config_time)
    );

    // Neither worked: the original files go back and sshd is started again.
    let mut host = Fake::with_config(STOCK);
    host.answers = VecDeque::from([stop_failed(), ServiceOutcome::Failed("no".into()), ServiceOutcome::Done]);
    let (accepted, said) = run(&mut host);
    assert!(!accepted);
    assert_eq!(host.config, STOCK.as_bytes());
    assert_eq!(host.drop_in, None);
    assert_eq!(host.starts(), 2);
    assert!(said.last().unwrap().contains("running again"), "{said:?}");

    // And the starts fail too: after a stop that failed it is not known that sshd is down.
    let mut host = Fake::with_config(STOCK);
    host.answers = VecDeque::from([
        stop_failed(),
        ServiceOutcome::Failed("no".into()),
        ServiceOutcome::Failed("still no".into()),
    ]);
    let (accepted, said) = run(&mut host);
    assert!(!accepted);
    let last = said.last().unwrap();
    assert!(
        last.contains("may not be running") && last.contains("still no") && !last.contains("NOT running"),
        "{said:?}"
    );
}

#[test]
fn a_start_that_fails_after_the_stop_puts_the_original_config_and_drop_in_back_and_starts_again_and_says_so() {
    // The drop-in did not exist before: it is removed.
    let mut host = Fake::with_config(STOCK);
    host.answers = VecDeque::from([
        ServiceOutcome::Done,
        ServiceOutcome::Failed("The service did not respond".into()),
        ServiceOutcome::Done,
    ]);
    let (accepted, said) = run(&mut host);
    assert!(!accepted);
    assert_eq!(host.config, STOCK.as_bytes(), "the original, byte for byte");
    assert_eq!(host.drop_in, None);
    assert_eq!(host.events.iter().filter(|e| *e == "start").count(), 2);
    let last = said.last().unwrap();
    assert!(
        last.contains("The service did not respond") && last.contains("running again"),
        "{said:?}"
    );
    assert!(!last.contains("NOT running"), "{last}");

    // A drop-in that was there with other text comes back as it was.
    let mut host = Fake::with_config(STOCK);
    host.drop_in = Some(b"AcceptEnv OTHER\r\n".to_vec());
    host.drop_in_time = Some(1);
    host.answers = VecDeque::from([
        ServiceOutcome::Done,
        ServiceOutcome::Failed("no".into()),
        ServiceOutcome::Done,
    ]);
    run(&mut host);
    assert_eq!(host.config, STOCK.as_bytes());
    assert_eq!(host.drop_in.as_deref(), Some(&b"AcceptEnv OTHER\r\n"[..]));
}

#[test]
fn a_second_failed_start_says_sshd_is_not_running_and_how_to_start_it() {
    let mut host = Fake::with_config(STOCK);
    host.answers = VecDeque::from([
        ServiceOutcome::Done,
        ServiceOutcome::Failed("first".into()),
        ServiceOutcome::Failed("second".into()),
    ]);
    let (accepted, said) = run(&mut host);
    assert!(!accepted);
    assert_eq!(host.config, STOCK.as_bytes(), "the original is back even so");
    let last = said.last().unwrap();
    assert!(
        last.contains("NOT running") && last.contains("net start sshd") && last.contains("second"),
        "{last}"
    );
}

#[test]
fn a_start_that_says_it_is_already_started_is_a_start() {
    let mut host = Fake::with_config(STOCK);
    host.answers = VecDeque::from([ServiceOutcome::Done, ServiceOutcome::Unchanged]);
    let (accepted, _) = run(&mut host);
    assert!(accepted);
    assert_eq!(host.config, with_line(STOCK.as_bytes(), INCLUDE_LINE).unwrap());
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
    host.answers = VecDeque::from([ServiceOutcome::Done, ServiceOutcome::Failed("x".into())]);
    let (accepted, said) = run(&mut host);
    assert!(!accepted && !said.is_empty());
}

// net.exe =====

#[test]
fn net_says_done_for_a_zero_exit_and_names_a_state_it_was_already_in() {
    assert_eq!(
        net_outcome(Service::Stop, 0, "The sshd service was stopped successfully.\r\n"),
        ServiceOutcome::Done
    );
    assert_eq!(
        net_outcome(
            Service::Stop,
            2,
            "The sshd service is not started.\r\n\r\nMore help is available by typing NET HELPMSG 3521.\r\n"
        ),
        ServiceOutcome::Unchanged
    );
    assert_eq!(
        net_outcome(
            Service::Start,
            2,
            "The requested service has already been started.\r\n\r\nMore help is available by typing NET HELPMSG 2182.\r\n"
        ),
        ServiceOutcome::Unchanged
    );
    // The code is the same in any language; the other service's code is a failure.
    assert!(matches!(
        net_outcome(Service::Start, 2, "NET HELPMSG 3521"),
        ServiceOutcome::Failed(_)
    ));
    assert!(matches!(
        net_outcome(Service::Stop, 2, "NET HELPMSG 2182"),
        ServiceOutcome::Failed(_)
    ));
}

#[test]
fn net_failure_carries_the_output_in_one_line() {
    let ServiceOutcome::Failed(said) = net_outcome(
        Service::Start,
        2,
        "System error 5 has occurred.\r\n\r\nAccess is denied.\r\n",
    ) else {
        panic!("a failure")
    };
    assert_eq!(said, "System error 5 has occurred. Access is denied.");
    let ServiceOutcome::Failed(empty) = net_outcome(Service::Stop, 1, "") else {
        panic!("a failure")
    };
    assert!(empty.contains("exit code 1"), "{empty}");
}
