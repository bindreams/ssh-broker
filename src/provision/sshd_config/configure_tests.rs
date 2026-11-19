//! Host tests for the flow of `apply`'s sshd step, over a stand-in for the machine: files in memory, the
//! answers of `sshd` scripted, and a clock that ticks at every write. The real files and the real `sshd` are
//! measured by `tests/sshd_config_windows.rs`, which CI runs.
use super::super::{ACCEPT_LINE, DROP_IN_NAME, INCLUDE_LINE, drop_in_text, with_line};
use super::*;
use std::cell::RefCell;
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
    /// The clock, which ticks at every write.
    clock: u64,
    /// When the running service started; `None` when it is not running.
    service_started_at: Option<u64>,
    config_time: u64,
    drop_in_time: Option<u64>,
    /// When `sshd_config.d` itself last changed; `None` when there is no such folder.
    folder_time: Option<u64>,
    /// The other files in `sshd_config.d`: name, change time, text.
    other_files: Vec<(&'static str, u64, Vec<u8>)>,
}

impl Fake {
    /// A machine whose sshd started after both files were written: it has read them.
    fn with_config(config: &str) -> Fake {
        Fake {
            config: config.as_bytes().to_vec(),
            clock: 100,
            service_started_at: Some(2),
            config_time: 1,
            ..Fake::default()
        }
    }

    /// The service is not running.
    fn stopped(mut self) -> Fake {
        self.service_started_at = None;
        self
    }

    /// `with_config` with the drop-in that `apply` writes, and an `Include` that reads it.
    fn configured() -> Fake {
        let mut host = Fake::with_config(&format!("Port 22\r\n{INCLUDE_LINE}\r\nMatch All\r\n"));
        host.drop_in = Some(drop_in_text().into_bytes());
        host.drop_in_time = Some(1);
        host.folder_time = Some(1);
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

    fn service_started(&mut self) -> anyhow::Result<Option<SystemTime>> {
        self.call("service_started");
        self.fails("service_started")?;
        Ok(self.service_started_at.map(at))
    }

    fn now(&self) -> SystemTime {
        self.call("now");
        at(self.clock)
    }

    fn config_files(&mut self) -> anyhow::Result<ConfigFiles> {
        self.call("config_files");
        self.fails("config_files")?;
        let mut files = vec![ConfigFile {
            path: PathBuf::from("sshd_config"),
            changed: at(self.config_time),
            text: self.config.clone(),
        }];
        if let Some(text) = &self.drop_in {
            files.push(ConfigFile {
                path: Fake::folder().join(DROP_IN_NAME),
                changed: at(self.drop_in_time.expect("a drop-in has a time")),
                text: text.clone(),
            });
        }
        for (name, time, text) in &self.other_files {
            files.push(ConfigFile {
                path: Fake::folder().join(name),
                changed: at(*time),
                text: text.clone(),
            });
        }
        Ok(ConfigFiles {
            folder: self.folder_time.map(at),
            files,
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
        let time = self.tick();
        self.drop_in_time = Some(time);
        self.folder_time = Some(time);
        Ok(())
    }

    fn read_config(&mut self) -> anyhow::Result<Vec<u8>> {
        self.call("read_config");
        self.fails("read_config")?;
        Ok(self.config.clone())
    }

    fn write_candidate(&mut self, text: &[u8]) -> anyhow::Result<PathBuf> {
        self.call("write_candidate");
        // A write that fails has made the file and put part of the text into it.
        if self.fail == Some("write_candidate") {
            self.candidate = Some(text[..text.len() / 2].to_vec());
        }
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

    fn discard_candidate(&mut self) {
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
        "apply: add `{ACCEPT_LINE}` above the first `Match` in sshd_config, then restart the sshd service; \
         `ssh-broker elevate` works without it"
    )
}

/// What `apply` says of a variable in force that the running sshd was started too early to have read.
fn unread(file: &str) -> String {
    format!(
        "apply: sshd was started before {file} was last changed, so it has not read it; restart the sshd service \
         for it to accept SSH_BROKER_ELEVATION (`ssh-broker verify` says whether it has)"
    )
}

const NOT_RUNNING: &str = "apply: sshd is not running; it reads the change when it starts";

fn drop_in_file() -> String {
    Fake::folder().join(DROP_IN_NAME).display().to_string()
}

fn said_advice(said: &[String]) -> bool {
    said.contains(&advice())
}

/// What `apply` says when it cannot ask sshd for its configuration.
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
fn a_config_that_already_accepts_the_variable_is_left_alone_and_nothing_is_said() {
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
fn a_variable_in_force_that_sshd_has_not_read_is_said_to_need_a_restart_and_nothing_is_written() {
    // The configuration was written after sshd started.
    let mut host = Fake::configured();
    host.config_time = 20;
    let (accepted, said) = run(&mut host);
    assert!(!accepted, "{said:?}");
    assert!(host.events.is_empty(), "{:?}", host.events);
    assert_eq!(said, [unread("sshd_config")]);

    // The drop-in is the later file: it is the one named.
    let mut host = Fake::configured();
    host.drop_in_time = Some(20);
    let (accepted, said) = run(&mut host);
    assert!(!accepted, "{said:?}");
    assert!(host.events.is_empty(), "{:?}", host.events);
    assert_eq!(said, [unread(&drop_in_file())]);

    // Written before it started: read, and nothing is said.
    let mut host = Fake::configured();
    host.service_started_at = Some(5);
    let (accepted, said) = run(&mut host);
    assert!(accepted && host.events.is_empty() && said.is_empty(), "{said:?}");
}

#[test]
fn a_service_that_is_not_running_reads_what_is_there_when_it_starts() {
    let mut host = Fake::configured().stopped();
    host.config_time = 20;
    let (accepted, said) = run(&mut host);
    assert!(accepted, "{said:?}");
    assert!(host.events.is_empty(), "{:?}", host.events);
    assert_eq!(said, [NOT_RUNNING]);

    // Whatever the time of a file.
    let mut host = Fake::configured().stopped();
    host.config_time = host.clock + 1000;
    let (accepted, said) = run(&mut host);
    assert!(accepted, "{said:?}");
    assert_eq!(said, [NOT_RUNNING]);
}

#[test]
fn a_file_written_in_the_tick_sshd_started_in_is_judged_unread() {
    let mut host = Fake::configured();
    host.service_started_at = Some(5);
    host.config_time = 5;
    let (accepted, said) = run(&mut host);
    assert!(!accepted, "{said:?}");
    assert_eq!(said, [unread("sshd_config")]);
}

#[test]
fn a_file_whose_time_is_ahead_of_the_clock_cannot_be_judged_and_is_said_so_each_time() {
    let mut host = Fake::configured();
    host.config_time = host.clock + 1000;
    let sentence = "apply: sshd_config's change time is ahead of this machine's clock, so it cannot be told \
                    whether sshd has read it; restart the sshd service for it to accept SSH_BROKER_ELEVATION";
    for _ in 0..2 {
        let (accepted, said) = run(&mut host);
        assert!(!accepted, "{said:?}");
        assert_eq!(said, [sentence]);
    }
    assert!(host.events.is_empty(), "{:?}", host.events);

    // The folder's own time is judged too, and named as the folder.
    let mut host = Fake::configured();
    host.folder_time = Some(host.clock + 1000);
    let (accepted, said) = run(&mut host);
    assert!(!accepted, "{said:?}");
    assert_eq!(
        said,
        [format!(
            "apply: {}'s change time is ahead of this machine's clock, so it cannot be told whether sshd has \
             read it; restart the sshd service for it to accept SSH_BROKER_ELEVATION",
            Fake::folder().display()
        )]
    );
}

#[test]
fn a_time_that_cannot_be_read_says_so() {
    for method in ["service_started", "config_files"] {
        let mut host = Fake::configured();
        host.config_time = 20;
        host.fail = Some(method);
        let (accepted, said) = run(&mut host);
        assert!(!accepted, "{method}");
        assert!(host.events.is_empty(), "{method}: {:?}", host.events);
        assert_eq!(said.len(), 1, "{method}: {said:?}");
        let line = &said[0];
        assert!(
            line.starts_with("apply: cannot tell whether sshd has read its configuration (")
                && line.contains(&format!("{method} failed"))
                && line.ends_with("); restart the sshd service for it to accept SSH_BROKER_ELEVATION"),
            "{method}: {said:?}"
        );
    }
}

// every file sshd reads =====

/// What `apply` says of an `Include` of another location in `file`.
fn includes_other(file: &str, line: &str) -> String {
    format!(
        "apply: {file} has `{line}`; files sshd includes from elsewhere are not judged, so it cannot be told \
         whether sshd has read its configuration; restart the sshd service to be sure it accepts \
         SSH_BROKER_ELEVATION"
    )
}

/// `sshd_config` with the drop-in's `Include` and then one of another location.
fn config_with_other_include() -> String {
    format!("Port 22\r\n{INCLUDE_LINE}\r\nInclude D:\\x\\*.conf\r\nMatch All\r\n")
}

#[test]
fn an_include_of_another_location_cannot_be_told() {
    // In sshd_config.
    let mut host = Fake::with_config(&config_with_other_include());
    host.drop_in = Some(drop_in_text().into_bytes());
    host.drop_in_time = Some(1);
    host.folder_time = Some(1);
    let (accepted, said) = run(&mut host);
    assert!(!accepted, "{said:?}");
    assert_eq!(said, [includes_other("sshd_config", r"Include D:\x\*.conf")]);
    assert!(host.events.is_empty(), "{:?}", host.events);

    // In another file of the folder.
    let mut host = Fake::configured();
    host.other_files = vec![("20-other.conf", 1, b"Include D:\\y\\*.conf\r\n".to_vec())];
    let (accepted, said) = run(&mut host);
    assert!(!accepted, "{said:?}");
    assert_eq!(
        said,
        [includes_other(
            &Fake::folder().join("20-other.conf").display().to_string(),
            r"Include D:\y\*.conf"
        )]
    );

    // A file that is not named `*.conf` is judged all the same.
    let mut host = Fake::configured();
    host.other_files = vec![("old.conf.bak", 1, b"Include D:\\z\r\n".to_vec())];
    let (_, said) = run(&mut host);
    assert_eq!(
        said,
        [includes_other(
            &Fake::folder().join("old.conf.bak").display().to_string(),
            r"Include D:\z"
        )]
    );

    // Not running: nothing to be told.
    let mut host = Fake::with_config(&config_with_other_include()).stopped();
    host.drop_in = Some(drop_in_text().into_bytes());
    host.drop_in_time = Some(1);
    host.folder_time = Some(1);
    let (accepted, said) = run(&mut host);
    assert!(accepted, "{said:?}");
    assert_eq!(said, [NOT_RUNNING]);
}

#[test]
fn a_file_written_after_sshd_started_is_unread_even_beside_an_include_of_another_location() {
    let mut host = Fake::with_config(&config_with_other_include());
    host.drop_in = Some(drop_in_text().into_bytes());
    host.drop_in_time = Some(20);
    host.folder_time = Some(1);
    let (accepted, said) = run(&mut host);
    assert!(!accepted, "{said:?}");
    assert_eq!(said, [unread(&drop_in_file())]);
}

#[test]
fn a_file_or_folder_that_changed_after_sshd_started_is_unread_and_named() {
    // Another file of the folder, written after sshd started.
    let mut host = Fake::configured();
    host.other_files = vec![("20-other.conf", 20, b"Port 22\r\n".to_vec())];
    let (accepted, said) = run(&mut host);
    assert!(!accepted, "{said:?}");
    assert_eq!(
        said,
        [unread(&Fake::folder().join("20-other.conf").display().to_string())]
    );

    // The folder alone changed (an entry went): the folder is named.
    let mut host = Fake::configured();
    host.folder_time = Some(20);
    let (accepted, said) = run(&mut host);
    assert!(!accepted, "{said:?}");
    assert_eq!(said, [unread(&Fake::folder().display().to_string())]);

    // A tie of a file and the folder names the file.
    let mut host = Fake::configured();
    host.folder_time = Some(20);
    host.other_files = vec![("20-other.conf", 20, b"Port 22\r\n".to_vec())];
    let (_, said) = run(&mut host);
    assert_eq!(
        said,
        [unread(&Fake::folder().join("20-other.conf").display().to_string())]
    );

    // No folder: sshd_config alone is judged.
    let mut host = Fake::with_config(&format!("Port 22\r\n{ACCEPT_LINE}\r\n"));
    host.config_time = 20;
    let (accepted, said) = run(&mut host);
    assert!(!accepted, "{said:?}");
    assert_eq!(said, [unread("sshd_config")]);
}

// the include =====

#[test]
fn a_config_that_has_the_include_but_no_drop_in_gets_the_drop_in_and_no_second_include() {
    let config = format!("Port 22\r\n{INCLUDE_LINE}\r\nMatch All\r\n");
    let mut host = Fake::with_config(&config);
    let (accepted, said) = run(&mut host);
    assert_eq!(host.config, config.as_bytes(), "the main file is left alone");
    assert_eq!(host.drop_in.as_deref(), Some(drop_in_text().as_bytes()));
    assert!(
        !host.events.iter().any(|e| e == "sshd -t"),
        "no candidate was made: {:?}",
        host.events
    );
    // The drop-in is a change: sshd reads it at its next start, which is said.
    assert_eq!(host.events, ["write drop-in"]);
    assert!(!accepted, "{said:?}");
    assert_eq!(said, [unread(&drop_in_file())]);
}

#[test]
fn a_config_that_does_not_gets_the_drop_in_and_the_include_and_the_original_is_replaced_only_after_sshd_t_passes() {
    let mut host = Fake::with_config(STOCK);
    let (accepted, said) = run(&mut host);
    assert!(!accepted, "{said:?}");
    assert_eq!(said, [unread("sshd_config")]);
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

#[test]
fn a_question_to_sshd_about_the_candidate_that_fails_leaves_the_original_and_removes_the_candidate() {
    let mut host = Fake::with_config(STOCK);
    host.sshd_t_fails_from = Some(2);
    let (accepted, said) = run(&mut host);
    assert!(!accepted);
    assert_eq!(host.config, STOCK.as_bytes());
    assert_eq!(host.config_replacements, 0);
    assert!(host.candidate.is_none(), "{:?}", host.events);
    assert!(
        host.events.contains(&"discard candidate".to_owned()),
        "{:?}",
        host.events
    );
    assert!(
        said.contains(
            &"apply: sshd_config was not changed: cannot ask sshd about the edited copy: sshd_t failed".to_owned()
        ),
        "{said:?}"
    );
    assert!(said_advice(&said), "{said:?}");
}

#[test]
fn a_candidate_that_fails_to_write_is_removed() {
    let mut host = Fake::with_config(STOCK);
    host.fail = Some("write_candidate");
    let (accepted, said) = run(&mut host);
    assert!(!accepted);
    assert_eq!(host.config, STOCK.as_bytes());
    assert!(host.candidate.is_none(), "the partial file is gone: {:?}", host.events);
    assert!(
        host.events.contains(&"discard candidate".to_owned()),
        "{:?}",
        host.events
    );
    assert!(
        said.iter()
            .any(|line| line.contains("cannot write a candidate beside it")),
        "{said:?}"
    );
}

#[test]
fn a_drop_in_with_other_text_is_rewritten_once_to_the_exact_text() {
    let mut host = Fake::configured();
    host.drop_in = Some(b"AcceptEnv SOMETHING_ELSE\r\n".to_vec());
    let (accepted, said) = run(&mut host);
    assert!(!accepted, "{said:?}");
    assert_eq!(host.drop_in_writes, 1);
    assert_eq!(host.drop_in.as_deref(), Some(drop_in_text().as_bytes()));
    assert_eq!(host.events, ["write drop-in"]);
    assert_eq!(said, [unread(&drop_in_file())]);
}

// a folder that cannot be used =====

#[test]
fn a_drop_in_folder_that_is_not_administrator_only_gets_the_acceptenv_line_in_sshd_config() {
    let mut host = Fake::with_config(STOCK);
    host.folder_problem = Some("its ACL is not the hardened one".into());
    let (accepted, said) = run(&mut host);
    assert!(!accepted, "{said:?}");
    assert_eq!(said.last().unwrap(), &unread("sshd_config"));
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
    // Through the same candidate, checks and rename.
    let order = |name: &str| position(&host.events, name);
    assert!(order("write candidate") < order("sshd -t") && order("sshd -t") < order("replace config"));
    assert_nothing_to_remove(&said);
}

#[test]
fn a_drop_in_folder_that_cannot_be_made_is_said_not_to_be_made_and_the_line_goes_into_sshd_config() {
    let mut host = Fake::with_config(STOCK);
    host.folder_not_made = Some("Access is denied".into());
    let (accepted, said) = run(&mut host);
    assert!(!accepted, "{said:?}");
    assert_eq!(said.last().unwrap(), &unread("sshd_config"));
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
        assert!(!accepted, "{method}: {said:?}");
        assert_eq!(said.last().unwrap(), &unread("sshd_config"), "{method}");
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

// a change made while sshd is not running =====

#[test]
fn a_change_made_while_sshd_is_not_running_is_read_when_it_starts() {
    let mut host = Fake::with_config(STOCK).stopped();
    let (accepted, said) = run(&mut host);
    assert!(accepted, "{said:?}");
    assert_eq!(said, [NOT_RUNNING]);
    assert_eq!(host.config, with_line(STOCK.as_bytes(), INCLUDE_LINE).unwrap());
    assert_eq!(host.drop_in.as_deref(), Some(drop_in_text().as_bytes()));
}

// a second run and failures =====

#[test]
fn a_second_run_after_sshd_started_changes_nothing_and_says_nothing() {
    let mut host = Fake::with_config(STOCK);
    let (first, said) = run(&mut host);
    assert!(!first, "{said:?}");
    let (config, drop_in) = (host.config.clone(), host.drop_in.clone());
    // sshd is started by someone after every write.
    host.service_started_at = Some(host.tick());
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
        assert_nothing_to_remove(&said);
    }
    // These make the folder unusable: the line goes into sshd_config instead.
    for method in ["ensure_drop_in_dir", "read_drop_in", "write_drop_in"] {
        let mut host = Fake::with_config(STOCK);
        host.fail = Some(method);
        let (_, said) = run(&mut host);
        assert!(!said.is_empty(), "{method}: it said nothing");
        assert_eq!(
            host.config,
            with_line(STOCK.as_bytes(), ACCEPT_LINE).unwrap(),
            "{method}"
        );
    }
}
