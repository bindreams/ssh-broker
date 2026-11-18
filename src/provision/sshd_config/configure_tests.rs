//! Host tests for the flow of `apply`'s sshd step, over a stand-in for the machine: files in memory, the
//! answers of `sshd` and `net` scripted. The real files, the real `sshd` and the service are measured by
//! `tests/sshd_config_windows.rs`, which CI runs.
use super::super::{DROP_IN_TEXT, INCLUDE_LINE, with_include};
use super::*;
use std::collections::VecDeque;

const STOCK: &str = "#Port 22\r\n#AcceptEnv LANG LC_*\r\nSubsystem sftp sftp-server.exe\r\n\r\nMatch Group administrators\r\n       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys\r\n";

/// The machine: what the host's methods read and write, what was done in which order, and what goes wrong.
#[derive(Default)]
struct Fake {
    config: Vec<u8>,
    drop_in: Option<Vec<u8>>,
    candidate: Option<Vec<u8>>,
    /// Every call that changes or runs something, in order.
    events: Vec<String>,
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
    drop_in_writes: usize,
    config_replacements: usize,
}

impl Fake {
    fn with_config(config: &str) -> Fake {
        Fake {
            config: config.as_bytes().to_vec(),
            ..Fake::default()
        }
    }

    fn event(&mut self, name: &str) {
        self.events.push(name.to_owned());
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
            accepted |= line == "AcceptEnv SSH_BROKER_ELEVATION"
                || (line == INCLUDE_LINE && self.drop_in.as_deref() == Some(DROP_IN_TEXT.as_bytes()));
        }
        let mut out = "port 22\r\n".to_owned();
        if accepted {
            out += "acceptenv SSH_BROKER_ELEVATION\r\n";
        }
        out
    }

    fn stops(&self) -> usize {
        self.events.iter().filter(|e| *e == "stop").count()
    }

    fn starts(&self) -> usize {
        self.events.iter().filter(|e| *e == "start").count()
    }
}

impl SshdHost for Fake {
    fn config_path(&self) -> PathBuf {
        PathBuf::from("sshd_config")
    }

    fn sshd_t(&mut self, config: Option<&Path>) -> anyhow::Result<String> {
        self.fails("sshd_t")?;
        Ok(match config {
            None => self.listing(&self.config),
            Some(_) if self.candidate_hides_variable => "port 22\r\n".into(),
            Some(_) => self.listing(self.candidate.as_deref().expect("the candidate was written")),
        })
    }

    fn sshd_check(&mut self, _config: &Path) -> Result<(), String> {
        self.events.push("sshd -t".into());
        self.config_at_check = Some(self.config.clone());
        self.check_error.clone().map_or(Ok(()), Err)
    }

    fn service(&mut self, verb: Service) -> ServiceOutcome {
        self.event(match verb {
            Service::Stop => "stop",
            Service::Start => "start",
        });
        self.answers.pop_front().unwrap_or(ServiceOutcome::Done)
    }

    fn ensure_drop_in_dir(&mut self) -> anyhow::Result<()> {
        self.fails("ensure_drop_in_dir")
    }

    fn read_drop_in(&mut self) -> anyhow::Result<Option<Vec<u8>>> {
        self.fails("read_drop_in")?;
        Ok(self.drop_in.clone())
    }

    fn write_drop_in(&mut self, text: &[u8]) -> anyhow::Result<()> {
        self.fails("write_drop_in")?;
        self.event("write drop-in");
        self.drop_in_writes += 1;
        self.drop_in = Some(text.to_vec());
        Ok(())
    }

    fn remove_drop_in(&mut self) -> anyhow::Result<()> {
        self.fails("remove_drop_in")?;
        self.event("remove drop-in");
        self.drop_in = None;
        Ok(())
    }

    fn read_config(&mut self) -> anyhow::Result<Vec<u8>> {
        self.fails("read_config")?;
        Ok(self.config.clone())
    }

    fn write_candidate(&mut self, text: &[u8]) -> anyhow::Result<PathBuf> {
        self.fails("write_candidate")?;
        self.event("write candidate");
        self.candidate = Some(text.to_vec());
        Ok(PathBuf::from("sshd_config.candidate"))
    }

    fn copy_security(&mut self, _candidate: &Path) -> anyhow::Result<()> {
        self.fails("copy_security")?;
        self.event("copy security");
        Ok(())
    }

    fn replace_config(&mut self, _candidate: &Path) -> anyhow::Result<()> {
        self.fails("replace_config")?;
        self.event("replace config");
        self.config_replacements += 1;
        self.config = self.candidate.take().expect("the candidate was written");
        Ok(())
    }

    fn discard_candidate(&mut self, _candidate: &Path) {
        self.event("discard candidate");
        self.candidate = None;
    }
}

/// Run the flow and return what it said with its outcome.
fn run(host: &mut Fake) -> (Outcome, Vec<String>) {
    let mut said = Vec::new();
    let outcome = configure(host, &mut |line| said.push(line.to_owned()));
    (outcome, said)
}

fn position(events: &[String], name: &str) -> usize {
    events
        .iter()
        .position(|e| e == name)
        .unwrap_or_else(|| panic!("no {name:?} in {events:?}"))
}

fn said_line_to_add(said: &[String]) -> bool {
    said.iter()
        .any(|line| line.contains(INCLUDE_LINE) && line.contains("above the first `Match`"))
}

// the include =====

#[test]
fn a_config_that_already_accepts_the_variable_gets_the_drop_in_and_no_include() {
    let config = format!("Port 22\r\n{INCLUDE_LINE}\r\nMatch All\r\n");
    let mut host = Fake::with_config(&config);
    let (outcome, said) = run(&mut host);
    assert_eq!(
        outcome,
        Outcome {
            accepts: true,
            restarted: true
        },
        "{said:?}"
    );
    assert_eq!(host.config, config.as_bytes(), "the main file is left alone");
    assert_eq!(host.drop_in.as_deref(), Some(DROP_IN_TEXT.as_bytes()));
    assert!(
        !host.events.iter().any(|e| e == "sshd -t"),
        "no candidate was made: {:?}",
        host.events
    );
    // The drop-in is a change: sshd reads it at its next start.
    assert_eq!(host.events, ["write drop-in", "stop", "start"]);
}

#[test]
fn a_config_that_does_not_gets_the_include_and_the_original_is_replaced_only_after_sshd_t_passes() {
    let mut host = Fake::with_config(STOCK);
    let (outcome, said) = run(&mut host);
    assert_eq!(
        outcome,
        Outcome {
            accepts: true,
            restarted: true
        },
        "{said:?}"
    );
    assert_eq!(host.config, with_include(STOCK.as_bytes()).unwrap());
    assert_eq!(
        host.config_at_check.as_deref(),
        Some(STOCK.as_bytes()),
        "the original, when sshd -t ran"
    );
    let order = |name: &str| position(&host.events, name);
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
    let (outcome, said) = run(&mut host);
    assert!(!outcome.accepts && !outcome.restarted);
    assert_eq!(host.config, STOCK.as_bytes());
    assert_eq!(host.config_replacements, 0);
    assert!(host.candidate.is_none(), "the candidate is removed: {:?}", host.events);
    assert!(said_line_to_add(&said), "{said:?}");
    assert!(
        said.iter().any(|line| line.contains("Bad configuration option")),
        "{said:?}"
    );
    // Nothing is in effect, so there is nothing to restart for.
    assert_eq!(host.stops(), 0, "{:?}", host.events);
}

#[test]
fn a_candidate_that_does_not_show_the_variable_leaves_the_original() {
    let mut host = Fake::with_config(STOCK);
    host.candidate_hides_variable = true;
    let (outcome, said) = run(&mut host);
    assert!(!outcome.accepts);
    assert_eq!(host.config, STOCK.as_bytes());
    assert_eq!(host.config_replacements, 0);
    assert!(host.candidate.is_none());
    assert!(said_line_to_add(&said), "{said:?}");
}

#[test]
fn a_config_that_cannot_be_edited_safely_is_left_and_says_which_line_to_add() {
    let mut host = Fake::with_config(STOCK);
    host.config = [&[0xFF, 0xFE][..], &[b'P', 0, b'o', 0]].concat();
    let before = host.config.clone();
    let (outcome, said) = run(&mut host);
    assert!(!outcome.accepts);
    assert_eq!(host.config, before);
    assert!(said_line_to_add(&said), "{said:?}");
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

// the restart =====

#[test]
fn sshd_is_restarted_only_after_a_change_and_not_when_it_is_stopped() {
    // A change restarts it, and the restart is the last thing done.
    let mut host = Fake::with_config(STOCK);
    let (outcome, _) = run(&mut host);
    assert!(outcome.restarted);
    assert_eq!(&host.events[host.events.len() - 2..], ["stop", "start"]);

    // A service that is not running stays stopped: it reads the change when it is started.
    let mut host = Fake::with_config(STOCK);
    host.answers = VecDeque::from([ServiceOutcome::Unchanged]);
    let (outcome, said) = run(&mut host);
    assert_eq!(
        outcome,
        Outcome {
            accepts: true,
            restarted: false
        },
        "{said:?}"
    );
    assert_eq!(host.starts(), 0, "{:?}", host.events);
    assert_eq!(host.config, with_include(STOCK.as_bytes()).unwrap(), "the change stays");
    assert!(said.last().unwrap().contains("not running"), "{said:?}");
}

#[test]
fn a_stop_that_fails_leaves_the_change_and_says_it_was_not_restarted() {
    let mut host = Fake::with_config(STOCK);
    host.answers = VecDeque::from([ServiceOutcome::Failed("Access is denied".into())]);
    let (outcome, said) = run(&mut host);
    assert_eq!(
        outcome,
        Outcome {
            accepts: true,
            restarted: false
        }
    );
    assert_eq!(host.starts(), 0);
    assert_eq!(host.config, with_include(STOCK.as_bytes()).unwrap());
    let last = said.last().unwrap();
    assert!(
        last.contains("Access is denied") && last.contains("restart"),
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
    let (outcome, said) = run(&mut host);
    assert_eq!(
        outcome,
        Outcome {
            accepts: false,
            restarted: false
        }
    );
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
    let (outcome, said) = run(&mut host);
    assert_eq!(
        outcome,
        Outcome {
            accepts: false,
            restarted: false
        }
    );
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
    let (outcome, _) = run(&mut host);
    assert_eq!(
        outcome,
        Outcome {
            accepts: true,
            restarted: true
        }
    );
    assert_eq!(host.config, with_include(STOCK.as_bytes()).unwrap());
}

// a second run and failures =====

#[test]
fn apply_twice_changes_nothing_and_restarts_nothing() {
    let mut host = Fake::with_config(STOCK);
    let (first, _) = run(&mut host);
    assert!(first.restarted);
    let (config, drop_in) = (host.config.clone(), host.drop_in.clone());
    let (writes, replacements, stops, starts) = (
        host.drop_in_writes,
        host.config_replacements,
        host.stops(),
        host.starts(),
    );
    let events = host.events.len();

    let (second, said) = run(&mut host);
    assert_eq!(
        second,
        Outcome {
            accepts: true,
            restarted: false
        },
        "{said:?}"
    );
    assert_eq!((&host.config, &host.drop_in), (&config, &drop_in));
    assert_eq!(
        (
            host.drop_in_writes,
            host.config_replacements,
            host.stops(),
            host.starts()
        ),
        (writes, replacements, stops, starts)
    );
    assert_eq!(
        host.events.len(),
        events,
        "nothing was done at all: {:?}",
        &host.events[events..]
    );
}

#[test]
fn a_failure_of_any_step_does_not_fail_apply() {
    let methods = [
        "ensure_drop_in_dir",
        "read_drop_in",
        "write_drop_in",
        "sshd_t",
        "read_config",
        "write_candidate",
        "copy_security",
        "replace_config",
        "remove_drop_in",
    ];
    for method in methods {
        let mut host = Fake::with_config(STOCK);
        host.fail = Some(method);
        // `remove_drop_in` is reached only by a rollback.
        if method == "remove_drop_in" {
            host.answers = VecDeque::from([ServiceOutcome::Done, ServiceOutcome::Failed("x".into())]);
        }
        let (outcome, said) = run(&mut host);
        assert!(!said.is_empty(), "{method}: it said nothing");
        if method != "remove_drop_in" {
            assert!(!outcome.restarted, "{method}");
        }
        // Whatever failed before the rename leaves the original as it was.
        if method != "remove_drop_in" {
            assert_eq!(host.config, STOCK.as_bytes(), "{method}");
            assert!(host.candidate.is_none(), "{method}: the candidate is not left behind");
        }
    }
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
