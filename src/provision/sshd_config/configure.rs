//! provision::sshd_config::configure — `apply`'s sshd step: the drop-in, the `Include` line and the restart.
//!
//! The flow is held apart from the machine ([`SshdHost`]) because `sshd -t` and the service cannot run on a
//! workstation: tests stand in for it, and `tests/sshd_config_windows.rs` measures the real one in CI. The
//! step never fails `apply`: the variable is a convenience, and `ssh-broker elevate` works without it. What
//! it must never do is leave a machine reached only over SSH without sshd, so the original `sshd_config` is
//! untouched until a candidate has passed sshd's own checks and then replaced in one rename, and a start that
//! fails after a stop puts the original back.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::Context;

use super::{ACCEPT_LINE, DROP_IN_DIR_NAME, DROP_IN_NAME, INCLUDE_LINE, VARIABLE, drop_in_text, in_force, with_line};

/// Something `apply` asks of the `sshd` service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Service {
    Stop,
    Start,
}

/// What the service manager says the `sshd` service is doing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceState {
    Running,
    Stopped,
    /// Every other state, by name: "stopping", "starting", "pausing", "paused", ...
    Changing(String),
}

impl std::fmt::Display for ServiceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceState::Running => f.write_str("running"),
            ServiceState::Stopped => f.write_str("stopped"),
            ServiceState::Changing(name) => f.write_str(name),
        }
    }
}

/// Why the drop-in folder or the drop-in cannot be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DropInProblem {
    /// The folder is not there and could not be made, with the cause.
    NotMade(String),
    /// What is there cannot be used, and is left as it is: a folder that is not the one `apply` makes, a file
    /// or a link in its place, or a drop-in that cannot be read or written. Why.
    Refused(String),
}

/// What the flow needs of the machine. Every file method is on a name this step owns or on `sshd_config`.
pub trait SshdHost {
    /// Where `sshd_config` is, for the sentences.
    fn config_path(&self) -> PathBuf;
    /// The text after the program in the sshd service's command line, `None` when there is none. With
    /// arguments the service can read another configuration file than `sshd_config`.
    fn service_arguments(&self) -> Option<String>;
    /// `sshd -T` (the effective configuration), of the file sshd reads or of `config`.
    fn sshd_t(&mut self, config: Option<&Path>) -> anyhow::Result<String>;
    /// `sshd -t -f config`: `Err` is what sshd says when it rejects the file.
    fn sshd_check(&mut self, config: &Path) -> Result<(), String>;
    /// The service manager's word on what the service is doing. `Err` when it cannot be read.
    fn service_state(&mut self) -> anyhow::Result<ServiceState>;
    /// Run `net stop sshd` or `net start sshd`, which waits itself. `Err` is what it said (white space
    /// collapsed) or its exit code. It is not interpreted: it is only quoted in sentences.
    fn net(&mut self, verb: Service) -> Result<(), String>;
    /// Return when the service has no process any more. `Err` when it still has one after
    /// `procwait::EXIT_BOUND`, the failure bound of a process that may never end: the service is still stopping,
    /// and nothing else is known.
    fn wait_while_stopping(&mut self) -> anyhow::Result<()>;
    /// When the running sshd service's process started; `None` when it is not running.
    fn service_started(&mut self) -> anyhow::Result<Option<SystemTime>>;
    /// This machine's clock.
    fn now(&self) -> SystemTime;
    /// The later last-write time of `sshd_config` and of the drop-in (when there is one), and the file it is of.
    fn config_written(&mut self) -> anyhow::Result<(PathBuf, SystemTime)>;
    /// Make `sshd_config.d` as the install directory is made, or accept it if it is. A folder that cannot be
    /// made is [`DropInProblem::NotMade`]; a file or a link where the folder belongs, or other permissions, is
    /// [`DropInProblem::Refused`]. Nothing that is there is changed.
    fn ensure_drop_in_dir(&mut self) -> Result<(), DropInProblem>;
    /// The drop-in's bytes, `None` when there is no such file.
    fn read_drop_in(&mut self) -> anyhow::Result<Option<Vec<u8>>>;
    /// Write the drop-in whole, administrator-only.
    fn write_drop_in(&mut self, text: &[u8]) -> anyhow::Result<()>;
    fn remove_drop_in(&mut self) -> anyhow::Result<()>;
    /// `sshd_config`'s bytes.
    fn read_config(&mut self) -> anyhow::Result<Vec<u8>>;
    /// A new file beside `sshd_config`, with `text`, on disk; its path.
    fn write_candidate(&mut self, text: &[u8]) -> anyhow::Result<PathBuf>;
    /// Give `candidate` the security descriptor of the original `sshd_config`.
    fn copy_security(&mut self, candidate: &Path) -> anyhow::Result<()>;
    /// Replace `sshd_config` with `candidate`, in one rename that is on disk when it returns.
    fn replace_config(&mut self, candidate: &Path) -> anyhow::Result<()>;
    /// Remove `candidate`, if it is there.
    fn discard_candidate(&mut self, candidate: &Path);
}

/// What a change was made to, kept for putting it back.
#[derive(Default)]
struct Before {
    drop_in: Option<Vec<u8>>,
    /// This run wrote the drop-in.
    drop_in_changed: bool,
    /// `sshd_config`'s original bytes, when this run replaced it.
    config: Option<Vec<u8>>,
}

impl Before {
    fn changed(&self) -> bool {
        self.drop_in_changed || self.config.is_some()
    }
}

/// Whether the running sshd has read the files of its configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigRead {
    /// It started after the files were last written, or it is not running (it reads what is there when it
    /// starts).
    Read,
    /// The file was last written when sshd started or after: sshd reads its configuration only when it starts,
    /// so it may not have been read. A tie counts: the cost is one restart that was not needed.
    Unread(PathBuf),
    /// The file's last-write time is ahead of the clock, so it cannot be compared with when sshd started.
    Unknowable(PathBuf),
}

/// Whether the running sshd has read its configuration, judged on the later last-write time of its files and
/// when the service started. `Err` when a time cannot be read, with the cause.
pub fn config_read(host: &mut dyn SshdHost) -> anyhow::Result<ConfigRead> {
    let Some(started) = host.service_started().context("read when the sshd service started")? else {
        return Ok(ConfigRead::Read);
    };
    let (file, written) = host
        .config_written()
        .context("read when sshd's configuration was last written")?;
    Ok(if written > host.now() {
        ConfigRead::Unknowable(file)
    } else if started <= written {
        ConfigRead::Unread(file)
    } else {
        ConfigRead::Read
    })
}

/// Make sshd accept the variable, and say what was done on `say` (a line each). Returns whether the running
/// sshd takes the variable, or reads it when it next starts (it is not running); false when it does not, when
/// a restart that was needed did not happen, and when that cannot be told.
///
/// The order: (0) a service started with arguments is not touched. (1) A question to sshd; a failure says so
/// and writes nothing. (2) A variable in force already ([`in_force`]) writes nothing, and a restart happens
/// only when sshd started before a file was written. (3) Otherwise the drop-in (written if it differs) and a
/// second question: when no `Include` reads it, the `Include` line goes into a candidate that must pass sshd's
/// checks before it replaces the original; when the folder or the drop-in cannot be used, the `AcceptEnv` line
/// goes there instead. (4) A restart when (3) changed something.
pub fn configure(host: &mut dyn SshdHost, say: &mut dyn FnMut(&str)) -> bool {
    if let Some(arguments) = host.service_arguments() {
        say(&format!(
            "apply: the sshd service runs with arguments (`{arguments}`), which can name another configuration \
             file, so nothing of sshd's was changed. To have sshd accept {VARIABLE}, add `{ACCEPT_LINE}` above the \
             first `Match` in the file it reads and restart sshd; `ssh-broker elevate` works without it."
        ));
        return false;
    }

    let listing = match host.sshd_t(None) {
        Ok(listing) => listing,
        Err(e) => {
            say(&ask_failed(host, &e, "nothing of sshd's was changed"));
            return false;
        }
    };
    if in_force(&listing) {
        return restart_if_unread(host, say);
    }

    let mut before = Before::default();
    match write_drop_in(host, &mut before) {
        Ok(()) => {
            // The drop-in is read through an `Include`, when there is one: plain `sshd -T` says.
            let listing = match host.sshd_t(None) {
                Ok(listing) => listing,
                Err(e) => {
                    say(&ask_failed(host, &e, "sshd_config was left as it is"));
                    return false;
                }
            };
            if !in_force(&listing) {
                match add_line(host, INCLUDE_LINE) {
                    Ok(original) => before.config = Some(original),
                    Err(why) => {
                        say(&format!("apply: sshd_config was not changed: {why}"));
                        say(&advice(host));
                        return false;
                    }
                }
            }
        }
        Err(problem) => {
            let folder = host.config_path().with_file_name(DROP_IN_DIR_NAME);
            let left = match problem {
                DropInProblem::NotMade(cause) => format!("apply: {} could not be made ({cause})", folder.display()),
                DropInProblem::Refused(problem) => {
                    format!("apply: {} is left as it is ({problem})", folder.display())
                }
            };
            match add_line(host, ACCEPT_LINE) {
                Ok(original) => {
                    before.config = Some(original);
                    say(&format!(
                        "{left}; {VARIABLE} is accepted by a line in sshd_config instead"
                    ));
                }
                Err(why) => {
                    say(&left);
                    say(&format!("apply: sshd_config was not changed: {why}"));
                    say(&advice(host));
                    return false;
                }
            }
        }
    }

    if !before.changed() {
        return restart_if_unread(host, say);
    }
    restart(host, say, &before)
}

/// What is said when sshd cannot be asked for its configuration (`left` says what that left as it was). The
/// next `apply` stops at the same place, so the advice is to add the line by hand, not to run `apply` again.
fn ask_failed(host: &dyn SshdHost, cause: &anyhow::Error, left: &str) -> String {
    format!(
        "apply: could not ask sshd for its configuration ({cause:#}), so {left}. To have sshd accept {VARIABLE}, \
         add `{ACCEPT_LINE}` above the first `Match` in {} and restart sshd; `ssh-broker elevate` works without it.",
        host.config_path().display()
    )
}

/// The sentence that says what to do by hand when a later `apply` does restart sshd.
fn advice(host: &dyn SshdHost) -> String {
    format!(
        "apply: add `{ACCEPT_LINE}` above the first `Match` in {}, then run `ssh-broker apply` again, which \
         restarts sshd; `ssh-broker elevate` works without it",
        host.config_path().display()
    )
}

/// Make the drop-in what [`drop_in_text`] says, in a folder that is as `apply` makes it. `Err` says why the
/// folder or the drop-in cannot be used; the flow then leaves them as they are.
fn write_drop_in(host: &mut dyn SshdHost, before: &mut Before) -> Result<(), DropInProblem> {
    let refused = |e: anyhow::Error| DropInProblem::Refused(format!("{e:#}"));
    host.ensure_drop_in_dir()?;
    before.drop_in = host.read_drop_in().map_err(refused)?;
    let text = drop_in_text();
    if before.drop_in.as_deref() != Some(text.as_bytes()) {
        host.write_drop_in(text.as_bytes()).map_err(refused)?;
        before.drop_in_changed = true;
    }
    Ok(())
}

/// A variable that is in force already: restart sshd if it may not have read a file, which it then says (a file
/// whose time is ahead of the clock cannot be judged, and each run restarts); a time that cannot be read is
/// said, and nothing is restarted.
fn restart_if_unread(host: &mut dyn SshdHost, say: &mut dyn FnMut(&str)) -> bool {
    match config_read(host) {
        Ok(ConfigRead::Read) => true,
        Ok(ConfigRead::Unread(file)) => {
            say(&format!(
                "apply: sshd was started before {} was last written, so it may not have read it; restarting sshd",
                file.display()
            ));
            restart(host, say, &Before::default())
        }
        Ok(ConfigRead::Unknowable(file)) => {
            say(&format!(
                "apply: {}'s last-write time is ahead of this machine's clock, so it cannot be told whether sshd \
                 has read it; restarting sshd",
                file.display()
            ));
            restart(host, say, &Before::default())
        }
        Err(e) => {
            say(&format!(
                "apply: cannot tell whether sshd has read its configuration ({e:#}); it was not restarted"
            ));
            false
        }
    }
}

/// Put `line` ([`INCLUDE_LINE`] or [`ACCEPT_LINE`]) into `sshd_config` through a candidate: made from the
/// original, checked by `sshd -t`, shown by `sshd -T` to put the variable in force, given the original's
/// security descriptor, and only then renamed over it. Returns the original's bytes. The original is
/// untouched on any failure, and the candidate is removed.
fn add_line(host: &mut dyn SshdHost, line: &str) -> Result<Vec<u8>, String> {
    let original = host.read_config().map_err(|e| format!("cannot read it: {e:#}"))?;
    let edited = with_line(&original, line).map_err(|cannot| format!("it cannot be edited safely: {cannot}"))?;
    let candidate = host
        .write_candidate(&edited)
        .map_err(|e| format!("cannot write a candidate beside it: {e:#}"))?;
    let installed = (|| {
        host.sshd_check(&candidate)
            .map_err(|said| format!("sshd rejects the edited copy: {said}"))?;
        let shown = host
            .sshd_t(Some(&candidate))
            .map_err(|e| format!("cannot ask sshd about the edited copy: {e:#}"))?;
        if !in_force(&shown) {
            return Err(format!(
                "sshd, reading the edited copy, still does not accept {VARIABLE}"
            ));
        }
        host.copy_security(&candidate)
            .map_err(|e| format!("cannot give the edited copy the original's permissions: {e:#}"))?;
        host.replace_config(&candidate)
            .map_err(|e| format!("cannot replace it with the edited copy: {e:#}"))
    })();
    match installed {
        Ok(()) => Ok(original),
        Err(why) => {
            host.discard_candidate(&candidate);
            Err(why)
        }
    }
}

/// Restart the service so that it reads the files, deciding on the state the service manager gives after each
/// action and never on what `net` said: (1) a stopped service is not started; (2) after the stop, a service
/// still running is left (no start is issued) and one that is on its way down is waited for; (3) after the
/// start, a service that is not running gets the original files back (`before`; nothing, when this run
/// changed none) and a second start. The last line said rests on a state read after the last action. Returns
/// whether the running sshd takes the variable.
fn restart(host: &mut dyn SshdHost, say: &mut dyn FnMut(&str), before: &Before) -> bool {
    // 1. A service that is stopped is not started: it reads the files when it is.
    if read_state(host) == Ok(ServiceState::Stopped) {
        say("apply: sshd is not running, so it was not started; it reads the change when it is");
        return true;
    }

    // 2. The stop. Its words are only quoted: what decides is the state read after it.
    let stop = host.net(Service::Stop);
    let mut state = read_state(host);
    if !matches!(state, Ok(ServiceState::Running | ServiceState::Stopped)) {
        let waited = host.wait_while_stopping();
        state = read_state(host);
        if let (Err(e), false) = (
            &waited,
            matches!(state, Ok(ServiceState::Running | ServiceState::Stopped)),
        ) {
            say(&format!("apply: {e:#}; starting sshd anyway"));
        }
    }
    if state == Ok(ServiceState::Running) {
        let said = match &stop {
            Ok(()) => "net reported success",
            Err(said) => said,
        };
        say(&format!(
            "apply: sshd could not be stopped ({said}) and is running with its earlier configuration, so it does \
             not accept {VARIABLE} yet; run `ssh-broker apply` again to restart it"
        ));
        return false;
    }

    // 3. The start. Stopped, or not known: the service manager's own word on sshd decides after it.
    let first = host.net(Service::Start);
    let state = read_state(host);
    if state == Ok(ServiceState::Running) {
        say(&match stop {
            Ok(()) => format!("apply: sshd restarted; it accepts {VARIABLE}"),
            Err(said) => format!("apply: sshd restarted (net stop had said: {said}); it accepts {VARIABLE}"),
        });
        return true;
    }

    // The start did not work: nothing may be serving SSH. Put back what was there.
    let first = start_said(&first, &state);
    let trouble = put_back(host, before);
    let second = host.net(Service::Start);
    let state = read_state(host);
    let trouble = if trouble.is_empty() {
        String::new()
    } else {
        format!(" ({})", trouble.join("; "))
    };
    let (failed, and_again) = if before.changed() {
        (
            format!("failed to start with {VARIABLE} accepted"),
            format!("again with the original configuration put back{trouble}"),
        )
    } else {
        ("failed to start".to_owned(), "again".to_owned())
    };
    match (&state, before.changed()) {
        (Ok(ServiceState::Running), true) => {
            say(&format!(
                "apply: sshd {failed} ({first}); the original configuration was put back{trouble} and sshd is \
                 running again. It does not accept {VARIABLE}."
            ));
            false
        }
        (Ok(ServiceState::Running), false) => {
            say(&format!(
                "apply: sshd failed to start once ({first}); a second start worked and sshd is running. It \
                 accepts {VARIABLE}."
            ));
            true
        }
        _ => {
            let second = start_said(&second, &state);
            let running = match state {
                Ok(_) => "sshd is NOT running",
                Err(_) => "sshd may not be running",
            };
            say(&format!(
                "apply: {running} ({}): it {failed} ({first}), and {and_again} ({second}). Start it at this PC: \
                 `net start sshd`.",
                says(&state)
            ));
            false
        }
    }
}

/// What the service manager said when asked, or why it could not be asked.
type StateRead = Result<ServiceState, String>;

fn read_state(host: &mut dyn SshdHost) -> StateRead {
    host.service_state().map_err(|e| format!("{e:#}"))
}

/// A state read as the clause of a sentence.
fn says(state: &StateRead) -> String {
    match state {
        Ok(state) => format!("the service manager says: {state}"),
        Err(cause) => format!("its state could not be read: {cause}"),
    }
}

/// What a `net start sshd` said, for a start that left sshd not running: its words, or when it reported
/// success, that and the state read after it.
fn start_said(net: &Result<(), String>, state: &StateRead) -> String {
    match net {
        Err(said) => said.clone(),
        Ok(()) => format!("net start sshd reported success, and {}", says(state)),
    }
}

/// Put the files back as they were before this run changed them (nothing, when it changed none). What could
/// not be put back, with why.
fn put_back(host: &mut dyn SshdHost, before: &Before) -> Vec<String> {
    let mut trouble = Vec::new();
    if let Some(original) = &before.config
        && let Err(e) = put_back_config(host, original)
    {
        trouble.push(format!("sshd_config could not be put back ({e})"));
    }
    if before.drop_in_changed {
        let restored = match &before.drop_in {
            Some(text) => host.write_drop_in(text),
            None => host.remove_drop_in(),
        };
        if let Err(e) = restored {
            trouble.push(format!("the {DROP_IN_NAME} drop-in could not be put back ({e:#})"));
        }
    }
    trouble
}

/// `sshd_config` as it was, through the same candidate and rename as the edit.
fn put_back_config(host: &mut dyn SshdHost, original: &[u8]) -> Result<(), String> {
    let candidate = host.write_candidate(original).map_err(|e| format!("{e:#}"))?;
    let put = host
        .copy_security(&candidate)
        .and_then(|()| host.replace_config(&candidate))
        .map_err(|e| format!("{e:#}"));
    if put.is_err() {
        host.discard_candidate(&candidate);
    }
    put
}

#[cfg(test)]
#[path = "configure_tests.rs"]
mod configure_tests;
