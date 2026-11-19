//! provision::sshd_config::configure — `apply`'s sshd step: the drop-in and the `Include` line, and whether
//! the running sshd has read them.
//!
//! The flow is held apart from the machine ([`SshdHost`]) because `sshd -t` and the service cannot run on a
//! workstation: tests stand in for it, and `tests/sshd_config_windows.rs` measures the real one in CI. The
//! step never fails `apply`: the variable is a convenience, and `ssh-broker elevate` works without it. The one
//! judgement for a change made in this run and one made earlier ([`config_read`]); an sshd that has not read
//! the files is restarted through the service manager ([`restart`]), which never leaves a machine reached only
//! over SSH without sshd it could have started. The original `sshd_config` is untouched until a
//! candidate has passed sshd's own checks and then replaced in one rename. The original is read once and
//! replaced whole: an edit another program makes to it while `apply` runs is lost. That is a contract
//! (README), not guarded: no lock other editors honour exists, and one that let the rename through would let
//! theirs through too.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::Context;

use super::restart::{Before, ServiceState, StartOutcome, StopOutcome, restart};
use super::{
    ACCEPT_LINE, DROP_IN_DIR_NAME, INCLUDE_LINE, VARIABLE, drop_in_text, in_force, include_elsewhere, with_line,
};

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
    /// When the running sshd service's process started; `None` when it is not running.
    fn service_started(&mut self) -> anyhow::Result<Option<SystemTime>>;
    /// What the service manager says the service is, once it says a settled state: it waits while the service
    /// is starting, stopping, pausing or continuing, with no bound, because the service manager never resolves
    /// a held pending state and a bound would only make `apply` give up. `Err` when the state cannot be read.
    fn settled(&mut self) -> anyhow::Result<ServiceState>;
    /// Send the service a STOP, wait for what the service manager says to settle, and when it says stopped, or
    /// when the STOP was answered with 1053 and it says running, wait for the process the service had before the
    /// STOP to exit. `Err`: no STOP was sent.
    ///
    /// `unanswered` is called once, with the service manager's reply, before a STOP answered with 1053 that
    /// leaves the service running is waited on.
    fn stop(&mut self, unanswered: &mut dyn FnMut(&str)) -> anyhow::Result<StopOutcome>;
    /// Start the service and wait, with no bound, for what the service manager says to settle and, when that is
    /// running, for sshd to listen or for its process to exit: the service manager says running before sshd has
    /// read its configuration.
    fn start(&mut self) -> StartOutcome;
    /// This machine's clock.
    fn now(&self) -> SystemTime;
    /// `sshd_config` and every file directly in `sshd_config.d`, whatever its extension, each with when it last
    /// changed and its bytes, and the folder's own change time.
    fn config_files(&mut self) -> anyhow::Result<ConfigFiles>;
    /// Make `sshd_config.d` as the install directory is made, or accept it if it is. A folder that cannot be
    /// made is [`DropInProblem::NotMade`]; a file or a link where the folder belongs, or other permissions, is
    /// [`DropInProblem::Refused`]. Nothing that is there is changed.
    fn ensure_drop_in_dir(&mut self) -> Result<(), DropInProblem>;
    /// The drop-in's bytes, `None` when there is no such file.
    fn read_drop_in(&mut self) -> anyhow::Result<Option<Vec<u8>>>;
    /// Write the drop-in whole, with the permissions its folder gives a file.
    fn write_drop_in(&mut self, text: &[u8]) -> anyhow::Result<()>;
    /// Remove the drop-in this run made.
    fn remove_drop_in(&mut self) -> anyhow::Result<()>;
    /// `sshd_config`'s bytes.
    fn read_config(&mut self) -> anyhow::Result<Vec<u8>>;
    /// A new file beside `sshd_config`, with `text`, on disk; its path.
    fn write_candidate(&mut self, text: &[u8]) -> anyhow::Result<PathBuf>;
    /// Give `candidate` the security descriptor of the original `sshd_config`.
    fn copy_security(&mut self, candidate: &Path) -> anyhow::Result<()>;
    /// Replace `sshd_config` with `candidate`, in one rename that is on disk when it returns.
    fn replace_config(&mut self, candidate: &Path) -> anyhow::Result<()>;
    /// Remove the candidate, if it is there: whole, or whatever a write that failed left of it.
    fn discard_candidate(&mut self);
}

/// The files sshd reads from its configuration folder, as [`SshdHost::config_files`] gives them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigFiles {
    /// When `sshd_config.d` itself last changed; `None` when there is no such folder.
    pub folder: Option<SystemTime>,
    /// `sshd_config` first, then every file directly in the folder.
    pub files: Vec<ConfigFile>,
}

/// One file of sshd's configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigFile {
    pub path: PathBuf,
    /// When the file last changed: a write, a rename and a copy all move it.
    pub changed: SystemTime,
    pub text: Vec<u8>,
}

/// Whether the running sshd has read the files of its configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigRead {
    /// It started after the files last changed.
    Read,
    /// It is not running: it reads what is there when it starts.
    NotRunning,
    /// The file (or the folder) last changed when sshd started or after: sshd reads its configuration only when
    /// it starts, so it may not have been read. A tie counts: the cost is one restart that was not needed.
    Unread(PathBuf),
    /// The file's (or the folder's) change time is ahead of the clock, so it cannot be compared with when sshd
    /// started.
    AheadOfClock(PathBuf),
    /// A file has an `Include` of another location, which is not judged: whether sshd has read what it
    /// includes cannot be told.
    IncludesOther { file: PathBuf, line: String },
}

/// Whether the running sshd has read its configuration, judged on when `sshd_config`, `sshd_config.d` and every
/// file in it last changed and on when the service started. `Err` when a time cannot be read, with the cause.
pub fn config_read(host: &mut dyn SshdHost) -> anyhow::Result<ConfigRead> {
    let Some(started) = host.service_started().context("read when the sshd service started")? else {
        return Ok(ConfigRead::NotRunning);
    };
    let judged = host
        .config_files()
        .context("read when sshd's configuration last changed")?;
    // The file that changed last; a tie goes to a file before the folder, and to the earlier of two files.
    let mut latest: Option<(PathBuf, SystemTime)> = None;
    let folder = judged
        .folder
        .map(|changed| (host.config_path().with_file_name(DROP_IN_DIR_NAME), changed));
    let candidates = judged.files.iter().map(|file| (file.path.clone(), file.changed));
    for (path, changed) in candidates.chain(folder) {
        if latest.as_ref().is_none_or(|(_, time)| changed > *time) {
            latest = Some((path, changed));
        }
    }
    if let Some((path, changed)) = latest {
        if changed > host.now() {
            return Ok(ConfigRead::AheadOfClock(path));
        }
        if started <= changed {
            return Ok(ConfigRead::Unread(path));
        }
    }
    for file in &judged.files {
        if let Some(line) = include_elsewhere(&file.text) {
            return Ok(ConfigRead::IncludesOther {
                file: file.path.clone(),
                line,
            });
        }
    }
    Ok(ConfigRead::Read)
}

/// Make sshd accept the variable, and say what was done on `say` (a line each). Returns whether the running
/// sshd takes the variable, or reads it when it next starts (it is not running); false when it does not,
/// because it could not be restarted to read the files or the variable could not be put in force, and when that
/// cannot be told.
///
/// A failed question to sshd writes nothing, and a candidate for `sshd_config` must pass sshd's checks before
/// it replaces the original.
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
    let mut before = Before::default();
    if in_force(&listing) {
        return say_whether_read(host, say, &before);
    }

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

    say_whether_read(host, say, &before)
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

/// The sentence that says what to do by hand when the step could not put the variable in force. The next
/// `apply` finds the line in force and restarts sshd, if it has not read it.
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
    let text = drop_in_text();
    before.drop_in = host.read_drop_in().map_err(refused)?;
    if before.drop_in.as_deref() != Some(text.as_bytes()) {
        host.write_drop_in(text.as_bytes()).map_err(refused)?;
        before.drop_in_changed = true;
    }
    Ok(())
}

/// The variable is in force in what sshd would read: say whether the running sshd has read it, restart it when
/// it has not, and return whether it takes the variable (or will, when it starts). A file whose time cannot be
/// judged, and an `Include` of another location, restart it to be sure. `before` is what this run changed: a
/// change sshd cannot have read restarts it even when the times cannot be read, and is put back if sshd cannot
/// start with it.
fn say_whether_read(host: &mut dyn SshdHost, say: &mut dyn FnMut(&str), before: &Before) -> bool {
    match config_read(host) {
        Ok(ConfigRead::Read) => true,
        Ok(ConfigRead::NotRunning) => {
            say("apply: sshd is not running; it reads the change when it starts");
            true
        }
        Ok(ConfigRead::Unread(file)) => {
            say(&format!(
                "apply: sshd was started before {} was last changed, so it has not read it",
                file.display()
            ));
            restart(host, say, before)
        }
        Ok(ConfigRead::AheadOfClock(file)) => {
            say(&format!(
                "apply: {}'s change time is ahead of this machine's clock, so it cannot be told whether sshd \
                 has read it",
                file.display()
            ));
            restart(host, say, before)
        }
        Ok(ConfigRead::IncludesOther { file, line }) => {
            say(&format!(
                "apply: {} has `{line}`; files sshd includes from elsewhere are not judged, so it cannot be told \
                 whether sshd has read its configuration, and it is restarted to be sure it accepts {VARIABLE}",
                file.display()
            ));
            restart(host, say, before)
        }
        Err(e) if before.changed() => {
            say(&format!(
                "apply: cannot tell whether sshd has read its configuration ({e:#}); this run changed it, so it \
                 has not"
            ));
            restart(host, say, before)
        }
        Err(e) => {
            say(&format!(
                "apply: cannot tell whether sshd has read its configuration ({e:#}); restart the sshd service for \
                 it to accept {VARIABLE}"
            ));
            false
        }
    }
}

/// Put `line` ([`INCLUDE_LINE`] or [`ACCEPT_LINE`]) into `sshd_config` through a candidate: made from the
/// original, checked by `sshd -t`, shown by `sshd -T` to put the variable in force, given the original's
/// security descriptor, and only then renamed over it. Returns the original's bytes. The original is untouched
/// on any failure, and the candidate is removed.
fn add_line(host: &mut dyn SshdHost, line: &str) -> Result<Vec<u8>, String> {
    let original = host.read_config().map_err(|e| format!("cannot read it: {e:#}"))?;
    let edited = with_line(&original, line).map_err(|cannot| format!("it cannot be edited safely: {cannot}"))?;
    let candidate = match host.write_candidate(&edited) {
        Ok(candidate) => candidate,
        Err(e) => {
            host.discard_candidate();
            return Err(format!("cannot write a candidate beside it: {e:#}"));
        }
    };
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
    if installed.is_err() {
        host.discard_candidate();
    }
    installed.map(|()| original)
}

#[cfg(test)]
#[path = "configure_tests.rs"]
pub(super) mod configure_tests;
