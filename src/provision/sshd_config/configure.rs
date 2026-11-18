//! provision::sshd_config::configure — `apply`'s sshd step: the drop-in and the `Include` line, and whether
//! the running sshd has read them.
//!
//! The flow is held apart from the machine ([`SshdHost`]) because `sshd -t` and the service cannot run on a
//! workstation: tests stand in for it, and `tests/sshd_config_windows.rs` measures the real one in CI. The
//! step never fails `apply`: the variable is a convenience, and `ssh-broker elevate` works without it. It
//! never restarts sshd, so a machine reached only over SSH keeps its sshd, and the original `sshd_config` is
//! untouched until a candidate has passed sshd's own checks and then replaced in one rename.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::Context;

use super::{ACCEPT_LINE, DROP_IN_DIR_NAME, INCLUDE_LINE, VARIABLE, drop_in_text, in_force, with_line};

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

/// Whether the running sshd has read the files of its configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigRead {
    /// It started after the files were last written.
    Read,
    /// It is not running: it reads what is there when it starts.
    NotRunning,
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
        return Ok(ConfigRead::NotRunning);
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

/// Make sshd accept the variable, and say what was done on `say` (a line each). Never restarts sshd. Returns
/// whether the running sshd takes the variable, or reads it when it next starts (it is not running); false
/// when it does not, because it has not read the files yet or the variable could not be put in force, and
/// when that cannot be told.
///
/// The order: (0) a service started with arguments is not touched. (1) A question to sshd; a failure says so
/// and writes nothing. (2) A variable in force already ([`in_force`]) writes nothing. (3) Otherwise the
/// drop-in (written if it differs) and a second question: when no `Include` reads it, the `Include` line goes
/// into a candidate that must pass sshd's checks before it replaces the original; when the folder or the
/// drop-in cannot be used, the `AcceptEnv` line goes there instead. (4) With the variable in force, one
/// judgement, the same for a change made in this run and for one made earlier: [`config_read`] says whether
/// sshd has read the files, and when it has not, what to do is said.
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
        return say_whether_read(host, say);
    }

    match write_drop_in(host) {
        Ok(()) => {
            // The drop-in is read through an `Include`, when there is one: plain `sshd -T` says.
            let listing = match host.sshd_t(None) {
                Ok(listing) => listing,
                Err(e) => {
                    say(&ask_failed(host, &e, "sshd_config was left as it is"));
                    return false;
                }
            };
            if !in_force(&listing)
                && let Err(why) = add_line(host, INCLUDE_LINE)
            {
                say(&format!("apply: sshd_config was not changed: {why}"));
                say(&advice(host));
                return false;
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
                Ok(()) => say(&format!(
                    "{left}; {VARIABLE} is accepted by a line in sshd_config instead"
                )),
                Err(why) => {
                    say(&left);
                    say(&format!("apply: sshd_config was not changed: {why}"));
                    say(&advice(host));
                    return false;
                }
            }
        }
    }

    say_whether_read(host, say)
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

/// The sentence that says what to do by hand when the step could not put the variable in force.
fn advice(host: &dyn SshdHost) -> String {
    format!(
        "apply: add `{ACCEPT_LINE}` above the first `Match` in {}, then restart the sshd service; `ssh-broker \
         elevate` works without it",
        host.config_path().display()
    )
}

/// Make the drop-in what [`drop_in_text`] says, in a folder that is as `apply` makes it. `Err` says why the
/// folder or the drop-in cannot be used; the flow then leaves them as they are.
fn write_drop_in(host: &mut dyn SshdHost) -> Result<(), DropInProblem> {
    let refused = |e: anyhow::Error| DropInProblem::Refused(format!("{e:#}"));
    host.ensure_drop_in_dir()?;
    let text = drop_in_text();
    if host.read_drop_in().map_err(refused)?.as_deref() != Some(text.as_bytes()) {
        host.write_drop_in(text.as_bytes()).map_err(refused)?;
    }
    Ok(())
}

/// The variable is in force in what sshd would read: say whether the running sshd has read it, and return
/// whether it takes it (or will, when it starts). The one judgement for a change made in this run and one made
/// earlier; sshd is never restarted here.
fn say_whether_read(host: &mut dyn SshdHost, say: &mut dyn FnMut(&str)) -> bool {
    match config_read(host) {
        Ok(ConfigRead::Read) => true,
        Ok(ConfigRead::NotRunning) => {
            say("apply: sshd is not running; it reads the change when it starts");
            true
        }
        Ok(ConfigRead::Unread(file)) => {
            say(&format!(
                "apply: sshd was started before {} was last written, so it has not read it; restart the sshd \
                 service for it to accept {VARIABLE} (`ssh-broker verify` says whether it has)",
                file.display()
            ));
            false
        }
        Ok(ConfigRead::Unknowable(file)) => {
            say(&format!(
                "apply: {}'s last-write time is ahead of this machine's clock, so it cannot be told whether sshd \
                 has read it; restart the sshd service for it to accept {VARIABLE}",
                file.display()
            ));
            false
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
/// security descriptor, and only then renamed over it. The original is untouched on any failure, and the
/// candidate is removed.
fn add_line(host: &mut dyn SshdHost, line: &str) -> Result<(), String> {
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
    if installed.is_err() {
        host.discard_candidate(&candidate);
    }
    installed
}

#[cfg(test)]
#[path = "configure_tests.rs"]
mod configure_tests;
