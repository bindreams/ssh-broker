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

/// How a [`Service`] request went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceOutcome {
    /// Done: stopped, or started.
    Done,
    /// The service was in the state asked for already: a stop of one that is not running, a start of one that
    /// is.
    Unchanged,
    /// It failed, with the system's words.
    Failed(String),
}

/// `net.exe`'s message numbers for "the service is not started" and "already been started". Its words are in
/// the system's language; the number it prints with `NET HELPMSG` is not. `tests/sshd_config_windows.rs`
/// measures both against the real `net.exe`.
const NOT_STARTED: u32 = 3521;
const ALREADY_STARTED: u32 = 2182;

/// What `net stop sshd` or `net start sshd` meant, from its exit `code` and its `output`.
pub fn net_outcome(service: Service, code: i32, output: &str) -> ServiceOutcome {
    if code == 0 {
        return ServiceOutcome::Done;
    }
    let already = match service {
        Service::Stop => NOT_STARTED,
        Service::Start => ALREADY_STARTED,
    };
    let mut words = output.split_whitespace();
    let help = words
        .by_ref()
        .find(|word| word.eq_ignore_ascii_case("HELPMSG"))
        .and_then(|_| words.next())
        .and_then(|number| number.trim_end_matches('.').parse::<u32>().ok());
    if help == Some(already) {
        return ServiceOutcome::Unchanged;
    }
    let said = output.split_whitespace().collect::<Vec<_>>().join(" ");
    ServiceOutcome::Failed(if said.is_empty() {
        format!("net exited with exit code {code}")
    } else {
        said
    })
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
    /// Stop or start the service; returns when it has, as `net` does.
    fn service(&mut self, verb: Service) -> ServiceOutcome;
    /// When the running sshd service's process started; `None` when it is not running.
    fn service_started(&mut self) -> anyhow::Result<Option<SystemTime>>;
    /// The later last-write time of `sshd_config` and of the drop-in (when there is one), and the file it is of.
    fn config_written(&mut self) -> anyhow::Result<(PathBuf, SystemTime)>;
    /// Make `sshd_config.d` as the install directory is made, or accept it if it is. A file or a link where the
    /// folder belongs, other permissions, or a folder that cannot be made is an error that says why; nothing
    /// there is changed.
    fn ensure_drop_in_dir(&mut self) -> anyhow::Result<()>;
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

/// The file written after the running sshd service started, if there is one: sshd reads its configuration only
/// when it starts, so such a file may not have been read. `None` too when the service is not running (it reads
/// what is there when it starts). `Err` when a time cannot be read, with the cause.
pub fn unread_file(host: &mut dyn SshdHost) -> anyhow::Result<Option<PathBuf>> {
    let Some(started) = host.service_started().context("read when the sshd service started")? else {
        return Ok(None);
    };
    let (file, written) = host
        .config_written()
        .context("read when sshd's configuration was last written")?;
    Ok((started < written).then_some(file))
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
            say(&format!(
                "apply: could not ask sshd for its configuration, so nothing of sshd's was changed: {e:#}"
            ));
            say(&advice(host));
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
                    say(&format!(
                        "apply: could not ask sshd for its configuration, so sshd_config was left as it is: {e:#}"
                    ));
                    say(&advice(host));
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
            let left = format!("apply: {} is left as it is ({problem})", folder.display());
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

/// The sentence that says what to do by hand.
fn advice(host: &dyn SshdHost) -> String {
    format!(
        "apply: add `{ACCEPT_LINE}` above the first `Match` in {}, then run `ssh-broker apply` again, which \
         restarts sshd; `ssh-broker elevate` works without it",
        host.config_path().display()
    )
}

/// Make the drop-in what [`drop_in_text`] says, in a folder that is as `apply` makes it. `Err` says why the
/// folder or the drop-in cannot be used; the flow then leaves them as they are.
fn write_drop_in(host: &mut dyn SshdHost, before: &mut Before) -> Result<(), String> {
    host.ensure_drop_in_dir().map_err(|e| format!("{e:#}"))?;
    before.drop_in = host.read_drop_in().map_err(|e| format!("{e:#}"))?;
    let text = drop_in_text();
    if before.drop_in.as_deref() != Some(text.as_bytes()) {
        host.write_drop_in(text.as_bytes()).map_err(|e| format!("{e:#}"))?;
        before.drop_in_changed = true;
    }
    Ok(())
}

/// A variable that is in force already: restart sshd only if it started before a file was written, which it
/// then says; a time that cannot be read is said, and nothing is restarted.
fn restart_if_unread(host: &mut dyn SshdHost, say: &mut dyn FnMut(&str)) -> bool {
    match unread_file(host) {
        Ok(None) => true,
        Ok(Some(file)) => {
            say(&format!(
                "apply: sshd was started before {} was last written, so it may not have read it; restarting sshd",
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

/// Restart the service so that it reads the files. A start is issued after any stop but "it was not running":
/// a stop that failed or timed out does not mean the service still runs. If the start fails, put the original
/// files back (`before`; nothing, when this run changed none) and start it with them. The last line said is
/// the plainest account of whether sshd is running. Returns whether the running sshd takes the variable.
fn restart(host: &mut dyn SshdHost, say: &mut dyn FnMut(&str), before: &Before) -> bool {
    let stop_failed = match host.service(Service::Stop) {
        ServiceOutcome::Done => None,
        ServiceOutcome::Unchanged => {
            say("apply: sshd is not running, so it was not started; it reads the change when it is");
            return true;
        }
        ServiceOutcome::Failed(said) => Some(said),
    };
    let first = match host.service(Service::Start) {
        ServiceOutcome::Done => {
            say(&match stop_failed {
                None => format!("apply: sshd restarted; it accepts {VARIABLE}"),
                Some(said) => format!(
                    "apply: sshd could not be stopped ({said}) but had stopped when it was started again; it was \
                     restarted and accepts {VARIABLE}"
                ),
            });
            return true;
        }
        ServiceOutcome::Unchanged => {
            let Some(said) = stop_failed else {
                say(&format!("apply: sshd restarted; it accepts {VARIABLE}"));
                return true;
            };
            say(&format!(
                "apply: sshd could not be stopped ({said}) and is running with its earlier configuration, so it \
                 does not accept {VARIABLE} yet; run `ssh-broker apply` again to restart it"
            ));
            return false;
        }
        ServiceOutcome::Failed(first) => first,
    };

    // The start did not work: nothing may be serving SSH. Put back what was there.
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
    let started_again = host.service(Service::Start);
    let trouble = if trouble.is_empty() {
        String::new()
    } else {
        format!(" ({})", trouble.join("; "))
    };
    let (failed, and_again) = if before.changed() {
        (
            format!("failed to start with {VARIABLE} accepted ({first})"),
            format!("again with the original configuration put back{trouble}"),
        )
    } else {
        (format!("failed to start ({first})"), "again".to_owned())
    };
    match started_again {
        ServiceOutcome::Done | ServiceOutcome::Unchanged if before.changed() => say(&format!(
            "apply: sshd {failed}; the original configuration was put back{trouble} and sshd is running again. It \
             does not accept {VARIABLE}."
        )),
        ServiceOutcome::Done | ServiceOutcome::Unchanged => {
            say(&format!(
                "apply: sshd {failed}; a second start worked and sshd is running again"
            ));
        }
        ServiceOutcome::Failed(second) => {
            let running = match stop_failed {
                None => "sshd is NOT running".to_owned(),
                Some(said) => format!("sshd may not be running (it could not be stopped either: {said})"),
            };
            say(&format!(
                "apply: {running}: it {failed}, and {and_again} ({second}). Start it at this PC: `net start sshd`."
            ));
        }
    }
    false
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
