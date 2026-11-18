//! provision::sshd_config::configure — `apply`'s sshd step: the drop-in, the `Include` line and the restart.
//!
//! The flow is held apart from the machine ([`SshdHost`]) because `sshd -t` and the service cannot run on a
//! workstation: tests stand in for it, and `tests/sshd_config_windows.rs` measures the real one in CI. The
//! step never fails `apply`: the variable is a convenience, and `ssh-broker elevate` works without it. What
//! it must never do is leave a machine reached only over SSH without sshd, so the original `sshd_config` is
//! untouched until a candidate has passed sshd's own checks and then replaced in one rename, and a start that
//! fails after a stop puts the original back.

use std::path::{Path, PathBuf};

use super::{DROP_IN_NAME, DROP_IN_TEXT, INCLUDE_LINE, VARIABLE, accepts, with_include};

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
/// the system's language; the number it prints with `NET HELPMSG` is not.
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
    /// `sshd -T` (the effective configuration), of the file sshd reads or of `config`.
    fn sshd_t(&mut self, config: Option<&Path>) -> anyhow::Result<String>;
    /// `sshd -t -f config`: `Err` is what sshd says when it rejects the file.
    fn sshd_check(&mut self, config: &Path) -> Result<(), String>;
    /// Stop or start the service; returns when it has, as `net` does.
    fn service(&mut self, verb: Service) -> ServiceOutcome;
    /// Make `sshd_config.d` administrator-only, or accept it if it is. A file or a link where the folder
    /// belongs is an error.
    fn ensure_drop_in_dir(&mut self) -> anyhow::Result<()>;
    /// The drop-in's bytes, `None` when there is no such file.
    fn read_drop_in(&mut self) -> anyhow::Result<Option<Vec<u8>>>;
    /// Write the drop-in whole, administrator-only.
    fn write_drop_in(&mut self, text: &[u8]) -> anyhow::Result<()>;
    fn remove_drop_in(&mut self) -> anyhow::Result<()>;
    /// `sshd_config`'s bytes.
    fn read_config(&mut self) -> anyhow::Result<Vec<u8>>;
    /// A new file beside `sshd_config`, with `text`; its path.
    fn write_candidate(&mut self, text: &[u8]) -> anyhow::Result<PathBuf>;
    /// Give `candidate` the security descriptor of the original `sshd_config`.
    fn copy_security(&mut self, candidate: &Path) -> anyhow::Result<()>;
    /// Replace `sshd_config` with `candidate`, in one rename.
    fn replace_config(&mut self, candidate: &Path) -> anyhow::Result<()>;
    /// Remove `candidate`, if it is there.
    fn discard_candidate(&mut self, candidate: &Path);
}

/// What [`configure`] left.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outcome {
    /// sshd's configuration accepts the variable, and a restart (if one was needed) has put it in force.
    pub accepts: bool,
    /// The service was stopped and started again.
    pub restarted: bool,
}

/// What a change was made to, kept for putting it back.
struct Before {
    drop_in: Option<Vec<u8>>,
    /// `sshd_config`'s original bytes, when this run replaced it.
    config: Option<Vec<u8>>,
}

/// Make sshd accept the variable, and say what was done on `say` (a line each). The order is the drop-in, then
/// a question to sshd (is it read already?), then, when it is not, the `Include` line on a candidate that must
/// pass sshd's checks before it replaces the original, then a restart, only when something changed and the
/// variable is accepted.
pub fn configure(host: &mut dyn SshdHost, say: &mut dyn FnMut(&str)) -> Outcome {
    let not_done = Outcome {
        accepts: false,
        restarted: false,
    };
    let mut before = Before {
        drop_in: None,
        config: None,
    };

    // The drop-in. sshd reads it only through an `Include`, so writing it first changes nothing by itself.
    if let Err(e) = host.ensure_drop_in_dir() {
        say(&format!("apply: sshd's {DROP_IN_NAME} drop-in was not written: {e:#}"));
        say(&line_to_add(host));
        return not_done;
    }
    match host.read_drop_in() {
        Ok(existing) => before.drop_in = existing,
        Err(e) => {
            say(&format!("apply: cannot read sshd's {DROP_IN_NAME} drop-in: {e:#}"));
            say(&line_to_add(host));
            return not_done;
        }
    }
    let drop_in_changed = before.drop_in.as_deref() != Some(DROP_IN_TEXT.as_bytes());
    if drop_in_changed && let Err(e) = host.write_drop_in(DROP_IN_TEXT.as_bytes()) {
        say(&format!("apply: sshd's {DROP_IN_NAME} drop-in was not written: {e:#}"));
        say(&line_to_add(host));
        return not_done;
    }

    // Is it read? Plain `sshd -T` says (a drop-in is in force in what it prints before a restart does).
    let listing = match host.sshd_t(None) {
        Ok(listing) => listing,
        Err(e) => {
            say(&format!(
                "apply: could not ask sshd for its configuration, so sshd_config was left as it is: {e:#}"
            ));
            say(&line_to_add(host));
            return not_done;
        }
    };
    let mut config_changed = false;
    if !accepts(&listing, VARIABLE) {
        match add_include(host) {
            Ok(original) => {
                before.config = Some(original);
                config_changed = true;
            }
            Err(why) => {
                say(&format!("apply: sshd_config was not changed: {why}"));
                say(&line_to_add(host));
                return not_done;
            }
        }
    }

    if !(drop_in_changed || config_changed) {
        return Outcome {
            accepts: true,
            restarted: false,
        };
    }
    restart(host, say, &before, drop_in_changed)
}

/// The sentence that says what to do by hand.
fn line_to_add(host: &dyn SshdHost) -> String {
    format!(
        "apply: to have sshd accept {VARIABLE}, add the line `{INCLUDE_LINE}` above the first `Match` in {} and \
         restart sshd; `ssh-broker elevate` works without it",
        host.config_path().display()
    )
}

/// Put [`INCLUDE_LINE`] into `sshd_config` through a candidate: made from the original, checked by `sshd -t`,
/// shown by `sshd -T` to give the variable, given the original's security descriptor, and only then renamed
/// over it. Returns the original's bytes. The original is untouched on any failure, and the candidate is
/// removed.
fn add_include(host: &mut dyn SshdHost) -> Result<Vec<u8>, String> {
    let original = host.read_config().map_err(|e| format!("cannot read it: {e:#}"))?;
    let edited = with_include(&original).map_err(|cannot| format!("it cannot be edited safely: {cannot}"))?;
    let candidate = host
        .write_candidate(&edited)
        .map_err(|e| format!("cannot write a candidate beside it: {e:#}"))?;
    let installed = (|| {
        host.sshd_check(&candidate)
            .map_err(|said| format!("sshd rejects the edited copy: {said}"))?;
        let shown = host
            .sshd_t(Some(&candidate))
            .map_err(|e| format!("cannot ask sshd about the edited copy: {e:#}"))?;
        if !accepts(&shown, VARIABLE) {
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

/// Restart the service so that it reads the change; if it will not start again, put the original files back
/// and start it with them. The last line said is the plainest account of whether sshd is running.
fn restart(host: &mut dyn SshdHost, say: &mut dyn FnMut(&str), before: &Before, drop_in_changed: bool) -> Outcome {
    match host.service(Service::Stop) {
        ServiceOutcome::Done => {}
        ServiceOutcome::Unchanged => {
            say("apply: sshd is not running, so it was not started; it reads the change when it is");
            return Outcome {
                accepts: true,
                restarted: false,
            };
        }
        ServiceOutcome::Failed(said) => {
            say(&format!(
                "apply: sshd could not be stopped ({said}), so it was not restarted; restart sshd for it to accept {VARIABLE}"
            ));
            return Outcome {
                accepts: true,
                restarted: false,
            };
        }
    }
    let ServiceOutcome::Failed(first) = host.service(Service::Start) else {
        say(&format!("apply: sshd restarted; it accepts {VARIABLE}"));
        return Outcome {
            accepts: true,
            restarted: true,
        };
    };

    // The stop succeeded and the start did not: nothing is serving SSH. Put back what was there.
    let mut trouble = Vec::new();
    if let Some(original) = &before.config
        && let Err(e) = put_back_config(host, original)
    {
        trouble.push(format!("sshd_config could not be put back ({e})"));
    }
    if drop_in_changed {
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
    match started_again {
        ServiceOutcome::Done | ServiceOutcome::Unchanged => say(&format!(
            "apply: sshd failed to start with {VARIABLE} accepted ({first}); the original configuration was put \
             back{trouble} and sshd is running again. It does not accept {VARIABLE}."
        )),
        ServiceOutcome::Failed(second) => say(&format!(
            "apply: sshd is NOT running: it failed to start with {VARIABLE} accepted ({first}), and again with \
             the original configuration put back{trouble} ({second}). Start it at this PC: `net start sshd`."
        )),
    }
    Outcome {
        accepts: false,
        restarted: false,
    }
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
