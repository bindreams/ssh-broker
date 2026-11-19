//! provision::sshd_config::restart — restarting the sshd service so that it reads the files, deciding only on
//! what the service manager says.

use super::configure::SshdHost;
use super::{DROP_IN_NAME, VARIABLE};

/// The settled states of the sshd service. The machine never returns a pending one: it waits for the service
/// manager to leave it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    Running,
    Stopped,
    Paused,
}

impl std::fmt::Display for ServiceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ServiceState::Running => "running",
            ServiceState::Stopped => "stopped",
            ServiceState::Paused => "paused",
        })
    }
}

/// How [`SshdHost::stop`] went, once a STOP was sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopOutcome {
    /// The service manager says stopped, and the process the service had before the STOP has exited.
    Stopped,
    /// The service manager settled in `state`, not stopped. `refusal` is what it answered the STOP when it
    /// refused it; `None` when it accepted it and the service did not stop. Never a service that is running after
    /// a STOP answered with 1053: that is [`StopOutcome::Stopped`] once the old process has exited, else
    /// [`StopOutcome::Unknown`].
    NotStopped {
        state: ServiceState,
        refusal: Option<String>,
    },
    /// The state or the process could not be read after the STOP: whether sshd is stopped is not known.
    Unknown { cause: String },
}

/// What the service manager answered a start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartReply {
    Accepted,
    /// Refused, with its reply.
    Refused(String),
}

/// The exit codes the service manager recorded for a service that stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitCodes {
    pub win32: u32,
    pub specific: u32,
}

/// How [`SshdHost::start`] went: what the service manager answered, and the state that settled after.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartOutcome {
    /// The service's process owns a listening TCP socket: sshd has read its configuration and serves. The service
    /// manager says running before that, so running alone is not this.
    Serving(StartReply),
    /// The service's process, which the service manager had reported running, exited with `code` before it
    /// listened.
    Exited {
        reply: StartReply,
        code: u32,
    },
    /// Settled stopped, with the exit codes it recorded.
    Stopped {
        reply: StartReply,
        exit: ExitCodes,
    },
    Paused(StartReply),
    /// The state could not be read after the start.
    Unreadable {
        reply: StartReply,
        cause: String,
    },
}

/// What a change was made to, kept for putting it back.
#[derive(Default)]
pub struct Before {
    /// The drop-in as it was before this run; `None` when there was none.
    pub drop_in: Option<Vec<u8>>,
    /// This run wrote the drop-in.
    pub drop_in_changed: bool,
    /// `sshd_config`'s original bytes, when this run replaced it.
    pub config: Option<Vec<u8>>,
}

impl Before {
    pub fn changed(&self) -> bool {
        self.drop_in_changed || self.config.is_some()
    }
}

/// Restart the sshd service so that it reads the files, and say what came of it on `say`. Returns whether the
/// running sshd takes the variable.
///
/// Nothing is done to a service whose state was not read, and every state decided on is one the service manager
/// settled in. (1) A stopped service is not started, and a paused one or one whose state cannot be read is left
/// alone. (2) The STOP; a service that did not stop gets no start. (3) The start, which is over when sshd listens
/// or its process has exited: the service manager says running before sshd has read a byte of its configuration.
/// A start that the service manager accepted and that ended before sshd listened (it settled stopped, or the
/// process exited) is the only evidence that sshd could not run the files: only then is what this run changed
/// (`before`) put back, and sshd started again.
pub fn restart(host: &mut dyn SshdHost, say: &mut dyn FnMut(&str), before: &Before) -> bool {
    say(
        "apply: restarting sshd; apply waits for the service manager at each step, and after a start for sshd to \
         listen or exit",
    );

    match host.settled() {
        Ok(ServiceState::Running) => {}
        Ok(ServiceState::Stopped) => {
            say("apply: sshd is not running, so it was not started; it reads the change when it is");
            return true;
        }
        Ok(ServiceState::Paused) => {
            say(
                "apply: the sshd service is paused, so it was not restarted; resume it (`sc continue sshd`) and run \
                 `ssh-broker apply` again",
            );
            return false;
        }
        Err(e) => {
            say(&format!(
                "apply: the sshd service's state cannot be read ({e:#}), so it was not restarted; run \
                 `ssh-broker apply` again to restart it"
            ));
            return false;
        }
    }

    // What is known of the stop: `None` when `Stopped` was read, else a clause with why it was not seen.
    let unseen = match host.stop() {
        Ok(StopOutcome::Stopped) => None,
        Ok(StopOutcome::Unknown { cause }) => Some(format!("whether sshd stopped could not be told ({cause})")),
        Ok(StopOutcome::NotStopped { state, refusal }) => {
            let why = refusal
                .unwrap_or_else(|| "the service manager accepted the stop and the service did not stop".to_owned());
            say(&not_stopped(&why, &state.to_string()));
            return false;
        }
        Err(e) => {
            say(&format!(
                "apply: no stop was sent to sshd ({e:#}), so it was not restarted. Its state was last read as \
                 running, before that, with its earlier configuration, so it does not accept {VARIABLE} yet; run \
                 `ssh-broker apply` again to restart it"
            ));
            return false;
        }
    };
    // "sshd was stopped" is said only of a stop that was read.
    let stopped = unseen.as_deref().unwrap_or("sshd was stopped");

    let first = host.start();
    match first {
        StartOutcome::Serving(StartReply::Accepted) => {
            say(&match &unseen {
                None => format!("apply: sshd restarted; it accepts {VARIABLE}"),
                Some(unseen) => format!(
                    "apply: sshd restarted; it accepts {VARIABLE} ({unseen}, and the service manager accepted a \
                     start)"
                ),
            });
            true
        }
        StartOutcome::Serving(StartReply::Refused(reply)) if unseen.is_none() => {
            say(&format!(
                "apply: sshd restarted (the service manager had started it again: {reply}); it accepts {VARIABLE}"
            ));
            true
        }
        StartOutcome::Serving(StartReply::Refused(reply)) => {
            say(&format!(
                "apply: sshd is running and whether it restarted cannot be told: {stopped}, and a start was \
                 refused ({reply}); `ssh-broker apply` restarts it if it has not read the change"
            ));
            false
        }
        StartOutcome::Stopped {
            reply: StartReply::Refused(reply),
            ..
        } => {
            say(&format!(
                "apply: sshd is NOT running: {}, and the service manager refused to start it ({reply}). \
                 {START_BY_HAND}",
                unseen.as_deref().unwrap_or("it was stopped")
            ));
            false
        }
        StartOutcome::Exited {
            reply: StartReply::Refused(reply),
            code,
        } => {
            say(&format!(
                "apply: sshd is not serving: {stopped}, the service manager refused a start ({reply}), and the sshd \
                 it reported running exited (code {code}) before it listened. {CHECK_OR_START_BY_HAND}"
            ));
            false
        }
        StartOutcome::Stopped { exit, .. } => {
            let first = match &unseen {
                None => stopped_again(exit),
                Some(unseen) => format!("{unseen}; {}", stopped_again(exit)),
            };
            start_again(host, say, before, &first)
        }
        StartOutcome::Exited { code, .. } => {
            let first = match &unseen {
                None => exited_before_listening(code),
                Some(unseen) => format!("{unseen}; {}", exited_before_listening(code)),
            };
            start_again(host, say, before, &first)
        }
        StartOutcome::Paused(reply) => {
            say(&format!(
                "apply: {stopped} and a start was {}; it is paused. {CHECK_BY_HAND}",
                replied(&reply)
            ));
            false
        }
        StartOutcome::Unreadable { reply, cause } => {
            say(&format!(
                "apply: {stopped} and a start was {}; its state cannot be read ({cause}). {CHECK_BY_HAND}",
                replied(&reply)
            ));
            false
        }
    }
}

const START_BY_HAND: &str = "Start it at this PC: `net start sshd`.";
const CHECK_BY_HAND: &str = "Check it at this PC: `sc query sshd`.";
const CHECK_OR_START_BY_HAND: &str =
    "Check it at this PC: `sc query sshd`; start it with `net start sshd` if it is stopped.";

/// What is said when sshd could not be stopped: why, and the state it is in.
fn not_stopped(why: &str, state: &str) -> String {
    format!(
        "apply: sshd could not be stopped ({why}) and is {state} with its earlier configuration, so it does not \
         accept {VARIABLE} yet; run `ssh-broker apply` again to restart it"
    )
}

/// A start the service manager accepted and then saw stop, in a sentence.
fn stopped_again(exit: ExitCodes) -> String {
    format!(
        "the start was accepted and sshd stopped again (exit codes {} and {})",
        exit.win32, exit.specific
    )
}

/// A start the service manager accepted whose sshd exited before it listened, in a sentence.
fn exited_before_listening(code: u32) -> String {
    format!("the start was accepted and sshd exited (code {code}) before it listened")
}

/// A second start that ended before sshd listened, in a clause: `accepted` is what is said of one the service
/// manager accepted.
fn second_ended(reply: StartReply, accepted: String) -> String {
    match reply {
        StartReply::Refused(reply) => format!("the service manager refused a second start ({reply})"),
        StartReply::Accepted => accepted,
    }
}

/// What the service manager answered a start, in a clause.
fn replied(reply: &StartReply) -> String {
    match reply {
        StartReply::Accepted => "accepted".to_owned(),
        StartReply::Refused(reply) => format!("refused ({reply})"),
    }
}

/// The first start was accepted and ended before sshd listened (`first` says how), so sshd could not run the files:
/// put back what this run changed, start once more, and say what that came to. Returns whether the running
/// sshd takes the variable.
fn start_again(host: &mut dyn SshdHost, say: &mut dyn FnMut(&str), before: &Before, first: &str) -> bool {
    let trouble = put_back(host, before);
    let changed = before.changed();
    let failed = if changed {
        format!("failed to start with {VARIABLE} accepted")
    } else {
        "failed to start".to_owned()
    };
    // What became of the files, when this run changed some: a sentence, and the same in brackets.
    let account = changed.then(|| {
        if trouble.is_empty() {
            "original configuration was put back".to_owned()
        } else {
            format!(
                "original configuration could only partly be put back: {}",
                trouble.join("; ")
            )
        }
    });
    let back = account.as_ref().map_or(String::new(), |said| format!(" The {said}."));
    let bracketed = account.map_or(String::new(), |said| format!(" (the {said})"));

    match host.start() {
        StartOutcome::Serving(StartReply::Accepted) if trouble.is_empty() && changed => {
            say(&format!(
                "apply: sshd {failed} ({first}); the original configuration was put back and sshd is running \
                 again. It does not accept {VARIABLE}."
            ));
            false
        }
        StartOutcome::Serving(StartReply::Accepted) if trouble.is_empty() => {
            say(&format!(
                "apply: sshd failed to start once ({first}); a second start worked and sshd is running. It \
                 accepts {VARIABLE}."
            ));
            true
        }
        StartOutcome::Serving(reply) => {
            let why = match reply {
                StartReply::Refused(reply) => format!("the service manager refused a second start ({reply})"),
                StartReply::Accepted => "not all of the files could be put back".to_owned(),
            };
            say(&format!(
                "apply: sshd {failed} ({first}); sshd is running now, but {why}, so which configuration it read \
                 cannot be told{bracketed}; run `ssh-broker apply` again"
            ));
            false
        }
        StartOutcome::Stopped { reply, exit } => {
            let second = second_ended(
                reply,
                format!(
                    "a second start was accepted and sshd stopped again (exit codes {} and {})",
                    exit.win32, exit.specific
                ),
            );
            say(&format!(
                "apply: sshd is NOT running: it {failed} ({first}), and {second}.{back} {START_BY_HAND}"
            ));
            false
        }
        StartOutcome::Exited { reply, code } => {
            let second = second_ended(
                reply,
                format!("a second start was accepted and sshd exited (code {code}) before it listened"),
            );
            say(&format!(
                "apply: sshd is NOT running: it {failed} ({first}), and {second}.{back} {START_BY_HAND}"
            ));
            false
        }
        StartOutcome::Paused(reply) => {
            say(&format!(
                "apply: sshd is paused: it {failed} ({first}), and a second start was {}; it is paused.{back} \
                 {CHECK_BY_HAND}",
                replied(&reply)
            ));
            false
        }
        StartOutcome::Unreadable { reply, cause } => {
            say(&format!(
                "apply: sshd may not be running: it {failed} ({first}), and a second start was {}; its state \
                 cannot be read ({cause}).{back} {CHECK_BY_HAND}",
                replied(&reply)
            ));
            false
        }
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
        host.discard_candidate();
    }
    put
}

#[cfg(test)]
#[path = "restart_tests.rs"]
mod restart_tests;
