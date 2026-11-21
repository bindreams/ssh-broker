//! provision::sshd_config::restart — restarting the sshd service so that it reads the files, deciding only on
//! what the service manager says.

use super::configure::SshdHost;
use super::{CHECK_SSHD, DROP_IN_NAME, VARIABLE};
use crate::provision::schtasks::INSTALL_SSHD_TASK;

/// The settled states of the sshd service.
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
    /// manager says running before that.
    Serving(StartReply),
    /// The service's process, which the service manager had reported running, exited with `code` without being
    /// seen to listen. With `unseen` `None` the service manager has seen the exit: it no longer says the service
    /// runs in that process, so a start sent now is not refused for it. With `unseen` set it is not known that it
    /// has, and a start sent now may be refused.
    Exited {
        reply: StartReply,
        code: u32,
        /// Why whether the service manager has seen the exit could not be read; `None` when it has.
        unseen: Option<String>,
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
/// settled in. A stopped service is not started, and a paused one, one whose state cannot be read and one that did
/// not stop are left alone. A start that the service manager accepted and that ended before sshd listened (it
/// settled stopped, or the process exited) is the only evidence that sshd could not run the files: only then is
/// what this run changed (`before`) put back, and sshd started again. After a stop that was not seen, a refused
/// start after which the service reads stopped or its process was seen to have exited is followed by one more
/// start, the first sent after a state was read.
pub fn restart(host: &mut dyn SshdHost, say: &mut dyn FnMut(&str), before: &Before) -> bool {
    say(
        "install: restarting sshd; install waits for the service manager at each step, and after a start for sshd to \
         listen or exit",
    );

    match host.settled() {
        Ok(ServiceState::Running) => {}
        Ok(ServiceState::Stopped) => {
            say("install: sshd is not running, so it was not started; it reads the change when it is");
            return true;
        }
        Ok(ServiceState::Paused) => {
            say(
                "install: the sshd service is paused, so it was not restarted; resume it (`sc continue sshd`) and run \
                 `ssh-broker install` again",
            );
            return false;
        }
        Err(e) => {
            say(&format!(
                "install: the sshd service's state cannot be read ({e:#}), so it was not restarted; run \
                 `ssh-broker install` again to restart it"
            ));
            return false;
        }
    }

    // What is not known of the stop: `None` when `Stopped` was read, else a clause with why it was not seen; after
    // the extra start below, that clause and the refused start. Every row after the starts says it.
    let mut unanswered_said = false;
    let mut unseen = match host.stop(&mut |reply| {
        unanswered_said = true;
        say(&stop_unanswered(reply));
    }) {
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
                "install: no stop was sent to sshd ({e:#}), so it was not restarted. Its state was last read as \
                 running, before that, with its earlier configuration, so it does not accept {VARIABLE} yet; run \
                 `ssh-broker install` again to restart it"
            ));
            return false;
        }
    };
    // "sshd was stopped" is said only of a stop that was read.
    let mut stopped = unseen.clone().unwrap_or_else(|| "sshd was stopped".to_owned());
    // The wait that was announced has ended: say what it came to before the start's own wait.
    if unanswered_said {
        say(&format!("install: {stopped}; starting sshd"));
    }

    // Whether sshd is known to have stopped (seen, or read stopped after the extra start below). It decides what a
    // start's reply means; `unseen` only says what is not known.
    let mut state_read = unseen.is_none();
    let mut first = host.start();
    if let Some(cause) = &unseen
        && let Some(read) = refused_then_stopped(&first)
    {
        stopped = format!("{cause}; {read}");
        unseen = Some(stopped.clone());
        state_read = true;
        say(&format!("install: {stopped}; starting sshd"));
        first = host.start();
    }
    match first {
        StartOutcome::Serving(StartReply::Accepted) => {
            say(&match (&unseen, state_read) {
                (Some(unseen), false) => format!(
                    "install: sshd restarted; it accepts {VARIABLE} ({unseen}, and the service manager accepted a \
                     start)"
                ),
                _ => format!("install: sshd restarted; it accepts {VARIABLE}"),
            });
            true
        }
        StartOutcome::Serving(StartReply::Refused(reply)) if state_read => {
            say(&format!(
                "install: sshd restarted (the service manager had started it again: {reply}); it accepts {VARIABLE}"
            ));
            true
        }
        StartOutcome::Serving(StartReply::Refused(reply)) => {
            say(&format!(
                "install: sshd is running and whether it restarted cannot be told: {stopped}, and a start was \
                 refused ({reply}); `ssh-broker install` restarts it if it has not read the change"
            ));
            false
        }
        StartOutcome::Stopped {
            reply: StartReply::Refused(reply),
            ..
        } => {
            say(&format!(
                "install: sshd is NOT running: {stopped}, and the service manager refused to start it ({reply}). \
                 {START_BY_HAND}"
            ));
            false
        }
        StartOutcome::Exited {
            reply: StartReply::Refused(reply),
            code,
            unseen: unread,
        } => {
            let unread = unread.map_or(String::new(), |cause| format!(" {}", unseen_exit(&cause)));
            say(&format!(
                "install: sshd is not serving: {stopped}, the service manager refused a start ({reply}), and the sshd \
                 it reported running exited (code {code}) without being seen to listen{unread}. {CHECK_SSHD}"
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
        StartOutcome::Exited {
            code, unseen: unread, ..
        } => {
            let exited = exited_before_listening(code, unread.as_deref());
            let first = match &unseen {
                None => exited,
                Some(unseen) => format!("{unseen}; {exited}"),
            };
            start_again(host, say, before, &first)
        }
        StartOutcome::Paused(reply) => {
            say(&format!(
                "install: {stopped} and a start was {}; it is paused. {CHECK_BY_HAND}",
                replied(&reply)
            ));
            false
        }
        StartOutcome::Unreadable { reply, cause } => {
            say(&format!(
                "install: {stopped} and a start was {}; its state cannot be read ({cause}). {CHECK_BY_HAND}",
                replied(&reply)
            ));
            false
        }
    }
}

const START_BY_HAND: &str = "Start it at this PC: `net start sshd`.";
const CHECK_BY_HAND: &str = "Check it at this PC: `sc query sshd`.";

/// What is said before the wait for an sshd that did not answer the stop in time (`reply` is the service
/// manager's answer): that the wait has no time limit, and how to end it.
fn stop_unanswered(reply: &str) -> String {
    format!(
        "install: sshd did not answer the stop in time ({reply}) and the service manager says it is still running; \
         install waits, with no time limit, for that sshd to exit, and then starts it. To stop waiting, end the task \
         {INSTALL_SSHD_TASK} (`schtasks /End /TN {INSTALL_SSHD_TASK}`, elevated) and run `ssh-broker install` again; \
         nothing then starts an sshd that exits later. {CHECK_SSHD}"
    )
}

/// What is said when sshd could not be stopped: why, and the state it is in.
fn not_stopped(why: &str, state: &str) -> String {
    format!(
        "install: sshd could not be stopped ({why}) and is {state} with its earlier configuration, so it does not \
         accept {VARIABLE} yet; run `ssh-broker install` again to restart it"
    )
}

/// A start the service manager accepted and then saw stop, in a sentence.
fn stopped_again(exit: ExitCodes) -> String {
    format!(
        "the start was accepted and sshd stopped again (exit codes {} and {})",
        exit.win32, exit.specific
    )
}

/// A start the service manager accepted whose sshd exited before it listened, in a sentence. `unseen` is why
/// whether the service manager had seen the exit could not be read, when it could not.
fn exited_before_listening(code: u32, unseen: Option<&str>) -> String {
    let said = format!("the start was accepted and sshd exited (code {code}) before it listened");
    match unseen {
        None => said,
        Some(cause) => format!("{said} {}", unseen_exit(cause)),
    }
}

/// Why whether the service manager had seen an exit could not be read, in brackets.
fn unseen_exit(cause: &str) -> String {
    format!("(whether the service manager had seen it exit could not be read: {cause})")
}

/// A start the service manager refused, after which the service reads stopped or its process was seen to have
/// exited, in a clause; `None` for any other outcome.
fn refused_then_stopped(outcome: &StartOutcome) -> Option<String> {
    match outcome {
        StartOutcome::Stopped {
            reply: StartReply::Refused(reply),
            ..
        } => Some(format!(
            "a start was refused ({reply}), and the service manager then said sshd is stopped"
        )),
        StartOutcome::Exited {
            reply: StartReply::Refused(reply),
            code,
            unseen: None,
        } => Some(format!(
            "a start was refused ({reply}), and the sshd the service manager reported running exited (code {code})"
        )),
        _ => None,
    }
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

    say(&format!(
        "install: sshd {failed} ({first}); starting it again{bracketed}"
    ));
    match host.start() {
        StartOutcome::Serving(StartReply::Accepted) if trouble.is_empty() && changed => {
            say(&format!(
                "install: sshd {failed} ({first}); the original configuration was put back and sshd is running \
                 again. It does not accept {VARIABLE}."
            ));
            false
        }
        StartOutcome::Serving(StartReply::Accepted) if trouble.is_empty() => {
            say(&format!(
                "install: sshd failed to start once ({first}); a second start worked and sshd is running. It \
                 accepts {VARIABLE}."
            ));
            true
        }
        StartOutcome::Serving(reply) => {
            let why = second_ended(reply, "not all of the files could be put back".to_owned());
            say(&format!(
                "install: sshd {failed} ({first}); sshd is running now, but {why}, so which configuration it read \
                 cannot be told{bracketed}; run `ssh-broker install` again"
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
                "install: sshd is NOT running: it {failed} ({first}), and {second}.{back} {START_BY_HAND}"
            ));
            false
        }
        StartOutcome::Exited { reply, code, .. } => {
            let second = second_ended(
                reply,
                format!("a second start was accepted and sshd exited (code {code}) before it listened"),
            );
            say(&format!(
                "install: sshd is NOT running: it {failed} ({first}), and {second}.{back} {START_BY_HAND}"
            ));
            false
        }
        StartOutcome::Paused(reply) => {
            say(&format!(
                "install: sshd is paused: it {failed} ({first}), and a second start was {}; it is paused.{back} \
                 {CHECK_BY_HAND}",
                replied(&reply)
            ));
            false
        }
        StartOutcome::Unreadable { reply, cause } => {
            say(&format!(
                "install: sshd may not be running: it {failed} ({first}), and a second start was {}; its state \
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
