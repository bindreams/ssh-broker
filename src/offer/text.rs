//! Every line the offer shows, in one place. Lines written to the pseudoterminal end in CRLF.

use crate::protocol::ElevationPolicy;

/// The cost of the plain shell, after Ctrl+C, a failed sign-in or a non-local account.
pub const COST_LINE: &str =
    "ssh-broker: starting a plain shell, without DPAPI, a loaded profile or symlink traversal.\r\n";

/// Shown when the session just started lives in a job that closes with the connection.
pub const SESSION_ENDS_WITH_CONNECTION_LINE: &str = "ssh-broker: this connection cannot let the Windows session outlive it, so the session ends when you disconnect.\r\n";

/// Shown when the session just started lives in a job that may close with the connection.
pub const SESSION_MAY_END_WITH_CONNECTION_LINE: &str = "ssh-broker: this connection may not let the Windows session outlive it; if so, the session ends when you disconnect.\r\n";

/// The prompt: the owner's sentence, then the sentence that names the way out.
pub fn prompt(user: &str) -> String {
    format!(
        "ssh-broker: {user} has no Windows session on this PC. Enter your Windows password to start one. \
         (The password goes to Windows to sign you in; ssh-broker does not store it.) \
         Press Ctrl+C for a plain shell.\r\n"
    )
}

/// Enter on an empty line.
pub const EMPTY_PASSWORD_LINE: &str = "ssh-broker: empty passwords are not supported yet (ssh-broker#45). \
     Enter a password, or press Ctrl+C for a plain shell.\r\n";

/// Windows refused the sign-in; `reason` is Windows' own text.
pub fn windows_failure(reason: &str) -> String {
    format!("ssh-broker: Windows did not sign you in: {reason}\r\n")
}

pub fn not_local(user: &str) -> String {
    format!(
        "ssh-broker: {user} is not a local account; starting a session from a password is not supported yet \
         (ssh-broker#45).\r\n"
    )
}

/// The one stderr line a session without a terminal gets. `exe` is the installed exe's full path:
/// `apply` does not put its directory on `PATH`.
pub fn non_interactive_notice(user: &str, exe: &str) -> String {
    format!(
        "ssh-broker: {user} has no Windows session on this PC, so this runs without DPAPI, a loaded profile or \
         symlink traversal. Use ssh -t to be asked for your password, or run {exe} auto-login on once."
    )
}

/// The stderr line for a login whose own token is an administrator's with elevation removed
/// (`account::Elevation::Filtered`): it cannot reach the account's agent, which runs elevated.
pub const FILTERED_SHIM_NOTICE: &str = "ssh-broker: this login is an administrator's with elevation removed and cannot reach the account's agent, which runs elevated, so this runs without DPAPI, a loaded profile or symlink traversal.";

/// What a login with an unrecognised `SSH_BROKER_ELEVATION` is told on stderr before anything runs. No line
/// terminator: the shim ends the line.
pub fn unknown_elevation(value: &str) -> String {
    format!(
        "ssh-broker: SSH_BROKER_ELEVATION is {value:?}, which is none of never, prompt, auto-approve or always \
         (lower case, nothing around it). Nothing was run."
    )
}

/// What a login that asked for `SSH_BROKER_ELEVATION=always` where this account's sessions cannot be elevated
/// is told, in two parts so that the agent, whose failure reply writes `ssh-broker: {what}: {cause}` and its
/// own line break, and the shim ([`always_below_high`]) say one sentence.
pub const ALWAYS_BELOW_HIGH_WHAT: &str =
    "this login asked for SSH_BROKER_ELEVATION=always, and this account's sessions cannot be elevated here";
/// The cause half of [`ALWAYS_BELOW_HIGH_WHAT`].
pub const ALWAYS_BELOW_HIGH_CAUSE: &str = "its agent does not run at High. Nothing was run.";

/// The whole line the shim prints when it refuses a login that asked for `always` below High.
pub fn always_below_high() -> String {
    format!("ssh-broker: {ALWAYS_BELOW_HIGH_WHAT}: {ALWAYS_BELOW_HIGH_CAUSE}\r\n")
}

/// What a login that asked for `always` is told when the level of this process cannot be read, so whether it can
/// be given an elevated session is not known: the one thing it must not be told is to ask for `always`.
/// Split into what and cause as [`ALWAYS_BELOW_HIGH_WHAT`] is.
pub const ALWAYS_LEVEL_UNREADABLE_WHAT: &str = "this login asked for SSH_BROKER_ELEVATION=always, and it cannot be told whether an elevated session can be given, so nothing was run";

/// The whole line the shim prints when it refuses a login that asked for `always`, because the level of its own
/// token cannot be read; `cause` is why.
pub fn always_level_unreadable(cause: &str) -> String {
    format!("ssh-broker: {ALWAYS_LEVEL_UNREADABLE_WHAT}: {cause}\r\n")
}

/// The whole line the shim prints when it refuses a login that asked for `always`, whose own token is an
/// administrator's with elevation removed (`account::Elevation::Filtered`): no level of its shim reaches an
/// elevated session.
pub fn always_filtered() -> String {
    "ssh-broker: this login asked for SSH_BROKER_ELEVATION=always, and its own token is an administrator's with \
     elevation removed, so it cannot be given an elevated session. Nothing was run.\r\n"
        .to_owned()
}

/// What a login that asked for a level is told when its unelevated session cannot be made: nothing was run, and
/// that a login that asked for none is not refused. Said by the agent and by the shim, so it is worded for
/// both: the agent hands such a login back, and the shim runs it. Split into what and cause as
/// [`ALWAYS_BELOW_HIGH_WHAT`] is.
pub const UNELEVATED_UNAVAILABLE_WHAT: &str = "could not prepare an unelevated session, so nothing was run (a login that leaves SSH_BROKER_ELEVATION unset is not refused)";

/// The `what` of a login that `asked` for a level and cannot be stepped down: for `always` the level of the process
/// could not be read ([`ALWAYS_LEVEL_UNREADABLE_WHAT`]), which is the only way it fails; for any other level the
/// unelevated session could not be made ([`UNELEVATED_UNAVAILABLE_WHAT`]).
pub fn unelevated_unavailable_what(asked: Option<ElevationPolicy>) -> &'static str {
    match asked {
        Some(ElevationPolicy::Always) => ALWAYS_LEVEL_UNREADABLE_WHAT,
        _ => UNELEVATED_UNAVAILABLE_WHAT,
    }
}

/// The line the shim prints when a login that `asked` for a level cannot be stepped down; `cause` is why.
pub fn unelevated_unavailable(asked: Option<ElevationPolicy>, cause: &str) -> String {
    format!("ssh-broker: {}: {cause}", unelevated_unavailable_what(asked))
}

/// The notice for a login that set nothing and could not be stepped down: its session has the token sshd gave it,
/// which for an administrator is elevated, and a login that sets `SSH_BROKER_ELEVATION` to `never`, `prompt` or
/// `auto-approve` is refused instead. `cause` is why the unelevated session could not be made. The shim says it
/// when it runs such a session itself. No line terminator.
pub fn unelevated_fallback(cause: &str) -> String {
    format!(
        "ssh-broker: could not prepare an unelevated session ({cause}), so this session has the token sshd gave this \
         login, which for an administrator is elevated. A login that sets SSH_BROKER_ELEVATION to never, prompt or \
         auto-approve is refused instead."
    )
}

/// The clause every line uses to say a token's elevation could not be read; `cause` is why.
pub fn elevation_unreadable_clause(cause: &str) -> String {
    format!("cannot tell how elevated this login is ({cause})")
}

/// The stderr line for a login whose token's elevation cannot be read: no session is offered, since its
/// logon depends on that elevation.
pub fn elevation_unreadable(cause: &str) -> String {
    format!(
        "ssh-broker: {}, so no session is offered and this runs without DPAPI, a loaded profile or symlink \
         traversal.",
        elevation_unreadable_clause(cause)
    )
}

/// What an administrator's unelevated process (`account::Elevation::Filtered`) is told when it asks for the
/// agent that serves its folder and finds none: the account's agent runs elevated and serves the elevated
/// folder, so the plain one it looks in has no `agent.sock`. A clause, for `verify`'s row and for `logout`'s line
/// when neither socket of the plain folder is served.
pub const FILTERED_LOOKS_ELSEWHERE: &str = "this account is an administrator and its agent serves elevated processes: run this from an elevated prompt or from an SSH login that asked for SSH_BROKER_ELEVATION=always";

/// Told when a High login lacks `SeImpersonatePrivilege`, which `CreateProcessWithTokenW` needs; the way
/// out is worded as in the batch-right sentence, and granting the right is not suggested.
pub fn impersonate_right_missing(user: &str) -> String {
    format!(
        "ssh-broker: this login is elevated, and starting an elevated session for {user} from a password needs the \
         right \"Impersonate a client after authentication\", which this login does not hold (a logon at the desktop \
         starts one without it; SSH logins use it while it runs)."
    )
}

/// The sentence for a background agent that ended before it served. 64 to 69 are the agent's own
/// refusals (see `agent_background::Refusal`); it has no console, so its exit code is all it can say.
/// `logs` is the folder of its log, if it could be found: without it the sentence has no pointer.
pub fn agent_ended(code: u32, logs: Option<&std::path::Path>) -> String {
    let sentence = match code {
        0 => "another agent took your session but did not answer.".to_string(),
        64 => "the background session started for a different account than yours and refused to serve.".to_string(),
        65 => "the agent refused to run in the session it was started in.".to_string(),
        66 => "the background session started, but your profile has no room for ssh-broker's socket. A profile path \
               over the 107-byte AF_UNIX limit cannot hold it."
            .to_string(),
        67 => "the background session started, but its ssh-broker folder could not be made or was not safe to use."
            .to_string(),
        68 => "the agent refused to run: its token is an administrator's with elevation removed, and an \
               administrator's agent runs elevated or not at all."
            .to_string(),
        69 => "the agent could not read how elevated its own token is, so it refused to serve.".to_string(),
        other => match logs {
            Some(logs) => format!(
                "the agent exited with code {other}; see the agent.log files in {}",
                logs.display()
            ),
            None => format!("the agent exited with code {other}"),
        },
    };
    format!("ssh-broker: {sentence}\r\n")
}

/// The background session could not be started or waited for, for a reason that is ours and not
/// Windows' (those use [`windows_failure`]).
pub fn start_failed(reason: &str) -> String {
    format!("ssh-broker: the background session did not start: {reason}\r\n")
}

/// The line for a login that finds the folder ssh-broker keeps the session's files in refused (a link
/// on the way to it, an owner that is not the user's, an ACL that is not the private one). `cause`
/// names the folder, which check failed and what to do about it. No session is offered, and the login
/// goes on in a plain shell.
pub fn folder_refused(cause: &str) -> String {
    format!("ssh-broker: no session is offered, because its folder cannot be used: {cause}")
}

/// The stated limit of CONTRIBUTING's paragraph "The walk holds the private folder": another program
/// holds the broker's own folder open in a way that keeps the broker from using it, and a walk that
/// cannot hold the folder does not go on. It does not wait for the holder; the next login, once that
/// program has let go, is brokered again.
pub fn folder_held(folder: &std::path::Path) -> String {
    format!(
        "{} is held open by another program in a way that keeps ssh-broker from using it (with the right to \
         delete or rename it, or without letting others read it), so it cannot be used while that lasts. The next \
         login, once that program has let go, is brokered again",
        folder.display()
    )
}
