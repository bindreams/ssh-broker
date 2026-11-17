//! Every line the offer shows, in one place. Lines written to the pseudoterminal end in CRLF.

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

/// The one stderr line a login whose own token is an administrator's with elevation removed gets
/// (`account::Elevation::Filtered`): the account's session serves elevated logins only, so there is no
/// offer and no wait, and the shell is a plain one.
pub const FILTERED_SHIM_NOTICE: &str = "ssh-broker: this account's session serves elevated logins only, and this login is an administrator's with elevation removed, so this runs without DPAPI, a loaded profile or symlink traversal.";

/// The sentence for a background agent that ended before it served. 64 to 68 are the agent's own
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
               administrator's session runs elevated or not at all."
            .to_string(),
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
