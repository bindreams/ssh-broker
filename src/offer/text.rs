//! Every line the offer shows, in one place. Lines written to the pseudoterminal end in CRLF.

/// The cost of the plain shell, after Ctrl+C, a failed sign-in or a non-local account.
pub const COST_LINE: &str =
    "ssh-broker: starting a plain shell, without DPAPI, a loaded profile or symlink traversal.\r\n";

/// Shown when the session just started lives in a job that closes with the connection.
pub const SESSION_ENDS_WITH_CONNECTION_LINE: &str = "ssh-broker: this connection cannot let the Windows session outlive it, so the session ends when you disconnect.\r\n";

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

/// The sentence for a background agent that ended before it served. 64 to 67 are the agent's own
/// refusals (see `agent_background::Refusal`); it has no console, so its exit code is all it can say.
/// `logs` is the folder of its log.
pub fn agent_ended(code: u32, logs: &std::path::Path) -> String {
    let sentence = match code {
        0 => "another agent took your session but did not answer.".to_string(),
        64 => "the background session started for a different account than yours and refused to serve.".to_string(),
        65 => "the agent refused to run in the session it was started in.".to_string(),
        66 => "the background session started, but your profile has no room for ssh-broker's socket. A profile path \
               over the 107-byte AF_UNIX limit cannot hold it."
            .to_string(),
        67 => "the background session started, but its ssh-broker folder was not safe to use.".to_string(),
        other => format!(
            "the agent exited with code {other}; see the agent.log files in {}",
            logs.display()
        ),
    };
    format!("ssh-broker: {sentence}\r\n")
}

/// The background session could not be started or waited for, for a reason that is ours and not
/// Windows' (those use [`windows_failure`]).
pub fn start_failed(reason: &str) -> String {
    format!("ssh-broker: the background session did not start: {reason}\r\n")
}
