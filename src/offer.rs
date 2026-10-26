//! The offer: what the shim does when a user has no reachable agent.
//!
//! Pure, with injected I/O. An interactive login on a local account is asked for the Windows
//! password once; the answer starts a background session, or the user gets the plain shell and a
//! line that says what it costs. Nothing here retries a logon, and nothing writes the password.

pub mod text;

use crate::password_entry::{Password, Step};

pub use text::non_interactive_notice;

/// How the login arrived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionKind {
    /// A terminal and no command.
    Pty,
    /// A command (exec, scp, sftp) or no terminal: never prompts.
    ExecOrNoTerminal,
}

/// Whether the account can be signed on from a password (local accounts only, ssh-broker#45).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountKind {
    Local,
    NotLocal,
}

/// Why the shim has no agent to relay into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Absence {
    /// Nothing listens at the user's socket location.
    NoAgent,
    /// The user has no profile, so no socket location yet.
    NoProfileYet,
    /// Anything else (access denied, a protocol error, a path that is too long): the fail-open
    /// message of the shim alone.
    Other,
}

/// The input is gone: the client disconnected or the console failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Disconnected;

#[derive(Debug)]
pub enum StartFailure {
    /// Windows refused; `reason` is its own text.
    Windows {
        reason: String,
    },
    /// Something of ours failed before or after the logon call.
    Internal {
        reason: String,
    },
    Disconnected,
}

pub trait OfferIo {
    /// Write to the terminal. Line ends are CRLF.
    fn write(&mut self, text: &str);
    /// Block until one entry step finishes.
    fn read_password(&mut self) -> Result<Step, Disconnected>;
    /// Sign the user on with `password` and start the background session. Returns once the
    /// logon call has; waiting for the agent to serve is the caller's.
    fn start_session(&mut self, password: &Password) -> Result<(), StartFailure>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Offered {
    /// A session was started; wait for it.
    Started,
    /// Carry on with the plain shell.
    Plain,
    /// The input is gone: do nothing more.
    Gone,
}

/// Run the offer for `user`. One password attempt per call.
pub fn offer(kind: SessionKind, account: AccountKind, absence: Absence, user: &str, io: &mut dyn OfferIo) -> Offered {
    if kind == SessionKind::ExecOrNoTerminal || absence == Absence::Other {
        return Offered::Plain;
    }
    if account == AccountKind::NotLocal {
        io.write(&text::not_local(user));
        io.write(text::COST_LINE);
        return Offered::Plain;
    }
    io.write(&text::prompt(user));
    loop {
        match io.read_password() {
            Err(Disconnected) => return Offered::Gone,
            Ok(Step::Continue) => {}
            Ok(Step::Empty) => io.write(text::EMPTY_PASSWORD_LINE),
            Ok(Step::Cancel) => {
                io.write(text::COST_LINE);
                return Offered::Plain;
            }
            Ok(Step::Submit(password)) => {
                return match io.start_session(&password) {
                    Ok(()) => Offered::Started,
                    Err(StartFailure::Disconnected) => Offered::Gone,
                    Err(StartFailure::Windows { reason }) => {
                        io.write(&text::windows_failure(&reason));
                        io.write(text::COST_LINE);
                        Offered::Plain
                    }
                    Err(StartFailure::Internal { reason }) => {
                        io.write(&text::start_failed(&reason));
                        io.write(text::COST_LINE);
                        Offered::Plain
                    }
                };
            }
        }
    }
}

#[cfg(test)]
#[path = "offer_tests.rs"]
mod offer_tests;
