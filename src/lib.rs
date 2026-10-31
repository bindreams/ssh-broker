//! ssh-broker: give a Windows SSH session the environment of a local console session.
//!
//! A key-authenticated SSH session on Windows gets a *network* logon in session 0, which
//! costs it DPAPI, the loaded user profile, and symlink traversal (RedirectionGuard). This
//! crate relays the shell from a real interactive session instead: the [`shim`] is installed
//! as sshd's `DefaultShell`, the [`agent`] runs inside the interactive session hosting the
//! shell in a pseudoconsole ([`conpty`]), and the two speak a length-prefixed frame
//! [`protocol`] over an ACL-gated AF_UNIX socket ([`afunix`], [`acl`]).
//!
//! The functionality lives here rather than in the binary so that it is reachable from tests
//! and from other consumers on every host platform. The binary is a thin argv dispatcher over
//! [`route`].

#[cfg(windows)]
pub mod account;
#[cfg(windows)]
pub mod acl;
pub mod afunix;
pub mod agent;
#[cfg(windows)]
pub mod agent_background;
#[cfg(windows)]
pub mod agent_lock;
#[cfg(windows)]
pub mod autologin;
pub mod cmdline;
#[cfg(test)]
#[path = "../tests/common/command_corpus.rs"]
mod command_corpus;
#[cfg(all(windows, test))]
#[path = "../tests/common/command_line_probe.rs"]
mod command_line_probe;
#[cfg(windows)]
pub mod conpty;
#[cfg(windows)]
pub mod console_modes;
#[cfg(windows)]
pub mod console_prompt;
pub mod fallback_file;
#[cfg(windows)]
pub mod filelog;
#[cfg(windows)]
pub mod hangup;
#[cfg(windows)]
pub mod logon;
#[cfg(windows)]
pub mod logout;
pub mod offer;
pub mod password_entry;
#[cfg(windows)]
pub mod pipes;
pub mod protocol;
pub mod provision;
pub mod relay;
pub mod route;
pub mod secret;
pub mod shell;
pub mod shim;
#[cfg(windows)]
pub mod shim_offer;
#[cfg(windows)]
pub mod shim_pty;
pub mod socket_loc;
#[cfg(windows)]
pub mod socket_watch;
#[cfg(windows)]
pub mod starting_agent;
#[cfg(all(windows, test))]
mod test_support;
#[cfg(windows)]
pub mod userdir;
pub mod vtinput;
#[cfg(windows)]
pub mod winutil;

pub use route::{Route, route};
