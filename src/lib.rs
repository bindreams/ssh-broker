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
pub mod acl;
pub mod afunix;
pub mod agent;
#[cfg(windows)]
pub mod conpty;
#[cfg(windows)]
pub mod pipes;
pub mod protocol;
pub mod provision;
pub mod relay;
pub mod route;
pub mod shim;
#[cfg(windows)]
pub mod shim_pty;
pub mod vtinput;
#[cfg(windows)]
pub mod winutil;

pub use route::{Route, route};
