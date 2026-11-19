//! The ids the agent gives its sessions (see [`SESSION_VARIABLE`](crate::protocol::SESSION_VARIABLE)).

use crate::protocol::SessionId;
use windows::Win32::Security::Cryptography::{BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom};

/// A new [`SessionId`] from the system's random generator.
pub(super) fn new_id() -> anyhow::Result<SessionId> {
    let mut bytes = [0u8; 16];
    // SAFETY: `bytes` is a live buffer of the length passed; no algorithm handle is used with the flag that
    // asks for the system's preferred generator.
    let status = unsafe { BCryptGenRandom(None, &mut bytes, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
    status
        .ok()
        .map_err(|e| anyhow::Error::new(e).context("BCryptGenRandom for a session id"))?;
    Ok(SessionId::from_bytes(bytes))
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod session_tests;
