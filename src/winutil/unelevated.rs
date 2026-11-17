//! The token a session's program is started with when the session is to be unelevated.

use anyhow::Context;
use windows::Win32::Foundation::{HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows::Win32::Security::{
    CreateRestrictedToken, GetLengthSid, LUA_TOKEN, PSID, SID_AND_ATTRIBUTES, SetTokenInformation,
    TOKEN_ADJUST_DEFAULT, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
    TokenIntegrityLevel,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::PCWSTR;

use super::{OwnedHandle, SE_GROUP_INTEGRITY};
use crate::account::{INTEGRITY_MEDIUM, integrity_of};
use crate::acl::{Sid, WellKnown, set_token_default_dacl};

/// A primary token for a session's program when the session is unelevated: this process's token with what
/// UAC takes from an administrator's (`LUA_TOKEN`: `Administrators` becomes deny-only, and the privileges
/// but the five a standard user has go), at Medium integrity or the process's own level when that is lower,
/// and with the default DACL UAC's filtered token has. Same logon session, so the profile, HKCU and DPAPI
/// are the process's own.
///
/// The default DACL is not optional. The elevated token's names `Administrators`, which is now deny-only,
/// so the objects the child's console is made with have no usable ACE for the user, and a child on pipes
/// dies at start (`0xC0000142`; measured).
///
/// Start a child with it through [`super::spawn_suspended`].
pub struct UnelevatedToken(OwnedHandle);

impl UnelevatedToken {
    /// The token made from this process's own. It opens the process token itself: making a token from it
    /// and setting the label and default DACL need more access than the `TOKEN_QUERY` of
    /// [`own_token`](super::own_token). The restricted token has the access of the handle it is made from,
    /// so it is changed and used directly.
    pub fn of_this_process() -> anyhow::Result<UnelevatedToken> {
        let mut own = HANDLE::default();
        // SAFETY: a valid out-pointer; the handle is closed by `OwnedHandle`. `TOKEN_QUERY` is for the user and
        // the logon SID read below, `TOKEN_ADJUST_DEFAULT` for the label and the default DACL.
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT,
                &mut own,
            )
        }
        .context("open the process token")?;
        let own = OwnedHandle(own);

        let mut made = HANDLE::default();
        // SAFETY: valid handles; the new token is closed by `OwnedHandle`. A token made from a primary one is
        // primary.
        unsafe { CreateRestrictedToken(own.0, LUA_TOKEN, None, None, None, &mut made) }
            .context("make the restricted token")?;
        let token = OwnedHandle(made);

        lower_integrity(token.0, INTEGRITY_MEDIUM).context("set the token's integrity level")?;
        let sddl = default_dacl_sddl(own.0).context("make the token's default DACL")?;
        set_token_default_dacl(token.0, &sddl).context("set the token's default DACL")?;
        Ok(UnelevatedToken(token))
    }

    /// The token, for `CreateProcessAsUserW`.
    pub(super) fn handle(&self) -> HANDLE {
        self.0.0
    }
}

/// The default DACL of UAC's filtered token for the account of `token`: Full Control for the user and SYSTEM,
/// execute and read for the logon session.
fn default_dacl_sddl(token: HANDLE) -> anyhow::Result<String> {
    let user = Sid::of_token(token)?.to_sddl()?;
    let system = Sid::well_known(WellKnown::System)?.to_sddl()?;
    let logon = Sid::logon_of_token(token)?.to_sddl()?;
    Ok(format!("D:(A;;GA;;;{user})(A;;GA;;;{system})(A;;GXGR;;;{logon})"))
}

/// Set the integrity label of `token` to the level `rid` ([`INTEGRITY_MEDIUM`]) when it is above it, and
/// leave it when it is at or below: a raise needs a privilege and fails. Lowering needs
/// `TOKEN_ADJUST_DEFAULT` and `TOKEN_QUERY`, and no privilege.
fn lower_integrity(token: HANDLE, rid: u32) -> anyhow::Result<()> {
    if integrity_of(token)? <= rid {
        return Ok(());
    }
    let label: Vec<u16> = format!("S-1-16-{rid}")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut sid = PSID::default();
    // SAFETY: a NUL-terminated string and a valid out-pointer; the SID is freed after the call that reads it.
    unsafe { ConvertStringSidToSidW(PCWSTR(label.as_ptr()), &mut sid) }.context("make the label's SID")?;
    let mandatory = TOKEN_MANDATORY_LABEL {
        Label: SID_AND_ATTRIBUTES {
            Sid: sid,
            Attributes: SE_GROUP_INTEGRITY,
        },
    };
    // SAFETY: `mandatory` and the SID it points to are live; the size is the structure's and the SID's, which
    // is what the call reads.
    let set = unsafe {
        SetTokenInformation(
            token,
            TokenIntegrityLevel,
            (&raw const mandatory).cast(),
            std::mem::size_of::<TOKEN_MANDATORY_LABEL>() as u32 + GetLengthSid(sid),
        )
    };
    // SAFETY: the allocation made by the conversion above, freed once.
    let _ = unsafe { LocalFree(Some(HLOCAL(sid.0))) };
    set.context("set the integrity label")
}

#[cfg(test)]
#[path = "unelevated_tests.rs"]
mod unelevated_tests;
