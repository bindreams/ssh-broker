//! account: who the invoking token is, and whether a password can start a session for it.
//!
//! The account is the SID of the process token, resolved to a name by `LookupAccountSidW`. It is
//! never read from the environment, a typed name or an argument: `USERNAME` is whatever the
//! caller set, and a password prompt for a name the caller chose would sign a different account on.

use std::mem::offset_of;

use anyhow::Context;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::{
    GetSidSubAuthority, GetSidSubAuthorityCount, IsWellKnownSid, PSID, SID_AND_ATTRIBUTES, TOKEN_GROUPS,
    TOKEN_MANDATORY_LABEL, TokenGroups, TokenIntegrityLevel, WinBuiltinAdministratorsSid,
};
use windows::Win32::System::WindowsProgramming::GetComputerNameW;
use windows::core::PWSTR;

use crate::acl::Sid;
pub use crate::offer::AccountKind;
use crate::winutil::{own_token, token_information};

/// An account of this PC, as ssh-broker names it in prompts, logon calls and tasks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalAccount {
    /// The account name without its domain, as the account database spells it.
    pub name: String,
    /// The SID in string form (`S-1-5-21-...`).
    pub sid: String,
    pub kind: AccountKind,
}

/// The account the process token belongs to.
pub fn current_account() -> anyhow::Result<LocalAccount> {
    account_of(&Sid::current_user()?)
}

/// The account called `name` (`user`, `PC\user`), by its SID and the name the database holds for it:
/// for `auto-login on <account>`, typed by an administrator.
pub fn account_named(name: &str) -> anyhow::Result<LocalAccount> {
    account_of(&Sid::lookup(name).with_context(|| format!("find the account {name}"))?)
}

fn account_of(sid: &Sid) -> anyhow::Result<LocalAccount> {
    let (domain, name) = sid.account()?;
    Ok(LocalAccount {
        name,
        sid: sid.to_sddl()?,
        kind: classify(&domain, &computer_name()?),
    })
}

/// Whether an account whose domain is `domain` is local to the PC named `machine`. Case-insensitive;
/// an empty domain is not provably local.
pub fn classify(domain: &str, machine: &str) -> AccountKind {
    if !domain.is_empty() && domain.to_lowercase() == machine.to_lowercase() {
        AccountKind::Local
    } else {
        AccountKind::NotLocal
    }
}

/// The NetBIOS name of this PC: the domain `LookupAccountSidW` gives its local accounts.
pub fn computer_name() -> anyhow::Result<String> {
    let mut len = 0u32;
    // SAFETY: a null buffer is the documented size probe; it fails with the length needed.
    let _ = unsafe { GetComputerNameW(None, &mut len) };
    anyhow::ensure!(len > 0, "GetComputerNameW size probe returned 0");
    let mut buf = vec![0u16; len as usize];
    // SAFETY: `buf` holds `len` units, which is what the call is told.
    unsafe { GetComputerNameW(Some(PWSTR(buf.as_mut_ptr())), &mut len) }.context("GetComputerNameW")?;
    Ok(String::from_utf16_lossy(&buf[..len as usize]))
}

/// The relative ids of the mandatory integrity labels (`S-1-16-<rid>`), as [`integrity_of`] gives them.
pub const INTEGRITY_LOW: u32 = 0x1000;
pub const INTEGRITY_MEDIUM: u32 = 0x2000;
pub const INTEGRITY_HIGH: u32 = 0x3000;
pub const INTEGRITY_SYSTEM: u32 = 0x4000;
/// `TOKEN_GROUPS` attribute bits (winnt.h).
const SE_GROUP_ENABLED: u32 = 0x4;
const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x10;

/// How much of an administrator's power a token carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Elevation {
    /// An administrator's full token: `Administrators` enabled, integrity High or above.
    Full,
    /// An administrator account's token cut down, as UAC gives a non-elevated process: the
    /// `Administrators` group is deny-only or disabled, or the integrity level is below High.
    Filtered,
    /// A token of an account that is not an administrator.
    Standard,
}

/// What a token's `BUILTIN\Administrators` entry says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdministratorsSid {
    /// Present and enabled: it grants access.
    Enabled,
    /// Present but only able to deny (the filtered token of a UAC split), or disabled.
    DenyOnly,
    /// Not in the token: the account is not an administrator.
    Absent,
}

/// The elevation of a token with `administrators` and the relative id `integrity_rid` of its
/// integrity label ([`INTEGRITY_MEDIUM`], [`INTEGRITY_HIGH`]).
pub fn classify_elevation(administrators: AdministratorsSid, integrity_rid: u32) -> Elevation {
    match administrators {
        AdministratorsSid::Absent => Elevation::Standard,
        AdministratorsSid::Enabled if integrity_rid >= INTEGRITY_HIGH => Elevation::Full,
        AdministratorsSid::Enabled | AdministratorsSid::DenyOnly => Elevation::Filtered,
    }
}

/// The relative id of the integrity label of `token` ([`INTEGRITY_MEDIUM`], [`INTEGRITY_HIGH`]), which
/// needs `TOKEN_QUERY`.
pub fn integrity_of(token: HANDLE) -> anyhow::Result<u32> {
    let buf = token_information(token, TokenIntegrityLevel).context("read the token's integrity level")?;
    // SAFETY: a `TOKEN_MANDATORY_LABEL` is a SID pointer and an integer.
    let label = unsafe { buf.header::<TOKEN_MANDATORY_LABEL>() }.context("read the token's integrity label")?;
    let sid = buf.sid(label.Label.Sid).context("read the token's integrity label")?;
    // SAFETY: `sid` is a SID `buf` holds whole, and `buf` lives to the end of this function.
    unsafe { rid_of_label(sid) }
}

/// The last sub-authority of the label SID `sid`, which is the relative id of the level. A SID
/// without a sub-authority is an error.
///
/// # Safety
/// `sid` points to a whole, readable SID, such as [`crate::winutil::TokenInformation::sid`] returns.
unsafe fn rid_of_label(sid: PSID) -> anyhow::Result<u32> {
    // SAFETY: `sid` is, by the caller's promise, a whole SID.
    unsafe {
        let count = *GetSidSubAuthorityCount(sid);
        anyhow::ensure!(count > 0, "the integrity label has no sub-authority");
        Ok(*GetSidSubAuthority(sid, u32::from(count) - 1))
    }
}

/// Whether, and how, `BUILTIN\Administrators` is in `token`, which needs `TOKEN_QUERY`.
fn administrators_of(token: HANDLE) -> anyhow::Result<AdministratorsSid> {
    let buf = token_information(token, TokenGroups).context("read the token's groups")?;
    // SAFETY: the group count is a `u32`.
    let count = unsafe { buf.header::<u32>() }.context("read the token's group count")?;
    // SAFETY: a `SID_AND_ATTRIBUTES` is a SID pointer and an integer.
    let groups = unsafe { buf.array::<SID_AND_ATTRIBUTES>(offset_of!(TOKEN_GROUPS, Groups), count as usize) }
        .context("read the token's groups")?;
    for group in groups {
        let sid = buf.sid(group.Sid).context("read a group of the token")?;
        // SAFETY: `sid` is a SID `buf` holds whole, and `buf` lives to the end of this function.
        if unsafe { IsWellKnownSid(sid, WinBuiltinAdministratorsSid) }.as_bool() {
            let attributes = group.Attributes;
            return Ok(
                if attributes & SE_GROUP_USE_FOR_DENY_ONLY != 0 || attributes & SE_GROUP_ENABLED == 0 {
                    AdministratorsSid::DenyOnly
                } else {
                    AdministratorsSid::Enabled
                },
            );
        }
    }
    Ok(AdministratorsSid::Absent)
}

/// The elevation of `token`, which needs `TOKEN_QUERY`.
pub fn elevation_of(token: HANDLE) -> anyhow::Result<Elevation> {
    Ok(classify_elevation(administrators_of(token)?, integrity_of(token)?))
}

/// The elevation of this process's token.
pub fn elevation() -> anyhow::Result<Elevation> {
    elevation_of(own_token()?.0)
}

#[cfg(test)]
#[path = "account_tests.rs"]
mod account_tests;
