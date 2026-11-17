//! account: who the invoking token is, and whether a password can start a session for it.
//!
//! The account is the SID of the process token, resolved to a name by `LookupAccountSidW`. It is
//! never read from the environment, a typed name or an argument: `USERNAME` is whatever the
//! caller set, and a password prompt for a name the caller chose would sign a different account on.

use anyhow::Context;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::{
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, IsWellKnownSid, TOKEN_GROUPS,
    TOKEN_INFORMATION_CLASS, TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TokenGroups, TokenIntegrityLevel,
    WinBuiltinAdministratorsSid,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::System::WindowsProgramming::GetComputerNameW;
use windows::core::PWSTR;

use crate::acl::Sid;
pub use crate::offer::AccountKind;
use crate::winutil::OwnedHandle;

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

/// The relative id of the High mandatory label, `S-1-16-12288`.
const SECURITY_MANDATORY_HIGH_RID: u32 = 0x3000;
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
/// integrity label (`0x2000` Medium, `0x3000` High).
pub fn classify_elevation(administrators: AdministratorsSid, integrity_rid: u32) -> Elevation {
    match administrators {
        AdministratorsSid::Absent => Elevation::Standard,
        AdministratorsSid::Enabled if integrity_rid >= SECURITY_MANDATORY_HIGH_RID => Elevation::Full,
        AdministratorsSid::Enabled | AdministratorsSid::DenyOnly => Elevation::Filtered,
    }
}

/// A `TOKEN_QUERY` handle on this process's token: the only place that opens it. Read the token
/// through this handle (`userdir`, `elevation`); a read that needs more access than `TOKEN_QUERY`
/// opens its own.
pub fn own_token() -> anyhow::Result<OwnedHandle> {
    let mut token = HANDLE::default();
    // SAFETY: `token` is a valid out-pointer; the handle is closed by `OwnedHandle`.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.context("open the process token")?;
    Ok(OwnedHandle(token))
}

/// The relative id of the integrity label of `token` (`0x2000` Medium, `0x3000` High), which needs
/// `TOKEN_QUERY`.
pub fn integrity_of(token: HANDLE) -> anyhow::Result<u32> {
    let buf = token_information(token, TokenIntegrityLevel).context("read the token's integrity level")?;
    // SAFETY: the buffer holds a `TOKEN_MANDATORY_LABEL` whose SID lies inside it, and `u64`
    // storage is aligned for both.
    unsafe {
        let label = &*buf.as_ptr().cast::<TOKEN_MANDATORY_LABEL>();
        let sid = label.Label.Sid;
        let count = *GetSidSubAuthorityCount(sid);
        anyhow::ensure!(count > 0, "the integrity label has no sub-authority");
        Ok(*GetSidSubAuthority(sid, u32::from(count) - 1))
    }
}

/// Whether, and how, `BUILTIN\Administrators` is in `token`, which needs `TOKEN_QUERY`.
fn administrators_of(token: HANDLE) -> anyhow::Result<AdministratorsSid> {
    let buf = token_information(token, TokenGroups).context("read the token's groups")?;
    // SAFETY: the buffer holds a `TOKEN_GROUPS` with `GroupCount` entries after its header,
    // `u64` storage being aligned for it; each entry's SID lies inside the buffer.
    unsafe {
        let groups = &*buf.as_ptr().cast::<TOKEN_GROUPS>();
        let first = groups.Groups.as_ptr();
        for index in 0..groups.GroupCount as usize {
            let group = &*first.add(index);
            if IsWellKnownSid(group.Sid, WinBuiltinAdministratorsSid).as_bool() {
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

/// `class` of `token`, as bytes in 8-aligned storage (the structures in it hold pointers).
fn token_information(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> anyhow::Result<Vec<u64>> {
    let mut len = 0u32;
    // SAFETY: a null buffer is the documented size probe; it fails with the length needed.
    let _ = unsafe { GetTokenInformation(token, class, None, 0, &mut len) };
    anyhow::ensure!(len > 0, "the token information size probe returned 0");
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: `buf` holds at least `len` bytes, which is what the call is told.
    unsafe { GetTokenInformation(token, class, Some(buf.as_mut_ptr().cast()), len, &mut len) }?;
    Ok(buf)
}

#[cfg(test)]
#[path = "account_tests.rs"]
mod account_tests;
