//! account: who the invoking token is, and whether a password can start a session for it.
//!
//! The account is the SID of the process token, resolved to a name by `LookupAccountSidW`. It is
//! never read from the environment, a typed name or an argument: `USERNAME` is whatever the
//! caller set, and a password prompt for a name the caller chose would sign a different account on.

use anyhow::Context;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::{
    GetSidSubAuthority, GetSidSubAuthorityCount, IsWellKnownSid, PSID, TOKEN_MANDATORY_LABEL, TokenIntegrityLevel,
    WinBuiltinAdministratorsSid,
};
use windows::Win32::System::WindowsProgramming::GetComputerNameW;
use windows::core::PWSTR;

use crate::acl::Sid;
pub use crate::offer::AccountKind;
use crate::protocol::ElevationPolicy;
use crate::socket_loc::Integrity;
pub use crate::socket_loc::{Elevation, StepDown};
use crate::winutil::{SE_GROUP_ENABLED, SE_GROUP_USE_FOR_DENY_ONLY, find_group, own_token, token_information};

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

/// The folder level of a process whose token has the integrity level `rid` ([`integrity_of`]): High at
/// [`INTEGRITY_HIGH`] and above, Medium below. The one rule that says which of the two folders (and which
/// agents) a process belongs to.
pub fn integrity_class(rid: u32) -> Integrity {
    if rid >= INTEGRITY_HIGH {
        Integrity::High
    } else {
        Integrity::Medium
    }
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
    // SAFETY: every bit pattern is a valid `TOKEN_MANDATORY_LABEL` (a pointer and an integer).
    let label = unsafe { buf.header::<TOKEN_MANDATORY_LABEL>() }.context("read the token's integrity label")?;
    let sid = buf.sid(label.Label.Sid).context("read the token's integrity label")?;
    // SAFETY: `sid` is a SID `buf` holds whole.
    unsafe { rid_of_label(sid) }
}

/// The last sub-authority of the label SID `sid`, which is the relative id of the level. A SID
/// without a sub-authority is an error.
///
/// # Safety
/// `sid` points to a whole, readable SID, such as [`crate::winutil::TokenInformation::sid`] returns.
unsafe fn rid_of_label(sid: PSID) -> anyhow::Result<u32> {
    // SAFETY: the caller's promise.
    unsafe {
        let count = *GetSidSubAuthorityCount(sid);
        anyhow::ensure!(count > 0, "the integrity label has no sub-authority");
        Ok(*GetSidSubAuthority(sid, u32::from(count) - 1))
    }
}

/// Whether, and how, `BUILTIN\Administrators` is in `token`, which needs `TOKEN_QUERY`.
fn administrators_of(token: HANDLE) -> anyhow::Result<AdministratorsSid> {
    let attributes = find_group(token, |sid, attributes| {
        // SAFETY: `sid` is a SID the token information holds whole.
        Ok(unsafe { IsWellKnownSid(sid, WinBuiltinAdministratorsSid) }
            .as_bool()
            .then_some(attributes))
    })?;
    Ok(match attributes {
        None => AdministratorsSid::Absent,
        Some(attributes) if attributes & SE_GROUP_USE_FOR_DENY_ONLY != 0 || attributes & SE_GROUP_ENABLED == 0 => {
            AdministratorsSid::DenyOnly
        }
        Some(_) => AdministratorsSid::Enabled,
    })
}

/// The elevation of `token`, which needs `TOKEN_QUERY`.
pub fn elevation_of(token: HANDLE) -> anyhow::Result<Elevation> {
    Ok(classify_elevation(administrators_of(token)?, integrity_of(token)?))
}

/// The elevation of this process's token.
pub fn elevation() -> anyhow::Result<Elevation> {
    elevation_of(own_token()?.0)
}

/// The folder level of this process's token ([`integrity_class`] of [`integrity_of`]).
pub fn integrity() -> anyhow::Result<Integrity> {
    Ok(integrity_class(integrity_of(own_token()?.0)?))
}

/// What a session of a login that `asked` for a level is started with in this process: the one rule that the
/// agent, the shim failing open and the filtered shim all use. `None` is a login that set nothing.
///
/// | asked | at High | below High |
/// |---|---|---|
/// | `Never`, `Prompt`, `AutoApprove` | [`StepDown::Token`] | [`StepDown::Own`] |
/// | `Always` | [`StepDown::Own`] | [`StepDown::Refused`] |
/// | nothing | [`StepDown::Token`] | [`StepDown::Own`] |
///
/// A login that asked for a level is refused when it cannot be given: a level that cannot be read, or a token
/// that cannot be made, is an error, since a guess would run the session as it is. A login that asked for
/// nothing gets [`StepDown::Fallback`] in the same two cases: this process's own token, and the cause for the
/// notice. `integrity` is read once, and `make` only for a [`StepDown::Token`]; both are parameters so that a
/// test can make either fail.
pub fn step_down<K>(
    asked: Option<ElevationPolicy>,
    integrity: impl FnOnce() -> anyhow::Result<Integrity>,
    make: impl FnOnce() -> anyhow::Result<K>,
) -> anyhow::Result<StepDown<K>> {
    let level = match integrity().context("read this process's integrity level") {
        Ok(level) => level,
        Err(cause) if asked.is_none() => return Ok(StepDown::Fallback(format!("{cause:#}"))),
        Err(cause) => return Err(cause),
    };
    Ok(match (asked, level) {
        (Some(ElevationPolicy::Always), Integrity::High) => StepDown::Own,
        (Some(ElevationPolicy::Always), Integrity::Medium) => StepDown::Refused,
        (_, Integrity::Medium) => StepDown::Own,
        (Some(_), Integrity::High) => StepDown::Token(make()?),
        (None, Integrity::High) => match make() {
            Ok(token) => StepDown::Token(token),
            Err(cause) => StepDown::Fallback(format!("{cause:#}")),
        },
    })
}

#[cfg(test)]
#[path = "account_tests.rs"]
mod account_tests;
