//! account: who the invoking token is, and whether a password can start a session for it.
//!
//! The account is the SID of the process token, resolved to a name by `LookupAccountSidW`. It is
//! never read from the environment, a typed name or an argument: `USERNAME` is whatever the
//! caller set, and a password prompt for a name the caller chose would sign a different account on.

use anyhow::Context;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
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
fn computer_name() -> anyhow::Result<String> {
    let mut len = 0u32;
    // SAFETY: a null buffer is the documented size probe; it fails with the length needed.
    let _ = unsafe { GetComputerNameW(None, &mut len) };
    anyhow::ensure!(len > 0, "GetComputerNameW size probe returned 0");
    let mut buf = vec![0u16; len as usize];
    // SAFETY: `buf` holds `len` units, which is what the call is told.
    unsafe { GetComputerNameW(Some(PWSTR(buf.as_mut_ptr())), &mut len) }.context("GetComputerNameW")?;
    Ok(String::from_utf16_lossy(&buf[..len as usize]))
}

/// Whether the process token is elevated (an administrator's full token).
pub fn is_elevated() -> anyhow::Result<bool> {
    let mut token = HANDLE::default();
    // SAFETY: a valid out-pointer; the handle is closed by `OwnedHandle`.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.context("open the process token")?;
    let token = OwnedHandle(token);
    let mut info = TOKEN_ELEVATION::default();
    let mut len = 0u32;
    // SAFETY: `info` is a `TOKEN_ELEVATION` and the length passed is its size.
    unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            Some(&mut info as *mut _ as *mut core::ffi::c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
    }
    .context("read the token's elevation")?;
    Ok(info.TokenIsElevated != 0)
}

#[cfg(test)]
#[path = "account_tests.rs"]
mod account_tests;
