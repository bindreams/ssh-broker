//! Throwaway local accounts, in the shape of `tests/user_isolation_windows.rs`'s fixture.

use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use std::process::Command;

use ssh_broker::acl::Sid;
use ssh_broker::winutil::OwnedHandle;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::NetManagement::{
    NetUserAdd, NetUserDel, UF_DONT_EXPIRE_PASSWD, UF_SCRIPT, USER_INFO_1, USER_PRIV_USER,
};
use windows::Win32::Security::{
    LOGON32_LOGON_BATCH, LOGON32_LOGON_INTERACTIVE, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, LogonUserW,
};
use windows::Win32::UI::Shell::{CreateProfile, DeleteProfileW};
use windows::core::{PCWSTR, PWSTR};

use crate::win::{kill_account_processes, wide};

/// What is different about an account.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Standard,
    Administrator,
    Disabled,
    MustChangePassword,
    BlankPassword,
}

/// The logon type of a token made for an account.
#[derive(Clone, Copy)]
pub enum LogonKind {
    Network,
    Interactive,
    Batch,
}

pub struct Account {
    pub name: String,
    pub password: String,
    pub sid_text: String,
    pub profile: Option<PathBuf>,
}

fn run(program: &str, args: &[&str]) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    let out = Command::new(program)
        .args(args)
        .creation_flags(0x0800_0000)
        .output()
        .map_err(|e| format!("{program} did not run: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{program} {args:?} failed: {} {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}

fn next_name(tag: &str) -> String {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let name = format!("sb{tag}{:x}_{n:x}", std::process::id());
    assert!(
        name.chars().count() <= 20,
        "{name} is longer than an account name may be"
    );
    name
}

impl Account {
    pub fn create(tag: &str, with_profile: bool, kind: Kind) -> Account {
        Account::try_create(tag, with_profile, kind).unwrap_or_else(|e| panic!("create account {tag}: {e}"))
    }

    pub fn try_create(tag: &str, with_profile: bool, kind: Kind) -> Result<Account, String> {
        let name = next_name(tag);
        let password = if kind == Kind::BlankPassword {
            String::new()
        } else {
            format!("Pw-{}-Aa1!", &name[2..])
        };
        let name_w = wide(&name);
        let mut password_w = wide(&password);
        let mut name_mut = name_w.clone();
        let info = USER_INFO_1 {
            usri1_name: PWSTR(name_mut.as_mut_ptr()),
            usri1_password: PWSTR(password_w.as_mut_ptr()),
            usri1_password_age: 0,
            usri1_priv: USER_PRIV_USER,
            usri1_home_dir: PWSTR::null(),
            usri1_comment: PWSTR::null(),
            usri1_flags: UF_SCRIPT | UF_DONT_EXPIRE_PASSWD,
            usri1_script_path: PWSTR::null(),
        };
        // SAFETY: `info` and the strings it points at outlive the call.
        let rc = unsafe { NetUserAdd(PCWSTR::null(), 1, &info as *const _ as *const u8, None) };
        if rc != 0 {
            return Err(format!("NetUserAdd({name}) failed with {rc}"));
        }
        let sid = Sid::lookup(&name).map_err(|e| format!("look up {name}: {e:#}"))?;
        let sid_text = sid.to_sddl().map_err(|e| format!("{e:#}"))?;
        let mut account = Account {
            name,
            password,
            sid_text,
            profile: None,
        };
        if with_profile {
            let mut buf = [0u16; 260];
            // SAFETY: NUL-terminated inputs; `buf` is the output buffer and its length.
            unsafe {
                CreateProfile(
                    PCWSTR(wide(&account.sid_text).as_ptr()),
                    PCWSTR(name_w.as_ptr()),
                    &mut buf,
                )
            }
            .map_err(|e| format!("CreateProfile: {e}"))?;
            let len = buf.iter().position(|&u| u == 0).unwrap();
            account.profile = Some(PathBuf::from(std::ffi::OsString::from_wide(&buf[..len])));
        }
        match kind {
            Kind::Administrator => run("net", &["localgroup", "Administrators", &account.name, "/add"])?,
            Kind::Disabled => run("net", &["user", &account.name, "/active:no"])?,
            Kind::MustChangePassword => run("net", &["user", &account.name, "/logonpasswordchg:yes"])?,
            Kind::Standard | Kind::BlankPassword => {}
        }
        Ok(account)
    }

    /// The token sshd's key-authenticated logon gives: a network logon, no loaded profile.
    pub fn network_token(&self) -> OwnedHandle {
        self.token(LogonKind::Network)
            .unwrap_or_else(|e| panic!("LogonUser({}) failed: {e}", self.name))
    }

    /// A token from `LogonUserW` of the given logon type.
    pub fn token(&self, kind: LogonKind) -> windows::core::Result<OwnedHandle> {
        let mut token = HANDLE::default();
        // SAFETY: NUL-terminated inputs, a valid out-pointer.
        unsafe {
            LogonUserW(
                PCWSTR(wide(&self.name).as_ptr()),
                PCWSTR(wide(".").as_ptr()),
                PCWSTR(wide(&self.password).as_ptr()),
                match kind {
                    LogonKind::Network => LOGON32_LOGON_NETWORK,
                    LogonKind::Interactive => LOGON32_LOGON_INTERACTIVE,
                    LogonKind::Batch => LOGON32_LOGON_BATCH,
                },
                LOGON32_PROVIDER_DEFAULT,
                &mut token,
            )
        }?;
        Ok(OwnedHandle(token))
    }

    pub fn set_password(&mut self, new: &str) {
        run("net", &["user", &self.name, new]).expect("net user <name> <password>");
        self.password = new.to_owned();
    }

    /// The profile directory, wherever it ended up (made by `CreateProfile` or by a first logon).
    pub fn profile_dir(&self) -> Option<PathBuf> {
        if let Some(p) = &self.profile {
            return Some(p.clone());
        }
        let key = format!(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{}",
            self.sid_text
        );
        let out = Command::new("reg")
            .args(["query", &key, "/v", "ProfileImagePath"])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let line = text.lines().find(|l| l.contains("ProfileImagePath"))?;
        let value = line
            .split("REG_EXPAND_SZ")
            .nth(1)
            .or_else(|| line.split("REG_SZ").nth(1))?;
        Some(PathBuf::from(value.trim()))
    }
}

impl Drop for Account {
    fn drop(&mut self) {
        kill_account_processes(&self.sid_text);
        // SAFETY: NUL-terminated inputs.
        unsafe {
            let _ = DeleteProfileW(PCWSTR(wide(&self.sid_text).as_ptr()), PCWSTR::null(), PCWSTR::null());
            let _ = NetUserDel(PCWSTR::null(), PCWSTR(wide(&self.name).as_ptr()));
        }
    }
}
