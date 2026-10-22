//! provision::registry — the `HKLM\SOFTWARE\OpenSSH` values `apply` owns (pure list + Windows Reg*).
//!
//! Uses windows-rs `Reg*` directly (not the `winreg` crate) — `windows` is already a
//! dependency and this matches the hand-rolled-FFI + RAII idiom of `acl.rs`/`winutil.rs`.
//! The production target is `HKLM\SOFTWARE\OpenSSH` (which needs elevation to write — `apply`
//! is an admin operation); the FFI core is root-parameterized so the unit test can exercise
//! the same code path under HKCU without elevation.

use super::report::Check;

/// A registry value `apply` writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegValue {
    Sz(String),
    Dword(u32),
}

/// The three `HKLM\SOFTWARE\OpenSSH` values `apply` owns, in FAIL-SAFE write order.
///
/// sshd reads `DefaultShell`, `DefaultShellCommandOption`, `DefaultShellArguments` and
/// `DefaultShellEscapeArguments` once per session (`pwd.c` `set_defaultshell`), so the shim cannot
/// ask later which form sshd used; `apply` sets the form instead. There is no atomicity across the
/// writes, so each crash point must be harmless:
///
/// - the escape flag FIRST: sshd escapes the command for every shell the flag does not exempt, so
///   it is right before the shim becomes the shell and costs nothing before then;
/// - the command option SECOND, the shell path LAST: a crash between them leaves `-c` with the
///   OLD/absent shell (sshd falls back to cmd.exe — harmless) rather than the NEW shell with no
///   option (which would mis-invoke `ssh host "cmd"`).
pub fn desired_values(exe: &str) -> [(&'static str, RegValue); 3] {
    [
        (ESCAPE_ARGUMENTS, RegValue::Dword(1)),
        ("DefaultShellCommandOption", RegValue::Sz("-c".to_string())),
        ("DefaultShell", RegValue::Sz(exe.to_string())),
    ]
}

/// The value sshd reads to decide whether to escape the command it hands the `DefaultShell`.
pub const ESCAPE_ARGUMENTS: &str = "DefaultShellEscapeArguments";

/// The `verify` row for the escape flag: `read` is [`escape_arguments_under`]'s answer, which
/// already follows how sshd reads the value. Off, and a value that cannot be read, both fail:
/// the shim decodes the escaped form only.
pub fn escape_arguments_check<E: std::fmt::Display>(read: Result<bool, E>) -> Check {
    let name = ESCAPE_ARGUMENTS;
    match read {
        Ok(true) => Check::new(name, true, "sshd escapes the command"),
        Ok(false) => Check::new(
            name,
            false,
            "sshd would not escape the command, which the shim cannot decode; run `ssh-broker apply`",
        ),
        Err(error) => Check::new(
            name,
            false,
            format!("cannot read it ({error}); run `ssh-broker apply` and check the key's permissions"),
        ),
    }
}

/// The production OpenSSH key under `HKEY_LOCAL_MACHINE`.
pub const OPENSSH_KEY: &str = r"SOFTWARE\OpenSSH";

#[cfg(windows)]
mod win {
    use super::{ESCAPE_ARGUMENTS, RegValue, desired_values};
    use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_PATH_NOT_FOUND, WIN32_ERROR};
    use windows::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_WOW64_64KEY, REG_DWORD, REG_SZ, REG_VALUE_TYPE, RRF_RT_REG_SZ,
        RegCloseKey, RegGetValueW, RegOpenKeyExW, RegQueryValueExW, RegSetKeyValueW,
    };
    use windows::core::PCWSTR;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Write [`desired_values`] under `<root>\<subkey>` (creating the key), in its fail-safe order.
    fn set_under(root: HKEY, subkey: &str, exe: &str) -> anyhow::Result<()> {
        let sub = wide(subkey);
        for (name, value) in desired_values(exe) {
            let name_w = wide(name);
            let (reg_type, bytes): (REG_VALUE_TYPE, Vec<u8>) = match value {
                RegValue::Sz(text) => (REG_SZ, wide(&text).into_iter().flat_map(u16::to_le_bytes).collect()),
                RegValue::Dword(number) => (REG_DWORD, number.to_le_bytes().to_vec()),
            };
            // SAFETY: `sub` and `name_w` are NUL-terminated and `bytes` is the value's data.
            unsafe {
                RegSetKeyValueW(
                    root,
                    PCWSTR(sub.as_ptr()),
                    PCWSTR(name_w.as_ptr()),
                    reg_type.0,
                    Some(bytes.as_ptr() as *const core::ffi::c_void),
                    bytes.len() as u32,
                )
                .ok()?;
            }
        }
        Ok(())
    }

    fn read_under(root: HKEY, subkey: &str) -> anyhow::Result<(String, String)> {
        Ok((
            read_value(root, subkey, "DefaultShell")?,
            read_value(root, subkey, "DefaultShellCommandOption")?,
        ))
    }

    fn read_value(root: HKEY, subkey: &str, name: &str) -> anyhow::Result<String> {
        let sub = wide(subkey);
        let name_w = wide(name);
        let mut buf = [0u16; 512];
        let mut cb = (buf.len() * 2) as u32;
        unsafe {
            RegGetValueW(
                root,
                PCWSTR(sub.as_ptr()),
                PCWSTR(name_w.as_ptr()),
                RRF_RT_REG_SZ,
                None,
                Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
                Some(&mut cb),
            )
            .ok()?;
        }
        let chars = (cb as usize / 2).saturating_sub(1); // drop the NUL terminator
        Ok(String::from_utf16_lossy(&buf[..chars.min(buf.len())]))
    }

    /// Production: write [`desired_values`] under `HKLM\<subkey>`.
    pub fn set_default_shell_under(subkey: &str, exe: &str) -> anyhow::Result<()> {
        set_under(HKEY_LOCAL_MACHINE, subkey, exe)
    }

    /// Production: read `(DefaultShell, DefaultShellCommandOption)` from `HKLM\<subkey>`.
    pub fn read_default_shell_under(subkey: &str) -> anyhow::Result<(String, String)> {
        read_under(HKEY_LOCAL_MACHINE, subkey)
    }

    /// Whether sshd escapes the command it hands the `DefaultShell`, read the way sshd reads
    /// `DefaultShellEscapeArguments` (`pwd.c` `set_defaultshell`): into four bytes that start as 1,
    /// whatever the value's type, nonzero meaning on. Anything that leaves sshd's read unsuccessful
    /// leaves its default (on) in place, and that is the answer when the value is missing or too
    /// long to fit (see [`escape_arguments_from_status`]). A value that exists but cannot be read
    /// for another reason leaves the real setting unknown, so it is an `Err` the caller can report.
    fn escape_arguments_in(root: HKEY, subkey: &str) -> windows::core::Result<bool> {
        let sub = wide(subkey);
        let name = wide(ESCAPE_ARGUMENTS);
        let mut key = HKEY::default();
        // sshd's `escape_option` starts at 1 (`pwd.c:83`); a value shorter than four bytes
        // overwrites only its own bytes.
        let mut value = 1u32.to_le_bytes();
        let mut cb = value.len() as u32;
        let opened = unsafe {
            RegOpenKeyExW(
                root,
                PCWSTR(sub.as_ptr()),
                None,
                KEY_QUERY_VALUE | KEY_WOW64_64KEY,
                &mut key,
            )
        };
        if is_absent(opened) {
            return Ok(true);
        }
        opened.ok()?;
        let read = unsafe {
            let read = RegQueryValueExW(
                key,
                PCWSTR(name.as_ptr()),
                None,
                None,
                Some(value.as_mut_ptr()),
                Some(&mut cb),
            );
            let _ = RegCloseKey(key);
            read
        };
        escape_arguments_from_status(read, value)
    }

    /// What `RegQueryValueExW`'s `status` and the four bytes it filled in say about
    /// `DefaultShellEscapeArguments`. sshd acts only on `ERROR_SUCCESS` and otherwise keeps escaping
    /// on (`pwd.c:91-92`), so a missing value and a value that does not fit (`ERROR_MORE_DATA`)
    /// both mean on. Any other failure means the setting could not be seen.
    pub fn escape_arguments_from_status(status: WIN32_ERROR, value: [u8; 4]) -> windows::core::Result<bool> {
        if is_absent(status) || status == ERROR_MORE_DATA {
            return Ok(true);
        }
        status.ok()?;
        Ok(u32::from_le_bytes(value) != 0)
    }

    /// The key or value is not there, as opposed to being there and unreadable.
    fn is_absent(status: WIN32_ERROR) -> bool {
        status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND
    }

    /// Production: whether sshd escapes the command, from `HKLM\<subkey>`.
    pub fn escape_arguments_under(subkey: &str) -> windows::core::Result<bool> {
        escape_arguments_in(HKEY_LOCAL_MACHINE, subkey)
    }

    // ── test helpers: same FFI core, under HKCU (writable without elevation) ──────────
    #[cfg(test)]
    pub fn set_hkcu(subkey: &str, exe: &str) -> anyhow::Result<()> {
        set_under(windows::Win32::System::Registry::HKEY_CURRENT_USER, subkey, exe)
    }
    #[cfg(test)]
    pub fn read_hkcu(subkey: &str) -> anyhow::Result<(String, String)> {
        read_under(windows::Win32::System::Registry::HKEY_CURRENT_USER, subkey)
    }
    #[cfg(test)]
    pub fn escape_arguments_hkcu(subkey: &str) -> windows::core::Result<bool> {
        escape_arguments_in(windows::Win32::System::Registry::HKEY_CURRENT_USER, subkey)
    }
    #[cfg(test)]
    pub fn read_dword_hkcu(subkey: &str, name: &str) -> windows::core::Result<u32> {
        use windows::Win32::System::Registry::{HKEY_CURRENT_USER, RRF_RT_REG_DWORD};
        let (sub, name) = (wide(subkey), wide(name));
        let mut value = 0u32;
        let mut cb = 4u32;
        // SAFETY: `value` is a four-byte buffer and `cb` its size; the strings are NUL-terminated.
        unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                PCWSTR(sub.as_ptr()),
                PCWSTR(name.as_ptr()),
                RRF_RT_REG_DWORD,
                None,
                Some(&mut value as *mut u32 as *mut core::ffi::c_void),
                Some(&mut cb),
            )
            .ok()?;
        }
        Ok(value)
    }
    #[cfg(test)]
    pub fn set_value_hkcu(subkey: &str, name: &str, reg_type: u32, data: &[u8]) {
        let (sub, name) = (wide(subkey), wide(name));
        unsafe {
            RegSetKeyValueW(
                windows::Win32::System::Registry::HKEY_CURRENT_USER,
                PCWSTR(sub.as_ptr()),
                PCWSTR(name.as_ptr()),
                reg_type,
                Some(data.as_ptr() as *const core::ffi::c_void),
                data.len() as u32,
            )
            .ok()
            .unwrap();
        }
    }
    #[cfg(test)]
    pub fn delete_hkcu(subkey: &str) {
        use windows::Win32::System::Registry::{HKEY_CURRENT_USER, RegDeleteKeyW, RegDeleteTreeW};
        let sub = wide(subkey);
        unsafe {
            let _ = RegDeleteTreeW(HKEY_CURRENT_USER, PCWSTR(sub.as_ptr()));
            let _ = RegDeleteKeyW(HKEY_CURRENT_USER, PCWSTR(sub.as_ptr()));
        }
    }
}

#[cfg(all(windows, test))]
pub use win::{
    delete_hkcu, escape_arguments_from_status, escape_arguments_hkcu, read_dword_hkcu, read_hkcu, set_hkcu,
    set_value_hkcu,
};
#[cfg(windows)]
pub use win::{escape_arguments_under, read_default_shell_under, set_default_shell_under};

#[cfg(test)]
#[path = "registry_tests.rs"]
mod registry_tests;
