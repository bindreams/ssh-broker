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

/// What sshd reads to start a session's shell (`pwd.c` `set_defaultshell`): the four
/// `HKLM\SOFTWARE\OpenSSH` values `apply` carries into the system config before it overwrites them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshdShell {
    /// `DefaultShell`; `None` when absent, empty or too long for sshd's buffer ([`SSHD_VALUE_BYTES`]).
    pub shell: Option<String>,
    /// `DefaultShellCommandOption`; `None` when absent, empty or too long for sshd's buffer.
    pub command_option: Option<String>,
    /// `DefaultShellArguments`; `None` when absent, empty or too long for sshd's buffer.
    pub arguments: Option<String>,
    /// Whether sshd escapes the command: absent or too long means yes (see
    /// [`escape_arguments_from_status`]).
    pub escape_arguments: bool,
}

impl SshdShell {
    /// No `DefaultShell`: sshd runs the system `cmd.exe` and ignores the other three values.
    pub fn none() -> SshdShell {
        SshdShell {
            shell: None,
            command_option: None,
            arguments: None,
            escape_arguments: true,
        }
    }
}

/// The size, in bytes, of the buffer sshd reads each of `DefaultShell`, `DefaultShellCommandOption`
/// and `DefaultShellArguments` into. `pwd.c` declares `wchar_t[PATH_MAX]` (32768) but passes
/// `_countof` of it, a count of wide characters, as the size in bytes.
pub const SSHD_VALUE_BYTES: u32 = 32768;

/// The production OpenSSH key under `HKEY_LOCAL_MACHINE`.
pub const OPENSSH_KEY: &str = r"SOFTWARE\OpenSSH";

#[cfg(windows)]
mod win {
    use super::{ESCAPE_ARGUMENTS, RegValue, SSHD_VALUE_BYTES, SshdShell, desired_values};
    use anyhow::Context;
    use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_PATH_NOT_FOUND, WIN32_ERROR};
    use windows::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_WOW64_64KEY, REG_DWORD, REG_SZ, REG_VALUE_TYPE, RRF_RT_REG_SZ,
        RegCloseKey, RegDeleteKeyValueW, RegGetValueW, RegOpenKeyExW, RegQueryValueExW, RegSetKeyValueW,
    };
    use windows::core::PCWSTR;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Write [`desired_values`] under `<root>\<subkey>` (creating the key), in its fail-safe order.
    /// Right after the flag is written, `confirm_flag` must report that sshd now reads it as on;
    /// otherwise this stops with the option and the shell untouched.
    fn set_under(
        root: HKEY,
        subkey: &str,
        exe: &str,
        confirm_flag: impl FnOnce() -> windows::core::Result<bool>,
    ) -> anyhow::Result<()> {
        let mut confirm_flag = Some(confirm_flag);
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
            if name == ESCAPE_ARGUMENTS
                && let Some(confirm_flag) = confirm_flag.take()
            {
                anyhow::ensure!(
                    confirm_flag().context("read back DefaultShellEscapeArguments")?,
                    "DefaultShellEscapeArguments read-back mismatch: sshd would not escape the command"
                );
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

    /// A string value as stored, unexpanded, read the way sshd reads it (see
    /// [`sshd_string_from_status`]): `None` when the key or value is absent, empty, or longer than
    /// sshd's buffer. Any other failure is an error: it leaves what sshd reads unknown.
    fn read_optional_string(root: HKEY, subkey: &str, name: &str) -> anyhow::Result<Option<String>> {
        let (sub, name_w) = (wide(subkey), wide(name));
        let mut key = HKEY::default();
        // SAFETY: `sub` is NUL-terminated and `key` receives the opened handle.
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
            return Ok(None);
        }
        opened.ok().with_context(|| format!("open the key of {name}"))?;
        let mut buffer = vec![0u16; SSHD_VALUE_BYTES as usize / 2];
        let mut bytes = SSHD_VALUE_BYTES;
        // SAFETY: `name_w` is NUL-terminated; `buffer` holds `bytes` bytes.
        let status = unsafe {
            let status = RegQueryValueExW(
                key,
                PCWSTR(name_w.as_ptr()),
                None,
                None,
                Some(buffer.as_mut_ptr().cast()),
                Some(&mut bytes),
            );
            let _ = RegCloseKey(key);
            status
        };
        sshd_string_from_status(name, status, &buffer, bytes)
    }

    /// What `RegQueryValueExW`'s answer says about one of the three string values. sshd acts only
    /// on `ERROR_SUCCESS` (`pwd.c:78-89`): a missing value and one that does not fit its buffer
    /// ([`SSHD_VALUE_BYTES`], `ERROR_MORE_DATA`) are both "not set". Any other failure leaves what
    /// sshd reads unknown. sshd never looks at the value's type: the bytes are the text, whether the
    /// value is a REG_SZ, a REG_EXPAND_SZ (not expanded), a REG_DWORD or anything else. Text ends at
    /// the first NUL, as a C string does; an empty value counts as absent.
    pub fn sshd_string_from_status(
        name: &str,
        status: WIN32_ERROR,
        buffer: &[u16],
        bytes: u32,
    ) -> anyhow::Result<Option<String>> {
        if is_absent(status) || status == ERROR_MORE_DATA {
            return Ok(None);
        }
        status.ok().with_context(|| format!("read {name}"))?;
        let units = (bytes as usize / 2).min(buffer.len());
        let text = &buffer[..units];
        let text = &text[..text.iter().position(|&unit| unit == 0).unwrap_or(text.len())];
        Ok((!text.is_empty()).then(|| String::from_utf16_lossy(text)))
    }

    fn read_sshd_shell_in(root: HKEY, subkey: &str) -> anyhow::Result<SshdShell> {
        let Some(shell) = read_optional_string(root, subkey, "DefaultShell")? else {
            // sshd ignores the other values when there is no shell.
            return Ok(SshdShell::none());
        };
        Ok(SshdShell {
            shell: Some(shell),
            command_option: read_optional_string(root, subkey, "DefaultShellCommandOption")?,
            arguments: read_optional_string(root, subkey, "DefaultShellArguments")?,
            escape_arguments: escape_arguments_in(root, subkey).context("read DefaultShellEscapeArguments")?,
        })
    }

    /// Remove `DefaultShellArguments` from `<root>\<subkey>`. A value or a key that is not there
    /// is already what this wants.
    fn remove_shell_arguments_in(root: HKEY, subkey: &str) -> anyhow::Result<()> {
        let (sub, name) = (wide(subkey), wide("DefaultShellArguments"));
        // SAFETY: both strings are NUL-terminated.
        let status = unsafe { RegDeleteKeyValueW(root, PCWSTR(sub.as_ptr()), PCWSTR(name.as_ptr())) };
        if is_absent(status) {
            return Ok(());
        }
        status.ok().context("remove DefaultShellArguments")
    }

    /// Production: remove `DefaultShellArguments` from `HKLM\<subkey>`.
    pub fn remove_shell_arguments_under(subkey: &str) -> anyhow::Result<()> {
        remove_shell_arguments_in(HKEY_LOCAL_MACHINE, subkey)
    }

    /// Production: the four shell values from `HKLM\<subkey>`, as sshd reads them.
    pub fn read_sshd_shell_under(subkey: &str) -> anyhow::Result<SshdShell> {
        read_sshd_shell_in(HKEY_LOCAL_MACHINE, subkey)
    }

    /// Production: write [`desired_values`] under `HKLM\<subkey>`.
    pub fn set_default_shell_under(subkey: &str, exe: &str) -> anyhow::Result<()> {
        set_under(HKEY_LOCAL_MACHINE, subkey, exe, || {
            escape_arguments_in(HKEY_LOCAL_MACHINE, subkey)
        })
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
        set_hkcu_confirming(subkey, exe, || escape_arguments_hkcu(subkey))
    }
    #[cfg(test)]
    pub fn set_hkcu_confirming(
        subkey: &str,
        exe: &str,
        confirm_flag: impl FnOnce() -> windows::core::Result<bool>,
    ) -> anyhow::Result<()> {
        set_under(
            windows::Win32::System::Registry::HKEY_CURRENT_USER,
            subkey,
            exe,
            confirm_flag,
        )
    }
    #[cfg(test)]
    pub fn read_sshd_shell_hkcu(subkey: &str) -> anyhow::Result<SshdShell> {
        read_sshd_shell_in(windows::Win32::System::Registry::HKEY_CURRENT_USER, subkey)
    }
    #[cfg(test)]
    pub fn remove_shell_arguments_hkcu(subkey: &str) -> anyhow::Result<()> {
        remove_shell_arguments_in(windows::Win32::System::Registry::HKEY_CURRENT_USER, subkey)
    }
    #[cfg(test)]
    pub fn read_string_hkcu(subkey: &str, name: &str) -> anyhow::Result<String> {
        read_value(windows::Win32::System::Registry::HKEY_CURRENT_USER, subkey, name)
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
    delete_hkcu, escape_arguments_from_status, escape_arguments_hkcu, read_dword_hkcu, read_hkcu, read_sshd_shell_hkcu,
    read_string_hkcu, remove_shell_arguments_hkcu, set_hkcu, set_hkcu_confirming, set_value_hkcu,
    sshd_string_from_status,
};
#[cfg(windows)]
pub use win::{
    escape_arguments_under, read_default_shell_under, read_sshd_shell_under, remove_shell_arguments_under,
    set_default_shell_under,
};

#[cfg(test)]
#[path = "registry_tests.rs"]
mod registry_tests;
