//! provision::registry — the OpenSSH DefaultShell pair (pure pair builder + Windows Reg*).
//!
//! Uses windows-rs `Reg*` directly (not the `winreg` crate) — `windows` is already a
//! dependency and this matches the hand-rolled-FFI + RAII idiom of `acl.rs`/`winutil.rs`.
//! The production target is `HKLM\SOFTWARE\OpenSSH` (which needs elevation to write — `apply`
//! is an admin operation); the FFI core is root-parameterized so the unit test can exercise
//! the same code path under HKCU without elevation.

/// The two `HKLM\SOFTWARE\OpenSSH` values in FAIL-SAFE write order: the command option FIRST,
/// the shell path SECOND. There is no atomicity across two REG_SZ writes; a crash between them
/// then leaves `-c` with the OLD/absent shell (sshd falls back to cmd.exe — harmless) rather
/// than the NEW shell with no option (which would mis-invoke `ssh host "cmd"`).
pub fn registry_pair(exe: &str) -> [(&'static str, String); 2] {
    [
        ("DefaultShellCommandOption", "-c".to_string()),
        ("DefaultShell", exe.to_string()),
    ]
}

/// The production OpenSSH key under `HKEY_LOCAL_MACHINE`.
pub const OPENSSH_KEY: &str = r"SOFTWARE\OpenSSH";

#[cfg(windows)]
mod win {
    use super::registry_pair;
    use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_PATH_NOT_FOUND, WIN32_ERROR};
    use windows::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_WOW64_64KEY, REG_SZ, RRF_RT_REG_SZ, RegCloseKey, RegGetValueW,
        RegOpenKeyExW, RegQueryValueExW, RegSetKeyValueW,
    };
    use windows::core::PCWSTR;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Write the DefaultShell pair under `<root>\<subkey>` (creating the key), in the fail-safe
    /// order from `registry_pair`.
    fn set_under(root: HKEY, subkey: &str, exe: &str) -> anyhow::Result<()> {
        let sub = wide(subkey);
        for (name, val) in registry_pair(exe) {
            let name_w = wide(name);
            let val_w = wide(&val);
            let cb = (val_w.len() * 2) as u32; // bytes including the UTF-16 NUL terminator
            unsafe {
                RegSetKeyValueW(
                    root,
                    PCWSTR(sub.as_ptr()),
                    PCWSTR(name_w.as_ptr()),
                    REG_SZ.0,
                    Some(val_w.as_ptr() as *const core::ffi::c_void),
                    cb,
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

    /// Production: write the DefaultShell pair under `HKLM\<subkey>`.
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
        let name = wide("DefaultShellEscapeArguments");
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

    /// The `DefaultShell` path as sshd reads it (`pwd.c:78-80`): the value's bytes, whatever their
    /// type and unexpanded, as UTF-16 up to the first NUL. `None` when the key or value is missing
    /// or empty, which is when sshd uses `cmd.exe` instead. Any other failure is an `Err`.
    fn default_shell_path_in(root: HKEY, subkey: &str) -> windows::core::Result<Option<String>> {
        let sub = wide(subkey);
        let name = wide("DefaultShell");
        let mut key = HKEY::default();
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
        opened.ok()?;
        let read = unsafe { query_bytes(key, PCWSTR(name.as_ptr())) };
        unsafe {
            let _ = RegCloseKey(key);
        }
        let bytes = match read {
            Ok(bytes) => bytes,
            Err(status) if is_absent(status) => return Ok(None),
            Err(status) => return Err(status.to_hresult().into()),
        };
        let units: Vec<u16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&pair| u16::from_le_bytes(pair))
            .take_while(|&unit| unit != 0)
            .collect();
        Ok((!units.is_empty()).then(|| String::from_utf16_lossy(&units)))
    }

    /// The raw bytes of the value `name` under `key`, however long, retrying while the value grows
    /// between the size query and the read.
    ///
    /// # Safety
    /// `key` must be an open registry key and `name` a NUL-terminated string.
    unsafe fn query_bytes(key: HKEY, name: PCWSTR) -> Result<Vec<u8>, WIN32_ERROR> {
        let mut cb = 0u32;
        loop {
            let size = unsafe { RegQueryValueExW(key, name, None, None, None, Some(&mut cb)) };
            if size != WIN32_ERROR(0) {
                return Err(size);
            }
            let mut buf = vec![0u8; cb as usize];
            let status = unsafe { RegQueryValueExW(key, name, None, None, Some(buf.as_mut_ptr()), Some(&mut cb)) };
            if status == ERROR_MORE_DATA {
                continue;
            }
            if status != WIN32_ERROR(0) {
                return Err(status);
            }
            buf.truncate(cb as usize);
            return Ok(buf);
        }
    }

    /// Production: the `DefaultShell` path from `HKLM\<subkey>`; see [`default_shell_path_in`].
    pub fn default_shell_path_under(subkey: &str) -> windows::core::Result<Option<String>> {
        default_shell_path_in(HKEY_LOCAL_MACHINE, subkey)
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
    pub fn default_shell_path_hkcu(subkey: &str) -> windows::core::Result<Option<String>> {
        default_shell_path_in(windows::Win32::System::Registry::HKEY_CURRENT_USER, subkey)
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
    default_shell_path_hkcu, delete_hkcu, escape_arguments_from_status, escape_arguments_hkcu, read_hkcu, set_hkcu,
    set_value_hkcu,
};
#[cfg(windows)]
pub use win::{default_shell_path_under, escape_arguments_under, read_default_shell_under, set_default_shell_under};

#[cfg(test)]
#[path = "registry_tests.rs"]
mod registry_tests;
