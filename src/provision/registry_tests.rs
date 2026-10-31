//! Tests for the values `apply` owns under `HKLM\SOFTWARE\OpenSSH`: the pure list and the verify
//! row (host) + the Reg* round-trips (Windows).
use super::{RegValue, desired_values, escape_arguments_check};

/// A throwaway HKCU subkey, deleted when the guard drops, so a failing assertion leaves nothing
/// behind.
#[cfg(windows)]
struct TestKey(String);

#[cfg(windows)]
impl TestKey {
    fn new(tag: &str) -> Self {
        Self(format!(r"SOFTWARE\ssh-broker-test-{tag}-{}", std::process::id()))
    }

    fn path(&self) -> &str {
        &self.0
    }
}

#[cfg(windows)]
impl Drop for TestKey {
    fn drop(&mut self) {
        super::delete_hkcu(&self.0);
    }
}

/// The flag comes first: sshd reads all four values once per session (`pwd.c`
/// `set_defaultshell`), so a crash between writes must never leave the shim as `DefaultShell` with
/// sshd's escaping still off. The option comes before the shell for the reason it always did.
#[test]
fn values_are_the_flag_then_the_option_then_the_shell() {
    let values = desired_values(r"C:\ProgramData\ssh-broker\ssh-broker.exe");
    assert_eq!(
        values,
        [
            ("DefaultShellEscapeArguments", RegValue::Dword(1)),
            ("DefaultShellCommandOption", RegValue::Sz("-c".into())),
            (
                "DefaultShell",
                RegValue::Sz(r"C:\ProgramData\ssh-broker\ssh-broker.exe".into())
            ),
        ]
    );
}

/// The verify row passes when sshd reads the value as on (a missing value included), and fails
/// otherwise, naming the value and `apply`. A read that cannot be made fails too: the setting is
/// then unknown.
#[test]
fn the_escape_row_passes_only_when_sshd_would_escape() {
    let on = escape_arguments_check(Ok::<_, String>(true));
    assert!(on.pass, "{}", on.detail);

    let off = escape_arguments_check(Ok::<_, String>(false));
    assert!(!off.pass);
    assert!(off.name.contains("DefaultShellEscapeArguments"), "{}", off.name);
    assert!(off.detail.contains("apply"), "{}", off.detail);

    let unreadable = escape_arguments_check(Err("Access is denied."));
    assert!(!unreadable.pass);
    assert!(unreadable.detail.contains("Access is denied."), "{}", unreadable.detail);
    assert!(unreadable.detail.contains("apply"), "{}", unreadable.detail);
}

/// Writing the values leaves `DefaultShellEscapeArguments` as the REG_DWORD 1 sshd reads as on,
/// whatever the value held before: 0, an empty string (whose two zero bytes sshd reads as 0), or
/// nothing.
#[cfg(windows)]
#[test]
fn writing_the_values_sets_the_escape_flag_to_dword_one() {
    use windows::Win32::System::Registry::{REG_DWORD, REG_SZ};
    const NAME: &str = "DefaultShellEscapeArguments";
    for before in [
        Some((REG_DWORD.0, 0u32.to_le_bytes().to_vec())),
        Some((REG_SZ.0, vec![0, 0])),
        None,
    ] {
        let key = TestKey::new("flag");
        let subkey = key.path();
        if let Some((reg_type, bytes)) = &before {
            super::set_value_hkcu(subkey, NAME, *reg_type, bytes);
        }
        super::set_hkcu(subkey, r"C:\x\ssh-broker.exe").unwrap();

        assert_eq!(
            super::read_dword_hkcu(subkey, NAME).unwrap(),
            1,
            "from {before:?}: a REG_DWORD of 1"
        );
        assert!(super::escape_arguments_hkcu(subkey).unwrap());
    }
}

/// The flag is read back right after it is written, before the option and the shell: a flag that
/// cannot be confirmed (off, or unreadable) must stop the writes while the old shell is still
/// registered, not after the shim is already `DefaultShell`.
#[cfg(windows)]
#[test]
fn a_flag_that_cannot_be_confirmed_stops_the_writes_before_the_option_and_the_shell() {
    use windows::Win32::Foundation::ERROR_ACCESS_DENIED;
    type Confirm = Box<dyn FnOnce() -> windows::core::Result<bool>>;
    let confirmations: [Confirm; 2] = [
        Box::new(|| Ok(false)),
        Box::new(|| Err(ERROR_ACCESS_DENIED.to_hresult().into())),
    ];
    for confirm in confirmations {
        let key = TestKey::new("unconfirmed");
        let subkey = key.path();
        super::set_hkcu_confirming(subkey, r"C:\x\ssh-broker.exe", confirm).unwrap_err();

        assert_eq!(
            super::read_dword_hkcu(subkey, "DefaultShellEscapeArguments").unwrap(),
            1
        );
        assert!(
            super::read_string_hkcu(subkey, "DefaultShellCommandOption").is_err(),
            "the option may not be written"
        );
        assert!(
            super::read_string_hkcu(subkey, "DefaultShell").is_err(),
            "the shell may not be written"
        );
    }
}

/// Round-trips the pair through a throwaway subkey on Windows (plan Task 7.1), exercising the
/// real Reg* FFI under HKCU so it needs no elevation (the production path is identical but
/// targets HKLM). Runs on a real Windows host; fails loudly on any Reg* error (never skips).
#[cfg(windows)]
#[test]
fn writes_and_reads_default_shell_pair() {
    let key = TestKey::new("pair");
    let subkey = key.path();
    let exe = r"C:\x\ssh-broker.exe";
    super::set_hkcu(subkey, exe).unwrap();
    let (shell, opt) = super::read_hkcu(subkey).unwrap();
    assert_eq!(shell, exe);
    assert_eq!(opt, "-c");
}

/// `escape_arguments` mirrors how sshd reads `DefaultShellEscapeArguments` (`pwd.c`
/// `set_defaultshell`): the value is read into four bytes whatever its type, and zero turns
/// escaping off. A missing key or value leaves escaping on. Runs under a throwaway HKCU key, so
/// it needs no elevation; the production path is identical but targets HKLM.
#[cfg(windows)]
#[test]
fn escape_arguments_reads_the_value_the_way_sshd_does() {
    use windows::Win32::System::Registry::{REG_DWORD, REG_SZ};
    const NAME: &str = "DefaultShellEscapeArguments";
    let key = TestKey::new("escape");
    let subkey = key.path();
    let dword = |v: u32| super::set_value_hkcu(subkey, NAME, REG_DWORD.0, &v.to_le_bytes());

    let absent_key = super::escape_arguments_hkcu(subkey);
    super::set_value_hkcu(subkey, "Other", REG_DWORD.0, &1u32.to_le_bytes());
    let absent_value = super::escape_arguments_hkcu(subkey);
    dword(0);
    let zero = super::escape_arguments_hkcu(subkey);
    dword(1);
    let one = super::escape_arguments_hkcu(subkey);
    dword(7);
    let seven = super::escape_arguments_hkcu(subkey);
    // The four bytes of a REG_SZ "0" and its terminator read as 0x30, which is nonzero.
    let sz: Vec<u8> = "0\0".encode_utf16().flat_map(u16::to_le_bytes).collect();
    super::set_value_hkcu(subkey, NAME, REG_SZ.0, &sz);
    let string_zero = super::escape_arguments_hkcu(subkey);

    assert!(absent_key.unwrap(), "a missing key leaves escaping on");
    assert!(absent_value.unwrap(), "a missing value leaves escaping on");
    assert!(!zero.unwrap(), "0 turns escaping off");
    assert!(one.unwrap(), "1 leaves it on");
    assert!(seven.unwrap(), "any nonzero value leaves it on");
    assert!(string_zero.unwrap(), "a string is read as raw bytes");
}

/// sshd's `escape_option` starts at 1 and `RegQueryValueExW` writes only the bytes the value has
/// (`pwd.c:83`, `:91`), so a value shorter than four bytes leaves the rest at their start. An
/// empty value leaves 1 (on); a lone zero byte clears the low byte (off).
#[cfg(windows)]
#[test]
fn escape_arguments_keeps_sshds_start_value_under_a_short_value() {
    use windows::Win32::System::Registry::REG_BINARY;
    const NAME: &str = "DefaultShellEscapeArguments";
    let key = TestKey::new("escape-short");
    let subkey = key.path();
    super::set_value_hkcu(subkey, NAME, REG_BINARY.0, &[]);
    let empty = super::escape_arguments_hkcu(subkey);
    super::set_value_hkcu(subkey, NAME, REG_BINARY.0, &[0]);
    let one_zero_byte = super::escape_arguments_hkcu(subkey);

    assert!(
        empty.unwrap(),
        "a zero-length value leaves sshd's start value, which is on"
    );
    assert!(
        !one_zero_byte.unwrap(),
        "one zero byte clears the low byte, which is off"
    );
}

/// A value longer than four bytes makes sshd's read fail with `ERROR_MORE_DATA`, which leaves
/// escaping on (`pwd.c:91-92`). The setting is then known, so it is an answer, not an error to
/// report.
#[cfg(windows)]
#[test]
fn escape_arguments_treats_a_value_longer_than_four_bytes_as_on() {
    use windows::Win32::System::Registry::REG_BINARY;
    let key = TestKey::new("escape-long");
    let subkey = key.path();
    super::set_value_hkcu(subkey, "DefaultShellEscapeArguments", REG_BINARY.0, &[0u8; 8]);
    let read = super::escape_arguments_hkcu(subkey);

    assert!(
        read.unwrap(),
        "an eight-byte value fails sshd's read, which leaves it on"
    );
}

/// A read that fails for any other reason leaves the real setting unknown, so it is an error the
/// caller can report. `ERROR_MORE_DATA` is the one failure that is an answer (above).
#[cfg(windows)]
#[test]
fn escape_arguments_reports_a_read_that_fails_for_another_reason() {
    use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_MORE_DATA, ERROR_SUCCESS};
    assert!(super::escape_arguments_from_status(ERROR_ACCESS_DENIED, [0; 4]).is_err());
    assert!(super::escape_arguments_from_status(ERROR_MORE_DATA, [0; 4]).unwrap());
    assert!(!super::escape_arguments_from_status(ERROR_SUCCESS, [0; 4]).unwrap());
    assert!(super::escape_arguments_from_status(ERROR_SUCCESS, [1, 0, 0, 0]).unwrap());
}

/// `apply` reads the four values the way sshd does before it overwrites them. Under a key of the
/// test's own (HKCU, deleted afterwards); CI only, as it writes the registry.
#[cfg(windows)]
#[test]
fn the_four_shell_values_are_read_as_sshd_reads_them() {
    use super::SshdShell;
    use windows::Win32::System::Registry::{REG_DWORD, REG_EXPAND_SZ, REG_SZ};
    let sz = |text: &str| -> Vec<u8> {
        text.encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(u16::to_le_bytes)
            .collect()
    };

    // No key at all: nothing to carry, and sshd's defaults.
    let key = TestKey::new("sshd-none");
    assert_eq!(super::read_sshd_shell_hkcu(key.path()).unwrap(), SshdShell::none());

    // All four, with an argument string longer than a fixed buffer of 512 would hold.
    let long = format!("-File {}", "x".repeat(2000));
    let key = TestKey::new("sshd-all");
    let sub = key.path();
    super::set_value_hkcu(
        sub,
        "DefaultShell",
        REG_SZ.0,
        &sz(r"C:\Program Files\PowerShell\7\pwsh.exe"),
    );
    super::set_value_hkcu(sub, "DefaultShellCommandOption", REG_SZ.0, &sz("-Command"));
    super::set_value_hkcu(sub, "DefaultShellArguments", REG_SZ.0, &sz(&long));
    super::set_value_hkcu(sub, "DefaultShellEscapeArguments", REG_DWORD.0, &0u32.to_le_bytes());
    let got = super::read_sshd_shell_hkcu(sub).unwrap();
    assert_eq!(got.shell.as_deref(), Some(r"C:\Program Files\PowerShell\7\pwsh.exe"));
    assert_eq!(got.command_option.as_deref(), Some("-Command"));
    assert_eq!(got.arguments.as_deref(), Some(long.as_str()));
    assert!(!got.escape_arguments);

    // Empty values count as absent, and the options are not expanded.
    let key = TestKey::new("sshd-empty");
    let sub = key.path();
    super::set_value_hkcu(sub, "DefaultShell", REG_EXPAND_SZ.0, &sz(r"%ProgramFiles%\x\sh.exe"));
    super::set_value_hkcu(sub, "DefaultShellCommandOption", REG_SZ.0, &sz(""));
    let got = super::read_sshd_shell_hkcu(sub).unwrap();
    assert_eq!(got.shell.as_deref(), Some(r"%ProgramFiles%\x\sh.exe"));
    assert_eq!(
        (got.command_option, got.arguments, got.escape_arguments),
        (None, None, true)
    );

    // With no DefaultShell, sshd ignores the rest.
    let key = TestKey::new("sshd-orphans");
    let sub = key.path();
    super::set_value_hkcu(sub, "DefaultShellCommandOption", REG_SZ.0, &sz("-x"));
    super::set_value_hkcu(sub, "DefaultShellEscapeArguments", REG_DWORD.0, &0u32.to_le_bytes());
    assert_eq!(super::read_sshd_shell_hkcu(sub).unwrap(), SshdShell::none());
}

/// sshd hands `RegQueryValueExW` a PATH_MAX (32768) buffer but passes `_countof` of it, a count of
/// wide characters, as the size in BYTES (`pwd.c` `set_defaultshell`). A value of more than 32768
/// bytes, terminator included, fails with `ERROR_MORE_DATA`, and sshd then treats it as absent.
/// sshd checks only the status, never the type: a value of any type is read as its bytes.
#[cfg(windows)]
#[test]
fn a_value_that_does_not_fit_sshds_buffer_is_absent() {
    use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_SUCCESS};
    let read = |status, text: &str| {
        let buffer: Vec<u16> = text.encode_utf16().collect();
        super::sshd_string_from_status("X", status, &buffer, (buffer.len() * 2) as u32)
    };

    assert_eq!(super::SSHD_VALUE_BYTES, 32768);
    assert_eq!(read(ERROR_MORE_DATA, "").unwrap(), None);
    assert_eq!(read(ERROR_FILE_NOT_FOUND, "").unwrap(), None);
    assert!(read(ERROR_ACCESS_DENIED, "").is_err());
    assert_eq!(read(ERROR_SUCCESS, "abc\0").unwrap().as_deref(), Some("abc"));
    // A value stored without its terminator, and text after an embedded one, which a C string
    // never reaches.
    assert_eq!(read(ERROR_SUCCESS, "abc").unwrap().as_deref(), Some("abc"));
    assert_eq!(read(ERROR_SUCCESS, "ab\0cd\0").unwrap().as_deref(), Some("ab"));
    assert_eq!(read(ERROR_SUCCESS, "\0").unwrap(), None);
}

/// sshd reads each of the three values as raw bytes, whatever the type: a REG_DWORD is two wide
/// characters, a REG_EXPAND_SZ is its text with the `%VAR%` left in (sshd does not expand it), and the
/// 32768-byte rule holds for a REG_BINARY too. The carry takes what sshd would run. Under a key of
/// the test's own (HKCU, deleted afterwards); CI only, as it writes the registry.
#[cfg(windows)]
#[test]
fn a_value_of_another_type_is_read_as_the_text_sshd_runs() {
    use windows::Win32::System::Registry::{REG_BINARY, REG_DWORD, REG_EXPAND_SZ, REG_SZ};
    let sz = |text: &str| -> Vec<u8> {
        text.encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(u16::to_le_bytes)
            .collect()
    };

    // 0x0058_0041 is the wide characters "A" and "X".
    let key = TestKey::new("sshd-dword");
    let sub = key.path();
    super::set_value_hkcu(sub, "DefaultShell", REG_DWORD.0, &0x0058_0041u32.to_le_bytes());
    super::set_value_hkcu(
        sub,
        "DefaultShellCommandOption",
        REG_DWORD.0,
        &0x0042_0000u32.to_le_bytes(),
    );
    super::set_value_hkcu(sub, "DefaultShellArguments", REG_BINARY.0, &sz("-x"));
    let got = super::read_sshd_shell_hkcu(sub).unwrap();
    assert_eq!(got.shell.as_deref(), Some("AX"), "a DWORD is two wide characters");
    assert_eq!(got.command_option, None, "a DWORD whose first character is 0 is empty");
    assert_eq!(got.arguments.as_deref(), Some("-x"));

    let key = TestKey::new("sshd-expand");
    let sub = key.path();
    super::set_value_hkcu(sub, "DefaultShell", REG_EXPAND_SZ.0, &sz(r"%ProgramFiles%\x\sh.exe"));
    super::set_value_hkcu(sub, "DefaultShellCommandOption", REG_EXPAND_SZ.0, &sz("%OPT%"));
    super::set_value_hkcu(sub, "DefaultShellArguments", REG_EXPAND_SZ.0, &sz("%ARGS%"));
    let got = super::read_sshd_shell_hkcu(sub).unwrap();
    assert_eq!(got.shell.as_deref(), Some(r"%ProgramFiles%\x\sh.exe"));
    assert_eq!(got.command_option.as_deref(), Some("%OPT%"));
    assert_eq!(got.arguments.as_deref(), Some("%ARGS%"));

    // 32768 bytes of a REG_BINARY are read, 32770 are not.
    let key = TestKey::new("sshd-binary");
    let sub = key.path();
    super::set_value_hkcu(sub, "DefaultShell", REG_SZ.0, &sz(r"C:\x\sh.exe"));
    super::set_value_hkcu(sub, "DefaultShellArguments", REG_BINARY.0, &vec![b'a'; 32768]);
    super::set_value_hkcu(sub, "DefaultShellCommandOption", REG_BINARY.0, &vec![b'a'; 32770]);
    let got = super::read_sshd_shell_hkcu(sub).unwrap();
    assert_eq!(got.arguments.map(|text| text.chars().count()), Some(16384));
    assert_eq!(got.command_option, None);
}

/// After `apply` carries `DefaultShellArguments` into the config it removes the value: left, sshd
/// would hand the arguments to the shim before `-c`. Removing a value that is not there, or under a
/// key that is not there, is not an error, and no other value goes. Under a key of the test's own
/// (HKCU, deleted afterwards); CI only, as it writes the registry.
#[cfg(windows)]
#[test]
fn removing_the_shell_arguments_removes_that_value_and_nothing_else() {
    use windows::Win32::System::Registry::REG_SZ;
    let sz = |text: &str| -> Vec<u8> {
        text.encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(u16::to_le_bytes)
            .collect()
    };
    let key = TestKey::new("remove-args");
    let sub = key.path();
    super::set_value_hkcu(sub, "DefaultShell", REG_SZ.0, &sz(r"C:\x\sh.exe"));
    super::set_value_hkcu(sub, "DefaultShellArguments", REG_SZ.0, &sz("-NoLogo"));

    super::remove_shell_arguments_hkcu(sub).unwrap();
    let got = super::read_sshd_shell_hkcu(sub).unwrap();
    assert_eq!(got.arguments, None);
    assert_eq!(got.shell.as_deref(), Some(r"C:\x\sh.exe"));

    super::remove_shell_arguments_hkcu(sub).unwrap();
    let missing_key = TestKey::new("remove-args-no-key");
    super::remove_shell_arguments_hkcu(missing_key.path()).unwrap();
}

/// The three string values at sshd's boundary: 16383 characters plus the terminator is 32768 bytes
/// and is read; one more character is not, and reads as absent. A `DefaultShell` that does not fit
/// makes sshd run the system `cmd.exe` and ignore the other three values. Under a key of the
/// test's own (HKCU, deleted afterwards); CI only, as it writes the registry.
#[cfg(windows)]
#[test]
fn string_values_at_sshds_buffer_boundary_are_read_and_one_character_more_is_absent() {
    use super::SshdShell;
    use windows::Win32::System::Registry::{REG_DWORD, REG_SZ};
    let sz = |text: &str| -> Vec<u8> {
        text.encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(u16::to_le_bytes)
            .collect()
    };
    let fits = "x".repeat(16383);
    let too_long = "x".repeat(16384);

    let key = TestKey::new("sshd-fits");
    let sub = key.path();
    super::set_value_hkcu(sub, "DefaultShell", REG_SZ.0, &sz(&fits));
    super::set_value_hkcu(sub, "DefaultShellCommandOption", REG_SZ.0, &sz(&fits));
    super::set_value_hkcu(sub, "DefaultShellArguments", REG_SZ.0, &sz(&fits));
    let got = super::read_sshd_shell_hkcu(sub).unwrap();
    assert_eq!(got.shell.as_deref(), Some(fits.as_str()));
    assert_eq!(got.command_option.as_deref(), Some(fits.as_str()));
    assert_eq!(got.arguments.as_deref(), Some(fits.as_str()));

    // The option and the arguments that do not fit are absent; the shell is still read.
    let key = TestKey::new("sshd-options-too-long");
    let sub = key.path();
    super::set_value_hkcu(sub, "DefaultShell", REG_SZ.0, &sz(r"C:\x\sh.exe"));
    super::set_value_hkcu(sub, "DefaultShellCommandOption", REG_SZ.0, &sz(&too_long));
    super::set_value_hkcu(sub, "DefaultShellArguments", REG_SZ.0, &sz(&too_long));
    super::set_value_hkcu(sub, "DefaultShellEscapeArguments", REG_DWORD.0, &0u32.to_le_bytes());
    let got = super::read_sshd_shell_hkcu(sub).unwrap();
    assert_eq!(
        (
            got.shell.as_deref(),
            got.command_option,
            got.arguments,
            got.escape_arguments
        ),
        (Some(r"C:\x\sh.exe"), None, None, false)
    );

    // A shell that does not fit is no shell, and the companions go with it.
    let key = TestKey::new("sshd-shell-too-long");
    let sub = key.path();
    super::set_value_hkcu(sub, "DefaultShell", REG_SZ.0, &sz(&too_long));
    super::set_value_hkcu(sub, "DefaultShellCommandOption", REG_SZ.0, &sz("-Command"));
    super::set_value_hkcu(sub, "DefaultShellArguments", REG_SZ.0, &sz("-NoLogo"));
    super::set_value_hkcu(sub, "DefaultShellEscapeArguments", REG_DWORD.0, &0u32.to_le_bytes());
    assert_eq!(super::read_sshd_shell_hkcu(sub).unwrap(), SshdShell::none());
}

/// sshd's service `ImagePath` is a `REG_EXPAND_SZ` that names the variables it uses: the directory
/// sshd runs from is the expanded value's.
#[test]
fn the_image_path_is_read_with_its_variables_expanded_and_is_none_when_absent() {
    use windows::Win32::System::Registry::REG_EXPAND_SZ;
    let key = TestKey::new("image-path");
    let subkey = key.path();
    assert_eq!(super::read_image_path_hkcu(subkey).unwrap(), None, "no key");
    super::set_value_hkcu(subkey, "Other", REG_EXPAND_SZ.0, &[0, 0]);
    assert_eq!(super::read_image_path_hkcu(subkey).unwrap(), None, "no value");

    let text = r#""%SystemRoot%\OpenSSH\sshd.exe" -x"#;
    let bytes: Vec<u8> = text.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect();
    super::set_value_hkcu(subkey, "ImagePath", REG_EXPAND_SZ.0, &bytes);
    let system_root = std::env::var("SystemRoot").expect("SystemRoot is set");
    assert_eq!(
        super::read_image_path_hkcu(subkey).unwrap().as_deref(),
        Some(format!(r#""{system_root}\OpenSSH\sshd.exe" -x"#).as_str())
    );
}
