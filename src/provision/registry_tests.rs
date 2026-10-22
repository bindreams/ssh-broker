//! Tests for the DefaultShell pair: the pure builder (host) + the Reg* round-trip (Windows).
use super::registry_pair;

#[test]
fn pair_is_option_first_then_shell() {
    let pair = registry_pair(r"C:\ProgramData\ssh-broker\ssh-broker.exe");
    assert_eq!(pair[0], ("DefaultShellCommandOption", "-c".to_string()));
    assert_eq!(pair[1].0, "DefaultShell");
    assert_eq!(pair[1].1, r"C:\ProgramData\ssh-broker\ssh-broker.exe");
}

/// Round-trips the pair through a throwaway subkey on Windows (plan Task 7.1), exercising the
/// real Reg* FFI under HKCU so it needs no elevation (the production path is identical but
/// targets HKLM). Runs on a real Windows host; fails loudly on any Reg* error (never skips).
#[cfg(windows)]
#[test]
fn writes_and_reads_default_shell_pair() {
    let subkey = format!(r"SOFTWARE\ssh-broker-test-{}", std::process::id());
    let exe = r"C:\x\ssh-broker.exe";
    super::set_hkcu(&subkey, exe).unwrap();
    let (shell, opt) = super::read_hkcu(&subkey).unwrap();
    super::delete_hkcu(&subkey);
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
    let subkey = format!(r"SOFTWARE\ssh-broker-escape-test-{}", std::process::id());
    let dword = |v: u32| super::set_value_hkcu(&subkey, NAME, REG_DWORD.0, &v.to_le_bytes());

    let absent_key = super::escape_arguments_hkcu(&subkey);
    super::set_value_hkcu(&subkey, "Other", REG_DWORD.0, &1u32.to_le_bytes());
    let absent_value = super::escape_arguments_hkcu(&subkey);
    dword(0);
    let zero = super::escape_arguments_hkcu(&subkey);
    dword(1);
    let one = super::escape_arguments_hkcu(&subkey);
    dword(7);
    let seven = super::escape_arguments_hkcu(&subkey);
    // The four bytes of a REG_SZ "0" and its terminator read as 0x30, which is nonzero.
    let sz: Vec<u8> = "0\0".encode_utf16().flat_map(u16::to_le_bytes).collect();
    super::set_value_hkcu(&subkey, NAME, REG_SZ.0, &sz);
    let string_zero = super::escape_arguments_hkcu(&subkey);
    super::delete_hkcu(&subkey);

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
    let subkey = format!(r"SOFTWARE\ssh-broker-escape-short-test-{}", std::process::id());
    super::set_value_hkcu(&subkey, NAME, REG_BINARY.0, &[]);
    let empty = super::escape_arguments_hkcu(&subkey);
    super::set_value_hkcu(&subkey, NAME, REG_BINARY.0, &[0]);
    let one_zero_byte = super::escape_arguments_hkcu(&subkey);
    super::delete_hkcu(&subkey);

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
    let subkey = format!(r"SOFTWARE\ssh-broker-escape-long-test-{}", std::process::id());
    super::set_value_hkcu(&subkey, "DefaultShellEscapeArguments", REG_BINARY.0, &[0u8; 8]);
    let read = super::escape_arguments_hkcu(&subkey);
    super::delete_hkcu(&subkey);

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

/// `default_shell_path` reads `DefaultShell` as sshd does (`pwd.c:78-80`): whatever its type, as
/// text up to the first NUL. A missing key, a missing value and an empty value all mean no
/// `DefaultShell` is set (sshd then uses `cmd.exe`).
#[cfg(windows)]
#[test]
fn default_shell_path_reads_the_value_the_way_sshd_does() {
    use windows::Win32::System::Registry::{REG_EXPAND_SZ, REG_SZ};
    let subkey = format!(r"SOFTWARE\ssh-broker-shell-path-test-{}", std::process::id());
    let utf16 = |s: &str| -> Vec<u8> { s.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect() };

    let absent_key = super::default_shell_path_hkcu(&subkey);
    super::set_value_hkcu(&subkey, "Other", REG_SZ.0, &utf16("x"));
    let absent_value = super::default_shell_path_hkcu(&subkey);
    super::set_value_hkcu(&subkey, "DefaultShell", REG_SZ.0, &utf16(""));
    let empty = super::default_shell_path_hkcu(&subkey);
    let long = format!(r"C:\{}\ssh-broker.exe", "d".repeat(600));
    super::set_value_hkcu(&subkey, "DefaultShell", REG_SZ.0, &utf16(&long));
    let long_read = super::default_shell_path_hkcu(&subkey);
    super::set_value_hkcu(
        &subkey,
        "DefaultShell",
        REG_EXPAND_SZ.0,
        &utf16(r"%ProgramFiles%\x.exe"),
    );
    let expand = super::default_shell_path_hkcu(&subkey);
    super::delete_hkcu(&subkey);

    assert_eq!(absent_key.unwrap(), None);
    assert_eq!(absent_value.unwrap(), None);
    assert_eq!(empty.unwrap(), None);
    assert_eq!(long_read.unwrap(), Some(long), "no fixed buffer size");
    assert_eq!(
        expand.unwrap().as_deref(),
        Some(r"%ProgramFiles%\x.exe"),
        "not expanded"
    );
}
