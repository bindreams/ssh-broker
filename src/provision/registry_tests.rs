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
/// `set_defaultshell`): the value is read into four bytes whatever its type, zero turns escaping
/// off, and any failure to read leaves it on. Runs under a throwaway HKCU key, so it needs no
/// elevation; the production path is identical but targets HKLM.
#[cfg(windows)]
#[test]
fn escape_arguments_reads_the_value_the_way_sshd_does() {
    use windows::Win32::System::Registry::{REG_DWORD, REG_SZ};
    const NAME: &str = "DefaultShellEscapeArguments";
    let subkey = format!(r"SOFTWARE\ssh-broker-escape-test-{}", std::process::id());
    let dword = |v: u32| super::set_value_hkcu(&subkey, NAME, REG_DWORD.0, &v.to_le_bytes());

    let absent = super::escape_arguments_hkcu(&subkey);
    dword(0);
    let zero = super::escape_arguments_hkcu(&subkey);
    dword(1);
    let one = super::escape_arguments_hkcu(&subkey);
    dword(7);
    let seven = super::escape_arguments_hkcu(&subkey);
    // Too big for four bytes, so sshd's read fails and escaping stays on.
    let sz: Vec<u8> = "0\0".encode_utf16().flat_map(u16::to_le_bytes).collect();
    super::set_value_hkcu(&subkey, NAME, REG_SZ.0, &sz);
    let string_zero = super::escape_arguments_hkcu(&subkey);
    super::delete_hkcu(&subkey);

    assert!(absent, "a missing key or value leaves escaping on");
    assert!(!zero, "0 turns escaping off");
    assert!(one, "1 leaves it on");
    assert!(seven, "any nonzero value leaves it on");
    assert!(string_zero, "a string that does not fit four bytes leaves it on");
}
