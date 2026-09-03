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
