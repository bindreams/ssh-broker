use ::windows::Win32::Foundation::ERROR_ACCESS_DENIED;

use super::{detect_piped, detect_piped_with, piped_encoding};
use crate::cmdline::Encoding;

#[test]
fn a_readable_setting_picks_the_form_without_a_warning() {
    let on = piped_encoding(Ok(true));
    assert_eq!((on.encoding, on.warning), (Encoding::Escaped, None));
    let off = piped_encoding(Ok(false));
    assert_eq!((off.encoding, off.warning), (Encoding::Wrapped, None));
}

/// sshd keeps escaping on when it cannot read the value, so the shim assumes the same, and says
/// so: if the value is really 0, the command is then decoded as the wrong form.
#[test]
fn an_unreadable_setting_assumes_escaped_and_says_so() {
    let error = ::windows::core::Error::from(ERROR_ACCESS_DENIED.to_hresult());
    let detected = piped_encoding(Err(error));

    assert_eq!(detected.encoding, Encoding::Escaped);
    let warning = detected.warning.expect("an unreadable setting must be reported");
    assert!(warning.contains("DefaultShellEscapeArguments"), "{warning}");
    assert!(warning.contains("Access is denied"), "names the cause: {warning}");
    assert!(warning.contains("assum"), "names the assumption: {warning}");
}

/// sshd decides the form from the DefaultShell path first (`w32-doexec.c:370-371`): the registry
/// flag only matters for a path that is none of cmd, PowerShell, ssh-shellhost, bash or cygwin.
#[test]
fn the_default_shell_path_decides_the_form_before_the_registry_flag() {
    let flag_off = || Ok(false);
    let unread = || -> ::windows::core::Result<bool> { panic!("the flag must not be read for this path") };

    // The flag says wrapped, but PowerShell, bash and cygwin are always escaped.
    for path in [r"c:\x\powershell.exe", r"c:\x\bash.exe", r"c:\cygwin\sh.exe"] {
        let d = detect_piped_with(path, flag_off);
        assert_eq!((d.encoding, d.warning), (Encoding::Escaped, None), "{path}");
    }
    // cmd and ssh-shellhost are always wrapped, and the flag is not read.
    for path in [r"c:\windows\system32\cmd.exe", r"c:\x\ssh-shellhost.exe"] {
        let d = detect_piped_with(path, unread);
        assert_eq!((d.encoding, d.warning), (Encoding::Wrapped, None), "{path}");
    }
    // Any other path follows the flag.
    let d = detect_piped_with(r"c:\programdata\ssh-broker\ssh-broker.exe", flag_off);
    assert_eq!(d.encoding, Encoding::Wrapped);
    let d = detect_piped_with(r"c:\programdata\ssh-broker\ssh-broker.exe", || Ok(true));
    assert_eq!(d.encoding, Encoding::Escaped);
}

#[test]
fn an_unreadable_flag_warns_only_when_the_flag_decides() {
    let denied = || Err(::windows::core::Error::from(ERROR_ACCESS_DENIED.to_hresult()));
    assert!(detect_piped_with(r"c:\x\ssh-broker.exe", denied).warning.is_some());
    assert!(detect_piped_with(r"c:\x\powershell.exe", denied).warning.is_none());
}

// The path the form is classified from =====

fn denied() -> ::windows::core::Error {
    ::windows::core::Error::from(ERROR_ACCESS_DENIED.to_hresult())
}

fn own(path: &str) -> Result<String, std::io::Error> {
    Ok(path.to_string())
}

const NO_FLAG: fn() -> ::windows::core::Result<bool> = || panic!("the flag must not be read for this path");

/// A registered `DefaultShell` is the path sshd classified; the shim's own path is not consulted.
#[test]
fn a_registered_shell_decides_over_the_shims_own_path() {
    let d = detect_piped(
        own(r"c:\x\powershell.exe"),
        || Ok(Some(r"c:\windows\system32\cmd.exe".to_string())),
        NO_FLAG,
    );
    assert_eq!((d.encoding, d.warning), (Encoding::Wrapped, None));
}

/// With no `DefaultShell`, sshd runs `cmd.exe`, and the shim runs only because sshd launched it
/// as that shell, so its own path stands in.
#[test]
fn without_a_registered_shell_the_shims_own_path_stands_in() {
    let d = detect_piped(own(r"c:\x\ssh-shellhost.exe"), || Ok(None), NO_FLAG);
    assert_eq!((d.encoding, d.warning), (Encoding::Wrapped, None));
    let d = detect_piped(own(r"c:\x\bash.exe"), || Ok(None), NO_FLAG);
    assert_eq!((d.encoding, d.warning), (Encoding::Escaped, None));
    let d = detect_piped(own(r"c:\x\ssh-broker.exe"), || Ok(None), || Ok(false));
    assert_eq!((d.encoding, d.warning), (Encoding::Wrapped, None), "the flag decides");
}

/// An unreadable `DefaultShell` is reported, and the shim's own path stands in for it; if the
/// flag is unreadable too, both are in the one warning.
#[test]
fn an_unreadable_shell_warns_and_merges_with_an_unreadable_flag() {
    let d = detect_piped(own(r"c:\x\ssh-shellhost.exe"), || Err(denied()), NO_FLAG);
    assert_eq!(d.encoding, Encoding::Wrapped);
    let warning = d.warning.expect("an unreadable DefaultShell must be reported");
    assert!(
        warning.contains("DefaultShell") && warning.contains("Access is denied"),
        "{warning}"
    );
    assert!(!warning.contains("DefaultShellEscapeArguments"), "{warning}");

    let d = detect_piped(own(r"c:\x\ssh-broker.exe"), || Err(denied()), || Err(denied()));
    assert_eq!(d.encoding, Encoding::Escaped);
    let warning = d.warning.expect("both failures must be reported");
    let shell = warning.find("DefaultShell (").expect(&warning);
    let flag = warning.find("DefaultShellEscapeArguments").expect(&warning);
    assert!(shell < flag, "{warning}");
    assert!(warning.contains("; "), "{warning}");
}

/// `current_exe` failing leaves no path to stand in. That matters only when no registered shell
/// supplies one, and then the warning says what was assumed.
#[test]
fn an_unknown_own_path_warns_only_when_it_was_needed() {
    let unknown = || Err(std::io::Error::other("no module path"));

    let d = detect_piped(
        unknown(),
        || Ok(Some(r"c:\windows\system32\cmd.exe".to_string())),
        NO_FLAG,
    );
    assert_eq!((d.encoding, d.warning), (Encoding::Wrapped, None));

    let d = detect_piped(unknown(), || Ok(None), || Ok(false));
    assert_eq!(d.encoding, Encoding::Wrapped, "the flag decides for an unknown path");
    let warning = d.warning.expect("an unknown own path must be reported");
    assert!(
        warning.contains("no module path") && warning.contains("assum"),
        "{warning}"
    );
}
