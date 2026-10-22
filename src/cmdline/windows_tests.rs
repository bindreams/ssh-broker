use ::windows::Win32::Foundation::ERROR_ACCESS_DENIED;

use super::{detect_piped_with, piped_encoding};
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
